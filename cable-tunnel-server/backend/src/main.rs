use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Request, Response, Server, StatusCode,
};

use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    error::CapacityError,
    protocol::{Message, Role},
};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Rx = UnboundedReceiver<Message>;
type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<TunnelId, Tunnel>>>;

/// Maximum amount of time a tunnel may be open for.
const TUNNEL_TTL: Duration = Duration::from_secs(120);

/// Maximum amount of messages that may be sent to a channel.
const MAX_MESSAGE_COUNT: u8 = 16;

/// Maximum message length.
const MAX_MESSAGE_LENGTH: usize = 65_535;

struct Tunnel {
    authenticator_rx: Rx,
    initiator_tx: Tx,
}

impl Tunnel {
    pub fn new(authenticator_rx: Rx, initiator_tx: Tx) -> Self {
        Self {
            authenticator_rx,
            initiator_tx,
        }
    }
}

async fn connect_stream(ws_stream: WebSocketStream<Upgraded>, tx: Tx, rx: Rx, addr: SocketAddr) {
    info!("{addr}: WebSocket connected");
    let (outgoing, incoming) = ws_stream.split();
    let mut message_count = 0u8;

    // TODO: add some limits on the size and number of messages
    let forwarder = incoming.try_for_each(|msg| {
        let msg = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => {
                info!("{addr}: closing connection");
                // Send a closing frame to the peer
                tx.unbounded_send(Message::Close(None)).ok();
                return future::err(tungstenite::Error::ConnectionClosed);
            }
            Message::Text(_) => {
                // Text messages are not allowed.
                error!("{addr}: text messages are not allowed");
                tx.unbounded_send(Message::Close(None)).ok();
                return future::err(tungstenite::Error::ConnectionClosed);
            }
            Message::Ping(_) | Message::Pong(_) => {
                // Ignore PING/PONG messages, and don't count them towards
                // quota.
                return future::ok(());
            }
            Message::Frame(_) => unreachable!(),
        };

        if msg.len() >= MAX_MESSAGE_LENGTH {
            error!("{addr}: maximum message length ({MAX_MESSAGE_LENGTH}) exceeded");
            tx.unbounded_send(Message::Close(None)).ok();
            return future::err(
                CapacityError::MessageTooLong {
                    size: msg.len(),
                    max_size: MAX_MESSAGE_LENGTH,
                }
                .into(),
            );
        }

        // Count the message towards the quota
        message_count += 1;

        if message_count > MAX_MESSAGE_COUNT {
            error!("{addr}: maximum message count ({MAX_MESSAGE_COUNT}) reached");
            tx.unbounded_send(Message::Close(None)).ok();
            return future::err(tungstenite::Error::ConnectionClosed);
        }

        info!("{addr}: message {message_count}: {}", hex::encode(&msg));
        tx.unbounded_send(Message::Binary(msg)).unwrap();

        future::ok(())
    });

    let receiver = rx.map(Ok).forward(outgoing);

    pin_mut!(forwarder, receiver);
    future::select(forwarder, receiver).await;

    info!("{addr}: finishing");
}

async fn handle_request(
    peer_map: PeerMap,
    mut req: Request<Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    info!("{addr}: {} {}", req.method(), req.uri().path());

    let (res, path) = match Router::route(&req) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(res, path) => (res, path),
    };

    let (tx, rx) = match path.method {
        CableMethod::New => {
            let mut lock = peer_map.lock().unwrap();
            if lock.contains_key(&path.tunnel_id) {
                error!("{addr}: tunnel already exists: {path}");
                return Ok(Response::builder()
                    .status(StatusCode::CONFLICT)
                    .body(Body::empty())
                    .unwrap());
            }

            // Create both channels in the authenticator side, as the first one here
            let (authenticator_tx, authenticator_rx) = unbounded();
            let (initiator_tx, initiator_rx) = unbounded();

            let tunnel = Tunnel::new(authenticator_rx, initiator_tx);
            lock.insert(path.tunnel_id, tunnel);

            drop(lock);

            (authenticator_tx, initiator_rx)
        }

        CableMethod::Connect => {
            let mut lock = peer_map.lock().unwrap();
            if let Some(c) = lock.remove(&path.tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("{addr}: no peer available for tunnel: {path}");
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap());
            }
        }
    };

    tokio::task::spawn(async move {
        tokio::time::timeout(TUNNEL_TTL, async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let ws_stream =
                        WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
                    connect_stream(ws_stream, tx, rx, addr).await;
                }
                Err(e) => error!("{addr}: upgrade error: {e}"),
            }
        })
        .await
        .map_err(|_| {
            info!("{addr}: connection TTL reached, disconnecting");
        })
        .ok();

        if path.method == CableMethod::New {
            // Remove any stale entry
            peer_map.lock().unwrap().remove(&path.tunnel_id);
        }
    });

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), hyper::Error> {
    tracing_subscriber::fmt::init();
    let state = PeerMap::new(Mutex::new(HashMap::new()));

    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8081".to_string())
        .parse()
        .unwrap();

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let state = state.clone();
        let service = service_fn(move |req| handle_request(state.clone(), req, remote_addr));
        async { Ok::<_, Infallible>(service) }
    });

    info!("Starting server on {:?}", addr);
    let server = Server::bind(&addr).serve(make_svc);

    server.await?;

    Ok::<_, hyper::Error>(())
}
