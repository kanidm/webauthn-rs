use std::{
    collections::HashMap, convert::Infallible, error::Error as StdError, net::SocketAddr,
    sync::Arc, time::Duration,
};

use clap::Parser;

use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::CONTENT_TYPE,
    http::HeaderValue,
    upgrade::Upgraded,
    Request, Response, StatusCode,
};

use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio::sync::RwLock;

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
type PeerMap = RwLock<HashMap<TunnelId, Tunnel>>;

struct ServerState {
    flags: Flags,
    peer_map: PeerMap,
}

#[derive(Debug, Parser)]
#[clap(about = "caBLE tunnel server backend")]
pub struct Flags {
    /// Bind address and port for the server.
    #[clap(long, default_value = "127.0.0.1:8081", value_name = "ADDR")]
    bind_address: String,

    /// If set, the routing ID to report on new tunnel requests. This is a 3
    /// byte, base-16 encoded value (eg: `123456`).
    ///
    /// Note: the routing ID provided in connect requests is never checked
    /// against this value.
    #[clap(long, default_value = "000000", value_parser = parse_hex::<RoutingId>, value_name = "ID")]
    routing_id: RoutingId,

    /// If set, the required Origin for requests sent to the WebSocket server.
    ///
    /// When not set, the tunnel server allows requests from any Origin.
    #[clap(long)]
    origin: Option<String>,

    /// Maximum amount of time a tunnel may be open for, in seconds.
    #[clap(long, default_value = "120", value_parser = parse_duration_secs, value_name = "SECONDS")]
    tunnel_ttl: Duration,

    /// Maximum number of messages that may be sent to a tunnel by each peer.
    #[clap(long, default_value = "16", value_name = "MESSAGES")]
    max_messages: u8,

    /// Maximum message length which may be sent to a tunnel by a peer. If a
    /// peer sends a longer message, the connection will be closed.
    #[clap(long, default_value = "16384", value_name = "BYTES")]
    max_length: usize,

    /// Serving protocol to use.
    #[clap(subcommand)]
    protocol: ServerTransportProtocol,
}

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

async fn connect_stream(
    state: Arc<ServerState>,
    ws_stream: WebSocketStream<Upgraded>,
    tx: Tx,
    rx: Rx,
    addr: SocketAddr,
) {
    info!("{addr}: WebSocket connected");
    let (outgoing, incoming) = ws_stream.split();
    let mut message_count = 0u8;

    // Add some limits on the size and number of messages
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

        if msg.len() >= state.flags.max_length {
            error!(
                "{addr}: maximum message length ({}) exceeded",
                state.flags.max_length
            );
            tx.unbounded_send(Message::Close(None)).ok();
            return future::err(
                CapacityError::MessageTooLong {
                    size: msg.len(),
                    max_size: state.flags.max_length,
                }
                .into(),
            );
        }

        // Count the message towards the quota
        message_count += 1;

        if message_count > state.flags.max_messages || message_count == u8::MAX {
            error!(
                "{addr}: maximum message count ({}) reached",
                state.flags.max_messages
            );
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
    state: Arc<ServerState>,
    addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("{addr}: {} {}", req.method(), req.uri().path());
    trace!("Request data: {req:?}");
    let mut req = req.map(|_| ());

    let (mut res, mut path) = match Router::route(&req, &state.flags.origin) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(res, path) => (res, path),
        Router::Debug => {
            let peer_map_read = state.peer_map.read().await;
            let debug = format!(
                "server_state.strong_count = {}\npeer_map.capacity = {}\npeer_map.len = {}\n",
                Arc::strong_count(&state),
                peer_map_read.capacity(),
                peer_map_read.len(),
            );
            let mut res = Response::new(Bytes::from(debug).into());
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            return Ok(res);
        }
    };

    let (tx, rx) = match path.method {
        CableMethod::New => {
            // Add the routing ID to the response header.
            path.routing_id.copy_from_slice(&state.flags.routing_id);
            path.insert_routing_id_header(res.headers_mut());

            // Create both channels in the authenticator side, as the first one here
            let (authenticator_tx, authenticator_rx) = unbounded();
            let (initiator_tx, initiator_rx) = unbounded();
            let tunnel = Tunnel::new(authenticator_rx, initiator_tx);

            // Put it in our peer_map, if we can...
            let mut lock = state.peer_map.write().await;
            if lock.contains_key(&path.tunnel_id) {
                error!("{addr}: tunnel already exists: {path}");
                return Ok(Response::builder()
                    .status(StatusCode::CONFLICT)
                    .body(Bytes::new().into())
                    .unwrap());
            }
            lock.insert(path.tunnel_id, tunnel);

            drop(lock);

            (authenticator_tx, initiator_rx)
        }

        CableMethod::Connect => {
            if let Some(c) = state.peer_map.write().await.remove(&path.tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("{addr}: no peer available for tunnel: {path}");
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Bytes::new().into())
                    .unwrap());
            }
        }
    };

    tokio::task::spawn(async move {
        let ss = state.clone();
        tokio::time::timeout(state.flags.tunnel_ttl, async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let ws_stream =
                        WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
                    connect_stream(ss, ws_stream, tx, rx, addr).await;
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
            state.peer_map.write().await.remove(&path.tunnel_id);
        }
    });

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    tracing_subscriber::fmt::init();
    let peer_map = RwLock::new(HashMap::new());

    let server_state = ServerState {
        flags: Flags::parse(),
        peer_map,
    };
    let bind_address: SocketAddr = server_state.flags.bind_address.parse()?;

    run_server(
        bind_address,
        server_state.flags.protocol.clone(),
        server_state,
        handle_request,
    )
    .await?;

    Ok(())
}
