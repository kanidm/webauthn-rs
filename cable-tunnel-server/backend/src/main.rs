use std::{
    collections::HashMap, convert::Infallible, fs::read, net::SocketAddr, num::ParseIntError,
    path::PathBuf, sync::Arc, time::Duration,
};

use clap::Parser;
use hex::{FromHex, FromHexError};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    http::HeaderValue,
    service::service_fn,
    upgrade::Upgraded,
    Request, Response, StatusCode,
};

use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio::{net::TcpListener, sync::RwLock};
use tokio_native_tls::{
    native_tls::{self, Identity},
    TlsAcceptor,
};
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
type PeerMap = Arc<RwLock<HashMap<TunnelId, Tunnel>>>;

#[derive(Debug, Parser)]
#[clap(about = "caBLE tunnel server backend")]
pub struct Flags {
    /// Bind address and port for the server.
    #[clap(long, default_value = "127.0.0.1:8081", value_name = "ADDR")]
    bind_address: String,

    /// If set, the routing ID to report on new tunnel requests. This is a 3
    /// byte, base-16 encoded value (eg: `123456`).
    ///
    /// When this flag is not set, this uses the `X-caBLE-Routing-ID` header
    /// sent by the client (load balancer). Otherwise, the routing ID `000000`
    /// is used.
    ///
    /// Note: the routing ID provided in connect requests is never checked
    /// against this value.
    #[clap(long, value_parser = parse_hex::<RoutingId>, value_name = "ID")]
    routing_id: Option<RoutingId>,

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

    #[clap(long, value_name = "PEM")]
    tls_public_key: PathBuf,

    #[clap(long, value_name = "PEM")]
    tls_private_key: PathBuf,
}

struct Tunnel {
    authenticator_rx: Rx,
    initiator_tx: Tx,
}

fn parse_hex<T>(i: &str) -> Result<T, FromHexError>
where
    T: FromHex<Error = FromHexError>,
{
    FromHex::from_hex(i)
}

fn parse_duration_secs(i: &str) -> Result<Duration, ParseIntError> {
    u64::from_str_radix(i, 10).map(Duration::from_secs)
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
    flags: Arc<Flags>,
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

        if msg.len() >= flags.max_length {
            error!(
                "{addr}: maximum message length ({}) exceeded",
                flags.max_length
            );
            tx.unbounded_send(Message::Close(None)).ok();
            return future::err(
                CapacityError::MessageTooLong {
                    size: msg.len(),
                    max_size: flags.max_length,
                }
                .into(),
            );
        }

        // Count the message towards the quota
        message_count += 1;

        if message_count > flags.max_messages || message_count == u8::MAX {
            error!(
                "{addr}: maximum message count ({}) reached",
                flags.max_messages
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
    flags: Arc<Flags>,
    peer_map: PeerMap,
    req: Request<Incoming>,
    addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("{addr}: {} {}", req.method(), req.uri().path());
    trace!("Request data: {req:?}");
    let mut req = req.map(|_| ());

    let (mut res, mut path) = match Router::route(&req, &flags.origin) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(res, path) => (res, path),
    };

    let (tx, rx) = match path.method {
        CableMethod::New => {
            if let Some(routing_id) = flags.routing_id {
                path.routing_id.copy_from_slice(&routing_id);
            }

            // Add a routing ID as a response header. This is from the request
            // header, if set by the frontend.
            res.headers_mut().append(
                CABLE_ROUTING_ID_HEADER,
                HeaderValue::from_str(&hex::encode_upper(path.routing_id)).unwrap(),
            );

            // Create both channels in the authenticator side, as the first one here
            let (authenticator_tx, authenticator_rx) = unbounded();
            let (initiator_tx, initiator_rx) = unbounded();
            let tunnel = Tunnel::new(authenticator_rx, initiator_tx);

            // Put it in our peer_map, if we can...
            let mut lock = peer_map.write().await;
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
            if let Some(c) = peer_map.write().await.remove(&path.tunnel_id) {
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
        tokio::time::timeout(flags.tunnel_ttl, async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let ws_stream =
                        WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
                    connect_stream(flags, ws_stream, tx, rx, addr).await;
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
            peer_map.write().await.remove(&path.tunnel_id);
        }
    });

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let flags = Arc::new(Flags::parse());
    let addr: SocketAddr = flags.bind_address.parse()?;
    let peer_map = Arc::new(RwLock::new(HashMap::new()));

    let tcp = TcpListener::bind(&addr).await?;
    let pem = read(&flags.tls_public_key)?;
    let key = read(&flags.tls_private_key)?;
    let identity = Identity::from_pkcs8(&pem, &key)?;
    let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::builder(identity).build()?);

    loop {
        let (stream, remote_addr) = match tcp.accept().await {
            Ok(o) => o,
            Err(e) => {
                error!("tcp.accept: {e}");
                continue;
            }
        };
        let stream = match tls_acceptor.accept(stream).await {
            Ok(o) => o,
            Err(e) => {
                error!("tls_acceptor.accept: {e}");
                continue;
            }
        };

        let flags = flags.clone();
        let peer_map = peer_map.clone();
        let service = service_fn(move |req| {
            handle_request(flags.clone(), peer_map.clone(), req, remote_addr)
        });

        tokio::task::spawn(async move {
            let conn = hyper::server::conn::http1::Builder::new().serve_connection(stream, service);
            let conn = conn.with_upgrades();

            match conn.await {
                Err(e) => {
                    error!("Connection error: {e}");
                    return;
                }
                _ => (),
            }
        });
    }
}
