use std::{
    borrow::Cow, collections::HashMap, convert::Infallible, error::Error as StdError,
    net::SocketAddr, sync::Arc, time::Duration,
};

use clap::{ArgAction, Parser, ValueHint};

use futures::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::CONTENT_TYPE,
    http::HeaderValue,
    upgrade::Upgraded,
    Request, Response, StatusCode,
};
use hyper_util::rt::tokio::TokioIo;
use tokio::{
    select,
    sync::{
        mpsc::{channel, error::TrySendError, Receiver, Sender},
        RwLock,
    },
};
use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    error::CapacityError,
    protocol::{frame::coding::CloseCode, CloseFrame, Message, Role, WebSocketConfig},
};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Rx = Receiver<Message>;
type Tx = Sender<Message>;
type PeerMap = RwLock<HashMap<TunnelId, Tunnel>>;
const CHANNEL_BUFFER_SIZE: usize = 6;

struct ServerState {
    peer_map: PeerMap,
    max_messages: u8,
    max_length: usize,
    origin: Option<String>,
    routing_id: RoutingId,
    tunnel_ttl: Duration,
    debug_handler: bool,
}

#[derive(Debug, Parser)]
#[clap(about = "caBLE tunnel server backend")]
pub struct Flags {
    /// Bind address and port for the server.
    #[clap(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    bind_address: SocketAddr,

    /// The routing ID to report on new tunnel requests. This is a 3 byte,
    /// base-16 encoded value (eg: `123456`).
    ///
    /// Note: all routing IDs will be accepted by the server for connect
    /// requests, and are never checked against this value.
    #[clap(long, default_value = "000000", value_parser = parse_hex::<RoutingId>, value_name = "ID")]
    routing_id: RoutingId,

    /// If set, the required Origin for requests sent to the WebSocket server.
    ///
    /// When not set, the tunnel server allows requests from any Origin, which
    /// could allow non-caBLE use of the server.
    #[clap(long, value_hint = ValueHint::Hostname)]
    origin: Option<String>,

    /// Maximum amount of time a tunnel may be open for, in seconds. The timer
    /// starts when the authenticator first connects, even if there is no peer.
    #[clap(long, default_value = "120", value_parser = parse_duration_secs, value_name = "SECONDS")]
    tunnel_ttl: Duration,

    /// Maximum number of messages that may be sent to a tunnel by each peer in
    /// a session. Once this limit has been reached, the tunnel will be closed.
    #[clap(long, default_value = "16", value_name = "MESSAGES")]
    max_messages: u8,

    /// Maximum message length which may be sent to a tunnel by a peer. If a
    /// peer sends a longer message, the connection and tunnels will be closed.
    #[clap(long, default_value = "16384", value_name = "BYTES")]
    max_length: usize,

    #[clap(flatten)]
    protocol: ServerTransportProtocol,

    /// Disables the `/debug` handler on the HTTP server.
    #[clap(long = "no-debug-handler", action = ArgAction::SetFalse)]
    debug_handler: bool,
}

impl From<&Flags> for ServerState {
    fn from(f: &Flags) -> Self {
        Self {
            peer_map: RwLock::new(HashMap::new()),
            max_messages: f.max_messages,
            max_length: f.max_length,
            origin: f.origin.to_owned(),
            routing_id: f.routing_id,
            tunnel_ttl: f.tunnel_ttl,
            debug_handler: f.debug_handler,
        }
    }
}

/// A tunnel which is pending connection from an initiator.
struct Tunnel {
    /// A channel to allow the authenticator to receive messages from the
    /// initiator.
    authenticator_rx: Rx,
    /// A channel to allow the initiator to send messages to the authenticator.
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

const PEER_DISCONNECTED_FRAME: CloseFrame = CloseFrame {
    code: CloseCode::Normal,
    reason: Cow::Borrowed("remote peer cleanly disconnected"),
};

#[derive(thiserror::Error, Debug)]
enum CableError {
    #[error("remote peer sent erroneous frame")]
    RemotePeerErrorFrame,
    #[error("remote peer abnormally disconnected")]
    RemotePeerAbnormallyDisconnected,
    #[error("client sent a message which was too long")]
    MessageTooLong,
    #[error("client sent too many messages")]
    TooManyMessages,
    #[error("client sent unsupported message type")]
    UnsupportedMessageType,
    #[error("tunnel TTL exceeded")]
    TtlExceeded,
    #[error("WebSocket error: {0}")]
    WebSocketError(tungstenite::Error),
}

impl From<tungstenite::Error> for CableError {
    fn from(e: tungstenite::Error) -> Self {
        if matches!(
            e,
            tungstenite::Error::Capacity(CapacityError::MessageTooLong { .. })
        ) {
            Self::MessageTooLong
        } else {
            Self::WebSocketError(e)
        }
    }
}

impl CableError {
    fn close_reason(&self) -> Option<CloseFrame<'_>> {
        use CableError::*;
        let code = match self {
            RemotePeerErrorFrame => CloseCode::Policy,
            RemotePeerAbnormallyDisconnected => CloseCode::Away,
            MessageTooLong => CloseCode::Size,
            TooManyMessages => CloseCode::Policy,
            UnsupportedMessageType => CloseCode::Unsupported,
            TtlExceeded => CloseCode::Policy,
            // Don't expose other error types
            _ => return None,
        };

        Some(CloseFrame {
            code,
            reason: self.to_string().into(),
        })
    }

    /// Create a message to notify the remote peer about a local error.
    fn peer_message(&self) -> Option<Message> {
        use CableError::*;
        let f = match self {
            // Remote peer is already gone, don't notify.
            RemotePeerErrorFrame | RemotePeerAbnormallyDisconnected => return None,

            // Other errors should notify peer
            TtlExceeded => TtlExceeded.close_reason(),
            TooManyMessages => TooManyMessages.close_reason(),
            WebSocketError(tungstenite::Error::ConnectionClosed) => Some(PEER_DISCONNECTED_FRAME),
            WebSocketError(_) => RemotePeerAbnormallyDisconnected.close_reason(),
            _ => RemotePeerErrorFrame.close_reason(),
        };

        Some(Message::Close(f))
    }
}

#[instrument(level = "info", skip_all, err, fields(addr = addr.to_string()))]
async fn handle_websocket(
    state: Arc<ServerState>,
    mut ws_stream: WebSocketStream<TokioIo<Upgraded>>,
    tx: Tx,
    mut rx: Rx,
    addr: SocketAddr,
) -> Result<(), CableError> {
    let mut message_count = 0u8;

    let r = tokio::time::timeout(state.tunnel_ttl, async {
        loop {
            select! {
                r = rx.recv() => match r {
                    Some(msg) => {
                        // A message was received from the remote peer, send it onward.
                        match msg {
                            Message::Close(reason) => {
                                info!("remote peer closed connection: {reason:?}");
                                ws_stream.close(reason).await?;
                                return Ok(());
                            }
                            msg => {
                                ws_stream.send(msg).await?;
                            }
                        }
                    },
                    None => {
                        // The peer disconnected
                        return Err(CableError::RemotePeerAbnormallyDisconnected);
                    }
                },

                r = ws_stream.next() => match r {
                    None => {
                        // Stream ended
                        info!("client disconnected");
                        tx.try_send(Message::Close(Some(PEER_DISCONNECTED_FRAME.clone()))).ok();
                        return Ok(());
                    },
                    Some(Err(e)) => {
                        // Websocket protocol error
                        error!("reading websocket: {e}");
                        return Err(e.into());
                    },
                    Some(Ok(msg)) => {
                        // A message was received from the local peer, validate it and
                        // send it onward
                        if msg.is_close() {
                            info!("closing connection");
                            tx.try_send(Message::Close(Some(PEER_DISCONNECTED_FRAME.clone()))).ok();
                            ws_stream.close(None).await?;
                            return Ok(());
                        }

                        if msg.is_ping() || msg.is_pong() {
                            // Ignore PING/PONG messages, and don't count them towards
                            // quota. Tungstenite handles replies for us.
                            continue;
                        }

                        let msg = if let Message::Binary(msg) = msg {
                            msg
                        } else {
                            // Drop connection on other message types.
                            return Err(CableError::UnsupportedMessageType);
                        };

                        // Count the message towards the quota
                        message_count += 1;

                        if message_count > state.max_messages || message_count == u8::MAX {
                            return Err(CableError::TooManyMessages);
                        }

                        trace!("message {message_count}: {}", hex::encode(&msg));
                        match tx.try_send(Message::Binary(msg)) {
                            Err(TrySendError::Closed(_)) =>
                                return Err(CableError::RemotePeerAbnormallyDisconnected),
                            Err(TrySendError::Full(_)) =>
                                return Err(CableError::TooManyMessages),
                            Ok(_) => (),
                        }
                    }
                }
            }
        }
    })
    .await
    // Convert Elapsed into TtlExceeded
    .unwrap_or(Err(CableError::TtlExceeded));

    if let Err(e) = &r {
        // An error result indicates that no Close message has been sent
        // already, and we may need to notify the peer. Sending messages or
        // closing may fail at this stage, but we don't care.
        if let Some(msg) = e.peer_message() {
            tx.try_send(msg).ok();
        }
        ws_stream.close(e.close_reason()).await.ok();
    }

    r
}

#[instrument(level = "info", skip_all, fields(
    req.method = req.method().to_string(),
    req.path = req.uri().path(),
))]
async fn handle_request(
    state: Arc<ServerState>,
    addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    trace!("request payload: {req:?}");
    let mut req = req.map(|_| ());

    let (mut res, mut path) = match Router::route(&req, state.origin.as_deref()) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(res, path) => (res, path),
        Router::Debug => {
            return Ok(if state.debug_handler {
                let peer_map_read = state.peer_map.read().await;
                let debug = format!(
                    "server_state.strong_count = {}\npeer_map.capacity = {}\npeer_map.len = {}\n",
                    Arc::strong_count(&state),
                    peer_map_read.capacity(),
                    peer_map_read.len(),
                );
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, HeaderValue::from_static("text/plain"))
                    .body(Bytes::from(debug).into())
                    .unwrap()
            } else {
                empty_response(StatusCode::NOT_FOUND)
            });
        }
    };

    let (tx, rx) = match path.method {
        CableMethod::New => {
            // Add the routing ID to the response header.
            path.routing_id.copy_from_slice(&state.routing_id);
            path.insert_routing_id_header(res.headers_mut());

            // Create both channels in the authenticator side, as the first one here
            let (authenticator_tx, authenticator_rx) = channel(CHANNEL_BUFFER_SIZE);
            let (initiator_tx, initiator_rx) = channel(CHANNEL_BUFFER_SIZE);
            let tunnel = Tunnel::new(authenticator_rx, initiator_tx);

            // Put it in our peer_map, if we can...
            {
                let mut lock = state.peer_map.write().await;
                if lock.contains_key(&path.tunnel_id) {
                    error!("tunnel already exists: {path}");
                    return Ok(empty_response(StatusCode::CONFLICT));
                }
                lock.insert(path.tunnel_id, tunnel);
            }

            (authenticator_tx, initiator_rx)
        }

        CableMethod::Connect => {
            if let Some(c) = state.peer_map.write().await.remove(&path.tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("no peer available for tunnel: {path}");
                return Ok(empty_response(StatusCode::NOT_FOUND));
            }
        }
    };

    tokio::task::spawn(async move {
        let ss = state.clone();
        let config = Some(WebSocketConfig {
            max_message_size: Some(ss.max_length),
            max_frame_size: Some(ss.max_length),
            ..Default::default()
        });

        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                let upgraded = TokioIo::new(upgraded);
                let ws_stream =
                    WebSocketStream::from_raw_socket(upgraded, Role::Server, config).await;
                handle_websocket(ss, ws_stream, tx, rx, addr).await.ok();
            }
            Err(e) => {
                error!("upgrade error: {e}");
            }
        }

        if path.method == CableMethod::New {
            // Remove any stale entry
            state.peer_map.write().await.remove(&path.tunnel_id);
        }
    });

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    setup_logging();
    let flags = Flags::parse();
    let server_state = ServerState::from(&flags);
    let tls_acceptor = flags.protocol.tls_acceptor()?;
    info!(
        "Starting webauthn-rs cable-tunnel-server-backend at {}",
        flags.protocol.uri(&flags.bind_address)?
    );

    run_server(
        flags.bind_address,
        tls_acceptor,
        server_state,
        handle_request,
    )
    .await?;

    Ok(())
}
