use std::{
    collections::HashMap, convert::Infallible, error::Error as StdError, fmt::Write,
    net::SocketAddr, sync::Arc,
};

use clap::{ArgAction, Parser, ValueHint};

use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::CONTENT_TYPE,
    http::HeaderValue,
    Request, Response, StatusCode,
};

use cable_tunnel_server_common::*;
use hyper_util::rt::TokioIo;
use tokio::{io::AsyncWriteExt as _, net::TcpStream, sync::RwLock};
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::MaybeTlsStream;

#[macro_use]
extern crate tracing;

const ROUTING_ID: RoutingId = [0xC0, 0xFF, 0xEE];
const FORWARDED_HEADER: &str = "X-WebAuthnRS-Forwarded";

struct ServerState {
    origin: Option<String>,
    tls_domain: Option<String>,
    backend_connector: Option<TlsConnector>,

    backends: RwLock<HashMap<RoutingId, SocketAddr>>,
    debug_handler: bool,
}

#[derive(Debug, Parser)]
#[clap(about = "caBLE tunnel server backend")]
pub struct Flags {
    /// Bind address and port for the server.
    #[clap(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    bind_address: SocketAddr,

    // Address for the service backend.
    #[clap(long, default_value = "127.0.0.1:8081", value_name = "ADDR")]
    backend_address: SocketAddr,

    #[clap(flatten)]
    backend_options: BackendClientOptions,

    /// If set, the required Origin for requests sent to the WebSocket server.
    ///
    /// When not set, the tunnel server allows requests from any Origin, which
    /// could allow non-caBLE use of the server.
    #[clap(long, value_hint = ValueHint::Hostname)]
    origin: Option<String>,

    #[clap(flatten)]
    protocol: ServerTransportProtocol,

    /// Disables the `/debug` handler on the HTTP server.
    #[clap(long = "no-debug-handler", action = ArgAction::SetFalse)]
    debug_handler: bool,
}

impl TryFrom<&Flags> for ServerState {
    type Error = TlsConfigError;

    fn try_from(f: &Flags) -> Result<Self, Self::Error> {
        Ok(Self {
            origin: f.origin.to_owned(),
            tls_domain: f.backend_options.domain.to_owned(),
            backend_connector: f.backend_options.tls_connector()?,
            backends: RwLock::new(HashMap::new()),
            debug_handler: f.debug_handler,
        })
    }
}

#[instrument(level = "info", skip_all, fields(
    req.method = req.method().to_string(),
    req.path = req.uri().path(),
    backend,
))]
async fn handle_request(
    state: Arc<ServerState>,
    _: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    trace!("request payload: {req:?}");

    // Drop the request body from future manipulation, because we never use it.
    let mut req = req.map(|_| ());

    // Use our usual routing logic for static files, except ignore the crafted
    // response for Websocket connections.
    let mut path = match Router::route(&req, state.origin.as_deref()) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(_, path) => path,
        Router::Debug => {
            return Ok(if state.debug_handler {
                let backends_read = state.backends.read().await;
                let backends_info: String =
                    backends_read.iter().fold(String::new(), |mut out, (k, v)| {
                        let _ = writeln!(out, "backends[{}] = {v}", hex::encode_upper(k));
                        out
                    });
                let debug = format!(
                    "server_state.strong_count = {}\nbackends.capacity = {}\nbackends.len = {}\n{}",
                    Arc::strong_count(&state),
                    backends_read.capacity(),
                    backends_read.len(),
                    backends_info,
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

    // Copy the incoming request to re-send to the backend.
    let mut backend_req = copy_request_empty_body(&req);
    if backend_req
        .headers_mut()
        .insert(FORWARDED_HEADER, HeaderValue::from_static("1"))
        .is_some()
    {
        // The request has been forwarded by us once before. Refuse to get into
        // a loop.
        error!("request seems to be previously forwarded - refusing to get in a loop!");
        return Ok(empty_response(StatusCode::LOOP_DETECTED));
    }
    // TODO: add standard proxy forwarding headers

    // Get the backend address, and set the Routing ID header in the request
    let backend = match &mut path.method {
        CableMethod::New => {
            // TODO: select a backend
            path.routing_id.copy_from_slice(&ROUTING_ID);
            let headers = backend_req.headers_mut();

            // Replace the Routing ID header sent to the backend with the
            // selected routing ID.
            path.insert_routing_id_header(headers);

            // TODO
            state
                .backends
                .read()
                .await
                .get(&ROUTING_ID)
                .unwrap()
                .to_owned()
        }

        CableMethod::Connect => {
            // TODO handle availability

            match state.backends.read().await.get(&path.routing_id) {
                Some(a) => a.to_owned(),
                None => {
                    error!("unknown routing ID");
                    return Ok(empty_response(StatusCode::NOT_FOUND));
                }
            }
        }
    };
    tracing::Span::current().record("backend", backend.to_string());

    // Connect to the backend task
    info!("connecting to backend");
    let backend_socket = match TcpStream::connect(backend).await {
        Ok(s) => s,
        Err(e) => {
            error!("unable to reach backend: {e}");
            return Ok(empty_response(StatusCode::GATEWAY_TIMEOUT));
        }
    };

    // Set up TLS
    let backend_socket = match &state.backend_connector {
        None => MaybeTlsStream::Plain(backend_socket),
        Some(tls_connector) => {
            let backend_ip = backend.ip().to_string();
            let domain = state.tls_domain.as_deref().unwrap_or(backend_ip.as_str());

            trace!("TLS handshake with backend using domain {domain}");
            match tls_connector.connect(domain, backend_socket).await {
                Ok(o) => MaybeTlsStream::NativeTls(o),
                Err(e) => {
                    error!("TLS handshake with backend failed: {e}");
                    return Ok(empty_response(StatusCode::BAD_GATEWAY));
                }
            }
        }
    };
    let backend_socket = TokioIo::new(backend_socket);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(backend_socket).await {
        Ok(v) => v,
        Err(e) => {
            error!("unable to handshake with backend: {e}");
            return Ok(empty_response(StatusCode::BAD_GATEWAY));
        }
    };

    // Spawn a task to poll the connection and drive the HTTP state
    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            error!("backend connection failed: {e:?}");
        }
    });

    // Pass the request to the selected backend
    let mut backend_res = match sender.send_request(backend_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("unable to send request to backend: {e}");
            return Ok(empty_response(StatusCode::BAD_GATEWAY));
        }
    };

    if backend_res.status() != StatusCode::SWITCHING_PROTOCOLS {
        error!(
            "backend returned unexpected status: {}",
            backend_res.status()
        );
        return Ok(empty_response(backend_res.status()));
    }

    // Copy the response for the client
    let mut res = copy_response_empty_body(&backend_res).map(|_| Default::default());
    path.insert_routing_id_header(res.headers_mut());

    // Set up the "upgrade" handler to connect the two sockets together
    tokio::task::spawn(async move {
        // Upgrade the connection to the backend
        let backend_upgraded = match hyper::upgrade::on(&mut backend_res).await {
            Ok(u) => u,
            Err(e) => {
                error!("failure upgrading connection to backend: {e}");
                return;
            }
        };
        let mut backend_upgraded = TokioIo::new(backend_upgraded);

        // Upgrade the connection from the client
        let client_upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => {
                error!("failure upgrading connection to client: {e}");
                return;
            }
        };
        let mut client_upgraded = TokioIo::new(client_upgraded);

        // Connect the two streams together directly.
        match tokio::io::copy_bidirectional(&mut backend_upgraded, &mut client_upgraded).await {
            Ok((backend_bytes, client_bytes)) => {
                info!("connection closed, backend sent {backend_bytes} bytes, client sent {client_bytes} bytes");
            }
            Err(e) => {
                error!("connection error: {e}");
                backend_upgraded.shutdown().await.ok();
                client_upgraded.shutdown().await.ok();
            }
        }
    });

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    setup_logging();
    let flags = Flags::parse();
    let server_state = ServerState::try_from(&flags)?;

    // TODO: implement properly
    assert_ne!(
        flags.bind_address, flags.backend_address,
        "--bind-address cannot not be the same as --backend--address"
    );
    server_state
        .backends
        .write()
        .await
        .insert(ROUTING_ID, flags.backend_address);
    let tls_acceptor = flags.protocol.tls_acceptor()?;
    info!(
        "Starting webauthn-rs cable-tunnel-server-frontend at {}",
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
