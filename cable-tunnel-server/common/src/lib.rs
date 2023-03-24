use std::{
    convert::Infallible, error::Error as StdError, fmt::Display, future::Future, mem::size_of,
    net::SocketAddr, num::ParseIntError, sync::Arc, time::Duration,
};

use hex::{FromHex, FromHexError};
use http_body::Body;
use http_body_util::{Empty, Full};
use hyper::{
    body::{Bytes, Incoming},
    header::{CONTENT_TYPE, ORIGIN, SEC_WEBSOCKET_PROTOCOL},
    http::HeaderValue,
    service::service_fn,
    HeaderMap, Method, Request, Response, StatusCode, Uri,
};
use tokio::net::TcpListener;
use tokio_tungstenite::MaybeTlsStream;
use tungstenite::handshake::server::create_response;

#[macro_use]
extern crate tracing;

mod tls;
pub use tls::*;

pub type RoutingId = [u8; 3];
pub type TunnelId = [u8; 16];

pub const CABLE_PROTOCOL: &str = "fido.cable";
pub const CABLE_ROUTING_ID_HEADER: &str = "X-caBLE-Routing-ID";

pub const CABLE_NEW_PATH: &str = "/cable/new/";
pub const CABLE_CONNECT_PATH: &str = "/cable/connect/";

pub const MAX_URL_LENGTH: usize =
    CABLE_CONNECT_PATH.len() + ((size_of::<RoutingId>() + size_of::<TunnelId>()) * 2) + 2;

const FAVICON: &[u8] = include_bytes!("favicon.ico");
const INDEX: &str = include_str!("index.html");

pub fn parse_hex<T>(i: &str) -> Result<T, FromHexError>
where
    T: FromHex<Error = FromHexError>,
{
    FromHex::from_hex(i)
}

pub fn parse_duration_secs(i: &str) -> Result<Duration, ParseIntError> {
    i.parse::<u64>().map(Duration::from_secs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CablePath {
    pub method: CableMethod,
    pub routing_id: RoutingId,
    pub tunnel_id: TunnelId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CableMethod {
    New,
    Connect,
}

impl CablePath {
    pub fn new(tunnel_id: TunnelId) -> Self {
        Self {
            method: CableMethod::New,
            routing_id: [0; size_of::<RoutingId>()],
            tunnel_id,
        }
    }

    pub fn connect(routing_id: RoutingId, tunnel_id: TunnelId) -> Self {
        Self {
            method: CableMethod::Connect,
            routing_id,
            tunnel_id,
        }
    }

    pub fn insert_routing_id_header(&self, headers: &mut HeaderMap) {
        headers.insert(
            CABLE_ROUTING_ID_HEADER,
            HeaderValue::from_str(&hex::encode_upper(self.routing_id)).unwrap(),
        );
    }
}

impl Display for CablePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.method {
            CableMethod::New => {
                write!(f, "{}{}", CABLE_NEW_PATH, hex::encode_upper(self.tunnel_id))
            }
            CableMethod::Connect => write!(
                f,
                "{}{}/{}",
                CABLE_CONNECT_PATH,
                hex::encode_upper(self.routing_id),
                hex::encode_upper(self.tunnel_id)
            ),
        }
    }
}

impl TryFrom<&str> for CablePath {
    type Error = ();
    fn try_from(path: &str) -> Result<Self, Self::Error> {
        if path.len() > MAX_URL_LENGTH {
            error!("path too long: {} > {MAX_URL_LENGTH} bytes", path.len());
            return Err(());
        } else if let Some(path) = path.strip_prefix(CABLE_NEW_PATH) {
            let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];
            if hex::decode_to_slice(path, &mut tunnel_id).is_ok() {
                return Ok(Self::new(tunnel_id));
            }
            error!("invalid new path: {path}");
        } else if let Some(path) = path.strip_prefix(CABLE_CONNECT_PATH) {
            let mut routing_id: RoutingId = [0; size_of::<RoutingId>()];
            let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];

            let mut splitter = path.split('/');

            if splitter
                .next()
                .and_then(|c| hex::decode_to_slice(c, &mut routing_id).ok())
                .is_none()
            {
                error!("invalid routing_id in connect path: {path}");
                return Err(());
            }

            if splitter
                .next()
                .and_then(|c| hex::decode_to_slice(c, &mut tunnel_id).ok())
                .is_none()
            {
                error!("invalid tunnel_id in connect path: {path}");
                return Err(());
            }

            if splitter.next().is_some() {
                error!("unexpected extra token in connect path: {path}");
                return Err(());
            }

            return Ok(Self::connect(routing_id, tunnel_id));
        } else {
            error!("unknown path: {path}")
        }

        Err(())
    }
}

pub enum Router {
    /// The web server should handle the request as a caBLE WebSocket
    /// connection.
    Websocket(Response<Full<Bytes>>, CablePath),
    /// The web server should return a static response. This may be an error
    /// message.
    Static(Response<Full<Bytes>>),

    Debug,
}

impl Router {
    /// Routes an incoming HTTP request.
    pub fn route(req: &Request<()>, origin: &Option<String>) -> Self {
        if req.method() != Method::GET {
            error!("method {} not allowed", req.method());
            let response = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Allow", "GET")
                .body(Default::default())
                .unwrap();
            return Self::Static(response);
        }

        let path = match req.uri().path() {
            "/" => return Self::Static(Response::new(Bytes::from(INDEX).into())),
            "/favicon.ico" => {
                let mut response = Response::new(Bytes::from(FAVICON).into());
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("image/vnd.microsoft.icon"),
                );

                return Self::Static(response);
            }
            "/debug" => return Self::Debug,
            path => match CablePath::try_from(path) {
                Err(()) => {
                    return Self::Static(
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Default::default())
                            .unwrap(),
                    );
                }
                Ok(p) => p,
            },
        };

        let mut res = match create_response(req) {
            Ok(r) => r,
            Err(e) => {
                error!("Bad request for WebSocket: {e}");
                return Self::Static(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Default::default())
                        .unwrap(),
                );
            }
        };

        // At this point, we have something that looks like a WebSocket on the
        // other side. We should check the parameters selected etc.
        if !req
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case(CABLE_PROTOCOL))
            .unwrap_or_default()
        {
            error!("Unsupported or missing WebSocket protocol");
            return Self::Static(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Default::default())
                    .unwrap(),
            );
        }

        // Check the origin header
        if let Some(origin) = origin {
            if !req
                .headers()
                .get(ORIGIN)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<Uri>().ok())
                .map(|v| {
                    v.host()
                        .map(|o| o.eq_ignore_ascii_case(origin))
                        .unwrap_or_default()
                })
                .unwrap_or_default()
            {
                error!("Incorrect or missing Origin header");
                return Self::Static(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Default::default())
                        .unwrap(),
                );
            }
        }

        // We have the correct protocol, include in the response
        res.headers_mut().append(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(CABLE_PROTOCOL),
        );
        let res = res.map(|_| Default::default());

        Router::Websocket(res, path)
    }
}

pub fn copy_request_empty_body<T>(r: &Request<T>) -> Request<Empty<Bytes>> {
    let mut o = Request::builder().method(r.method()).uri(r.uri());
    {
        let headers = o.headers_mut().unwrap();
        headers.extend(r.headers().to_owned());
    }

    o.body(Default::default()).unwrap()
}

pub fn copy_response_empty_body<T>(r: &Response<T>) -> Response<Empty<Bytes>> {
    let mut o = Response::builder().status(r.status());
    {
        let headers = o.headers_mut().unwrap();
        headers.extend(r.headers().to_owned());
    }

    o.body(Default::default()).unwrap()
}

pub async fn run_server<F, R, ResBody, T>(
    bind_address: SocketAddr,
    protocol: ServerTransportProtocol,
    server_state: T,
    mut request_handler: F,
) -> Result<(), Box<dyn StdError>>
where
    F: FnMut(Arc<T>, SocketAddr, Request<Incoming>) -> R + Copy + Send + Sync + 'static,
    R: Future<Output = Result<Response<ResBody>, Infallible>> + Send,
    ResBody: Body + Send + 'static,
    <ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
    <ResBody as Body>::Data: Send,
    T: Send + Sync + 'static,
{
    let server_state = Arc::new(server_state);
    let tcp = TcpListener::bind(&bind_address).await?;
    let tls_acceptor = protocol.tls_acceptor()?.map(Arc::new);
    let uri = protocol.uri(&bind_address)?;
    info!("Started server at {uri}");

    loop {
        let (stream, remote_addr) = match tcp.accept().await {
            Ok(o) => o,
            Err(e) => {
                error!("tcp.accept: {e}");
                continue;
            }
        };
        let server_state = server_state.clone();
        let service =
            service_fn(move |req| request_handler(server_state.clone(), remote_addr, req));
        let tls_acceptor = tls_acceptor.clone();

        tokio::task::spawn(async move {
            let stream = match tls_acceptor {
                None => MaybeTlsStream::Plain(stream),
                Some(tls_acceptor) => match tls_acceptor.accept(stream).await {
                    Ok(o) => MaybeTlsStream::NativeTls(o),
                    Err(e) => {
                        error!("tls_acceptor.accept: {e}");
                        return;
                    }
                },
            };

            let conn = hyper::server::conn::http1::Builder::new().serve_connection(stream, service);
            let conn = conn.with_upgrades();

            if let Err(e) = conn.await {
                error!("Connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        let _ = tracing_subscriber::fmt::try_init();

        // Parse valid paths in upper case
        assert_eq!(
            CablePath::new(*b"hello, webauthn!"),
            CablePath::try_from("/cable/new/68656C6C6F2C20776562617574686E21").unwrap()
        );
        assert_eq!(
            CablePath::connect(*b"abc", *b"hello, webauthn!"),
            CablePath::try_from("/cable/connect/616263/68656C6C6F2C20776562617574686E21").unwrap()
        );

        // Converting to string should always return upper-case paths
        assert_eq!(
            "/cable/new/68656C6C6F2C20776562617574686E21",
            CablePath::new(*b"hello, webauthn!").to_string(),
        );
        assert_eq!(
            "/cable/connect/616263/68656C6C6F2C20776562617574686E21",
            CablePath::connect(*b"abc", *b"hello, webauthn!").to_string(),
        );

        // Parse valid paths in lower case
        assert_eq!(
            CablePath::new(*b"hello, webauthn!"),
            CablePath::try_from("/cable/new/68656c6c6f2c20776562617574686e21").unwrap()
        );
        assert_eq!(
            CablePath::connect(*b"abc", *b"hello, webauthn!"),
            CablePath::try_from("/cable/connect/616263/68656c6c6f2c20776562617574686e21").unwrap()
        );

        // Parsing lower-case paths should return strings in upper case.
        assert_eq!(
            "/cable/new/68656C6C6F2C20776562617574686E21",
            CablePath::try_from("/cable/new/68656c6c6f2c20776562617574686e21")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            "/cable/connect/616263/68656C6C6F2C20776562617574686E21",
            CablePath::try_from("/cable/connect/616263/68656c6c6f2c20776562617574686e21")
                .unwrap()
                .to_string()
        );

        // Invalid paths
        assert!(CablePath::try_from("/").is_err());

        assert!(CablePath::try_from("/cable/new/").is_err());
        assert!(CablePath::try_from("/cable/new/not_hex_digits_here_but_32_chars").is_err());
        assert!(CablePath::try_from("/cable/new/C0FFEE").is_err());
        assert!(CablePath::try_from("/cable/new/C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEE").is_err());
        assert!(CablePath::try_from("/cable/new/68656C6C6F2C20776562617574686E21/").is_err());
        assert!(CablePath::try_from("/cable/new/../new/68656C6C6F2C20776562617574686E21").is_err());

        assert!(
            CablePath::try_from("/cable/connect/C0FFEE/not_hex_digits_here_but_32_chars").is_err()
        );
        assert!(CablePath::try_from("/cable/connect/C0FFEE/COFFEE").is_err());
        assert!(CablePath::try_from("/cable/connect/C0/FFEE").is_err());
        assert!(CablePath::try_from("/cable/connect/C0/68656C6C6F2C20776562617574686E21").is_err());
        assert!(
            CablePath::try_from("/cable/connect/C0F/68656C6C6F2C20776562617574686E21").is_err()
        );
        assert!(
            CablePath::try_from("/cable/connect/C0FFEECO/68656C6C6F2C20776562617574686E21")
                .is_err()
        );
        assert!(
            CablePath::try_from("/cable/connect/C0FFEE/68656C6C6F2C20776562617574686E21/1234")
                .is_err()
        );
        assert!(
            CablePath::try_from("/cable/connect/C0FFEE/68656C6C6F2C20776562617574686E21/").is_err()
        );

        // other nonsense
        assert!(CablePath::try_from("cable/new/68656C6C6F2C20776562617574686E21").is_err());
        assert!(CablePath::try_from("../cable/new/68656C6C6F2C20776562617574686E21").is_err());
        assert!(CablePath::try_from("/../cable/new/68656C6C6F2C20776562617574686E21").is_err());
        assert!(CablePath::try_from("../../../etc/passwd").is_err());

        // Should be rejected by length limits
        assert!(CablePath::try_from(include_str!("lib.rs")).is_err());
    }
}
