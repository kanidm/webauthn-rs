use std::mem::size_of;

use hyper::{
    header::{CONTENT_TYPE, SEC_WEBSOCKET_PROTOCOL},
    http::HeaderValue,
    Body, Method, Request, Response,
};
use tungstenite::handshake::server::create_response_with_body;

pub type RoutingId = [u8; 3];
pub type TunnelId = [u8; 16];

pub const CABLE_PROTOCOL: &str = "fido.cable";
pub const CABLE_PROTOCOLS: [&str; 1] = [CABLE_PROTOCOL];
pub const CABLE_ROUTING_ID_HEADER: &str = "X-caBLE-Routing-ID";

pub const CABLE_NEW_PATH: &str = "/cable/new/";
pub const CABLE_CONNECT_PATH: &str = "/cable/connect/";

pub const MAX_URL_LENGTH: usize =
    CABLE_CONNECT_PATH.len() + ((size_of::<RoutingId>() + size_of::<TunnelId>()) * 2) + 1;

const FAVICON: &[u8] = include_bytes!("favicon.ico");
const INDEX: &str = include_str!("index.html");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CablePath {
    New(RoutingId, TunnelId),
    Connect(RoutingId, TunnelId),
}

impl TryFrom<&str> for CablePath {
    type Error = ();
    fn try_from(path: &str) -> Result<Self, Self::Error> {
        if path.len() > MAX_URL_LENGTH {
            return Err(());
        } else if let Some(path) = path.strip_prefix(CABLE_NEW_PATH) {
            let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];
            if hex::decode_to_slice(path, &mut tunnel_id).is_ok() {
                return Ok(Self::New([0; size_of::<RoutingId>()], tunnel_id));
            }
        } else if let Some(path) = path.strip_prefix(CABLE_CONNECT_PATH) {
            let mut routing_id: RoutingId = [0; size_of::<RoutingId>()];
            let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];

            let mut splitter = path.split('/');

            if splitter
                .next()
                .and_then(|c| hex::decode_to_slice(c, &mut routing_id).ok())
                .is_none()
            {
                return Err(());
            }

            if splitter
                .next()
                .and_then(|c| hex::decode_to_slice(c, &mut tunnel_id).ok())
                .is_none()
            {
                return Err(());
            }

            if splitter.next().is_some() {
                return Err(());
            }

            return Ok(Self::Connect(routing_id, tunnel_id));
        }
        return Err(());
    }
}

pub enum Router {
    /// The web server should handle the request as a caBLE WebSocket
    /// connection.
    Websocket(Response<Body>, CablePath),
    /// The web server should return a static response. This may be an error
    /// message.
    Static(Response<Body>),
}

impl Router {
    /// Routes an incoming HTTP request.
    pub fn route(req: &Request<Body>) -> Self {
        if req.method() != Method::GET {
            let response = Response::builder()
                .status(405)
                .header("Allow", "GET")
                .body(Body::empty())
                .unwrap();
            return Self::Static(response);
        }

        if req.uri().path().eq("/") {
            return Self::Static(Response::new(Body::from(INDEX)));
        }

        if req.uri().path().eq_ignore_ascii_case("/favicon.ico") {
            let mut response = Response::new(Body::from(FAVICON));
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("image/vnd.microsoft.icon"),
            );

            return Self::Static(response);
        }

        // Find the path
        let mut path = match CablePath::try_from(req.uri().path()) {
            Err(()) => {
                return Self::Static(Response::builder().status(404).body(Body::empty()).unwrap());
            }
            Ok(p) => p,
        };

        let mut res = match create_response_with_body(&req, || Body::empty()) {
            Ok(r) => r,
            Err(_) => {
                return Self::Static(
                    Response::builder()
                        .status(400)
                        .body(Body::from("Bad request for websocket"))
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
            return Self::Static(
                Response::builder()
                    .status(400)
                    .body(Body::from("Unsupported websocket protocol"))
                    .unwrap(),
            );
        }

        if let CablePath::New(mut r, _) = &mut path {
            // The "new" URL has no routing_id. Check to see if the routing ID
            // header was set (by the load balancer), and if it is valid,
            // insert it.
            if let Some(routing_id) = req
                .headers()
                .get(CABLE_ROUTING_ID_HEADER)
                .and_then(|v| v.to_str().ok())
            {
                hex::decode_to_slice(routing_id, &mut r).ok();
            }
        }

        // We have the correct protocol, include in the response
        res.headers_mut().append(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(CABLE_PROTOCOL),
        );
        Router::Websocket(res, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        const NULL_ROUTING_ID: RoutingId = [0, 0, 0];
        // Upper-case valid paths
        assert_eq!(
            CablePath::New(NULL_ROUTING_ID, *b"hello, webauthn!"),
            CablePath::try_from("/cable/new/68656C6C6F2C20776562617574686E21").unwrap()
        );
        assert_eq!(
            CablePath::Connect(*b"abc", *b"hello, webauthn!"),
            CablePath::try_from("/cable/connect/616263/68656C6C6F2C20776562617574686E21").unwrap()
        );

        // Lower-case valid paths
        assert_eq!(
            CablePath::New(NULL_ROUTING_ID, *b"hello, webauthn!"),
            CablePath::try_from("/cable/new/68656c6c6f2c20776562617574686e21").unwrap()
        );
        assert_eq!(
            CablePath::Connect(*b"abc", *b"hello, webauthn!"),
            CablePath::try_from("/cable/connect/616263/68656c6c6f2c20776562617574686e21").unwrap()
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

        // other nonsense
        assert!(CablePath::try_from("cable/new/68656C6C6F2C20776562617574686E21").is_err());
        assert!(CablePath::try_from("../cable/new/68656C6C6F2C20776562617574686E21").is_err());
        assert!(CablePath::try_from("/../cable/new/68656C6C6F2C20776562617574686E21").is_err());
        assert!(CablePath::try_from("../../../etc/passwd").is_err());

        // Should be rejected by length limits
        assert!(CablePath::try_from(include_str!("lib.rs")).is_err());
    }
}
