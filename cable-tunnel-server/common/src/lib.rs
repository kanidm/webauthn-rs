use std::mem::size_of;

pub type RoutingId = [u8; 3];
pub type TunnelId = [u8; 16];

pub const CABLE_PROTOCOL: &str = "fido.cable";
pub const CABLE_PROTOCOLS: [&str; 1] = [CABLE_PROTOCOL];
pub const CABLE_ROUTING_ID_HEADER: &str = "X-caBLE-Routing-ID";

pub const CABLE_NEW_PATH: &str = "/cable/new/";
pub const CABLE_CONNECT_PATH: &str = "/cable/connect/";

pub const MAX_URL_LENGTH: usize =
    CABLE_CONNECT_PATH.len() + ((size_of::<RoutingId>() + size_of::<TunnelId>()) * 2) + 1;

pub const FAVICON: &[u8] = include_bytes!("favicon.ico");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CablePath {
    Unknown,
    New(TunnelId),
    Connect(RoutingId, TunnelId),
}

impl From<&str> for CablePath {
    fn from(path: &str) -> Self {
        if path.len() > MAX_URL_LENGTH {
            return Self::Unknown;
        } else if let Some(path) = path.strip_prefix(CABLE_NEW_PATH) {
            let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];
            if hex::decode_to_slice(path, &mut tunnel_id).is_ok() {
                return Self::New(tunnel_id);
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
                return Self::Unknown;
            }

            if splitter
                .next()
                .and_then(|c| hex::decode_to_slice(c, &mut tunnel_id).ok())
                .is_none()
            {
                return Self::Unknown;
            }

            if splitter.next().is_some() {
                return Self::Unknown;
            }

            return Self::Connect(routing_id, tunnel_id);
        }
        return Self::Unknown;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        // Upper-case valid paths
        assert_eq!(
            CablePath::New(*b"hello, webauthn!"),
            CablePath::from("/cable/new/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(
            CablePath::Connect(*b"abc", *b"hello, webauthn!"),
            CablePath::from("/cable/connect/616263/68656C6C6F2C20776562617574686E21")
        );

        // Lower-case valid paths
        assert_eq!(
            CablePath::New(*b"hello, webauthn!"),
            CablePath::from("/cable/new/68656c6c6f2c20776562617574686e21")
        );
        assert_eq!(
            CablePath::Connect(*b"abc", *b"hello, webauthn!"),
            CablePath::from("/cable/connect/616263/68656c6c6f2c20776562617574686e21")
        );

        // Invalid paths
        assert_eq!(CablePath::Unknown, CablePath::from("/"));

        assert_eq!(CablePath::Unknown, CablePath::from("/cable/new/"));
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/new/not_hex_digits_here_but_32_chars")
        );
        assert_eq!(CablePath::Unknown, CablePath::from("/cable/new/C0FFEE"));
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/new/C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEE")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/new/68656C6C6F2C20776562617574686E21/")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/new/../new/68656C6C6F2C20776562617574686E21")
        );

        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0FFEE/not_hex_digits_here_but_32_chars")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0FFEE/COFFEE")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0/FFEE")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0F/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0FFEECO/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/cable/connect/C0FFEE/68656C6C6F2C20776562617574686E21/1234")
        );

        // other nonsense
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("cable/new/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("../cable/new/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(
            CablePath::Unknown,
            CablePath::from("/../cable/new/68656C6C6F2C20776562617574686E21")
        );
        assert_eq!(CablePath::Unknown, CablePath::from("../../../etc/passwd"));

        // Should be rejected by length limits
        assert_eq!(
            CablePath::Unknown,
            CablePath::from(include_str!("lib.rs"))
        );
    }
}
