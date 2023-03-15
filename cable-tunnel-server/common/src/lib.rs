use tide::{Error, Request, Result, StatusCode};
#[macro_use]
extern crate tracing;

pub type RoutingId = [u8; 3];
pub type TunnelId = [u8; 16];

pub const CABLE_PROTOCOL: &str = "fido.cable";
pub const CABLE_PROTOCOLS: [&str; 1] = [CABLE_PROTOCOL];
pub const CABLE_NEW_URL: &str = "/cable/new/:tunnel_id";
pub const CABLE_CONNECT_URL: &str = "/cable/connect/:routing_id/:tunnel_id";

fn get_hex_param<const L: usize, S: Send + Sync + Clone + 'static>(
    req: &Request<S>,
    param: &str,
) -> Result<[u8; L]> {
    let mut o: [u8; L] = [0; L];
    let v = req.param(param)?.as_bytes();
    info!(?v);
    hex::decode_to_slice(v, &mut o).map_err(|e| {
        error!("converting {param}: {e:?}");
        Error::from_str(StatusCode::BadRequest, "Invalid Base16")
    })?;

    Ok(o)
}

pub fn get_tunnel_id<S: Send + Sync + Clone + 'static>(req: &Request<S>) -> Result<TunnelId> {
    get_hex_param(req, "tunnel_id")
}

pub fn get_routing_id<S: Send + Sync + Clone + 'static>(req: &Request<S>) -> Result<RoutingId> {
    get_hex_param(req, "routing_id")
}

pub fn check_cable_protocol_header<S: Send + Sync + Clone + 'static>(
    req: &Request<S>,
) -> Result<()> {
    if !req
        .header("Sec-Websocket-Protocol")
        .map(|h| {
            h.get(0)
                .map(|f| f.as_str() == CABLE_PROTOCOL)
                .unwrap_or_default()
        })
        .unwrap_or_default()
    {
        return Err(tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "missing protocol header",
        ));
    }
    Ok(())
}
