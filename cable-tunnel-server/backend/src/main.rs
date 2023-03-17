use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use hyper::{
    header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Method, Request, Response, Server,
};

use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    handshake::server::create_response_with_body,
    protocol::{Message, Role},
};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Rx = UnboundedReceiver<Message>;
type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<TunnelId, Tunnel>>>;

struct Tunnel {
    authenticator_rx: Rx,
    initiator_tx: Tx,
}

async fn handle_connection(
    peer_map: PeerMap,
    ws_stream: WebSocketStream<Upgraded>,
    addr: SocketAddr,
    path: CablePath,
) {
    info!("WebSocket connection established: {}", addr);
    let (tx, rx) = match path {
        CablePath::New(tunnel_id) => {
            let mut lock = peer_map.lock().unwrap();
            if lock.contains_key(&tunnel_id) {
                // bad request
                error!("bad request, tunnel exists");
                return;
            }

            // Create both channels in the authenticator side, as the first one here
            let (authenticator_tx, authenticator_rx) = unbounded();
            let (initiator_tx, initiator_rx) = unbounded();

            let tunnel = Tunnel {
                authenticator_rx,
                initiator_tx,
            };

            lock.insert(tunnel_id, tunnel);

            drop(lock);

            (authenticator_tx, initiator_rx)
        }

        CablePath::Connect(routing_id, tunnel_id) => {
            let mut lock = peer_map.lock().unwrap();
            if let Some(c) = lock.remove(&tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("No peer available");
                return;
            }
        }

        _ => unreachable!(),
    };

    let (outgoing, incoming) = ws_stream.split();

    let forwarder = incoming.try_for_each(|msg| {
        info!(
            "Received a message from {}: {}",
            addr,
            msg.to_text().unwrap()
        );
        tx.unbounded_send(msg.clone()).unwrap();

        future::ok(())
    });

    let receiver = rx.map(Ok).forward(outgoing);

    pin_mut!(forwarder, receiver);
    future::select(forwarder, receiver).await;

    info!("{} disconnected", &addr);

    // TODO: Clean up stale peer_map entry
}

async fn handle_request(
    peer_map: PeerMap,
    mut req: Request<Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    info!("Received a new, potentially ws handshake");
    info!("The request's path is: {}", req.uri().path());
    info!("The request's headers are:");
    for (ref header, _value) in req.headers() {
        info!("* {}", header);
    }

    if req.method() != Method::GET {
        let response = Response::builder()
            .status(405)
            .header("Allow", "GET")
            .body(Body::from("Method not allowed"))
            .unwrap();
        return Ok(response);
    }

    if req.uri().path().eq_ignore_ascii_case("/favicon.ico") {
        info!("have an icon");
        let mut response = Response::new(Body::from(FAVICON));
        response.headers_mut().insert(
            "Content-type",
            HeaderValue::from_static("image/vnd.microsoft.icon"),
        );

        return Ok(response);
    }

    // Find the path
    let path = CablePath::from(req.uri().path());
    if let CablePath::Unknown = path {
        info!("unknown url");
        let response = Response::builder()
            .status(404)
            .body(Body::from("Not found"))
            .unwrap();
        return Ok(response);
    }

    let mut res = match create_response_with_body(&req, || Body::empty()) {
        Ok(r) => r,
        Err(e) => {
            error!("Error making websocket: {e:?}");
            return Ok(Response::builder()
                .status(400)
                .body(Body::from("Bad request for websocket"))
                .unwrap());
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
        error!("Unsupported or missing websocket protocol");
        return Ok(Response::builder()
            .status(400)
            .body(Body::from("Missing websocket protocol"))
            .unwrap());
    } else {
        // We have the correct protocol, include in the response
        res.headers_mut().append(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(CABLE_PROTOCOL),
        );
    }

    // TODO: handle routing ID properly
    if matches!(path, CablePath::New(_)) {
        res.headers_mut()
            .append(CABLE_ROUTING_ID_HEADER, HeaderValue::from_static("C0FFEE"));
    }

    tokio::task::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                handle_connection(
                    peer_map,
                    WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await,
                    addr,
                    path,
                )
                .await;
            }
            Err(e) => info!("upgrade error: {}", e),
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
        .unwrap_or_else(|| "127.0.0.1:8080".to_string())
        .parse()
        .unwrap();

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let state = state.clone();
        let service = service_fn(move |req| handle_request(state.clone(), req, remote_addr));
        async { Ok::<_, Infallible>(service) }
    });

    let server = Server::bind(&addr).serve(make_svc);

    server.await?;

    Ok::<_, hyper::Error>(())
}
