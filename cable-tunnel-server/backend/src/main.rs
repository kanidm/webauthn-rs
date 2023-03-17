use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use hyper::{
    header::HeaderValue,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Request, Response, Server,
};

use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::{Message, Role};

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
        CablePath::New(_, tunnel_id) => {
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

        CablePath::Connect(_, tunnel_id) => {
            let mut lock = peer_map.lock().unwrap();
            if let Some(c) = lock.remove(&tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("No peer available");
                return;
            }
        }
    };

    let (outgoing, incoming) = ws_stream.split();

    // TODO: add some limits on the size and number of messages
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

    // Clean up possible stale entry on disconnect
    if let CablePath::New(_, tunnel_id) = path {
        peer_map.lock().unwrap().remove(&tunnel_id);
    }
}

async fn handle_request(
    peer_map: PeerMap,
    mut req: Request<Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    info!("Received a new, potentially ws handshake");
    info!("The request's path is: {}", req.uri().path());
    // info!("The request's headers are:");
    // for (ref header, _value) in req.headers() {
    //     info!("* {}", header);
    // }

    let (mut res, path) = match Router::route(&req) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(res, path) => (res, path),
    };

    // Send a routing ID back
    if let CablePath::New(routing_id, _) = path {
        res.headers_mut().append(
            CABLE_ROUTING_ID_HEADER,
            HeaderValue::from_str(&hex::encode(&routing_id)).unwrap(),
        );
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
