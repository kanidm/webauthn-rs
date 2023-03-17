use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use hyper::{
    header::{
        HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, UPGRADE,
    },
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Method, Request, Response, Server, StatusCode, Version,
};

use futures_channel::mpsc::{unbounded, UnboundedSender, UnboundedReceiver};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    handshake::{
        derive_accept_key,
        server::{create_response, create_response_with_body},
    },
    protocol::{Message, Role},
};

use std::mem::size_of;

// use async_std::{prelude::*, sync::Mutex};
// use futures_channel::mpsc::UnboundedSender;

use openssl::rand::rand_bytes;
// use tide::{
//     http::headers::{HeaderName, CONNECTION, UPGRADE},
//     Middleware, Request,
// };
// use tide_websockets::{Message, WebSocket, WebSocketConnection};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Rx = UnboundedReceiver<Message>;
type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<TunnelId, Tunnel>>>;

const ROUTING_ID: RoutingId = [0xC0, 0xFF, 0xEE];
const BACKEND: &str = "127.0.0.1:8081";

const FAVICON: &[u8] = include_bytes!("favicon.ico");

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
        },

        CablePath::Connect(routing_id, tunnel_id) => {
            let mut lock = peer_map.lock().unwrap();
            if let Some(c) = lock.remove(&tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("No peer available");
                return;
            }
        },

        _ => unreachable!()
    };


    let (outgoing, incoming) = ws_stream.split();

    let forwarder = incoming.try_for_each(|msg| {
        info!("Received a message from {}: {}", addr, msg.to_text().unwrap());
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

    // let upgrade = HeaderValue::from_static("Upgrade");
    // let websocket = HeaderValue::from_static("websocket");
    // let headers = req.headers();
    // let key = headers.get(SEC_WEBSOCKET_KEY);
    // let derived = key.map(|k| derive_accept_key(k.as_bytes()));
    // if req.method() != Method::GET
    //     || req.version() < Version::HTTP_11
    //     || !headers
    //         .get(CONNECTION)
    //         .and_then(|h| h.to_str().ok())
    //         .map(|h| {
    //             h.split(|c| c == ' ' || c == ',')
    //                 .any(|p| p.eq_ignore_ascii_case(upgrade.to_str().unwrap()))
    //         })
    //         .unwrap_or(false)
    //     || !headers
    //         .get(UPGRADE)
    //         .and_then(|h| h.to_str().ok())
    //         .map(|h| h.eq_ignore_ascii_case("websocket"))
    //         .unwrap_or(false)
    //     || !headers.get(SEC_WEBSOCKET_VERSION).map(|h| h == "13").unwrap_or(false)
    //     || key.is_none()
    //     || req.uri() != "/socket"
    // {
    //     return Ok(Response::new(Body::from("Hello World!")));
    // }

    // let ver = req.version();

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
    // let mut res = Response::new(Body::empty());
    // *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    // *res.version_mut() = ver;
    // res.headers_mut().append(CONNECTION, upgrade);
    // res.headers_mut().append(UPGRADE, websocket);
    // res.headers_mut().append(SEC_WEBSOCKET_ACCEPT, derived.unwrap().parse().unwrap());
    // Let's add an additional header to our response to the client.
    // res.headers_mut()
    //     .append("MyCustomHeader", ":)".parse().unwrap());
    // res.headers_mut()
    //     .append("SOME_TUNGSTENITE_HEADER", "header_value".parse().unwrap());
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

// struct CableFrontendMiddleware {
//     initiator: bool,
// }

// impl CableFrontendMiddleware {
//     fn new(initiator: bool) -> Self {
//         Self { initiator }
//     }
// }

// fn header_contains_ignore_case<T>(req: &Request<T>, header_name: HeaderName, value: &str) -> bool {
//     req.header(header_name)
//         .map(|h| {
//             h.as_str()
//                 .split(',')
//                 .any(|s| s.trim().eq_ignore_ascii_case(value.trim()))
//         })
//         .unwrap_or(false)
// }

// #[tide::utils::async_trait]
// impl<S> Middleware<S> for CableFrontendMiddleware
// where
//     S: Send + Sync + Clone + 'static,
// {
//     async fn handle(&self, req: Request<S>, next: tide::Next<'_, S>) -> tide::Result {
//         let connection_upgrade = header_contains_ignore_case(&req, CONNECTION, "upgrade");
//         let upgrade_to_websocket = header_contains_ignore_case(&req, UPGRADE, "websocket");
//         let upgrade_requested = connection_upgrade && upgrade_to_websocket;

//         if !upgrade_requested {
//             return Ok(next.run(req).await);
//         }

//         check_cable_protocol_header(&req)?;
//         let _tunnel_id = get_tunnel_id(&req)?;

//         let routing_id = if self.initiator {
//             get_routing_id(&req)?
//         } else {
//             // TODO
//             ROUTING_ID
//         };

//         // Forward the request to a backend
//         // TODO: here we need a nice escape hatch. It's probable that surf isn't
//         // the best library for it, and there doesn't seem to be any examples of
//         // using the Upgrade mechanism AFAICT.
//         //
//         // The basic design is that the frontend accepts requests, has a list of
//         // known backends, and can forward it appropriately based on the
//         // RoutingID header. It also needs to be able to _set_ the RoutingID
//         // header.
//         //
//         // For the authenticator, we need to be able to:
//         // 1. Create a connection to a healthy backend
//         // 2. Forward through the client's set-up request to a backend
//         // 3. Get the HTTP response from the backend
//         // 4. Add in the routing ID header, and return that to the client
//         // 5. Now the socket is WebSockets mode, proxy messages from one side
//         //    to the other.
//         //
//         // For the initiator, we need to be able to:
//         // 1. Create a connection to a _specific_ backend
//         // 2. Now just pass through the original request to the backend and
//         //    proxy the rest of the connection.
//         //
//         // This is probably also blocked on https://github.com/http-rs/tide-websockets/issues/26
//         //
//         // Tungstenite has an example using Hyper and custom headers:
//         // https://github.com/snapview/tokio-tungstenite/blob/e48a3af778a9913b9f957e89f0eec7015386ddd0/examples/server-custom-accept.rs#L146

//         let req: &tide::http::Request = req.as_ref();
//         let req = req.clone();
//         // req.set

//         let client = surf::Client::new();
//         req.host();

//         todo!()
//     }
// }

// async fn handle_authenticator(
//     request: tide::Request<AppState>,
//     mut stream: WebSocketConnection,
// ) -> Result<(), tide::Error> {
//     info!("Handle authenticator");
//     let tunnel_id = get_tunnel_id(&request)?;
//     info!("Tunnel ID: {tunnel_id:?}");

//     while let Some(Ok(Message::Text(input))) = stream.next().await {
//         let output: String = input.chars().rev().collect();

//         stream
//             .send_string(format!("{} | {}", &input, &output))
//             .await?;
//     }
//     Ok(())
// }

// async fn handle_initator(
//     request: tide::Request<AppState>,
//     mut stream: WebSocketConnection,
// ) -> Result<(), tide::Error> {
//     info!("Handle initiator");
//     let tunnel_id = get_tunnel_id(&request)?;
//     info!("Tunnel ID: {tunnel_id:?}");

//     while let Some(Ok(Message::Text(input))) = stream.next().await {
//         let output: String = input.chars().rev().collect();

//         stream
//             .send_string(format!("{} | {}", &input, &output))
//             .await?;
//     }
//     Ok(())
// }

// #[async_std::main]
// async fn main() -> Result<(), std::io::Error> {
//     tracing_subscriber::fmt::init();

//     // Create the app
//     let app_state = AppState::default();
//     let mut app = tide::with_state(app_state);
//     // Enable logging
//     app.with(tide::log::LogMiddleware::new());

//     // Handler
//     app.at(CABLE_NEW_URL)
//         .with(CableFrontendMiddleware::new(false))
//         .get(WebSocket::new(handle_authenticator).with_protocols(&CABLE_PROTOCOLS));
//     app.at(CABLE_CONNECT_URL)
//         .with(CableFrontendMiddleware::new(true))
//         .get(WebSocket::new(handle_initator).with_protocols(&CABLE_PROTOCOLS));

//     app.at("/")
//         .get(|_| async move { Ok("Hello cable tunnel backend server") });

//     app.listen("127.0.0.1:8080").await?;

//     Ok(())
// }
