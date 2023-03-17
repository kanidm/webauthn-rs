use std::{
    convert::Infallible,
    env,
    net::SocketAddr,
};

use hyper::{
    header::HeaderValue,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Request, Response, Server,
};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

const ROUTING_ID: RoutingId = [0xC0, 0xFF, 0xEE];
const BACKEND: &str = "127.0.0.1:8081";

async fn handle_request(
    mut req: Request<Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    info!("Received a new, potentially ws handshake");
    info!("The request's path is: {}", req.uri().path());
    info!("The request's headers are:");
    for (ref header, _value) in req.headers() {
        info!("* {}", header);
    }

    let mut path = match Router::route(&req) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(_, path) => path,
    };

    let backend = match &mut path {
        CablePath::New(routing_id, tunnel_id) => {
            // TODO
            routing_id.copy_from_slice(&ROUTING_ID);

            // Add the routing ID to the request header to be passed to the
            // backend
            req.headers_mut().append(
                CABLE_ROUTING_ID_HEADER,
                HeaderValue::from_str(&hex::encode(&routing_id)).unwrap(),
            );

            // TODO
            BACKEND
        }

        CablePath::Connect(routing_id, tunnel_id) => {
            // TODO check routing ID

            BACKEND
        }
    };

    // TODO: connect to the backend task

    // TODO: pass the entire request to the selected backend

    // TODO: set up the "upgrade" handler to connect the two sockets together

    // TODO: pass back the backend's response

    todo!()
    // tokio::task::spawn(async move {
    //     match hyper::upgrade::on(&mut req).await {
    //         Ok(upgraded) => {
    //             handle_connection(
    //                 peer_map,
    //                 WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await,
    //                 addr,
    //                 path,
    //             )
    //             .await;
    //         }
    //         Err(e) => info!("upgrade error: {}", e),
    //     }
    // });

    // Ok(res)
    
}

#[tokio::main]
async fn main() -> Result<(), hyper::Error> {
    tracing_subscriber::fmt::init();

    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string())
        .parse()
        .unwrap();

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let service = service_fn(move |req| handle_request(req, remote_addr));
        async move { Ok::<_, Infallible>(service) }
    });

    info!("Starting frontend server on {:?}", addr);
    let server = Server::bind(&addr).serve(make_svc);

    server.await?;

    Ok::<_, hyper::Error>(())
}
