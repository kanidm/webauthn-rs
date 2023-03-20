use std::{convert::Infallible, env, net::SocketAddr};

use hyper::{
    client::conn::handshake,
    header::HeaderValue,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};

use cable_tunnel_server_common::*;
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[macro_use]
extern crate tracing;

const ROUTING_ID: RoutingId = [0xC0, 0xFF, 0xEE];
const BACKEND: &str = "127.0.0.1:8081";

async fn handle_request(
    mut req: Request<Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    info!("{addr}: {} {}", req.method(), req.uri().path());

    // Use our usual routing logic for static files, except ignore the crafted
    // response for Websocket connections.
    let mut path = match Router::route(&req) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(_, path) => path,
    };

    // Copy the incoming request to re-send to the backend.
    let mut backend_req = copy_request_empty_body(&req);
    // TODO: add forwarding headers

    // Get the backend address, and set the Routing ID header in the request
    let backend = match &mut path.method {
        CableMethod::New => {
            // TODO
            path.routing_id.copy_from_slice(&ROUTING_ID);
            let headers = backend_req.headers_mut();

            // Replace the Routing ID header sent to the backend with the
            // selected routing ID.
            headers.insert(
                CABLE_ROUTING_ID_HEADER,
                HeaderValue::from_str(&hex::encode_upper(path.routing_id)).unwrap(),
            );

            // TODO
            BACKEND
        }

        CableMethod::Connect => {
            // TODO lookup routing ID
            // if path.routing_id != ROUTING_ID {
            //     error!("{addr}: unknown routing ID");
            //     return Ok(Response::builder()
            //         .status(StatusCode::NOT_FOUND)
            //         .body(Body::empty())
            //         .unwrap());
            // }

            BACKEND
        }
    };

    // Connect to the backend task
    info!("{addr}: connecting to backend {backend}");
    let backend_socket = match TcpStream::connect(backend).await {
        Ok(s) => s,
        Err(e) => {
            error!("{addr}: unable to reach backend {backend}: {e}");
            return Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Body::empty())
                .unwrap());
        }
    };

    let (mut sender, conn) = match handshake(backend_socket).await {
        Ok(v) => v,
        Err(e) => {
            error!("{addr}: unable to handshake with backend {backend}: {e}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .unwrap());
        }
    };

    // Spawn a task to poll the connection and drive the HTTP state
    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            error!("{addr}: backend connection failed: {e:?}");
        }
    });

    // Pass the request to the selected backend
    let mut backend_res = match sender.send_request(backend_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("{addr}: unable to send request to backend {backend}: {e}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .unwrap());
        }
    };

    if backend_res.status() != StatusCode::SWITCHING_PROTOCOLS {
        error!(
            "{addr}: backend {backend} returned unexpected status: {}",
            backend_res.status()
        );
        return Ok(Response::builder()
            .status(backend_res.status())
            .body(Body::empty())
            .unwrap());
    }

    // Copy the response for the client
    let res = copy_response_empty_body(&backend_res);

    // Set up the "upgrade" handler to connect the two sockets together
    tokio::task::spawn(async move {
        // Upgrade the connection to the backend
        let mut backend_upgraded = match hyper::upgrade::on(&mut backend_res).await {
            Ok(u) => u,
            Err(e) => {
                error!("{addr}: failure upgrading connection to backend {backend}: {e}");
                return;
            }
        };

        // Upgrade the connection from the client
        let mut client_upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => {
                error!("{addr}: failure upgrading connection to client: {e}");
                return;
            }
        };

        // Connect the two streams together directly.
        match tokio::io::copy_bidirectional(&mut backend_upgraded, &mut client_upgraded).await {
            Ok((backend_bytes, client_bytes)) => {
                info!("{addr}: connection closed, backend sent {backend_bytes} bytes, client sent {client_bytes} bytes");
            }
            Err(e) => {
                error!("{addr}: connection error: {e}");
                backend_upgraded.shutdown().await.ok();
                client_upgraded.shutdown().await.ok();
            }
        }
    });

    Ok(res)
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
