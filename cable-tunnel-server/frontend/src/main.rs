use std::{convert::Infallible, env, net::SocketAddr};

use hyper::{
    header::HeaderValue,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
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
    info!("Received a new, potentially ws handshake");
    info!("The request's path is: {}", req.uri().path());
    // info!("The request's headers are:");
    // for (ref header, _value) in req.headers() {
    //     info!("* {}", header);
    // }

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
    let target_stream = TcpStream::connect(backend).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::handshake(target_stream).await.unwrap();

    // Await  disconnection
    // tokio::task::spawn(async move {
    //     if let Err(err) = conn.await {
    //         println!("Connection failed: {:?}", err);
    //     }
    // });

    // TODO: pass the entire request to the selected backend
    let mut req_copy = Request::builder().method(req.method());
    req_copy.headers_mut().unwrap().extend(req.headers().to_owned());
    let req_copy = req_copy.body(Body::empty()).unwrap();

    let mut res = sender.send_request(req_copy).await.unwrap();
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        error!("backend didn't upgrade!");
        return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
    }

    // TODO: set up the "upgrade" handler to connect the two sockets together
    tokio::task::spawn(async move {
        // On the client
        // match hyper::upgrade::on(&mut res).await {
        //     Ok(upgraded) => {
        //         todo!()
        //     }
        //     Err(e) => error!("upgrade error: {}", e),
        // }

        // TODO: pass the TcpStream
        let mut parts = conn.without_shutdown().await.unwrap();
        let (mut ro, mut wo) = parts.io.split();

        // On the server
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => {
                error!("upgrade error: {}", e);
                return;
            }
        };

        let mut upgraded = upgraded.downcast::<TcpStream>().unwrap();
        let (mut ri, mut wi) = upgraded.io.split();

        let client_to_server = async {
            tokio::io::copy(&mut ri, &mut wo).await?;
            wo.shutdown().await
        };

        let server_to_client = async {
            tokio::io::copy(&mut ro, &mut wi).await?;
            wi.shutdown().await
        };

        tokio::try_join!(client_to_server, server_to_client).map_err(|e| {
            error!("socket broke? {e:?}");
            ()
        }).ok();
    });

    // TODO: pass back the backend's response
    Ok(res)

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
