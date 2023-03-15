use std::{collections::HashMap, mem::size_of, sync::Arc};

use async_std::{prelude::*, sync::Mutex};
use futures_channel::mpsc::UnboundedSender;

use openssl::rand::rand_bytes;
use tide::{
    http::headers::{HeaderName, CONNECTION, UPGRADE},
    Middleware, Request,
};
use tide_websockets::{Message, WebSocket, WebSocketConnection};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<TunnelId, Tunnel>>>;

const ROUTING_ID: RoutingId = [0xCO, 0xFF, 0xEE];
const BACKEND: &str = "127.0.0.1:8081";

#[derive(Default, Clone)]
struct AppState {}

struct CableFrontendMiddleware {
    initiator: bool,
}

impl CableFrontendMiddleware {
    fn new(initiator: bool) -> Self {
        Self { initiator }
    }
}

struct Tunnel {
    authenticator: Tx,
    initiator: Option<Tx>,
}

fn header_contains_ignore_case<T>(req: &Request<T>, header_name: HeaderName, value: &str) -> bool {
    req.header(header_name)
        .map(|h| {
            h.as_str()
                .split(',')
                .any(|s| s.trim().eq_ignore_ascii_case(value.trim()))
        })
        .unwrap_or(false)
}

#[tide::utils::async_trait]
impl<S> Middleware<S> for CableFrontendMiddleware
where
    S: Send + Sync + Clone + 'static,
{
    async fn handle(&self, req: Request<S>, next: tide::Next<'_, S>) -> tide::Result {
        let connection_upgrade = header_contains_ignore_case(&req, CONNECTION, "upgrade");
        let upgrade_to_websocket = header_contains_ignore_case(&req, UPGRADE, "websocket");
        let upgrade_requested = connection_upgrade && upgrade_to_websocket;

        if !upgrade_requested {
            return Ok(next.run(req).await);
        }

        check_cable_protocol_header(&req)?;
        let _tunnel_id = get_tunnel_id(&req)?;

        let routing_id = if self.initiator {
            get_routing_id(&req)?
        } else {
            // TODO
            ROUTING_ID
        };
        
        // Forward the request to a backend
        // TODO: here we need a nice escape hatch. It's probable that surf isn't
        // the best library for it, and there doesn't seem to be any examples of
        // using the Upgrade mechanism AFAICT.
        //
        // The basic design is that the frontend accepts requests, has a list of
        // known backends, and can forward it appropriately based on the
        // RoutingID header. It also needs to be able to _set_ the RoutingID
        // header.
        //
        // For the authenticator, we need to be able to:
        // 1. Create a connection to a healthy backend
        // 2. Forward through the client's set-up request to a backend
        // 3. Get the HTTP response from the backend
        // 4. Add in the routing ID header, and return that to the client
        // 5. Now the socket is WebSockets mode, proxy messages from one side
        //    to the other.
        //
        // For the initiator, we need to be able to:
        // 1. Create a connection to a _specific_ backend
        // 2. Now just pass through the original request to the backend and
        //    proxy the rest of the connection.
        //
        // This is probably also blocked on https://github.com/http-rs/tide-websockets/issues/26
        //
        // Tungstenite has an example using Hyper and custom headers:
        // https://github.com/snapview/tokio-tungstenite/blob/e48a3af778a9913b9f957e89f0eec7015386ddd0/examples/server-custom-accept.rs#L146
        

        let req: &tide::http::Request = req.as_ref();
        let req = req.clone();
        // req.set
        
        let client = surf::Client::new();
        req.host();
        

        todo!()
    }
}

async fn handle_authenticator(
    request: tide::Request<AppState>,
    mut stream: WebSocketConnection,
) -> Result<(), tide::Error> {
    info!("Handle authenticator");
    let tunnel_id = get_tunnel_id(&request)?;
    info!("Tunnel ID: {tunnel_id:?}");

    while let Some(Ok(Message::Text(input))) = stream.next().await {
        let output: String = input.chars().rev().collect();

        stream
            .send_string(format!("{} | {}", &input, &output))
            .await?;
    }
    Ok(())
}

async fn handle_initator(
    request: tide::Request<AppState>,
    mut stream: WebSocketConnection,
) -> Result<(), tide::Error> {
    info!("Handle initiator");
    let tunnel_id = get_tunnel_id(&request)?;
    info!("Tunnel ID: {tunnel_id:?}");

    while let Some(Ok(Message::Text(input))) = stream.next().await {
        let output: String = input.chars().rev().collect();

        stream
            .send_string(format!("{} | {}", &input, &output))
            .await?;
    }
    Ok(())
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt::init();

    // Create the app
    let app_state = AppState::default();
    let mut app = tide::with_state(app_state);
    // Enable logging
    app.with(tide::log::LogMiddleware::new());

    // Handler
    app.at(CABLE_NEW_URL)
        .with(CableFrontendMiddleware::new(false))
        .get(WebSocket::new(handle_authenticator).with_protocols(&CABLE_PROTOCOLS));
    app.at(CABLE_CONNECT_URL)
        .with(CableFrontendMiddleware::new(true))
        .get(WebSocket::new(handle_initator).with_protocols(&CABLE_PROTOCOLS));

    app.at("/")
        .get(|_| async move { Ok("Hello cable tunnel backend server") });

    app.listen("127.0.0.1:8080").await?;

    Ok(())
}
