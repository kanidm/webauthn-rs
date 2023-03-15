use std::{collections::HashMap, sync::Arc};

use async_std::{prelude::*, sync::Mutex};
use futures_channel::mpsc::UnboundedSender;

use tide::{Middleware, Request};
use tide_websockets::{Message, WebSocket, WebSocketConnection};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<TunnelId, Tunnel>>>;

#[derive(Default, Clone)]
struct AppState {}

struct CableMiddleware
{
    initiator: bool,
}

impl CableMiddleware
{
    fn new(initiator: bool) -> Self {
        Self { initiator }
    }
}

struct Tunnel {
    authenticator: Tx,
    initiator: Option<Tx>,
}

#[tide::utils::async_trait]
impl<S> Middleware<S> for CableMiddleware
where
    S: Send + Sync + Clone + 'static,
{
    async fn handle(&self, req: Request<S>, next: tide::Next<'_, S>) -> tide::Result {
        check_cable_protocol_header(&req)?;
        let _tunnel_id = get_tunnel_id(&req)?;
        if self.initiator {
            let _routing_id = get_routing_id(&req)?;
        }

        // TODO: consider using tide Extensions in the request passed back

        // // Generate a random RoutingId
        // let mut routing_id: RoutingId = [0; size_of::<RoutingId>()];
        // rand_bytes(&mut routing_id)?;

        // TODO: figure out how to send another HTTP header back
        Ok(next.run(req).await)
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
        .with(CableMiddleware::new(false))
        .get(WebSocket::new(handle_authenticator).with_protocols(&CABLE_PROTOCOLS));
    app.at(CABLE_CONNECT_URL)
        .with(CableMiddleware::new(true))
        .get(WebSocket::new(handle_initator).with_protocols(&CABLE_PROTOCOLS));

    app.at("/")
        .get(|_| async move { Ok("Hello cable tunnel backend server") });

    app.listen("127.0.0.1:8081").await?;

    Ok(())
}
