use axum::{
    error_handling::HandleErrorLayer, extract::Extension, http::StatusCode, routing::post,
    BoxError, Router,
};
use std::{net::SocketAddr, path::PathBuf};
use tower::ServiceBuilder;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

mod error;
/*
 * Webauthn RS server side tutorial.
 */

// The handlers that process the data can be found in the auth.rs file
// This file contains the wasm client loading code and the axum routing
use crate::auth::{finish_authentication, finish_register, start_authentication, start_register};
use crate::startup::AppState;

#[macro_use]
extern crate tracing;

mod auth;
mod startup;

#[cfg(all(feature = "javascript", feature = "wasm", not(doc)))]
compile_error!("Feature \"javascript\" and feature \"wasm\" cannot be enabled at the same time");

// 7. That's it! The user has now authenticated!

// =======
// Below is glue/stubs that are needed to make the above work, but don't really affect
// the work flow too much.

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // Create the app
    let app_state = AppState::new();

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(
            SessionManagerLayer::new(session_store)
                .with_name("webauthnrs")
                .with_same_site(SameSite::Strict)
                .with_secure(false) // TODO: change this to true when running on an HTTPS/production server instead of locally
                .with_expiry(Expiry::OnInactivity(Duration::seconds(360))),
        );

    // build our application with a route
    let app = Router::new()
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(session_service);

    #[cfg(feature = "wasm")]
    if !PathBuf::from("./assets/wasm").exists() {
        panic!("Can't find WASM files to serve!")
    }

    #[cfg(feature = "wasm")]
    let app = Router::new()
        .merge(app)
        .nest_service("/", tower_http::services::ServeDir::new("assets/wasm"));

    #[cfg(feature = "javascript")]
    let app = Router::new()
        .merge(app)
        .nest_service("/assets", tower_http::services::ServeDir::new("assets/js"));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("listening on {addr}");
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
