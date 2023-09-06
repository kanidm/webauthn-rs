use axum::{extract::Extension, routing::post, Router};
use axum_extra::routing::SpaRouter;
use axum_sessions::{async_session::MemoryStore, SameSite, SessionLayer};
use std::net::SocketAddr;
mod error;
/*
 * Webauthn RS server side tutorial.
 */

// The handlers that process the data can be found in the auth.rs file
// This file contains the wasm client loading code and the axum routing
use crate::auth::{finish_authentication, finish_register, start_authentication, start_register};
use crate::startup::AppState;

use rand::prelude::*;

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

    //Configure cookie based sessions
    let store = MemoryStore::new();
    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(store, &secret)
        .with_cookie_name("webauthnrs")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(false); // TODO: change this to true when running on an HTTPS/production server instead of locally

    // build our application with a route
    let app = Router::new()
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(session_layer);

    #[cfg(feature = "wasm")]
    let app = Router::new()
        .merge(app)
        .merge(SpaRouter::new("/assets", "assets").index_file("wasm_index.html"));

    #[cfg(feature = "javascript")]
    let app = Router::new()
        .merge(app)
        .merge(SpaRouter::new("/assets", "assets").index_file("js_index.html"));

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
