use axum::{
    extract::Extension,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use axum_sessions::{async_session::MemoryStore, SameSite, SessionLayer};
use std::net::SocketAddr;
mod error;
mod file;
/*
 * Webauthn RS server side tutorial.
 */

// The handlers that process the data can be found in the auth.rs file
// This file contains the wasm client loading code and the axum routing
use crate::auth::{finish_authentication, finish_register, start_authentication, start_register};
use crate::file::file_handler;
use crate::startup::AppState;

use rand::prelude::*;

#[macro_use]
extern crate tracing;

mod auth;
mod startup;

// 7. That's it! The user has now authenticated!

// =======
// Below is glue/stubs that are needed to make the above work, but don't really affect
// the work flow too much.

async fn index_view() -> impl IntoResponse {
    Html(
        r#"
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WebAuthn-rs Tutorial</title>

    <script type="module">
        import init, { run_app } from './pkg/wasm.js';
        async function main() {
           await init('./pkg/wasm_bg.wasm');
           run_app();
        }
        main()
    </script>
  </head>
  <body>
  <p>Welcome to the WebAuthn Server!</p>
  </body>
</html>
    "#,
    )
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // Create the app
    let app_state = AppState::new();

    //Configure cookie based sessions
    let store = MemoryStore::new();
    let secret = rand::thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(store, &secret)
        .with_cookie_name("webauthnrs")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(true);

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(index_view))
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        .nest("/pkg", get(file_handler))
        .layer(Extension(app_state))
        .layer(session_layer);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("listening on {}", addr);
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
