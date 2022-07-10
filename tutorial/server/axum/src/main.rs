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

// 1. Import the prelude - this contains everything needed for the server to function.
// use webauthn_rs::prelude::*;

// These are other imports needed to make the site generally work.

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

// #[tokio::main]
// async fn main() -> tide::Result<()> {
//     tracing_subscriber::fmt::init();

//     // Create the app
//     let app_state = AppState::new();
//     let mut app = tide::with_state(app_state);

//     // Allow cookies so that we can bind some data to sessions.
//     // In production, you should NOT use the memory store, since
//     // it does not have cleanup.
//     let cookie_sig = StdRng::from_entropy().gen::<[u8; 32]>();
//     let memory_store = tide::sessions::MemoryStore::new();

//     let sessions = tide::sessions::SessionMiddleware::new(memory_store.clone(), &cookie_sig)
//         .with_cookie_domain("localhost")
//         .with_same_site_policy(tide::http::cookies::SameSite::Strict)
//         .with_session_ttl(Some(Duration::from_secs(3600)))
//         .with_cookie_name("webauthnrs");

//     // Bind the sessions to our app
//     app.with(sessions);
//     // Enable logging
//     app.with(tide::log::LogMiddleware::new());

//     // Serve our wasm content
//     app.at("/pkg").serve_dir("../wasm/pkg")?;

//     // Bind our apis to our functions.
//     app.at("/register_start/:username").post(start_register);
//     app.at("/register_finish").post(finish_register);
//     app.at("/login_start/:username").post(start_authentication);
//     app.at("/login_finish").post(finish_authentication);

//     // Serve our base html that bootstraps the wasm context.
//     app.at("/").get(index_view);
//     app.at("/*").get(index_view);

//     info!("Spawning on http://localhost:8080");

//     // Spawn the socket listener, and run the actual site.
//     app.listen("127.0.0.1:8080").await?;

//     Ok(())
// }
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

    // // Serve our wasm content
    // app.at("/pkg").serve_dir("../wasm/pkg")?;

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
