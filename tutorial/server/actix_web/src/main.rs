use std::path::Path;

use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::middleware::Logger;
use actix_web::web::JsonConfig;
use actix_web::web::{get, post};
use actix_web::{App, HttpServer};
use tracing::info;

use crate::handler::auth::{
    finish_authentication, finish_register, start_authentication, start_register,
};
use crate::handler::serve_assets::{serve_assets, serve_index, ASSETS_DIR};
use crate::session::MemorySession;
use crate::startup::startup;

mod handler;
mod session;
mod startup;

#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO");
    }
    // initialize tracing
    tracing_subscriber::fmt::init();

    // Generate secret key for cookies.
    // Normally you would read this from a configuration file.
    let key = Key::generate();

    let (webauthn, webauthn_users) = startup();

    if !Path::new(ASSETS_DIR).exists() {
        panic!("{ASSETS_DIR} does not exist, can't start tutorial server.");
    } else {
        info!("Found asset dir OK");
    }

    // Build the webserver and run it
    info!("Listening on: http://0.0.0.0:8080 / http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(MemorySession, key.clone())
                    .cookie_name("webauthnrs".to_string())
                    .cookie_http_only(true)
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(JsonConfig::default())
            .app_data(webauthn.clone())
            .app_data(webauthn_users.clone())
            .route("/", get().to(serve_index))
            .route("/{filename:.*}", get().to(serve_assets))
            .route("/register_start/{username}", post().to(start_register))
            .route("/register_finish", post().to(finish_register))
            .route("/login_start/{username}", post().to(start_authentication))
            .route("/login_finish", post().to(finish_authentication))
    })
    .bind(("0.0.0.0", 8080))
    .expect("Failed to start a listener on 0.0.0.0:8080")
    .run()
    .await
    .unwrap();
}
