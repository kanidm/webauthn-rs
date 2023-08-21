use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::middleware::Logger;
use actix_web::web::JsonConfig;
use actix_web::web::{get, post};
use actix_web::{App, HttpServer};
use log::info;

use crate::handler::auth::{
    finish_authentication, finish_register, start_authentication, start_register,
};
use crate::handler::index::index;
use crate::handler::serve_wasm::serve_wasm;
use crate::session::MemorySession;
use crate::startup::startup;

mod handler;
mod session;
mod startup;

#[tokio::main]
async fn main() {
    // Initialize env-logger
    env_logger::init();

    // Generate secret key for cookies.
    // Normally you would read this from a configuration file.
    let key = Key::generate();

    let (webauthn, webauthn_users) = startup();

    // Build the webserver and run it
    info!("Start listening on: http://0.0.0.0:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(MemorySession, key.clone())
                    .cookie_name("webauthnrs".to_string())
                    .build(),
            )
            .app_data(JsonConfig::default())
            .app_data(webauthn.clone())
            .app_data(webauthn_users.clone())
            .route("/", get().to(index))
            .route("/pkg/{filename:.*}", get().to(serve_wasm))
            .route("/register_start/{username}", post().to(start_register))
            .route("/register_finish", post().to(finish_register))
            .route("/login_start/{username}", post().to(start_authentication))
            .route("/login_finish", post().to(finish_authentication))
    })
    .bind(("0.0.0.0", 8080))
    .unwrap()
    .run()
    .await
    .unwrap();
}
