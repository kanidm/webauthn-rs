use std::path::Path;

use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::middleware::Logger;
use actix_web::web::JsonConfig;
use actix_web::web::{get, post};
use actix_web::{App, HttpServer};
use tracing::{error, info};

use crate::handler::auth::{
    finish_authentication, finish_register, start_authentication, start_register,
};
use crate::handler::index::{index, WASM_BG_FILE, WASM_JS_FILE};
use crate::handler::serve_wasm::{serve_wasm, WASM_DIR};
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

    if !Path::new(WASM_DIR).exists() {
        panic!("{WASM_DIR} does not exist, can't serve WASM files.");
    } else {
        info!("Found WASM dir OK");
    }

    let mut missing_file = false;
    for file in [WASM_BG_FILE, WASM_JS_FILE] {
        if !Path::new(WASM_DIR).join(file).exists() {
            error!("{} does not exist, can't serve WASM files.", file);
            missing_file = true;
        } else {
            info!("Found {} OK", file);
        }
    }
    if missing_file {
        error!("Missing WASM files, can't continue.");
        return;
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
            .route("/", get().to(index))
            .route("/pkg/{filename:.*}", get().to(serve_wasm))
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
