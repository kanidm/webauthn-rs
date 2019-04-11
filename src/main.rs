extern crate actix;
extern crate actix_web;

#[macro_use]
extern crate askama;
extern crate base64;
extern crate env_logger;
// extern crate futures;

#[macro_use]
extern crate serde_derive;
extern crate byteorder;

use askama::Template;

// use actix::prelude::*;
use actix_web::{
    fs, http, middleware, server, App, HttpRequest, HttpResponse, Path, State, Json,
};

// use futures::future::Future;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

mod proto;
mod webauthn;

use proto::*;
use webauthn::*;

#[derive(Template)]
#[template(path = "index.html")]
// struct IndexTemplate<'a> {
struct IndexTemplate {
    // list: Vec<&'a str>,
}

struct AppState<'a> {
    // Maintain a map of all the lists and their items.
    db: BTreeMap<&'a str, Vec<&'a str>>,
    wan: Arc<Mutex<Webauthn>>,
}

impl<'a> AppState<'a> {
    fn new() -> Self {
        let s = AppState {
            db: BTreeMap::new(),
            wan: Arc::new(Mutex::new(Webauthn::new(
                "http://127.0.0.1:8000/auth".to_string(),
                vec![Algorithm::ALG_ECDSA_SHA256],
            ))),
        };
        s
    }
}

fn index_view(req: &HttpRequest<AppState>) -> HttpResponse {
    let s = IndexTemplate {
            // list: l,
        }
    .render()
    .unwrap();
    HttpResponse::Ok().content_type("text/html").body(s)
}

fn challenge((username, state): (Path<String>, State<AppState>)) -> HttpResponse {
    let chal = {
        state
            .wan
            .lock()
            .expect("Failed to lock!")
            .generate_challenge(username.into_inner())
    };
    println!("{:?}", chal);
    HttpResponse::Ok().json(chal)
}

fn register((reg, state): (Json<RegisterResponse>, State<AppState>)) -> HttpResponse {
    state.wan.lock().expect("Failed to lock!")
        .register_credential(reg.into_inner()).unwrap();

    HttpResponse::Ok().json(())
}

fn login((lgn, state): (Json<LoginRequest>, State<AppState>)) -> HttpResponse {
    state.wan.lock().expect("Failed to lock!")
        .verify_credential(lgn.into_inner()).unwrap();

    HttpResponse::Ok().json(())
}

fn main() {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    let sys = actix::System::new("checklists");

    // Start http server
    server::new(move || {
        App::with_state(AppState::new())
            // For production
            .prefix("/auth")
            // enable logger
            .middleware(middleware::Logger::default())
            .handler(
                "/static",
                fs::StaticFiles::new("./static")
                    .unwrap()
                    .show_files_listing(),
            )
            .resource("", |r| r.f(index_view))
            .resource("/", |r| r.f(index_view))
            // Need a challenge generation
            .resource("/challenge/{username}", |r| {
                r.method(http::Method::POST).with(challenge)
            })
            // Need a registration
            .resource("/register", |r| r.method(http::Method::POST)
                .with_config(register, |((cfg), )| {
                    cfg.0.limit(4096);
                })
            )
            .resource("/login", |r| r.method(http::Method::POST)
                .with_config(login, |((cfg), )| {
                    cfg.0.limit(4096);
                })
            )
        // Need login
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .start();

    println!("Started http server: http://127.0.0.1:8080/auth/");
    let _ = sys.run();
}

