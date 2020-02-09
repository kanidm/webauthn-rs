// Why is this only actix 0.7?
//
// At this time (April 2019) actix 0.8 and actix_web 1.0(?) are in early releases, and are currently
// undocumented on how to perform async operations between async_web to actors with json extraction.
// As a result, I'm unable to work out how to make this work. If someone wants to help upgrade this
// example that would be lovely <3

extern crate actix;
extern crate actix_web;

extern crate time;

// #[macro_use]
extern crate askama;
extern crate cookie;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate structopt;
use structopt::StructOpt;
extern crate openssl;

extern crate webauthn_rs;

use askama::Template;

use actix::prelude::*;
use actix_web::{
    fs, http, middleware, server, App, Error, HttpRequest, HttpResponse, Json, Path, State,
};
// Bring in the trait for session()
use actix_web::middleware::session::RequestSession;
use futures::future::Future;

use rand::prelude::*;
// use time::Duration;

use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::proto::{PublicKeyCredential, RegisterPublicKeyCredential};

mod actors;
mod crypto;

use crate::actors::*;
use crate::crypto::generate_dyn_ssl_params;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

struct AppState {
    wan: Addr<WebauthnActor>,
}

impl AppState {
    fn new(wan: Addr<WebauthnActor>) -> Self {
        AppState { wan }
    }
}

#[derive(Debug, StructOpt)]
struct CmdOptions {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "p", long = "prefix", default_value = "/auth")]
    prefix: String,
    #[structopt(
        short = "n",
        long = "name",
        default_value = "https://localhost:8443/auth"
    )]
    rp_name: String,
    #[structopt(short = "o", long = "origin", default_value = "https://localhost:8443")]
    rp_origin: String,
    #[structopt(short = "i", long = "id", default_value = "localhost")]
    rp_id: String,
    #[structopt(short = "b", long = "bind", default_value = "127.0.0.1:8443")]
    bind: String,
}

fn index_view(req: &HttpRequest<AppState>) -> HttpResponse {
    let some_userid = match req.session().get::<String>("userid") {
        Ok(v) => v,
        Err(_e) => {
            return HttpResponse::InternalServerError().body("Internal Server Error");
        }
    };

    // println!("{:?}", some_userid);

    if some_userid.is_none() {
        match req.session().set("anonymous", true) {
            Ok(_) => {}
            Err(_e) => {
                return HttpResponse::InternalServerError().body("Internal Server Error");
            }
        }
    };

    let s = IndexTemplate {
            // list: l,
        }
    .render()
    .unwrap();
    HttpResponse::Ok().content_type("text/html").body(s)
}

fn challenge_register(
    (username, state): (Path<String>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    state
        .wan
        .send(ChallengeRegister {
            username: username.into_inner(),
        })
        .from_err()
        .and_then(|res| {
            match res {
                Ok(chal) => Ok(HttpResponse::Ok().json(chal)),
                Err(e) => {
                    debug!("challenge_register -> {:?}", e);
                    Ok(HttpResponse::InternalServerError().json(()))
                }
            }
        })
}

fn challenge_login(
    (username, state): (Path<String>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    state
        .wan
        .send(ChallengeAuthenticate {
            username: username.into_inner(),
        })
        .from_err()
        .and_then(|res| {
            match res {
                Ok(chal) => Ok(HttpResponse::Ok().json(chal)),
                Err(e) => {
                    debug!("challenge_login -> {:?}", e);
                    Ok(HttpResponse::InternalServerError().json(()))
                }
            }
        })
}

fn register(
    (reg, username, state): (
        Json<RegisterPublicKeyCredential>,
        Path<String>,
        State<AppState>,
    ),
) -> impl Future<Item = HttpResponse, Error = Error> {
    state
        .wan
        .send(Register {
            username: username.into_inner(),
            reg: reg.into_inner(),
        })
        .from_err()
        .and_then(|res| {
            match res {
                Ok(_) => Ok(HttpResponse::Ok().json(())),
                Err(e) => {
                    debug!("register -> {:?}", e);
                    Ok(HttpResponse::InternalServerError().json(()))
                }
            }
        })
}

fn login(
    (lgn, username, state, req): (
        Json<PublicKeyCredential>,
        Path<String>,
        State<AppState>,
        HttpRequest<AppState>,
    ),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uname = username.into_inner().clone();

    state
        .wan
        .send(Authenticate {
            username: uname.clone(),
            lgn: lgn.into_inner(),
        })
        .from_err()
        .and_then(move |res| {
            match res {
                Ok(_) => {
                    // Clear the anonymous flag
                    req.session().remove("anonymous");
                    // Set the userid
                    match req.session().set("userid", uname) {
                        Ok(_) => Ok(HttpResponse::Ok().json(())),
                        Err(_) => {
                            Ok(HttpResponse::InternalServerError().body("Internal Server Error"))
                        }
                    }
                }
                Err(e) => {
                    // TODO: Log this error
                    debug!("login -> {:?}", e);
                    Ok(HttpResponse::InternalServerError().json(()))
                }
            }
        })
}

fn main() {
    let opt = CmdOptions::from_args();

    if opt.debug {
        std::env::set_var("RUST_LOG", "actix_web=info,webauthn_rs=debug,actix=debug");
    }
    env_logger::init();

    debug!("Started logging ...");

    let sys = actix::System::new("webauthn-rs-demo");

    let prefix = opt.prefix.clone();
    let domain = opt.rp_id.clone();

    // Generate TLS certs as needed.
    let ssl_params = generate_dyn_ssl_params(domain.as_str());

    let wan_c = WebauthnEphemeralConfig::new(
        opt.rp_name.as_str(),
        opt.rp_origin.as_str(),
        opt.rp_id.as_str(),
    );

    let wan = WebauthnActor::new(wan_c);
    let wan_addr = wan.start();

    let mut stdrng = StdRng::from_entropy();
    let cookie_sig: Vec<_> = (0..32).map(|_| stdrng.gen()).collect();

    // Start http server
    server::new(move || {
        App::with_state(AppState::new(wan_addr.clone()))
            // For production
            .prefix(prefix.as_str())
            // enable logger
            .middleware(middleware::Logger::default())
            .middleware(middleware::session::SessionStorage::new(
                // Signed prevents tampering.
                middleware::session::CookieSessionBackend::signed(&cookie_sig)
                    .path(prefix.as_str())
                    // Should this be rp_id?
                    .domain(domain.as_str())
                    .same_site(cookie::SameSite::Strict)
                    .name("webauthnrs")
                    // if true, only allow to https
                    .secure(false), // Valid for 5 minutes
                                    // .max_age(Duration::minutes(5))
            ))
            .handler(
                "/static",
                fs::StaticFiles::new("./static")
                    .unwrap()
                    .show_files_listing(),
            )
            .resource("", |r| r.f(index_view))
            .resource("/", |r| r.f(index_view))
            // Need a challenge generation
            .resource("/challenge/register/{username}", |r| {
                r.method(http::Method::POST).with_async(challenge_register)
            })
            .resource("/challenge/login/{username}", |r| {
                r.method(http::Method::POST).with_async(challenge_login)
            })
            // Need a registration
            .resource("/register/{username}", |r| {
                r.method(http::Method::POST)
                    .with_async_config(register, |(cfg,)| {
                        cfg.0.limit(4096);
                    })
            })
            .resource("/login/{username}", |r| {
                r.method(http::Method::POST)
                    .with_async_config(login, |(cfg,)| {
                        cfg.0.limit(4096);
                    })
            })
        // Need login
    })
    .bind_ssl(opt.bind.as_str(), ssl_params)
    .unwrap()
    .start();

    println!("Started http server: {}", opt.rp_name.as_str());
    let _ = sys.run();
}
