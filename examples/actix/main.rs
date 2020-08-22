extern crate actix;
extern crate actix_web;

extern crate time;

// #[macro_use]
extern crate askama;
// extern crate cookie;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate structopt;
use structopt::StructOpt;
extern crate openssl;

extern crate webauthn_rs;

use askama::Template;

use actix::prelude::*;
use actix_files as fs;
use actix_session::{CookieSession, Session};
use actix_web::web::{self, Data, HttpResponse, Json, Path};
use actix_web::{cookie, middleware, App, HttpServer};
// Bring in the trait for session()

use rand::prelude::*;

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
    #[structopt(short = "n", long = "name", default_value = "localhost")]
    rp_name: String,
    #[structopt(short = "o", long = "origin", default_value = "http://localhost:8080")]
    /// Must match your sites domain/port/url
    rp_origin: String,
    #[structopt(short = "i", long = "id", default_value = "localhost")]
    rp_id: String,
    #[structopt(short = "b", long = "bind", default_value = "localhost:8080")]
    bind: String,
    #[structopt(short = "s", long = "tls")]
    enable_tls: bool,
}

// fn index_view(session: Session) -> HttpResponse {
async fn index_view(session: Session) -> HttpResponse {
    let some_userid = match session.get::<String>("userid") {
        Ok(v) => v,
        Err(_e) => {
            return HttpResponse::InternalServerError().body("Internal Server Error");
        }
    };

    // println!("{:?}", some_userid);

    if some_userid.is_none() {
        match session.set("anonymous", true) {
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

async fn challenge_register((username, state): (Path<String>, Data<AppState>)) -> HttpResponse {
    let actor_res = state
        .wan
        .send(ChallengeRegister {
            username: username.into_inner(),
        })
        .await;
    match actor_res {
        Ok(res) => match res {
            Ok(chal) => HttpResponse::Ok().json(chal),
            Err(e) => {
                debug!("challenge_register -> {:?}", e);
                HttpResponse::InternalServerError().json(())
            }
        },
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            HttpResponse::InternalServerError().json(())
        }
    }
}

async fn challenge_login((username, state): (Path<String>, Data<AppState>)) -> HttpResponse {
    let actor_res = state
        .wan
        .send(ChallengeAuthenticate {
            username: username.into_inner(),
        })
        .await;
    match actor_res {
        Ok(res) => match res {
            Ok(chal) => HttpResponse::Ok().json(chal),
            Err(e) => {
                debug!("challenge_login -> {:?}", e);
                HttpResponse::InternalServerError().json(())
            }
        },
        Err(e) => {
            debug!("challenge_login -> {:?}", e);
            HttpResponse::InternalServerError().json(())
        }
    }
}

async fn register(
    (reg, username, state): (
        Json<RegisterPublicKeyCredential>,
        Path<String>,
        Data<AppState>,
    ),
) -> HttpResponse {
    let actor_res = state
        .wan
        .send(Register {
            username: username.into_inner(),
            reg: reg.into_inner(),
        })
        .await;
    match actor_res {
        Ok(res) => match res {
            Ok(_) => HttpResponse::Ok().json(()),
            Err(e) => {
                debug!("register -> {:?}", e);
                HttpResponse::InternalServerError().json(())
            }
        },
        Err(e) => {
            debug!("register -> {:?}", e);
            HttpResponse::InternalServerError().json(())
        }
    }
}

async fn login(
    (lgn, username, state, session): (
        Json<PublicKeyCredential>,
        Path<String>,
        Data<AppState>,
        Session,
    ),
) -> HttpResponse {
    let uname = username.into_inner().clone();

    let actor_res = state
        .wan
        .send(Authenticate {
            username: uname.clone(),
            lgn: lgn.into_inner(),
        })
        .await;
    match actor_res {
        Ok(res) => {
            match res {
                Ok(_) => {
                    // Clear the anonymous flag
                    session.remove("anonymous");
                    // Set the userid
                    match session.set("userid", uname) {
                        Ok(_) => HttpResponse::Ok().json(()),
                        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error"),
                    }
                }
                Err(e) => {
                    // TODO: Log this error
                    debug!("login -> {:?}", e);
                    HttpResponse::InternalServerError().json(())
                }
            }
        }
        Err(e) => {
            debug!("login -> {:?}", e);
            HttpResponse::InternalServerError().json(())
        }
    }
}

fn main() {
    let opt: CmdOptions = CmdOptions::from_args();

    if opt.debug {
        std::env::set_var("RUST_LOG", "actix_web=info,webauthn_rs=debug,actix=debug");
    }
    env_logger::init();

    debug!("Started logging ...");

    let sys = actix::System::new("webauthn-rs-demo");

    let prefix = opt.prefix.clone();
    let domain = opt.rp_id.clone();

    let wan_c = WebauthnEphemeralConfig::new(
        opt.rp_name.as_str(),
        opt.rp_origin.as_str(),
        opt.rp_id.as_str(),
        None,
        // Some(AuthenticatorAttachment::Platform),
    );

    let wan = WebauthnActor::new(wan_c);
    let wan_addr = wan.start();

    let mut stdrng = StdRng::from_entropy();
    let cookie_sig: Vec<_> = (0..32).map(|_| stdrng.gen()).collect();

    // Start http server
    let server = HttpServer::new(move || {
        App::new()
            .data(AppState::new(wan_addr.clone()))
            .wrap(middleware::Logger::default())
            .wrap(
                CookieSession::signed(&cookie_sig)
                    .path(prefix.as_str())
                    .domain(domain.as_str())
                    .same_site(cookie::SameSite::Strict)
                    .name("webauthnrs")
                    // if true, only allow to https
                    .secure(false), // Valid for 5 minutes
                                    // .max_age(Duration::minutes(5))
            )
            .service(
                web::scope(prefix.as_str())
                    .service(fs::Files::new("/static", "./static"))
                    .route("", web::get().to(index_view))
                    .route("/", web::get().to(index_view))
                    .route("/index.html", web::get().to(index_view))
                    .route(
                        "/challenge/register/{username}",
                        web::post().to(challenge_register),
                    )
                    .route(
                        "/challenge/login/{username}",
                        web::post().to(challenge_login),
                    )
                    .route("/register/{username}", web::post().to(register))
                    .route("/login/{username}", web::post().to(login)),
            )
    });

    let server = if opt.enable_tls {
        // Generate TLS certs as needed.
        let ssl_params = generate_dyn_ssl_params(opt.rp_id.as_str());
        server.bind_openssl(opt.bind.as_str(), ssl_params)
    } else {
        server.bind(opt.bind.as_str())
    };

    server.unwrap().run();

    println!("Started http server: {}", opt.rp_name.as_str());
    let _ = sys.run();
}
