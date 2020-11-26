extern crate actix;
extern crate actix_web;

use tide::prelude::*;

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

use xactor::*;

use rand::prelude::*;

use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::proto::{PublicKeyCredential, RegisterPublicKeyCredential};

mod actors;
mod crypto;

use crate::actors::*;
// use crate::crypto::generate_dyn_ssl_params;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Clone)]
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
async fn index_view(mut request: tide::Request<AppState>) -> tide::Result {
    let session = request.session_mut();
    let some_userid = session.get::<String>("userid");

    // println!("{:?}", some_userid);

    if some_userid.is_none() {
        if session.insert("anonymous", true).is_err() {
            return Ok(tide::Response::new(tide::StatusCode::InternalServerError));
        }
    }

    Ok(askama_tide::into_response(&IndexTemplate {}, "html"))
}

async fn challenge_register(request: tide::Request<AppState>) -> tide::Result {
    let username = request.param("username")?.parse()?;
    let actor_res = request
        .state()
        .wan
        .call(ChallengeRegister { username })
        .await?;
    match actor_res {
        Ok(chal) => Ok(tide::Response::builder(tide::StatusCode::Ok)
            .body(tide::Body::from_json(&chal)?)
            .build()),
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            Ok(tide::Response::new(tide::StatusCode::InternalServerError))
        }
    }
}

async fn challenge_login(request: tide::Request<AppState>) -> tide::Result {
    let username = request.param("username")?.parse()?;
    let actor_res = request
        .state()
        .wan
        .call(ChallengeAuthenticate { username })
        .await?;
    match actor_res {
        Ok(chal) => Ok(tide::Response::builder(tide::StatusCode::Ok)
            .body(tide::Body::from_json(&chal)?)
            .build()),
        Err(e) => {
            debug!("challenge_login -> {:?}", e);
            Ok(tide::Response::new(tide::StatusCode::InternalServerError))
        }
    }
}

async fn register(mut request: tide::Request<AppState>) -> tide::Result {
    let username = request.param("username")?.parse()?;
    let reg = request.body_json::<RegisterPublicKeyCredential>().await?;
    let actor_res = request.state().wan.call(Register { username, reg }).await?;
    match actor_res {
        Ok(()) => Ok(tide::Response::new(tide::StatusCode::Ok)),
        Err(e) => {
            debug!("register -> {:?}", e);
            Ok(tide::Response::new(tide::StatusCode::InternalServerError))
        }
    }
}

async fn login(mut request: tide::Request<AppState>) -> tide::Result {
    // (lgn, username, state, session): (
    //     Json<PublicKeyCredential>,
    //     Path<String>,
    //     Data<AppState>,
    //     Session,
    // ),
    // ) -> HttpResponse {
    let username: String = request.param("username")?.parse()?;
    let lgn = request.body_json::<PublicKeyCredential>().await?;

    let actor_res = request
        .state()
        .wan
        .call(Authenticate {
            username: username.clone(),
            lgn,
        })
        .await?;

    let session = request.session_mut();
    match actor_res {
        Ok(_) => {
            // Clear the anonymous flag
            session.remove("anonymous");
            // Set the userid
            match session.insert("userid", username) {
                Ok(_) => Ok(tide::Response::new(tide::StatusCode::Ok)),
                Err(_) => Ok(tide::Response::new(tide::StatusCode::InternalServerError)),
            }
        }
        Err(e) => {
            debug!("login -> {:?}", e);
            Ok(tide::Response::new(tide::StatusCode::InternalServerError))
        }
    }
}

#[xactor::main]
async fn main() -> tide::Result<()> {
    let opt: CmdOptions = CmdOptions::from_args();

    if opt.debug {
        std::env::set_var("RUST_LOG", "actix_web=info,webauthn_rs=debug,actix=debug");
    }
    env_logger::init();

    debug!("Started logging ...");

    let prefix = opt.prefix.clone();
    let domain = opt.rp_id.clone();

    let wan_c = WebauthnEphemeralConfig::new(
        opt.rp_name.as_str(),
        opt.rp_origin.as_str(),
        opt.rp_id.as_str(),
        None,
    );

    let wan = WebauthnActor::new(wan_c);
    let wan_addr = wan.start().await?;
    let app_state = AppState::new(wan_addr);

    let mut app = tide::with_state(app_state);
    let cookie_sig = StdRng::from_entropy().gen::<[u8; 32]>();
    let sessions =
        tide::sessions::SessionMiddleware::new(tide::sessions::MemoryStore::new(), &cookie_sig)
            .with_cookie_path(prefix.as_str())
            .with_cookie_domain(domain.as_str())
            .with_same_site_policy(tide::http::cookies::SameSite::Strict)
            .with_cookie_name("webauthnrs");
    app.with(sessions);
    app.at("/auth").get(index_view);
    app.at("/auth/challenge/register/:username")
        .post(challenge_register);
    app.at("/auth/challenge/login/:username")
        .post(challenge_login);
    app.at("/auth/register/:username").post(register);
    app.at("/auth/login/:username").post(login);
    app.at("/auth/static/").serve_dir("static")?;

    // TODO: tide_rustls uses version 0.14.0 (we're on 0.15.0) and uses rustls over openssl
    // if opt.enable_tls {
    //     let ssl_params = generate_dyn_ssl_params(opt.rp_id.as_str());
    //     let listener = tide_rustls::TlsListener::build()
    //         .addrs(opt.bind.as_str())
    //         .cert(std::env::var("TIDE_CERT_PATH").unwrap())
    //         .key(std::env::var("TIDE_KEY_PATH").unwrap())
    //         .finish()?;
    //     app.listen(listener).await?;
    // } else {
    app.listen(opt.bind).await?;
    // };

    // app.listen(listener).await?;
    Ok(())
}
