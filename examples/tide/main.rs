extern crate structopt;
use structopt::StructOpt;
extern crate openssl;

extern crate webauthn_rs;

use askama::Template;

use std::sync::Arc;

use rand::prelude::*;

use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::proto::{PublicKeyCredential, RegisterPublicKeyCredential};

mod actors;
mod crypto;

use crate::actors::*;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

type AppState = Arc<WebauthnActor>;

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

async fn index_view(mut request: tide::Request<AppState>) -> tide::Result {
    let session = request.session_mut();
    let some_userid = session.get::<String>("userid");

    if some_userid.is_none() {
        if session.insert("anonymous", true).is_err() {
            return Ok(tide::Response::new(tide::StatusCode::InternalServerError));
        }
    }

    Ok(askama_tide::into_response(&IndexTemplate {}, "html"))
}

async fn challenge_register(request: tide::Request<AppState>) -> tide::Result {
    let username = request.param("username")?.parse()?;
    let actor_res = request.state().challenge_register(username).await;
    let res = match actor_res {
        Ok(chal) => tide::Response::builder(tide::StatusCode::Ok)
            .body(tide::Body::from_json(&chal)?)
            .build(),
        Err(e) => {
            tide::log::debug!("challenge_register -> {:?}", e);
            tide::Response::new(tide::StatusCode::InternalServerError)
        }
    };
    Ok(res)
}

async fn challenge_login(request: tide::Request<AppState>) -> tide::Result {
    let username = request.param("username")?.parse()?;
    let actor_res = request.state().challenge_authenticate(&username).await;
    let res = match actor_res {
        Ok(chal) => tide::Response::builder(tide::StatusCode::Ok)
            .body(tide::Body::from_json(&chal)?)
            .build(),
        Err(e) => {
            tide::log::debug!("challenge_login -> {:?}", e);
            tide::Response::new(tide::StatusCode::InternalServerError)
        }
    };
    Ok(res)
}

async fn register(mut request: tide::Request<AppState>) -> tide::Result {
    let username = request.param("username")?.parse()?;
    let reg = request.body_json::<RegisterPublicKeyCredential>().await?;
    let actor_res = request.state().register(&username, &reg).await;
    let res = match actor_res {
        Ok(()) => tide::Response::new(tide::StatusCode::Ok),
        Err(e) => {
            tide::log::debug!("register -> {:?}", e);
            tide::Response::new(tide::StatusCode::InternalServerError)
        }
    };
    Ok(res)
}

async fn login(mut request: tide::Request<AppState>) -> tide::Result {
    let username: String = request.param("username")?.parse()?;
    let username_copy = username.clone();
    let lgn = request.body_json::<PublicKeyCredential>().await?;

    match request.state().authenticate(&username_copy, &lgn).await {
        Ok(()) => (),
        Err(e) => {
            tide::log::debug!("login -> {:?}", e);
            return Ok(tide::Response::new(tide::StatusCode::InternalServerError));
        }
    };

    let session = request.session_mut();

    // Clear the anonymous flag
    session.remove("anonymous");
    tide::log::debug!("removed anonymous flag");

    // Set the userid
    session.insert_raw("userid", username);

    Ok(tide::Response::new(tide::StatusCode::Ok))
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let opt: CmdOptions = CmdOptions::from_args();

    if opt.debug {
        tide::log::with_level(tide::log::LevelFilter::Debug);
    }

    tide::log::debug!("Started logging ...");

    let prefix = opt.prefix.clone();
    let domain = opt.rp_id.clone();

    let wan_c = WebauthnEphemeralConfig::new(
        opt.rp_name.as_str(),
        opt.rp_origin.as_str(),
        opt.rp_id.as_str(),
        None,
    );

    let wan = WebauthnActor::new(wan_c);

    let app_state = Arc::new(wan);

    let mut app = tide::with_state(app_state);
    let cookie_sig = StdRng::from_entropy().gen::<[u8; 32]>();
    let sessions =
        tide::sessions::SessionMiddleware::new(tide::sessions::MemoryStore::new(), &cookie_sig)
            .with_cookie_path(prefix.as_str())
            .with_cookie_domain(domain.as_str())
            .with_same_site_policy(tide::http::cookies::SameSite::Strict)
            .with_cookie_name("webauthnrs");
    app.with(sessions);
    app.with(tide::log::LogMiddleware::new());
    {
        let prefix_copy = prefix.clone();
        app.at("/")
            .get(move |_| async_std::future::ready(Ok(tide::Redirect::new(prefix_copy.clone()))));
    }
    // Serve our wasm content
    app.at("/pkg").serve_dir("pkg")?;
    app.at(&prefix).get(index_view);
    app.at(&format!("{}/challenge/register/:username", prefix))
        .post(challenge_register);
    app.at(&format!("{}/challenge/login/:username", prefix))
        .post(challenge_login);
    app.at(&format!("{}/register/:username", prefix))
        .post(register);
    app.at(&format!("{}/login/:username", prefix)).post(login);

    if opt.enable_tls {
        tide::log::debug!("Starting with TLS ...");
        let server_config = crypto::generate_dyn_ssl_config(opt.rp_id.as_str());
        app.listen(
            tide_rustls::TlsListener::build()
                .addrs(opt.bind.as_str())
                .config(server_config),
        )
        .await?;
    } else {
        tide::log::debug!("Starting without TLS ...");
        app.listen(opt.bind).await?;
    };

    Ok(())
}
