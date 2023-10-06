#![deny(warnings)]
#![warn(unused_extern_crates)]

#[macro_use]
extern crate tracing;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;

use rand::prelude::*;

use tide_openssl::TlsListener;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use webauthn_rs::prelude::Uuid;
use webauthn_rs::prelude::{
    AttestedResidentKey,
    AttestedResidentKeyRegistration,
    // Passkey,
    // PasskeyRegistration,
};
use webauthn_rs_core::proto::{Credential, PublicKeyCredential, RegisterPublicKeyCredential};
use webauthn_rs_demo_shared::*;

mod actors;

use crate::actors::*;

type AppState = Arc<WebauthnActor>;

#[derive(Debug, StructOpt)]
struct CmdOptions {
    #[structopt(
        short = "n",
        long = "name",
        default_value = "localhost",
        env = "RP_NAME"
    )]
    rp_name: String,
    #[structopt(
        short = "o",
        long = "origin",
        default_value = "http://localhost:8080",
        env = "RP_ORIGIN"
    )]
    /// Must match your sites domain/port/url
    rp_origin: String,
    #[structopt(short = "i", long = "id", default_value = "localhost", env = "RP_ID")]
    rp_id: String,
    #[structopt(
        short = "b",
        long = "bind",
        default_value = "localhost:8080",
        env = "BIND_ADDRESS"
    )]
    bind: String,
    /// TLS public key, in PEM format
    #[structopt(long = "tls-public-key", env = "TLS_PUBLIC_KEY")]
    tls_public_key: Option<String>,
    /// TLS private key, in PEM format
    #[structopt(long = "tls-private-key", env = "TLS_PRIVATE_KEY")]
    tls_private_key: Option<String>,
}

async fn index_view(_request: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_content_type("text/html;charset=utf-8");
    res.set_body(
        r#"
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WebAuthn-rs</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>


    <link href="/pkg/bundle.css" rel="stylesheet">
    <script type="module">
        import init, { run_app } from './pkg/webauthn_rs_demo_wasm.js';
        async function main() {
           await init('./pkg/webauthn_rs_demo_wasm_bg.wasm');
           run_app();
        }
        main()
    </script>

  </head>

  <body>
  </body>
</html>

    "#,
    );
    Ok(res)
}

async fn demo_start_register(mut request: tide::Request<AppState>) -> tide::Result {
    let session = request.session_mut();
    session.remove("d_rs");

    let reg_settings: RegisterStart = request.body_json().await?;
    debug!(?reg_settings);

    let actor_res = request
        .state()
        .demo_start_register(Uuid::new_v4(), reg_settings.username, reg_settings.reg_type)
        .await;

    let res = match actor_res {
        Ok((chal, rs)) => {
            request
                .session_mut()
                .insert("d_rs", rs)
                .expect("Failed to insert");
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&chal)?)
                .build()
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };
    Ok(res)
}

async fn demo_finish_register(mut request: tide::Request<AppState>) -> tide::Result {
    let reg_finish: RegisterFinish = request.body_json().await?;

    debug!("session - {:?}", request.session().get_raw("d_cred_map"));
    let session = request.session_mut();
    let rs = match session.get("d_rs") {
        Some(v) => v,
        None => {
            error!("no reg session state");
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::SessionStateInvalid)?)
                .build());
        }
    };
    session.remove("d_rs");

    let mut cred_map: BTreeMap<String, Vec<TypedCredential>> =
        session.get("d_cred_map").unwrap_or_default();

    let mut creds: Vec<_> = cred_map.remove(&reg_finish.username).unwrap_or_default();

    let actor_res = request
        .state()
        .demo_finish_register(&reg_finish.username, &reg_finish.rpkc, rs)
        .await;
    let res = match actor_res {
        Ok(cred) => {
            // TODO make this a fn call back for cred exist
            creds.push(cred);
            cred_map.insert(reg_finish.username, creds);
            // Set the credmap back
            request
                .session_mut()
                .insert("d_cred_map", cred_map)
                .expect("Failed to insert");
            debug!(
                "write session to cookie - {:?}",
                request.session().get_raw("d_cred_map")
            );

            /*
            let reg_response = RegistrationSuccess {
                cred_id: cred.cred_id,
                // cred,
                uv: cred.user_verified,
                alg: cred.cred.type_,
                // counter: auth_data.counter,
                /*
                extensions: auth_data
                    .extensions
                    .unwrap_or_else(|| RegistrationSignedExtensions::default()),
                */
            };

            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&reg_response)?)
                .build()
            */
            tide::Response::builder(tide::StatusCode::Ok).build()
        }
        Err(e) => {
            debug!("register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };

    debug!("session - {:?}", request.session().get_raw("d_cred_map"));
    Ok(res)
}

async fn demo_start_login(mut request: tide::Request<AppState>) -> tide::Result {
    debug!("session - {:?}", request.session().get_raw("d_cred_map"));

    let auth_start: AuthenticateStart = request.body_json().await?;
    debug!(?auth_start);

    let session = request.session_mut();
    session.remove("d_st");

    let mut cred_map: BTreeMap<String, Vec<TypedCredential>> =
        session.get("d_cred_map").unwrap_or_default();

    let creds = match cred_map.remove(&auth_start.username) {
        Some(v) => v,
        None => {
            error!("no creds for {}", auth_start.username);
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(
                    &ResponseError::CredentialRetrievalError,
                )?)
                .build());
        }
    };

    let actor_res = request
        .state()
        .demo_start_login(&auth_start.username, creds, auth_start.auth_type)
        .await;

    let session = request.session_mut();
    session.remove("d_st");

    let res = match actor_res {
        Ok((chal, st)) => {
            request
                .session_mut()
                .insert("d_st", st)
                .expect("Failed to insert");
            debug!(
                "Session - inserted auth state - {:?}",
                request.session().get_raw("d_st")
            );
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&chal)?)
                .build()
        }
        Err(e) => {
            debug!("challenge_login -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };
    Ok(res)
}

async fn demo_finish_login(mut request: tide::Request<AppState>) -> tide::Result {
    let auth_finish: AuthenticateFinish = request.body_json().await?;
    let session = request.session_mut();

    let st = match session.get("d_st") {
        Some(v) => v,
        None => {
            error!("no auth session state");
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::SessionStateInvalid)?)
                .build());
        }
    };
    session.remove("d_st");

    let res = match request
        .state()
        .demo_finish_login(&auth_finish.username, &auth_finish.pkc, st)
        .await
    {
        Ok(_auth_result) => tide::Response::builder(tide::StatusCode::Ok).build(),
        Err(e) => {
            debug!("login -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };

    Ok(res)
}

async fn compat_start_register(mut request: tide::Request<AppState>) -> tide::Result {
    let session = request.session_mut();
    session.remove("rs");

    let reg_settings = request.body_json::<RegisterWithSettings>().await?;
    debug!(?reg_settings);

    let username = reg_settings.username.clone();

    let actor_res = request.state().compat_start_register(reg_settings).await;

    let res = match actor_res {
        Ok((chal, rs)) => {
            request
                .session_mut()
                .insert("rs", (rs, username))
                .expect("Failed to insert");
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&chal)?)
                .build()
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };
    Ok(res)
}

async fn compat_start_login(mut request: tide::Request<AppState>) -> tide::Result {
    debug!("session - {:?}", request.session().get_raw("cred_map"));

    let auth_settings = request.body_json::<AuthenticateWithSettings>().await?;
    debug!(?auth_settings);

    let session = request.session_mut();
    session.remove("st");

    let mut cred_map: BTreeMap<String, Vec<Credential>> =
        session.get("cred_map").unwrap_or_default();

    let creds = match cred_map.remove(&auth_settings.username) {
        Some(v) => v,
        None => {
            error!("no creds for {}", auth_settings.username);
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(
                    &ResponseError::CredentialRetrievalError,
                )?)
                .build());
        }
    };

    let username = auth_settings.username.clone();

    let actor_res = request
        .state()
        .compat_start_login(creds, auth_settings)
        .await;

    let session = request.session_mut();
    session.remove("st");

    let res = match actor_res {
        Ok((chal, st)) => {
            request
                .session_mut()
                .insert("st", (st, username))
                .expect("Failed to insert");
            debug!(
                "Session - inserted auth state - {:?}",
                request.session().get_raw("st")
            );
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&chal)?)
                .build()
        }
        Err(e) => {
            debug!("challenge_login -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };
    Ok(res)
}

async fn compat_finish_register(mut request: tide::Request<AppState>) -> tide::Result {
    debug!("session - {:?}", request.session().get_raw("cred_map"));
    let session = request.session_mut();
    let (rs, username) = match session.get("rs") {
        Some(v) => v,
        None => {
            error!("no reg session state");
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::SessionStateInvalid)?)
                .build());
        }
    };
    session.remove("rs");

    let mut cred_map: BTreeMap<String, Vec<Credential>> =
        session.get("cred_map").unwrap_or_default();

    let reg = request.body_json::<RegisterPublicKeyCredential>().await?;

    let mut creds = cred_map.remove(&username).unwrap_or_default();

    let actor_res = request
        .state()
        .compat_finish_register(&username, &reg, rs)
        .await;
    let res = match actor_res {
        Ok(cred) => {
            // TODO make this a fn call back for cred exist
            creds.push(cred.clone());
            cred_map.insert(username, creds);
            // Set the credmap back
            request
                .session_mut()
                .insert("cred_map", cred_map)
                .expect("Failed to insert");
            debug!(
                "write session to cookie - {:?}",
                request.session().get_raw("cred_map")
            );

            let reg_response = RegistrationSuccess {
                cred_id: cred.cred_id,
                // cred,
                uv: cred.user_verified,
                alg: cred.cred.type_,
                // counter: auth_data.counter,
                extensions: cred.extensions,
            };

            trace!(?reg_response);

            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&reg_response)?)
                .build()
        }
        Err(e) => {
            debug!("register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };

    debug!("session - {:?}", request.session().get_raw("cred_map"));
    Ok(res)
}

async fn compat_finish_login(mut request: tide::Request<AppState>) -> tide::Result {
    debug!("session - {:?}", request.session().get_raw("cred_map"));

    let session = request.session_mut();

    let (st, username): (_, String) = match session.get("st") {
        Some(v) => v,
        None => {
            error!("no auth session state");
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::SessionStateInvalid)?)
                .build());
        }
    };
    session.remove("st");

    let username_copy: String = username.clone();

    let mut cred_map: BTreeMap<String, Vec<Credential>> =
        session.get("cred_map").unwrap_or_default();
    let creds = match cred_map.remove(&username) {
        Some(v) => v,
        None => {
            error!("no creds for {}", username);
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(
                    &ResponseError::CredentialRetrievalError,
                )?)
                .build());
        }
    };

    let lgn = request.body_json::<PublicKeyCredential>().await?;

    let res = match request
        .state()
        .compat_finish_login(&username_copy, &lgn, st, creds)
        .await
    {
        Ok((creds, auth_result)) => {
            cred_map.insert(username, creds);
            // Set the credmap back
            request
                .session_mut()
                .insert("cred_map", cred_map)
                .expect("Failed to insert");

            let auth_response = AuthenticationSuccess {
                cred_id: auth_result.cred_id().clone(),
                uv: auth_result.user_verified(),
                // counter: auth_data.counter,
                extensions: auth_result.extensions().clone(),
            };

            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&auth_response)?)
                .build()
        }
        Err(e) => {
            debug!("login -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };

    debug!("session - {:?}", request.session().get_raw("cred_map"));

    Ok(res)
}

async fn condui_start_register(mut request: tide::Request<AppState>) -> tide::Result {
    let username: String = request.body_json().await?;

    let session = request.session_mut();
    session.remove("cu_rs");

    // Setup the uuid to name map.
    let mut uuid_map: BTreeMap<String, Uuid> = session.get("cu_id_map").unwrap_or_default();

    let u = if let Some(u) = uuid_map.get(&username) {
        *u
    } else {
        let u = Uuid::new_v4();
        uuid_map.insert(username.clone(), u);
        u
    };

    let actor_res = request.state().condui_start_register(u, username).await;

    let res = match actor_res {
        Ok((chal, rs)) => {
            request
                .session_mut()
                .insert("cu_rs", (u, rs))
                .expect("Failed to insert");
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&chal)?)
                .build()
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };
    Ok(res)
}

async fn condui_finish_register(mut request: tide::Request<AppState>) -> tide::Result {
    debug!("session - {:?}", request.session().get_raw("cu_cred_map"));
    let session = request.session_mut();
    let (u, rs): (Uuid, AttestedResidentKeyRegistration) = match session.get("cu_rs") {
        Some(v) => v,
        None => {
            error!("no reg session state");
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::SessionStateInvalid)?)
                .build());
        }
    };
    session.remove("cu_rs");

    let mut cred_map: BTreeMap<Uuid, Vec<AttestedResidentKey>> =
        session.get("cu_cred_map").unwrap_or_default();

    // Safe to remove, since we aren't mutating the session.
    let mut creds = cred_map.remove(&u).unwrap_or_default();

    let reg = request.body_json::<RegisterPublicKeyCredential>().await?;

    let actor_res = request.state().condui_finish_register(&reg, rs).await;
    let res = match actor_res {
        Ok(cred) => {
            creds.push(cred);
            cred_map.insert(u, creds);
            // Set the credmap back
            request
                .session_mut()
                .insert("cu_cred_map", cred_map)
                .expect("Failed to insert");
            debug!(
                "write session to cookie - {:?}",
                request.session().get_raw("cu_cred_map")
            );
            tide::Response::builder(tide::StatusCode::Ok).build()
        }
        Err(e) => {
            debug!("register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };

    debug!("session - {:?}", request.session().get_raw("cu_cred_map"));
    Ok(res)
}

async fn condui_start_login(mut request: tide::Request<AppState>) -> tide::Result {
    debug!("session - {:?}", request.session().get_raw("d_cred_map"));

    let actor_res = request.state().condui_start_login().await;

    let session = request.session_mut();
    session.remove("cu_st");

    let res = match actor_res {
        Ok((chal, st)) => {
            request
                .session_mut()
                .insert("cu_st", st)
                .expect("Failed to insert");
            debug!(
                "Session - inserted auth state - {:?}",
                request.session().get_raw("c_st")
            );
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&chal)?)
                .build()
        }
        Err(e) => {
            debug!("challenge_login -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };
    Ok(res)
}

async fn condui_finish_login(mut request: tide::Request<AppState>) -> tide::Result {
    let session = request.session_mut();

    let st = match session.get("cu_st") {
        Some(v) => v,
        None => {
            error!("no auth session state");
            return Ok(tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::SessionStateInvalid)?)
                .build());
        }
    };
    session.remove("cu_st");

    let cred_map: BTreeMap<Uuid, Vec<AttestedResidentKey>> =
        session.get("cu_cred_map").unwrap_or_default();

    let lgn = request.body_json::<PublicKeyCredential>().await?;

    let res = match request
        .state()
        .condui_finish_login(&cred_map, &lgn, st)
        .await
    {
        // Normally we should update the counters here.
        Ok(_auth_result) => tide::Response::builder(tide::StatusCode::Ok).build(),
        Err(e) => {
            debug!("login -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest)
                .body(tide::Body::from_json(&ResponseError::from(e))?)
                .build()
        }
    };

    Ok(res)
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let opt: CmdOptions = CmdOptions::from_args();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .compact()
        .init();

    let domain = opt.rp_id.clone();

    info!("Using origin - {}", opt.rp_origin);

    let wan = WebauthnActor::new(
        opt.rp_name.as_str(),
        opt.rp_origin.as_str(),
        opt.rp_id.as_str(),
    );

    let app_state = Arc::new(wan);

    let mut app = tide::with_state(app_state);

    let cookie_sig = StdRng::from_entropy().gen::<[u8; 32]>();
    let memory_store = tide::sessions::MemoryStore::new();

    let sessions = tide::sessions::SessionMiddleware::new(memory_store.clone(), &cookie_sig)
        .with_cookie_domain(domain.as_str())
        .with_same_site_policy(tide::http::cookies::SameSite::Strict)
        .with_session_ttl(Some(Duration::from_secs(3600)))
        .with_cookie_name("webauthnrs");

    async_std::task::spawn(async move {
        // some work here
        loop {
            async_std::task::sleep(Duration::from_secs(900)).await;
            memory_store
                .cleanup()
                .await
                .expect("Failed to clean up sessions!");
        }
    });

    app.with(sessions);
    app.with(tide::log::LogMiddleware::new());
    // Serve our wasm content
    app.at("/pkg").serve_dir("pkg")?;

    app.at("/compat/register_start").post(compat_start_register);
    app.at("/compat/register_finish")
        .post(compat_finish_register);
    app.at("/compat/login_start").post(compat_start_login);
    app.at("/compat/login_finish").post(compat_finish_login);

    app.at("/demo/register_start").post(demo_start_register);
    app.at("/demo/register_finish").post(demo_finish_register);
    app.at("/demo/login_start").post(demo_start_login);
    app.at("/demo/login_finish").post(demo_finish_login);

    app.at("/condui/register_start").post(condui_start_register);
    app.at("/condui/register_finish")
        .post(condui_finish_register);
    app.at("/condui/login_start").post(condui_start_login);
    app.at("/condui/login_finish").post(condui_finish_login);

    app.at("/").get(index_view);
    app.at("/*").get(index_view);

    match (opt.tls_public_key, opt.tls_private_key) {
        (Some(tls_cert), Some(tls_key)) => {
            info!("Starting server with TLS...");
            app.listen(
                TlsListener::build()
                    .addrs(opt.bind.as_str())
                    .cert(tls_cert)
                    .key(tls_key),
            )
            .await?;
        }

        (None, None) => {
            info!("Starting without TLS ...");
            app.listen(opt.bind).await?;
        }

        (_, _) => {
            panic!("Must specify both --tls-public-key and --tls-private-key, or neither");
        }
    }
    Ok(())
}
