/*
 * Webauthn RS server side tutorial.
 */

// 1. Import the prelude - this contains everything needed for the server to function.
use webauthn_rs::prelude::*;

// These are other imports needed to make the site generally work.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_std::sync::Mutex;

use rand::prelude::*;

#[macro_use]
extern crate tracing;

// 2. Configure the Webauthn instance by using the WebauthnBuilder. This defines
// the options needed for your site, and has some implications. One of these is that
// you can NOT change your rp_id (relying party id), without invalidating all
// webauthn credentials. Remember, rp_id is derived from your URL origin, meaning
// that it is your effective domain name.

struct Data {
    name_to_id: HashMap<String, Uuid>,
    keys: HashMap<Uuid, Vec<Passkey>>,
}

#[derive(Clone)]
struct AppState {
    // Webauthn has no mutable inner state, so Arc and read only is sufficent.
    // Alternately, you could use a reference here provided you can work out
    // lifetimes.
    webauthn: Arc<Webauthn>,
    // This needs mutability, so does require a mutex.
    users: Arc<Mutex<Data>>,
}

impl AppState {
    fn new() -> Self {
        // Effective domain name.
        let rp_id = "localhost";
        // Url containing the effective domain name
        // MUST include the port number!
        let rp_origin = Url::parse("http://localhost:8080").expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");

        // Now, with the builder you can define other options.
        // Set a "nice" relying party name. Has no security properties and
        // may be changed in the future.
        let builder = builder.rp_name("LocalHost");

        // Consume the builder and create our webauthn instance.
        let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

        let users = Arc::new(Mutex::new(Data {
            name_to_id: HashMap::new(),
            keys: HashMap::new(),
        }));

        AppState { webauthn, users }
    }
}

// 3. The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.

async fn start_register(mut request: tide::Request<AppState>) -> tide::Result {
    info!("Start register");
    // We get the username from the URL, but you could get this via form submission or
    // some other process. In some parts of Webauthn, you could also use this as a "display name"
    // instead of a username. Generally you should consider that the user *can* and *will* change
    // their username at any time.
    let username: String = request.param("username")?.parse()?;

    // Since a user's username could change at any time, we need to bind to a unique id.
    // We use uuid's for this purpose, and you should generate these randomly. If the
    // username does exist and is found, we can match back to our unique id. This is
    // important in authentication, where presented credentials may *only* provide
    // the unique id, and not the username!
    let user_unique_id = {
        let users_guard = request.state().users.lock().await;
        users_guard
            .name_to_id
            .get(&username)
            .copied()
            .unwrap_or_else(Uuid::new_v4)
    };

    // Remove any previous registrations that may have occurred from the session.
    let session = request.session_mut();
    session.remove("reg_state");

    // If the user has any other credentials, we exclude these here so they can't be duplicate registered.
    // It also hints to the browser that only new credentials should be "blinked" for interaction.
    let exclude_credentials = {
        let users_guard = request.state().users.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect())
    };

    let res = match request.state().webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            // Note that due to the session store in use being a server side memory store, it is
            // safe to store the reg_state into the session since it is not client controlled and
            // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
            request
                .session_mut()
                .insert("reg_state", (username, user_unique_id, reg_state))
                .expect("Failed to insert");
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&ccr)?)
                .build()
        }
        Err(e) => {
            info!("challenge_register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest).build()
        }
    };
    Ok(res)
}

// 4. The browser has completed its steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.

async fn finish_register(mut request: tide::Request<AppState>) -> tide::Result {
    let reg = request.body_json::<RegisterPublicKeyCredential>().await?;

    let session = request.session_mut();

    let (username, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) =
        session.get("reg_state").ok_or_else(|| {
            error!("Failed to get session!");
            tide::Error::new(500u16, anyhow::Error::msg("Corrupt Session"))
        })?;

    session.remove("reg_state");

    let res = match request
        .state()
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
    {
        Ok(sk) => {
            let mut users_guard = request.state().users.lock().await;

            info!(?sk, "The following credential was registered");

            users_guard
                .keys
                .entry(user_unique_id)
                .and_modify(|keys| keys.push(sk.clone()))
                .or_insert_with(|| vec![sk.clone()]);

            users_guard.name_to_id.insert(username, user_unique_id);

            tide::Response::builder(tide::StatusCode::Ok).build()
        }
        Err(e) => {
            info!("challenge_register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest).build()
        }
    };

    Ok(res)
}

// 5. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

async fn start_authentication(mut request: tide::Request<AppState>) -> tide::Result {
    info!("Start Authentication");
    // We get the username from the URL, but you could get this via form submission or
    // some other process.
    let username: String = request.param("username")?.parse()?;

    // Remove any previous authentication that may have occurred from the session.
    let session = request.session_mut();
    session.remove("auth_state");

    // Get the set of keys that the user possesses
    let users_guard = request.state().users.lock().await;

    // Look up their unique id from the username
    let user_unique_id = users_guard
        .name_to_id
        .get(&username)
        .copied()
        .ok_or_else(|| tide::Error::new(400u16, anyhow::Error::msg("User not found")))?;

    let allow_credentials = users_guard
        .keys
        .get(&user_unique_id)
        .ok_or_else(|| tide::Error::new(400u16, anyhow::Error::msg("User has no credentials")))?;

    let res = match request
        .state()
        .webauthn
        .start_passkey_authentication(allow_credentials)
    {
        Ok((rcr, auth_state)) => {
            // Drop the mutex to allow the mut borrows below to proceed
            drop(users_guard);

            // Note that due to the session store in use being a server side memory store, it is
            // safe to store the auth_state into the session since it is not client controlled and
            // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
            request
                .session_mut()
                .insert("auth_state", (user_unique_id, auth_state))
                .expect("Failed to insert");
            tide::Response::builder(tide::StatusCode::Ok)
                .body(tide::Body::from_json(&rcr)?)
                .build()
        }
        Err(e) => {
            info!("challenge_authenticate -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest).build()
        }
    };
    Ok(res)
}

// 6. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

async fn finish_authentication(mut request: tide::Request<AppState>) -> tide::Result {
    let auth = request.body_json::<PublicKeyCredential>().await?;

    let session = request.session_mut();

    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) = session
        .get("auth_state")
        .ok_or_else(|| tide::Error::new(500u16, anyhow::Error::msg("Corrupt Session")))?;

    session.remove("auth_state");

    let res = match request
        .state()
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            let mut users_guard = request.state().users.lock().await;

            // Update the credential counter, if possible.
            info!(?auth_result, "The following auth_result was returned");

            users_guard
                .keys
                .get_mut(&user_unique_id)
                .map(|keys| {
                    keys.iter_mut().for_each(|sk| {
                        // This will update the credential if it's the matching
                        // one. Otherwise it's ignored. That is why it is safe to
                        // iterate this over the full list.
                        sk.update_credential(&auth_result);
                    })
                })
                .ok_or_else(|| {
                    tide::Error::new(400u16, anyhow::Error::msg("User has no credentials"))
                })?;

            tide::Response::builder(tide::StatusCode::Ok).build()
        }
        Err(e) => {
            info!("challenge_register -> {:?}", e);
            tide::Response::builder(tide::StatusCode::BadRequest).build()
        }
    };

    Ok(res)
}

// 7. That's it! The user has now authenticated!

// =======
// Below is glue/stubs that are needed to make the above work, but don't really affect
// the work flow too much.

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
  </body>
</html>
    "#,
    );
    Ok(res)
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt::init();

    // Create the app
    let app_state = AppState::new();
    let mut app = tide::with_state(app_state);

    // Allow cookies so that we can bind some data to sessions.
    // In production, you should NOT use the memory store, since
    // it does not have cleanup.
    let cookie_sig = StdRng::from_entropy().gen::<[u8; 32]>();
    let memory_store = tide::sessions::MemoryStore::new();

    let sessions = tide::sessions::SessionMiddleware::new(memory_store.clone(), &cookie_sig)
        .with_same_site_policy(tide::http::cookies::SameSite::Strict)
        .with_session_ttl(Some(Duration::from_secs(3600)))
        .with_cookie_name("webauthnrs");

    // Bind the sessions to our app
    app.with(sessions);
    // Enable logging
    app.with(tide::log::LogMiddleware::new());

    // Serve our wasm content
    app.at("/pkg").serve_dir("../../wasm/pkg")?;

    // Bind our apis to our functions.
    app.at("/register_start/:username").post(start_register);
    app.at("/register_finish").post(finish_register);
    app.at("/login_start/:username").post(start_authentication);
    app.at("/login_finish").post(finish_authentication);

    // Serve our base html that bootstraps the wasm context.
    app.at("/").get(index_view);
    app.at("/*").get(index_view);

    info!("Spawning on http://localhost:8080");

    // Spawn the socket listener, and run the actual site.
    app.listen("127.0.0.1:8080").await?;

    Ok(())
}
