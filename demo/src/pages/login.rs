use crate::pages::is_username_valid;
#[cfg(feature = "ssr")]
use crate::server::{
    check_api_request,
    cookie::{delete_session_cookie, get_cookie_jar, put_cookie_jar, SessionCookie},
    set_http_response_code,
    state::ServerState,
};
#[cfg(feature = "ssr")]
use axum::http::StatusCode;
#[cfg(feature = "ssr")]
use cookie::CookieJar;
#[cfg(not(feature = "ssr"))]
use leptos::logging::*;
use leptos::{
    ev::SubmitEvent,
    prelude::*,
    server_fn::codec::{Json, JsonEncoding, Post},
    task::spawn_local,
};
#[cfg(not(feature = "ssr"))]
use leptos_use::use_window;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, IfIsHumanReadable, TimestampMilliSeconds,
};
#[cfg(feature = "ssr")]
use std::sync::Arc;
use time::OffsetDateTime;
#[cfg(feature = "ssr")]
use tracing::*;
#[cfg(feature = "ssr")]
use webauthn_rs::prelude::Passkey;
use webauthn_rs_proto::{PublicKeyCredential, RequestChallengeResponse};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StartLoginResponse {
    rcr: RequestChallengeResponse,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FinishLoginResponse {
    enrolled_keys: u64,

    #[serde_as(as = "TimestampMilliSeconds<i64>")]
    created: OffsetDateTime,

    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
    cred_id: Vec<u8>,
}

#[server(
    endpoint = "start_login",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn start_login(username: String) -> Result<StartLoginResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<ServerState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };
    check_api_request(&state.webauthn).await?;

    let username = username.to_ascii_lowercase();
    if !is_username_valid(&username) {
        set_http_response_code(StatusCode::BAD_REQUEST);
        return Err(ServerFnError::new("invalid username"));
    }

    let account = state
        .get_user_by_username(&username)
        .await
        .map_err(|err| {
            error!("get_by_username: {err}");
            ServerFnError::new("Database error")
        })?
        .ok_or_else(|| {
            // In a real service implementation, you may want to send a RequestChallengeResponse
            // with some deterministically generated key identifiers to prevent account enmueration.
            set_http_response_code(StatusCode::PRECONDITION_FAILED);
            ServerFnError::new("User not found")
        })?;

    let passkeys = state
        .get_passkeys_for_account(&account)
        .await
        .map_err(|err| {
            error!("get_passkeys_for_account: {err}");
            ServerFnError::new("Database error")
        })?;

    if passkeys.is_empty() {
        // Another vector for account enumeration.
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("No enrolled passkeys"));
    }

    let passkeys: Vec<Passkey> = passkeys.into_iter().map(From::from).collect();

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|err| {
            error!("start_passkey_authentication: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("start_passkey_authentication")
        })?;

    let mut session = SessionCookie::new();
    session.store_passkey_authentication(auth_state, account.id);

    let mut cookie_jar = CookieJar::new();
    session
        .put_to_jar(&state.wrap_key, &mut cookie_jar, state.secure)
        .map_err(|err| {
            error!("put_to_jar: {err}");
            ServerFnError::new("Cookie error")
        })?;

    put_cookie_jar(cookie_jar).await.map_err(|err| {
        error!("put_cookie_jar: {err}");
        ServerFnError::new("Cookie error")
    })?;

    Ok(StartLoginResponse { rcr })
}

#[server(
    endpoint = "finish_login",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn finish_login(pkc: PublicKeyCredential) -> Result<FinishLoginResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<ServerState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };
    check_api_request(&state.webauthn).await?;

    let mut cookie_jar = get_cookie_jar().await.map_err(|err| {
        error!("get_cookie_jar: {err}");
        set_http_response_code(StatusCode::BAD_REQUEST);
        ServerFnError::new("Cookie error")
    })?;

    let Some(mut session) = SessionCookie::from_jar(&cookie_jar, &state.wrap_key) else {
        error!("SessionCookie::from_jar: missing cookie");
        set_http_response_code(StatusCode::BAD_REQUEST);
        return Err(ServerFnError::new("Missing cookie"));
    };

    let Some((auth_state, user_unique_id)) = session.take_passkey_authentication() else {
        error!("take_passkey_authentication: incorrect state");
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("Incorrect state"));
    };

    delete_session_cookie(&mut cookie_jar, state.secure);
    put_cookie_jar(cookie_jar).await?;

    let sk = state
        .webauthn
        .finish_passkey_authentication(&pkc, &auth_state)
        .map_err(|err| {
            error!("finish_passkey_authentication: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Authentication failed")
        })?;

    let account = state
        .get_user_by_id(user_unique_id)
        .await
        .map_err(|err| {
            error!("get_by_username: {err}");
            ServerFnError::new("Database error")
        })?
        .ok_or_else(|| {
            // This shouldn't happen
            set_http_response_code(StatusCode::PRECONDITION_FAILED);
            ServerFnError::new("User not found")
        })?;

    let enrolled_keys = state
        .get_passkey_count_for_account(&account)
        .await
        .map_err(|err| {
            error!("get_passkey_count_for_account: {err}");
            ServerFnError::new("Database error")
        })?;

    Ok(FinishLoginResponse {
        enrolled_keys,
        created: account.created,
        cred_id: sk.cred_id().clone(),
    })
}

/// Login page.
#[component]
pub fn LoginPage() -> impl IntoView {
    let username: RwSignal<String> = RwSignal::new("".to_string());
    let (resp, set_resp) = signal(None);
    let (err, set_err) = signal(None);
    #[allow(unused)]
    let (finished, set_finished) = signal(None::<FinishLoginResponse>);

    #[cfg(not(feature = "ssr"))]
    let credentials_get = Action::new_unsync(move |start_login: &StartLoginResponse| {
        let cro = start_login.rcr.clone().into();

        async move {
            log!("hello from credentials_get");
            let Some(navigator) = use_window().navigator() else {
                return;
            };

            let r = match wasm_bindgen_futures::JsFuture::from(
                navigator.credentials().get_with_options(&cro).unwrap(),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    web_sys::console::log_2(&("get error".into()), &e);
                    set_resp.set(None);
                    set_err.set(e.as_string());
                    return;
                }
            };

            let w_rpkc = web_sys::PublicKeyCredential::from(r);
            web_sys::console::log_2(&("get response".into()), &w_rpkc);

            // Serialise for webauthn-rs
            let rpkc = PublicKeyCredential::from(w_rpkc);

            match finish_login(rpkc).await {
                Ok(r) => {
                    set_err.set(None);
                    set_finished.set(Some(r));
                }

                Err(e) => {
                    log!("finish login error: {e:?}");
                    set_resp.set(None);
                    set_err.set(Some(e.to_string()));
                    set_finished.set(None);
                }
            }
        }
    });

    let on_submit = move |ev: SubmitEvent| {
        ev.prevent_default();

        let username = username.get();

        // if !is_username_valid(&username) {
        // panic!("empty username");
        // }

        let set_resp = set_resp.clone();
        spawn_local(async move {
            match start_login(username).await {
                Ok(ret) => {
                    #[cfg(not(feature = "ssr"))]
                    log!("response: {ret:?}");
                    set_resp.set(Some(ret.clone()));
                    set_err.set(None);

                    // Trigger client-side stuff too
                    #[cfg(not(feature = "ssr"))]
                    credentials_get.dispatch(ret);
                }

                Err(e) => {
                    set_resp.set(None);
                    set_err.set(Some(e.to_string()));
                }
            }
        });
    };

    view! {
        <h1>"Login with your authenticator"</h1>
        <p>
            "From here, you use your authenticator to login with a passkey - you just need the \
            username."
        </p>

        <p>
            "You can visit this demo app from another device or browser, and use any \
            authenticators that you've previously enrolled there."
        </p>

        <p>
            "If you want to register a new credential, "
            <a href="/register">
                "go to the registration page"
            </a>
            "."
        </p>

        <form on:submit=on_submit>
            <div class="mb-3">
                <label for="username" class="form-label">
                    "Username"
                </label>
                <input
                    type="text"
                    class="form-control"
                    id="username"
                    placeholder="example"
                    bind:value=username
                />

                // FIXME
                <Show when=move || !is_username_valid(&username.get())>
                    <div class="invalid-feedback">
                        "Username must be at least 3 characters, and may not contain whitespace."
                    </div>
                </Show>
            </div>

            <input type="submit" value="Login" />

            {move || finished.get().map(|finished_resp| {
                let created = finished_resp.created.format(&time::format_description::well_known::Rfc2822);

                view! {
                    <h2>"Logged in!"</h2>
                    <p>
                        "Account created at "
                        {created}
                    </p>
                    <p>
                        "The account has "
                        {finished_resp.enrolled_keys}
                        " credential(s) enrolled."
                    </p>
                }
            })}

            {move || resp.get().map(|start_reg| {
                view! {
                    <h2>"Start authentication response"</h2>
                    <p>
                        "Challenge: "
                        {format!("{:?}", start_reg.rcr)}
                    </p>
                }
            })}

            {move || err.get().map(|err| {
                view! {
                    <h2>"Error!"</h2>
                    <p>{err}</p>
                }
            })}
        </form>
    }
}
