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
use serde_with::{serde_as, TimestampMilliSeconds};
#[cfg(feature = "ssr")]
use std::sync::Arc;
use time::OffsetDateTime;
#[cfg(feature = "ssr")]
use tracing::*;
#[cfg(feature = "ssr")]
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{CreationChallengeResponse, RegisterPublicKeyCredential};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StartRegistrationResponse {
    ccr: CreationChallengeResponse,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FinishRegistrationResponse {
    enrolled_keys: u64,

    #[serde_as(as = "TimestampMilliSeconds<i64>")]
    created: OffsetDateTime,
}

#[server(
    endpoint = "start_registration",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn start_registration(
    username: String,
) -> Result<StartRegistrationResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<ServerState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };
    check_api_request(&state.webauthn).await?;

    let username = username.to_ascii_lowercase();
    if !is_username_valid(&username) {
        set_http_response_code(StatusCode::BAD_REQUEST);
        return Err(ServerFnError::new("invalid username"));
    }

    let (account, existing) = state.get_or_create_user(username).await?;

    let exclude_credentials: Option<Vec<CredentialID>> = if existing {
        Some(
            state
                .get_passkeys_for_account(&account)
                .await?
                .iter()
                .map(|r| r.cred.cred_id().clone())
                .collect(),
        )
    } else {
        None
    };

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(
            account.id,
            &account.username,
            &account.username,
            exclude_credentials,
        )
        .map_err(|err| {
            error!("start_passkey_registration: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Registration failure")
        })?;

    let mut session = SessionCookie::new();
    session.store_passkey_registration(reg_state, account.id);

    let mut cookie_jar = CookieJar::new();
    // TODO: secure bit
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

    info!("start_registration: {}, challenge: {ccr:?}", account.id);

    Ok(StartRegistrationResponse { ccr })
}

#[server(
    endpoint = "finish_registration",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn finish_registration(
    rpkc: RegisterPublicKeyCredential,
) -> Result<FinishRegistrationResponse, ServerFnError> {
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

    let Some((reg_state, user_unique_id)) = session.take_passkey_registration() else {
        error!("take_passkey_registration: incorrect state");
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("Incorrect state"));
    };

    delete_session_cookie(&mut cookie_jar, state.secure);
    put_cookie_jar(cookie_jar).await?;

    let account = state
        .get_user_by_id(user_unique_id)
        .await
        .map_err(|err| {
            error!("get_user_by_id: {err}");
            ServerFnError::new("Database error")
        })?
        .ok_or_else(|| {
            // In a real service implementation, you may want to send a RequestChallengeResponse
            // with some deterministically generated key identifiers to prevent account enmueration.
            set_http_response_code(StatusCode::PRECONDITION_FAILED);
            ServerFnError::new("User not found")
        })?;

    let cred = state
        .webauthn
        .finish_passkey_registration(&rpkc, &reg_state)
        .map_err(|err| {
            error!("finish_passkey_registration: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Registration failure")
        })?;

    state
        .add_passkey_for_account(&account, cred)
        .await
        .map_err(|err| {
            error!("add_passkey_for_user_id: {err}");
            ServerFnError::new("Database error")
        })?;

    let enrolled_keys = state
        .get_passkey_count_for_account(&account)
        .await
        .map_err(|err| {
            error!("get_passkey_count_for_account: {err}");
            ServerFnError::new("Database error")
        })?;

    Ok(FinishRegistrationResponse {
        enrolled_keys,
        created: account.created,
    })
}

/// Registration page.
#[component]
pub fn RegisterPage() -> impl IntoView {
    let username: RwSignal<String> = RwSignal::new("".to_string());
    let (resp, set_resp) = signal(None);
    let (err, set_err) = signal(None);
    #[allow(unused)]
    let (finished, set_finished) = signal(None::<FinishRegistrationResponse>);

    #[cfg(not(feature = "ssr"))]
    let credentials_create = Action::new_unsync(move |start_reg: &StartRegistrationResponse| {
        let cco = start_reg.ccr.clone().into();

        async move {
            log!("hello from credentials_create");
            let Some(navigator) = use_window().navigator() else {
                return;
            };

            let r = match wasm_bindgen_futures::JsFuture::from(
                navigator.credentials().create_with_options(&cco).unwrap(),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    web_sys::console::log_2(&("create error ".into()), &e);
                    set_resp.set(None);
                    set_err.set(e.as_string());
                    return;
                }
            };

            let w_rpkc = web_sys::PublicKeyCredential::from(r);
            web_sys::console::log_2(&("create response ".into()), &w_rpkc);

            // Serialise for webauthn-rs
            let rpkc = RegisterPublicKeyCredential::from(w_rpkc);

            match finish_registration(rpkc).await {
                Ok(r) => {
                    set_err.set(None);
                    set_finished.set(Some(r));
                }

                Err(e) => {
                    log!("finish registration error: {e:?}");
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
            match start_registration(username).await {
                Ok(ret) => {
                    #[cfg(not(feature = "ssr"))]
                    log!("response: {ret:?}");
                    set_resp.set(Some(ret.clone()));
                    set_err.set(None);

                    // Trigger client-side stuff too
                    #[cfg(not(feature = "ssr"))]
                    credentials_create.dispatch(ret);
                }

                Err(e) => {
                    set_resp.set(None);
                    set_err.set(Some(e.to_string()));
                }
            }
        });
    };

    view! {
        <h1>"Enroll your authenticator"</h1>

        <p>
            "From here, you can enroll your authenticator to create a passkey."
        </p>

        <p>
            "This runs "<code>"webauthn-rs"</code>" in "<em>"non-attested passkey"</em>" mode. \
            You can use any WebAuthn-compliant authenticator that supports user verification (PIN \
            or biometric authentication), such as FIDO2 hardware security keys, secure enclaves, \
            TPMs and synchronised credential managers (like iCloud Keychain). "
            <em>"U2F-only security keys are not supported in this mode."</em>
        </p>

        <p>
            "Unlike many other WebAuthn libraries, "<code>"webauthn-rs"</code>" discourages \
            resident (\"discoverable\") credentials by default, so it won't consume the limited, \
            non-reusable storage space on hardware security keys. Synchronised credential \
            managers may still create a resident key anyway, and they work too!"
        </p>

        <p>
            "Because this is just a demo, you can enroll credentials for "<em>"any"</em>
            " username without authentication. This demo will be periodically reset, deleting all \
            credentials from the server. In a real application, you'd authenticate the user \
            before allowing them to enroll new credentials, and persist them in some way."
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

            <input type="submit" value="Register" />

            {move || finished.get().map(|finished_resp| {
                let created = finished_resp.created.format(&time::format_description::well_known::Rfc2822);

                view! {
                    <h2>"Authenticator enrolled!"</h2>
                    <p>
                        "Account created at "
                        {created}
                    </p>
                    <p>
                        "The account now has "
                        {finished_resp.enrolled_keys}
                        " credential(s) enrolled."
                    </p>
                    <p>
                        "Now try to use the credential "
                        <a href="/login">
                            "on the login page"
                        </a>
                        "."
                    </p>
                }
            })}

            {move || resp.get().map(|start_reg| {
                view! {
                    <h2>"Start registration response"</h2>
                    <p>
                        "Challenge: "
                        {format!("{:?}", start_reg.ccr)}
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
