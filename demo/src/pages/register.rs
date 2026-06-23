#[cfg(feature = "ssr")]
use crate::server::{
    check_api_request,
    cookie::{delete_session_cookie, get_cookie_jar, put_cookie_jar, SessionCookie},
    set_http_response_code,
    state::ServerState,
};
use crate::{
    api::EnrolledPasskeyInfo,
    components::CredentialList,
    pages::{is_username_valid, random_username},
};
#[cfg(feature = "ssr")]
use axum::http::StatusCode;
#[cfg(feature = "ssr")]
use cookie::CookieJar;
#[cfg(not(feature = "ssr"))]
use leptos::logging::*;
use leptos::{
    ev::{MouseEvent, SubmitEvent},
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
#[cfg(not(feature = "ssr"))]
use wasm_bindgen::JsCast;
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
    enrolled_passkeys: Vec<EnrolledPasskeyInfo>,

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
    label: String,
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

    let mut session = SessionCookie::from_jar(&cookie_jar, &state.wrap_key).map_err(|err| {
        error!("SessionCookie::from_jar: missing or invalid cookie: {err}");
        set_http_response_code(StatusCode::BAD_REQUEST);
        ServerFnError::new("Missing or invalid cookie")
    })?;

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

    let current_id = cred.cred_id().clone();

    state
        .add_passkey_for_account(&account, cred, label)
        .await
        .map_err(|err| {
            error!("add_passkey_for_user_id: {err}");
            ServerFnError::new("Database error")
        })?;

    let enrolled_passkeys = state
        .get_passkeys_for_account(&account)
        .await
        .map_err(|err| {
            error!("get_passkeys_for_account: {err}");
            ServerFnError::new("Database error")
        })?;

    Ok(FinishRegistrationResponse {
        enrolled_passkeys: enrolled_passkeys
            .iter()
            .map(|p| p.as_enrolled_passkey_info(p.cred.cred_id() == &current_id))
            .collect(),
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
            let Some(ref window) = *use_window() else {
                return;
            };
            let navigator = window.navigator();

            let r = match wasm_bindgen_futures::JsFuture::from(
                navigator.credentials().create_with_options(&cco).unwrap(),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    web_sys::console::log_2(&("nav.cred.create() error:".into()), &e);
                    set_resp.set(None);
                    set_finished.set(None);

                    if let Ok(e) = e.dyn_into::<web_sys::DomException>() {
                        set_err.set(Some(e.to_string().into()));
                    } else {
                        set_err.set(Some("Unknown error type".to_string()));
                    }
                    return;
                }
            };

            let w_rpkc = web_sys::PublicKeyCredential::from(r);
            web_sys::console::log_2(&("create response ".into()), &w_rpkc);

            // Serialise for webauthn-rs
            let rpkc = RegisterPublicKeyCredential::from(w_rpkc);

            // Prompt for a credential label
            let Ok(Some(label)) =
                web_sys::Window::prompt_with_message(&window, "Set a label for this authenticator")
            else {
                log!("labelling cancelled");
                set_resp.set(None);
                set_err.set(Some("Labelling passkey cancelled".to_string()));
                set_finished.set(None);
                return;
            };

            match finish_registration(rpkc, label).await {
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

    let on_random = move |ev: MouseEvent| {
        ev.prevent_default();
        username.set(random_username());
    };

    let is_invalid = move || {
        let username = username.get();
        !username.is_empty() && !is_username_valid(&username)
    };

    let username_class = move || {
        if is_invalid() {
            "form-control is-invalid"
        } else if !username.get().is_empty() {
            "form-control is-valid"
        } else {
            "form-control"
        }
    };

    view! {
        <h1>"Enroll your authenticator"</h1>

        <p>
            "This lets you enroll your authenticator with this demo app to create a passkey."
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
            resident (\"discoverable\") passkeys by default, so it won't consume the limited, \
            non-reusable storage space on hardware security keys. Non-resident passkeys are still \
            strong, self-contained multi-factor authentication, can replace a password, and are no \
            less secure than resident passkeys!"
        </p>

        <p>
            "Because this is just a demo, you can enroll credentials for "<em>"any"</em>
            " username without authentication, regardless of whether it has been \"taken\" by \
            someone else. In a real application, you'd authenticate the user before allowing them \
            to enroll a new credential."
        </p>

        <p>
            "This demo will be periodically reset, deleting all credentials from the server."
        </p>

        <form on:submit=on_submit>
            <div class="input-group mb-3">
                <div class="form-floating">
                    <input
                        type="text"
                        class=username_class
                        id="username"
                        autocomplete="username"
                        placeholder="example"
                        bind:value=username
                    />

                    <label for="username" class="form-label">
                        "Username"
                    </label>

                    <Show when=is_invalid>
                        <div class="invalid-feedback">
                            "Usernames must 3-16 characters, and consist only of numbers and basic Latin letters."
                        </div>
                    </Show>
                </div>

                <button
                    class="btn btn-secondary"
                    type="button"
                    on:click=on_random
                >
                    "Random username"
                </button>
            </div>

            <button
                class="btn btn-primary"
                type="submit"
            >
                "Enroll an authenticator"
            </button>
        </form>

        <ShowLet
            some=finished.get()
            let(finished_resp)
        >
            <h2>"Your authenticator has been enrolled!"</h2>
            <p>
                "Account created at "
                {finished_resp.created.format(&time::format_description::well_known::Rfc2822)}
            </p>
            <p>
                "Now try using the passkey "
                <a href="/login">
                    "on the login page"
                </a>
                "."
            </p>
            <CredentialList
                credentials={finished_resp.enrolled_passkeys}
            />
        </ShowLet>

        <ShowLet
            some=resp.get()
            let(start_reg)
        >
            <h2>"Start registration challenge"</h2>
                <pre>
                    {serde_json::to_string_pretty(&start_reg.ccr).unwrap_or_default()}
                </pre>

        </ShowLet>

        <ShowLet
            some=err.get()
            let(err)
        >
            <h2>"Error!"</h2>
            <p>{err}</p>
        </ShowLet>
    }
}
