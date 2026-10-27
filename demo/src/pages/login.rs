#[cfg(not(feature = "ssr"))]
use crate::app::MAX_AGE;
#[cfg(feature = "ssr")]
use crate::server::{
    check_api_request,
    cookie::{delete_session_cookie, get_cookie_jar, put_cookie_jar, SessionCookie},
    set_http_response_code,
    state::ServerState,
};
use crate::{api::EnrolledPasskeyInfo, components::CredentialList, pages::is_username_valid};
#[cfg(feature = "ssr")]
use axum::http::StatusCode;
#[cfg(feature = "ssr")]
use cookie::CookieJar;
use leptos::{
    ev::SubmitEvent,
    prelude::*,
    server_fn::codec::{Json, JsonEncoding, Post},
    task::spawn_local,
};
#[cfg(not(feature = "ssr"))]
use leptos::{logging::*, wasm_bindgen::JsCast};
#[cfg(not(feature = "ssr"))]
use leptos_use::use_window;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampMilliSeconds};
#[cfg(feature = "ssr")]
use std::sync::Arc;
#[cfg(not(feature = "ssr"))]
use std::time::Duration;
use time::OffsetDateTime;
#[cfg(feature = "ssr")]
use tracing::*;
#[cfg(not(feature = "ssr"))]
use wasm_bindgen_futures::JsFuture;
#[cfg(not(feature = "ssr"))]
use web_sys::{AbortController, CredentialRequestOptions};
#[cfg(feature = "ssr")]
use webauthn_rs::prelude::Passkey;
#[cfg(not(feature = "ssr"))]
use webauthn_rs_proto::PublicKeyCredentialExt;
use webauthn_rs_proto::{PublicKeyCredential, RequestChallengeResponse};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StartLoginResponse {
    rcr: RequestChallengeResponse,

    /// The login flow used to authenticate the user.
    flow: LoginFlow,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FinishLoginResponse {
    /// Username for the account.
    ///
    /// When using discoverable UI flows, the server must tell the client what it is.
    username: String,

    /// [`EnrolledPasskeyInfo`][] for all passkeys associated with the account.
    enrolled_passkeys: Vec<EnrolledPasskeyInfo>,

    #[serde_as(as = "TimestampMilliSeconds<i64>")]
    created: OffsetDateTime,

    /// The login flow used to authenticate the user.
    flow: LoginFlow,
}

/// Login flow types.
#[derive(Default, Deserialize, Serialize, Debug, Clone)]
pub enum LoginFlow {
    /// Unknown
    #[default]
    Unknown,

    /// Username flow (non-resident)
    Username,

    /// Conditional UI flow (resident / auto-fill)
    ConditionalUi,
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

    let mut session = SessionCookie::default();
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

    Ok(StartLoginResponse {
        rcr,
        flow: LoginFlow::Username,
    })
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

    let mut session =
        SessionCookie::from_jar(&cookie_jar, &state.wrap_key, state.secure).map_err(|err| {
            error!("SessionCookie::from_jar: missing or invalid cookie: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Missing cookie")
        })?;

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

    let current_id = sk.cred_id();

    let enrolled_passkeys = state
        .get_passkeys_for_account(&account)
        .await
        .map_err(|err| {
            error!("get_passkeys_for_account: {err}");
            ServerFnError::new("Database error")
        })?;

    Ok(FinishLoginResponse {
        username: account.username.clone(),
        enrolled_passkeys: enrolled_passkeys
            .iter()
            .map(|p| p.as_enrolled_passkey_info(p.cred.cred_id() == current_id))
            .collect(),
        created: account.created,
        flow: LoginFlow::Username,
    })
}

#[server(
    endpoint = "start_condui",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn start_condui() -> Result<StartLoginResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<ServerState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };
    check_api_request(&state.webauthn).await?;

    let (rcr, auth_state) = state
        .webauthn
        .start_discoverable_authentication()
        .map_err(|err| {
            error!("start_discoverable_authentication: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("start_passkey_authentication")
        })?;

    let mut session = SessionCookie::default();
    session.store_discoverable_authentication(auth_state);

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

    Ok(StartLoginResponse {
        rcr,
        flow: LoginFlow::ConditionalUi,
    })
}

#[server(
    endpoint = "finish_condui",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn finish_condui(pkc: PublicKeyCredential) -> Result<FinishLoginResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<ServerState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };
    check_api_request(&state.webauthn).await?;

    let mut cookie_jar = get_cookie_jar().await.map_err(|err| {
        error!("get_cookie_jar: {err}");
        set_http_response_code(StatusCode::BAD_REQUEST);
        ServerFnError::new("Cookie error")
    })?;

    let mut session =
        SessionCookie::from_jar(&cookie_jar, &state.wrap_key, state.secure).map_err(|err| {
            error!("SessionCookie::from_jar: missing or invalid cookie: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Missing cookie")
        })?;

    let Some(auth_state) = session.take_discoverable_authentication() else {
        error!("take_discoverable_authentication: incorrect state");
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("Incorrect state"));
    };

    delete_session_cookie(&mut cookie_jar, state.secure);
    put_cookie_jar(cookie_jar).await?;

    let (user_id, credential_id) = state
        .webauthn
        .identify_discoverable_authentication(&pkc)
        .map_err(|err| {
            error!("identify_discoverable_authentication: cannot read user ID: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Missing user ID")
        })?;

    // Locate the user ID.
    let account = state
        .get_user_by_id(user_id)
        .await
        .map_err(|err| {
            error!("get_by_user_id: {err}");
            ServerFnError::new("Database error")
        })?
        .ok_or_else(|| {
            set_http_response_code(StatusCode::PRECONDITION_FAILED);
            ServerFnError::new("User not found")
        })?;

    let enrolled_passkeys = state
        .get_passkeys_for_account(&account)
        .await
        .map_err(|err| {
            error!("get_passkeys_for_account: {err}");
            ServerFnError::new("Database error")
        })?;

    if enrolled_passkeys.is_empty() {
        // Another vector for account enumeration.
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("No enrolled passkeys"));
    }

    // Select the specific passkey that matches the given credential ID.
    let mut passkeys = enrolled_passkeys.iter().filter_map(|p| {
        if p.cred_id() == credential_id {
            Some(p.cred.as_ref())
        } else {
            None
        }
    });

    let Some(passkey) = passkeys.next() else {
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("No matching passkey"));
    };

    if passkeys.next().is_some() {
        set_http_response_code(StatusCode::PRECONDITION_FAILED);
        return Err(ServerFnError::new("Multiple matching passkeys"));
    }

    let sk = state
        .webauthn
        .finish_discoverable_authentication_v2(&pkc, auth_state, passkey)
        .map_err(|err| {
            error!("finish_passkey_authentication: {err}");
            set_http_response_code(StatusCode::BAD_REQUEST);
            ServerFnError::new("Authentication failed")
        })?;

    let current_id = sk.cred_id();

    Ok(FinishLoginResponse {
        username: account.username.clone(),
        enrolled_passkeys: enrolled_passkeys
            .iter()
            .map(|p| p.as_enrolled_passkey_info(p.cred.cred_id() == current_id))
            .collect(),
        created: account.created,
        flow: LoginFlow::ConditionalUi,
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
    #[allow(unused)]
    let (supports_condui, set_supports_condui) = signal(None::<bool>);
    #[allow(unused)]
    let (condui_timeout, set_condui_timeout) = signal(false);
    #[allow(unused)]
    let (condui_done, set_condui_done) = signal(false);

    // Conditional UI
    #[cfg(not(feature = "ssr"))]
    Effect::new(move |_| {
        let Some(navigator) = use_window().navigator() else {
            return;
        };

        let Ok(aborter) = AbortController::new() else {
            warn!("AbortController error, disabling conditional UI");
            set_supports_condui.set(Some(false));
            return;
        };

        spawn_local(async move {
            let Ok(icma) = PublicKeyCredentialExt::is_conditional_mediation_available() else {
                warn!("is_conditional_mediation_available() error");
                set_supports_condui.set(Some(false));
                return;
            };

            match JsFuture::from(icma).await {
                Err(e) => {
                    web_sys::console::warn_2(
                        &("is_conditional_mediation_available() error:".into()),
                        &e,
                    );
                    set_supports_condui.set(Some(false));
                    return;
                }

                Ok(r) => {
                    let supports_condui = r.is_truthy();
                    set_supports_condui.set(Some(supports_condui));

                    if !supports_condui {
                        warn!("Conditional mediation unavailable");
                        web_sys::console::warn_1(&("conditional mediation unavailable".into()));
                        return;
                    }
                }
            };

            // Request a challenge for conditional mediation.
            let ret = match start_condui().await {
                Ok(ret) => {
                    log!("condui response: {ret:?}");
                    set_resp.set(Some(ret.clone()));
                    set_err.set(None);
                    ret
                }

                Err(e) => {
                    set_resp.set(None);
                    set_err.set(Some(e.to_string()));
                    return;
                }
            };

            // Automatically abort the request if the timeout is reached.
            let timeout = ret
                .rcr
                .public_key
                .timeout
                .map(|x| Duration::from_millis(x.into()))
                .unwrap_or(MAX_AGE.unsigned_abs());

            let signal = aborter.signal();
            set_timeout(
                move || {
                    if !condui_done.get() {
                        error!("Conditional UI timeout!");
                        set_condui_timeout.set(true);
                        aborter.abort();
                    }
                },
                timeout,
            );

            // Got challenge, send it
            let cro = CredentialRequestOptions::from(ret.rcr.clone());
            cro.set_signal(&signal);
            let r = match JsFuture::from(navigator.credentials().get_with_options(&cro).unwrap())
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    web_sys::console::log_2(&("nav.cred.get() condui error:".into()), &e);
                    return;
                }
            };

            set_condui_done.set(true);
            let w_rpkc = web_sys::PublicKeyCredential::from(r);
            web_sys::console::log_2(&("get condui response".into()), &w_rpkc);
            let rpkc = PublicKeyCredential::from(w_rpkc);

            // Try to authenticate this
            match finish_condui(rpkc).await {
                Ok(r) => {
                    set_err.set(None);
                    username.set(r.username.clone());
                    set_finished.set(Some(r));
                }

                Err(e) => {
                    log!("finish condui login error: {e:?}");
                    set_err.set(Some(e.to_string()));
                    set_finished.set(None);
                }
            };
        });
    });

    #[cfg(not(feature = "ssr"))]
    let credentials_get = Action::new_unsync(move |start_login: &StartLoginResponse| {
        // User has entered a username and we've got a response from the server.

        let timeout = start_login
            .rcr
            .public_key
            .timeout
            .map(|x| Duration::from_millis(x.into()))
            .unwrap_or(MAX_AGE.unsigned_abs());
        let cro = CredentialRequestOptions::from(start_login.rcr.clone());

        async move {
            log!("hello from credentials_get");
            let Some(navigator) = use_window().navigator() else {
                return;
            };

            let Ok(aborter) = AbortController::new() else {
                warn!("AbortController error");
                return;
            };

            // Automatically abort the request if the timeout is reached.
            let signal = aborter.signal();
            set_timeout(
                move || {
                    error!("Username flow timeout!");
                    aborter.abort();
                },
                timeout,
            );

            cro.set_signal(&signal);

            let r = match JsFuture::from(navigator.credentials().get_with_options(&cro).unwrap())
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    web_sys::console::log_2(&("nav.cred.get() error:".into()), &e);
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
        set_finished.set(None);
        set_resp.set(None);
        set_err.set(None);

        let username = username.get();

        if !is_username_valid(&username) {
            set_err.set(Some("Invalid username".to_string()));
            return;
        }

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

    let autocomplete = move || {
        if supports_condui.get().unwrap_or_default() && !condui_timeout.get() {
            "username webauthn"
        } else {
            // When conditional UI is unavailable or has timed out, don't add any hints, as browsers
            // may not suggest usernames unless they have a password associated with it.
            ""
        }
    };

    view! {
        <h1>"Login with a passkey"</h1>
        <p>
            "Here you can use your authenticator to login with a passkey - you just need the \
            username."
        </p>

        <p>
            "You can also visit this demo app from another device or browser, and use any \
            authenticators that you've previously enrolled."
        </p>

        <Show
            when=move || supports_condui.get().unwrap_or_default()
        >
            <p>
                "If you've stored your passkeys in a credential manager, they will appear in your \
                browser's auto-fill UI after you click / touch the username field. Due to browser \
                limitations, you will need to reload the page if you want to authenticate this \
                way a second time, or you wait too long after loading the page."
            </p>
        </Show>

        <p>
            "If you want to enrol a new authenticator, "
            <a href="/register">
                "go to the registration page"
            </a>
            "."
        </p>

        <form on:submit=on_submit>
            <div class="form-floating mb-3">
                <input
                    type="text"
                    class=username_class
                    id="username"
                    autocomplete=autocomplete
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
                class="btn btn-primary"
                type="submit"
            >
                "Login with passkey"
            </button>

            <Show
                when=move || condui_timeout.get()
            >
                <div class="alert alert-warning" role="alert">
                    "⚠️ Auto-fill UI timed out! Reload the page to use it, or enter your username \
                    manually."
                </div>
            </Show>
        </form>

        <ShowLet
            some=move || finished.get()
            let(finished_resp)
        >
            <h2>"Logged in with a passkey!"</h2>
            <p>
                "Account "
                <code>{finished_resp.username}</code>
                " created at "
                {finished_resp.created.format(&time::format_description::well_known::Rfc2822)}
            </p>
            <p>
                "Login flow: "
                {format!("{:?}", finished_resp.flow)}
            </p>
            <CredentialList
                credentials={finished_resp.enrolled_passkeys}
            />
        </ShowLet>

        <ShowLet
            some=move || resp.get()
            let(start_auth)
        >
            <h2>"Start authentication challenge"</h2>
            <p>
                "Login flow: "
                {format!("{:?}", start_auth.flow)}
            </p>
            <pre>
                {serde_json::to_string_pretty(&start_auth.rcr).unwrap_or_default()}
            </pre>
        </ShowLet>

        <ShowLet
            some=move || err.get()
            let(err)
        >
            <h2>"Error!"</h2>
            <p>{err}</p>
        </ShowLet>
    }
}
