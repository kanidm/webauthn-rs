use crate::pages::is_username_valid;
#[cfg(feature = "ssr")]
use crate::state::{DemoState, UserAccount};
#[cfg(feature = "ssr")]
use axum::http::StatusCode;
#[cfg(not(feature = "ssr"))]
use leptos::logging::*;
use leptos::{
    ev::SubmitEvent,
    prelude::*,
    server_fn::codec::{Json, JsonEncoding, Post},
    task::spawn_local,
};
#[cfg(feature = "ssr")]
use leptos_axum::ResponseOptions;
#[cfg(not(feature = "ssr"))]
use leptos_use::use_window;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampMilliSeconds};
#[cfg(feature = "ssr")]
use std::sync::Arc;
use time::OffsetDateTime;
#[cfg(feature = "ssr")]
use tracing::*;
use uuid::Uuid;
#[cfg(feature = "ssr")]
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{CreationChallengeResponse, RegisterPublicKeyCredential};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StartRegistrationResponse {
    ccr: CreationChallengeResponse,
    user_unique_id: Uuid,
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
    if !is_username_valid(&username) {
        if let Some(response) = use_context::<ResponseOptions>() {
            response.set_status(StatusCode::BAD_REQUEST);
        }

        return Err(ServerFnError::new("invalid username"));
    }

    let username = username.to_ascii_lowercase();

    let Some(state) = use_context::<Arc<DemoState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };

    let user_unique_id = {
        let mut users_guard = state.users.write();
        if let Some(uuid) = users_guard.name_to_id.get(&username) {
            uuid.clone()
        } else {
            let uuid = Uuid::new_v4();
            users_guard
                .name_to_id
                .insert(username.clone(), uuid.clone());
            users_guard.commit();
            uuid
        }
    };

    let exclude_credentials: Option<Vec<CredentialID>> = {
        let users_guard = state.users.read();
        users_guard.accounts.get(&user_unique_id).map(|account| {
            account
                .passkeys
                .iter()
                .map(|key| key.cred_id().clone())
                .collect()
        })
    };

    match state.webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            let mut users_guard = state.users.write();
            users_guard
                .registrations
                .insert(user_unique_id.clone(), reg_state);
            users_guard.commit();

            info!("challenge_register -> {user_unique_id}, {ccr:?}");

            Ok(StartRegistrationResponse {
                ccr,
                user_unique_id,
            })
        }

        Err(e) => {
            error!("challenge_register -> {e:?}");

            if let Some(response) = use_context::<ResponseOptions>() {
                response.set_status(StatusCode::BAD_REQUEST);
            }
            Err(ServerFnError::new("registration error"))
        }
    }
}

#[server(
    endpoint = "finish_registration",
    input = Post<JsonEncoding>,
    output = Json,
)]
pub async fn finish_registration(
    rpkc: RegisterPublicKeyCredential,
    user_unique_id: Uuid,
) -> Result<FinishRegistrationResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<DemoState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };

    let mut users_guard = state.users.write();
    let Some(reg_state) = users_guard.registrations.remove(&user_unique_id) else {
        if let Some(response) = use_context::<ResponseOptions>() {
            response.set_status(StatusCode::BAD_REQUEST);
        }
        return Err(ServerFnError::new("No active registration request"));
    };
    users_guard.commit();

    match state
        .webauthn
        .finish_passkey_registration(&rpkc, &reg_state)
    {
        Ok(sk) => {
            let mut users_guard = state.users.write();

            let account = users_guard
                .accounts
                .entry(user_unique_id)
                .and_modify(|account| account.passkeys.push(sk.clone()))
                .or_insert_with(|| UserAccount::new(sk.clone()));

            let enrolled_keys = account.passkeys.len() as u64;
            let created = account.created;
            users_guard.commit();

            Ok(FinishRegistrationResponse {
                enrolled_keys,
                created,
            })
        }

        Err(e) => {
            error!("challenge_register => {e:?}");

            if let Some(response) = use_context::<ResponseOptions>() {
                response.set_status(StatusCode::BAD_REQUEST);
            }

            Err(ServerFnError::new(e.to_string()))
        }
    }
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
        let user_unique_id = start_reg.user_unique_id;
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

            match finish_registration(rpkc, user_unique_id).await {
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
                        "User ID: "
                        {start_reg.user_unique_id.to_string()}
                    </p>
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
