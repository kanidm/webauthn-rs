#[cfg(feature = "ssr")]
use crate::state::{DemoState, UserAccount};
use leptos::{ev::SubmitEvent, logging::*, prelude::*, task::spawn_local};
#[cfg(not(feature = "ssr"))]
use leptos_use::use_window;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampMilliSeconds};
#[cfg(feature = "ssr")]
use std::sync::Arc;
use time::OffsetDateTime;
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

#[server(endpoint = "start_registration")]
pub async fn start_registration(
    username: String,
) -> Result<StartRegistrationResponse, ServerFnError> {
    if !is_username_valid(&username) {
        // FIXME: this returns HTTP 500, when it should be 400
        return Err(ServerFnError::new("invalid username"));
    }

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

            Ok(StartRegistrationResponse {
                ccr,
                user_unique_id,
            })
        }

        Err(e) => {
            error!("challenge_register -> {e:?}");
            Err(ServerFnError::new("registration error"))
        }
    }
}

#[server(endpoint = "finish_registration")]
pub async fn finish_registration(
    rpkc: RegisterPublicKeyCredential,
    user_unique_id: Uuid,
) -> Result<FinishRegistrationResponse, ServerFnError> {
    let Some(state) = use_context::<Arc<DemoState>>() else {
        return Err(ServerFnError::new("Server init failure"));
    };

    let mut users_guard = state.users.write();
    let Some(reg_state) = users_guard.registrations.remove(&user_unique_id.clone()) else {
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
            log!("challenge_register => {e:?}");
            Err(ServerFnError::new("Bad request"))
        }
    }
}

fn is_username_valid(username: &str) -> bool {
    username.len() >= 3 && !username.contains(char::is_whitespace)
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
        <h1>"Register"</h1>

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
                    <p>"Now try to use the credential on the login page."</p>
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
