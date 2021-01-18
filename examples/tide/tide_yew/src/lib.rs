#![recursion_limit = "512"]

use anyhow::Error;
use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew::format::{Json, Nothing};
use yew::services::ConsoleService;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};
use web_sys::window;
use webauthn_rs::proto::{CreationChallengeResponse, RegisterPublicKeyCredential, AuthenticatorAttestationResponseRaw};
use webauthn_rs::base64_data::Base64UrlSafeData;
use js_sys::{Uint8Array, Object, ArrayBuffer};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen::JsCast;

pub struct App {
    link: ComponentLink<Self>,
    username: String,
    // An active fetch task/cb cycle.
    ft: Option<FetchTask>,
}

pub enum AppMsg {
    UserNameInput(String),
    Login,
    Register,
    DoNothing,
    BeginRegisterChallenge(web_sys::CredentialCreationOptions, String),
    CompleteRegisterChallenge(JsValue, String),
    Toast(String)
}

impl App {
    fn register_begin(&mut self, username: String) -> FetchTask {
        let username_copy = username.clone();
        let callback = self.link.callback(
            move |response: Response<Json<Result<CreationChallengeResponse, Error>>>| {
                let (parts, body) = response.into_parts();
                ConsoleService::log(format!("parts -> {:?}", parts).as_str());
                ConsoleService::log(format!("body -> {:?}", body).as_str());
                match body {
                    Json(Ok(ccr)) => {
                        let chal = Uint8Array::from(ccr.public_key.challenge.0.as_slice());
                        let userid = Uint8Array::from(ccr.public_key.user.id.0.as_slice());

                        let jsv = JsValue::from_serde(&ccr).unwrap();
                        ConsoleService::log(format!("jsv -> {:?}", jsv).as_str());

                        let pkcco = js_sys::Reflect::get(&jsv, &JsValue::from("publicKey")).unwrap();
                        js_sys::Reflect::set(&pkcco,
                            &JsValue::from("challenge"),
                            &chal
                        );

                        let user = js_sys::Reflect::get(&pkcco, &JsValue::from("user")).unwrap();
                        js_sys::Reflect::set(
                            &user,
                            &JsValue::from("id"),
                            &userid
                        );

                        ConsoleService::log(format!("jsv -> {:?}", jsv).as_str());

                        let c_options = web_sys::CredentialCreationOptions::from(jsv);

                        AppMsg::BeginRegisterChallenge(c_options, username_copy.clone())
                    }

                    Json(Err(_)) => {
                        AppMsg::DoNothing
                    }
                }
            }
        );
        let request = Request::post(format!("/auth/challenge/register/{}", username))
            .body(Nothing)
            .unwrap();
        FetchService::fetch_binary(request, callback).unwrap()
    }

    fn register_complete(&mut self, data: JsValue, username: String) -> FetchTask {
        // First, we have to b64 some data here.
        // data.raw_id

        let data_raw_id=
            Uint8Array::new(
                &js_sys::Reflect::get(&data, &JsValue::from("rawId")).unwrap()
            ).to_vec();

        let data_response =
            js_sys::Reflect::get(&data, &JsValue::from("response")).unwrap();
        let data_response_attestation_object =
        Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &JsValue::from("attestationObject")).unwrap()
        ).to_vec();

        let data_response_client_data_json =
        Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &JsValue::from("clientDataJSON")).unwrap()
        ).to_vec();

        // ConsoleService::log(format!("data -> {:?}", data).as_str());
        ConsoleService::log(format!("data_raw_id -> {:?}", data_raw_id).as_str());
        ConsoleService::log(format!("data_response -> {:?}", data_response).as_str());
        ConsoleService::log(format!("data_response_attestation_object -> {:?}", data_response_attestation_object).as_str());
        ConsoleService::log(format!("data_response_client_data_json -> {:?}", data_response_client_data_json).as_str());

        // Now we can convert to the base64 values for json.
        let data_raw_id_b64 = Base64UrlSafeData(data_raw_id);

        let data_response_attestation_object_b64 = Base64UrlSafeData(data_response_attestation_object);

        let data_response_client_data_json_b64 = Base64UrlSafeData(data_response_client_data_json);
        let rpkc = RegisterPublicKeyCredential {
            id: format!("{}", data_raw_id_b64),
            raw_id: data_raw_id_b64,
            type_: "public-key".to_string(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: data_response_attestation_object_b64,
                client_data_json: data_response_client_data_json_b64,
            }
        };

        ConsoleService::log(format!("rpkc -> {:?}", rpkc).as_str());

        // Send the fetch task.
        //    on success trigger the notification.

        let callback = self.link.callback(
            move |response: Response<Nothing>| {
                let (parts, _body) = response.into_parts();
                ConsoleService::log(format!("parts -> {:?}", parts).as_str());
                AppMsg::Toast("It worked".to_string())
            });

        let request = Request::post(format!("/auth/register/{}", username))
            .body(Json(&rpkc))
            .unwrap();
        FetchService::fetch_binary(request, callback).unwrap()
    }
}

impl Component for App {
    type Message = AppMsg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log(format!("create").as_str());
        App { link, username: "".to_string(), ft: None }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            AppMsg::DoNothing => {}
            AppMsg::UserNameInput(mut username) => {
                std::mem::swap(&mut self.username, &mut username)
            }
            AppMsg::Register => {
                let username = self.username.clone();
                ConsoleService::log(format!("register -> {:?}", username).as_str());
                self.ft = Some(self.register_begin(username));
            }
            AppMsg::BeginRegisterChallenge(ccr, username) => {
                if let Some(win) = web_sys::window() {
                    ConsoleService::log(format!("ccr -> {:?}", ccr).as_str());

                    let promise = win.navigator()
                        .credentials()
                        .create_with_options(&ccr)
                        .expect("Unable to create promise");
                    let fut = JsFuture::from(promise);
                    let linkc = self.link.clone();

                    spawn_local(async move {
                        match fut.await {
                            Ok(data) => {
                                linkc.send_message(AppMsg::CompleteRegisterChallenge(data, username));
                            }
                            Err(e) => {
                                ConsoleService::log(format!("error -> {:?}", e).as_str());
                                linkc.send_message(AppMsg::DoNothing);
                            }
                        }
                    });
                } else {
                    ConsoleService::log(format!("register failed for -> {:?}", self.username).as_str());
                }
            }
            AppMsg::CompleteRegisterChallenge(jsval, username) => {
                self.ft = Some(self.register_complete(jsval, username));
            }
            AppMsg::Toast(msg) => {
                ConsoleService::log(format!("toast -> {:?}", msg).as_str());
            }
            AppMsg::Login => {
                ConsoleService::log(format!("login -> {:?}", self.username).as_str());
            }
        };
        true
    }

    fn view(&self) -> Html {
        html! {
            <div>
                <div aria-live="polite" aria-atomic="true">
                  <div id="toast_arena" style="position: absolute; top: 20px; right: 20px;">
                  </div>
                </div>

                <div id="content" class="container">
                  <div class="row d-flex justify-content-center align-items-center" style="min-height: 100vh;">
                    <div class="col">
                    </div>
                    <div class="col-sm-6">
                        <div class="container">
                            <h2>{ "Webauthn-RS Demo" }</h2>
                            <p>
                            { "Webauthn is a modern, passwordless method of securely authenticating to a website. You can
                           test your token here by registering, then logging in. Try also login with a different username
                           and no registration! "}
                            </p>
                            <p>
                            {" This site is backed by the rust webauthn library. "}
                            </p>
                        </div>
                        <div class="container">
                            <div>
                                <input id="username" type="text" class="form-control" value=self.username oninput=self.link.callback(|e: InputData| AppMsg::UserNameInput(e.value)) />
                                <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| AppMsg::Register)>{" Register "}</button>
                                <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| AppMsg::Login)>{" Login "}</button>
                            </div>
                        </div>
                    </div>
                    <div class="col">
                    </div>
                  </div>
                </div>
            </div>
        }
    }
}

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<App>();
    Ok(())
}

