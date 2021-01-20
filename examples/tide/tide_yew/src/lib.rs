#![recursion_limit = "512"]

use anyhow::Error;
use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew::format::{Json, Nothing};
use yew::services::ConsoleService;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};
use webauthn_rs::proto::{CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse, PublicKeyCredential};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_futures::spawn_local;

pub struct App {
    link: ComponentLink<Self>,
    username: String,
    toastmsg: Option<String>,
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
    BeginLoginChallenge(web_sys::CredentialRequestOptions, String),
    CompleteLoginChallenge(JsValue, String),
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
                        let c_options = ccr.into();
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

    fn register_complete(&mut self, data: web_sys::PublicKeyCredential, username: String) -> FetchTask {
        let rpkc = RegisterPublicKeyCredential::from(data);

        ConsoleService::log(format!("rpkc -> {:?}", rpkc).as_str());

        // Send the fetch task.
        //    on success trigger the notification.

        let callback = self.link.callback(
            move |response: Response<Nothing>| {
                let (parts, _body) = response.into_parts();
                ConsoleService::log(format!("parts -> {:?}", parts).as_str());
                AppMsg::Toast("Registration Success!".to_string())
            });

        let request = Request::post(format!("/auth/register/{}", username))
            .body(Json(&rpkc))
            .unwrap();
        FetchService::fetch_binary(request, callback).unwrap()
    }

    fn login_begin(&mut self, username: String) -> FetchTask {
        let username_copy = username.clone();
        let callback = self.link.callback(
            move |response: Response<Json<Result<RequestChallengeResponse, Error>>>| {
                let (parts, body) = response.into_parts();
                ConsoleService::log(format!("parts -> {:?}", parts).as_str());
                ConsoleService::log(format!("body -> {:?}", body).as_str());
                match body {
                    Json(Ok(rcr)) => {
                        let c_options = rcr.into();
                        AppMsg::BeginLoginChallenge(c_options, username_copy.clone())
                    }
                    Json(Err(_)) => {
                        AppMsg::DoNothing
                    }
                }
            }
        );
        let request = Request::post(format!("/auth/challenge/login/{}", username))
            .body(Nothing)
            .unwrap();
        FetchService::fetch_binary(request, callback).unwrap()
    }

    fn login_complete(&mut self, data: web_sys::PublicKeyCredential, username: String) -> FetchTask {

        let pkc = PublicKeyCredential::from(data);

        let callback = self.link.callback(
            move |response: Response<Nothing>| {
                let (parts, _body) = response.into_parts();
                ConsoleService::log(format!("parts -> {:?}", parts).as_str());
                AppMsg::Toast("Authentication Success! 🎉".to_string())
            });
        let request = Request::post(format!("/auth/login/{}", username))
            .body(Json(&pkc))
            .unwrap();
        FetchService::fetch_binary(request, callback).unwrap()
    }

}

impl Component for App {
    type Message = AppMsg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log(format!("create").as_str());
        App { link, username: "".to_string(), ft: None, toastmsg: 
            None
        }
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
            AppMsg::Toast(msg) => {
                ConsoleService::log(format!("toast -> {:?}", msg).as_str());
                self.toastmsg = Some(msg)
            }
            // Rego
            AppMsg::Register => {
                ConsoleService::log(format!("register -> {:?}", self.username).as_str());
                let username = self.username.clone();
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
                self.ft = Some(self.register_complete(
                   web_sys::PublicKeyCredential::from(jsval)
                    , username));
            }
            // Loggo
            AppMsg::Login => {
                ConsoleService::log(format!("login -> {:?}", self.username).as_str());
                let username = self.username.clone();
                self.ft = Some(self.login_begin(username));
            }
            AppMsg::BeginLoginChallenge(cro, username) => {
                if let Some(win) = web_sys::window() {
                    ConsoleService::log(format!("cro -> {:?}", cro).as_str());
                    let promise = win.navigator()
                        .credentials()
                        .get_with_options(&cro)
                        .expect("Unable to create promise");
                    let fut = JsFuture::from(promise);
                    let linkc = self.link.clone();

                    spawn_local(async move {
                        match fut.await {
                            Ok(data) => {
                                linkc.send_message(AppMsg::CompleteLoginChallenge(data, username));
                            }
                            Err(e) => {
                                ConsoleService::log(format!("error -> {:?}", e).as_str());
                                linkc.send_message(AppMsg::DoNothing);
                            }
                        }
                    });
                } else {
                    ConsoleService::log(format!("login failed for -> {:?}", self.username).as_str());
                }
            }
            AppMsg::CompleteLoginChallenge(jsv, username) => {
                self.ft = Some(self.login_complete(
                    web_sys::PublicKeyCredential::from(jsv)
                    , username));
            }
        };
        true
    }

    fn view(&self) -> Html {
        html! {
            <div>
                <div aria-live="polite" aria-atomic="true">
                  <div id="toast_arena" style="position: absolute; top: 20px; right: 20px;">
                  {
                        if let Some(message) = &self.toastmsg {
                            html! {
                                <>
                                <div id="error_toast" class="toast" role="alert" aria-live="assertive" aria-atomic="true" data-autohide="false"  >
                                  <div class="toast-header">
                                    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
                                    </button>
                                  </div>
                                  <div class="toast-body">
                                    { message }
                                  </div>
                                </div>
                                <script>{" $('#error_toast').toast('show') "}</script>
                                </>
                            }
                        } else {
                            html!{
                                <div></div>
                            }
                        }
                  }
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

