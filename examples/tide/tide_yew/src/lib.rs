#![recursion_limit = "512"]

use anyhow::Error;
use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew::format::{Json, Nothing};
use yew::services::ConsoleService;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};
use web_sys::window;
use webauthn_rs::proto::CreationChallengeResponse;
use js_sys::{Uint8Array, Object, ArrayBuffer};

fn b64_to_object(data: &[u8]) -> ArrayBuffer {
    let arr = Uint8Array::from(data);
    arr.buffer()
}

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
    BeginRegisterChallenge(web_sys::CredentialCreationOptions),
}

impl App {
    fn register_begin(&mut self, username: String) -> FetchTask {
        let callback = self.link.callback(
            move |response: Response<Json<Result<CreationChallengeResponse, Error>>>| {
                let (parts, body) = response.into_parts();
                ConsoleService::log(format!("parts -> {:?}", parts).as_str());
                ConsoleService::log(format!("body -> {:?}", body).as_str());
                match body {
                    Json(Ok(ccr)) => {

                        let challenge = b64_to_object(&ccr.public_key.challenge.0);

                        // This is an awful hack to get around some issues in websys
                        // and how it represents this field. JsValues are hard to
                        // construct, so we can just yolo this.
                        let pkcp = JsValue::null();

                        let mut rp = web_sys::PublicKeyCredentialRpEntity::new(
                            &ccr.public_key.rp.name
                        );
                        rp.id(&ccr.public_key.rp.id);

                        let user_id = b64_to_object(&ccr.public_key.user.id.0);
                        let user = web_sys::PublicKeyCredentialUserEntity::new(
                            &ccr.public_key.user.name,
                            &ccr.public_key.user.display_name,
                            &user_id
                        );

                        let mut pkcco = web_sys::PublicKeyCredentialCreationOptions::new(
                            &challenge,
                            &pkcp,
                            &rp,
                            &user,
                        );
                        let mut c_options = web_sys::CredentialCreationOptions::new();
                        c_options.public_key(&pkcco);
                        AppMsg::BeginRegisterChallenge(c_options)
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
            AppMsg::BeginRegisterChallenge(ccr) => {
                if let Some(win) = web_sys::window() {
                    ConsoleService::log(format!("ccr -> {:?}", ccr).as_str());

                    win.navigator().credentials().create_with_options(&ccr);
                } else {
                    ConsoleService::log(format!("register failed for -> {:?}", self.username).as_str());
                }
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

