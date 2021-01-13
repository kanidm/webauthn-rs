#![recursion_limit = "512"]

use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew::services::ConsoleService;


// ITS ALL IN RUST!!!!

pub struct App {
    link: ComponentLink<Self>,
    username: String,
}

pub enum AppMsg {
    UserNameInput(String),
    Login,
    Register,
}

impl Component for App {
    type Message = AppMsg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log(format!("create").as_str());
        App { link, username: "".to_string() }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            AppMsg::UserNameInput(mut username) => {
                std::mem::swap(&mut self.username, &mut username)
            }
            AppMsg::Register => {
                ConsoleService::log(format!("register -> {:?}", self.username).as_str());
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

