#![recursion_limit = "512"]
mod error;

// use anyhow::Error;
use crate::error::*;
use gloo::console;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use webauthn_rs::proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use yew::prelude::*;

pub struct App {
    username: String,
    toastmsg: Option<String>,
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
    Toast(String),
    FetchError(String),
}

impl From<FetchError> for AppMsg {
    fn from(fe: FetchError) -> Self {
        AppMsg::FetchError(fe.as_string())
    }
}

mod utils {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::UnwrapThrowExt;
    use web_sys::Event;
    use web_sys::HtmlInputElement;
    use web_sys::InputEvent;
    use web_sys::Window;

    pub fn get_value_from_input_event(e: InputEvent) -> String {
        let event: Event = e.dyn_into().unwrap_throw();
        let event_target = event.target().unwrap_throw();
        let target: HtmlInputElement = event_target.dyn_into().unwrap_throw();
        target.value()
    }

    pub fn window() -> Window {
        web_sys::window().expect("Unable to retrieve window")
    }
}

impl App {
    async fn register_begin(username: String) -> Result<AppMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        let dest = format!("/auth/challenge/register/{}", username);
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let ccr: CreationChallengeResponse = jsval.into_serde().unwrap();
            let c_options = ccr.into();
            Ok(AppMsg::BeginRegisterChallenge(c_options, username))
        } else {
            let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(AppMsg::FetchError(emsg))
        }
    }

    async fn register_complete(
        data: web_sys::PublicKeyCredential,
        username: String,
    ) -> Result<AppMsg, FetchError> {
        let rpkc = RegisterPublicKeyCredential::from(data);
        console::log!(format!("rpkc -> {:?}", rpkc).as_str());

        let req_jsvalue = serde_json::to_string(&rpkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise rpkc");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let dest = format!("/auth/register/{}", username);
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        let status = resp.status();

        if status == 200 {
            Ok(AppMsg::Toast("Registration Success!".to_string()))
        } else {
            let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(AppMsg::FetchError(emsg))
        }
    }

    async fn login_begin(username: String) -> Result<AppMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        let dest = format!("/auth/challenge/login/{}", username);
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let ccr: RequestChallengeResponse = jsval.into_serde().unwrap();
            let c_options = ccr.into();
            Ok(AppMsg::BeginLoginChallenge(c_options, username))
        } else {
            let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(AppMsg::FetchError(emsg))
        }
    }

    async fn login_complete(
        data: web_sys::PublicKeyCredential,
        username: String,
    ) -> Result<AppMsg, FetchError> {
        let pkc = PublicKeyCredential::from(data);
        console::log!(format!("pkc -> {:?}", pkc).as_str());

        let req_jsvalue = serde_json::to_string(&pkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise pkc");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let dest = format!("/auth/login/{}", username);
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        let status = resp.status();

        if status == 200 {
            Ok(AppMsg::Toast("Authentication Success! 🎉".to_string()))
        } else {
            let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(AppMsg::FetchError(emsg))
        }
    }
}

impl Component for App {
    type Message = AppMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        App {
            username: "".to_string(),
            toastmsg: None,
        }
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AppMsg::DoNothing => {}
            AppMsg::FetchError(msg) => {
                console::log!(format!("fetch task error -> {:?}", msg).as_str());
                self.toastmsg = Some(msg)
            }
            AppMsg::UserNameInput(mut username) => {
                std::mem::swap(&mut self.username, &mut username)
            }
            AppMsg::Toast(msg) => {
                console::log!(format!("toast -> {:?}", msg).as_str());
                self.toastmsg = Some(msg)
            }
            // Rego
            AppMsg::Register => {
                console::log!(format!("register -> {:?}", self.username).as_str());
                let username = self.username.clone();
                ctx.link().send_future(async {
                    match Self::register_begin(username).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            AppMsg::BeginRegisterChallenge(ccr, username) => {
                if let Some(win) = web_sys::window() {
                    console::log!(format!("ccr -> {:?}", ccr).as_str());

                    let promise = win
                        .navigator()
                        .credentials()
                        .create_with_options(&ccr)
                        .expect("Unable to create promise");
                    let fut = JsFuture::from(promise);

                    ctx.link().send_future(async {
                        match fut.await {
                            Ok(data) => AppMsg::CompleteRegisterChallenge(data, username),
                            Err(e) => {
                                console::log!(format!("error -> {:?}", e).as_str());
                                AppMsg::DoNothing
                            }
                        }
                    });
                } else {
                    console::log!(format!("register failed for -> {:?}", self.username).as_str());
                }
            }
            AppMsg::CompleteRegisterChallenge(jsval, username) => {
                ctx.link().send_future(async {
                    match Self::register_complete(
                        web_sys::PublicKeyCredential::from(jsval),
                        username,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            // Loggo
            AppMsg::Login => {
                console::log!(format!("login -> {:?}", self.username).as_str());
                let username = self.username.clone();
                ctx.link().send_future(async {
                    match Self::login_begin(username).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            AppMsg::BeginLoginChallenge(cro, username) => {
                if let Some(win) = web_sys::window() {
                    console::log!(format!("cro -> {:?}", cro).as_str());
                    let promise = win
                        .navigator()
                        .credentials()
                        .get_with_options(&cro)
                        .expect("Unable to create promise");
                    let fut = JsFuture::from(promise);

                    ctx.link().send_future(async {
                        match fut.await {
                            Ok(data) => AppMsg::CompleteLoginChallenge(data, username),
                            Err(e) => {
                                console::log!(format!("error -> {:?}", e).as_str());
                                AppMsg::DoNothing
                            }
                        }
                    });
                } else {
                    console::log!(format!("login failed for -> {:?}", self.username).as_str());
                }
            }
            AppMsg::CompleteLoginChallenge(jsv, username) => {
                ctx.link().send_future(async {
                    match Self::login_complete(web_sys::PublicKeyCredential::from(jsv), username)
                        .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
        };
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let username = self.username.clone();
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
                                <input id="username" type="text" class="form-control" value={ username }
                                    oninput={ ctx.link().callback(|e: InputEvent| AppMsg::UserNameInput(utils::get_value_from_input_event(e))) } />
                                <button type="button" class="btn btn-dark" onclick={ ctx.link().callback(|_| AppMsg::Register) }>{" Register "}</button>
                                <button type="button" class="btn btn-dark" onclick={ ctx.link().callback(|_| AppMsg::Login) }>{" Login "}</button>
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
