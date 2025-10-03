#![recursion_limit = "512"]

/*
 * Webauthn RS client side tutorial.
 */

// 1. Import our protocol bindings. This provides nothing else than the ability to serialise
// and deserialise what the server sends us.
//
// If you choose not to use these, and want to opt for manually writing javascript instead
// you MUST pay attention to the fact that some fields must be base64url safe decoded
// in the browser into Uint8Array's. There is NO VIABLE WAY to unpack json direct to a
// Uint8Array without client side JS assistance.
//
// The benefit of this wasm library is it magically does all that for you :)
use webauthn_rs_proto::*;

// Other imports needed to make the SPA (single page application) work.
use gloo::console;
use std::error::Error;
use std::fmt;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Document, Request, RequestInit, RequestMode, Response, Window};
use yew::prelude::*;

impl App {
    // 2. First, we render the first page to the user. This prompts them to register
    // and enter a username.
    fn view_register(&self, ctx: &Context<Self>) -> Html {
        html! {
          <>
            <main>
              <form
                    onsubmit={ ctx.link().callback(|e: FocusEvent| {
                    console::log!("prevent_default()");
                    e.prevent_default();
                    AppMsg::Register
                } ) }
                action="javascript:void(0);"
              >
                <input id="username" type="text"/>
                <button type="submit">
                    { "Start Registration" }
                </button>
              </form>
            </main>
          </>
        }
    }

    // 3. The user entered their username, and hit start. We issue a fetch request
    // to the server, requesting it to generate our challenge for us.
    fn update_start_register(&mut self, ctx: &Context<Self>) -> AppState {
        let username = get_value_from_element_id("username").unwrap_or_default();

        if username.is_empty() {
            return AppState::Error("A username must be provided".to_string());
        }

        self.last_username.clone_from(&username);

        // The fetch is done in a future/promise.
        ctx.link().send_future(async {
            match Self::register_begin(username).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AppState::Waiting
    }

    // While they wait, we show some dots ...
    fn view_waiting(&self, _ctx: &Context<Self>) -> Html {
        html! {
          <>
            <main>
              <p>{ ". . ." }</p>
            </main>
          </>
        }
    }

    // Do the fetch in the background.
    async fn register_begin(username: String) -> Result<AppMsg, FetchError> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::SameOrigin);

        let dest = format!("/register_start/{username}");
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let ccr: CreationChallengeResponse =
                serde_wasm_bindgen::from_value(jsval).unwrap_throw();
            Ok(AppMsg::BeginRegisterChallenge(ccr))
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text
                .as_string()
                .unwrap_or_else(|| "No message provided".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    // 4. The challenge has arrived, so we now trigger the browser to sign it
    // and yield the public key.
    fn update_register_challenge(
        &mut self,
        ctx: &Context<Self>,
        ccr: CreationChallengeResponse,
    ) -> AppState {
        // First, convert from our webauthn proto json safe format, into the browser
        // compatible struct, with everything decoded as needed.
        let c_options: web_sys::CredentialCreationOptions = ccr.into();

        // Create a promise that calls the browsers navigator.credentials.create api.
        let promise = window()
            .navigator()
            .credentials()
            .create_with_options(&c_options)
            .expect_throw("Unable to create promise");
        let fut = JsFuture::from(promise);

        // Wait on the promise, when complete it will issue a callback.
        ctx.link().send_future(async move {
            match fut.await {
                Ok(jsval) => {
                    // Convert from the raw js value into the expected PublicKeyCredential
                    let w_rpkc = web_sys::PublicKeyCredential::from(jsval);
                    // Serialise the web_sys::pkc into the webauthn proto version, ready to
                    // handle/transmit.
                    let rpkc = RegisterPublicKeyCredential::from(w_rpkc);
                    // start the fetch routine to post to the server
                    match Self::register_complete(rpkc).await {
                        Ok(v) => v,
                        // If an error occured, convert it as needed
                        Err(v) => v.into(),
                    }
                }
                Err(e) => {
                    console::log!(format!("error -> {e:?}").as_str());
                    AppMsg::Error(format!("{e:?}"))
                }
            }
        });
        AppState::Waiting
    }

    // 5. We have the public key, which we now submit to the server. When complete
    // it will issue us a 200 ok, and this will trigger the re-render of the page.
    async fn register_complete(rpkc: RegisterPublicKeyCredential) -> Result<AppMsg, FetchError> {
        console::log!(format!("rpkc -> {rpkc:?}").as_str());

        let req_jsvalue = serde_json::to_string(&rpkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise rpkc");

        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::SameOrigin);
        opts.set_body(&req_jsvalue);

        let request = Request::new_with_str_and_init("/register_finish", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            Ok(AppMsg::RegisterSuccess)
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            Ok(AppMsg::Error(emsg))
        }
    }

    // 6. Prompt the user to login
    fn view_authenticate(&self, ctx: &Context<Self>) -> Html {
        let last_username = self.last_username.clone();
        html! {
          <>
            <main>
              <form
                    onsubmit={ ctx.link().callback(|e: FocusEvent| {
                    console::log!("prevent_default()");
                    e.prevent_default();
                    AppMsg::Authenticate
                } ) }
                action="javascript:void(0);"
              >
                <span>{"Username: "}</span><input id="username" type="text" value={ last_username }/>
                <br />
                <button type="submit">
                    { "Start Authentication" }
                </button>
              </form>
            </main>
          </>
        }
    }

    // 7. Issue the fetch request to the server, getting the authentication
    // challenge.
    fn update_start_authenticate(&mut self, ctx: &Context<Self>) -> AppState {
        let username = get_value_from_element_id("username").unwrap_or_default();

        if username.is_empty() {
            return AppState::Error("A username must be provided".to_string());
        }

        self.last_username.clone_from(&username);

        // The fetch is done in a future/promise.
        ctx.link().send_future(async {
            match Self::authenticate_begin(username).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AppState::Waiting
    }

    // Do the fetch in the background.
    async fn authenticate_begin(username: String) -> Result<AppMsg, FetchError> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::SameOrigin);

        let dest = format!("/login_start/{username}");
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let rcr: RequestChallengeResponse =
                serde_wasm_bindgen::from_value(jsval).unwrap_throw();
            Ok(AppMsg::BeginAuthenticateChallenge(rcr))
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text
                .as_string()
                .unwrap_or_else(|| "No message provided".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    // 8. We got the challenge, now trigger the browser to sign it.
    fn update_authenticate_challenge(
        &mut self,
        ctx: &Context<Self>,
        rcr: RequestChallengeResponse,
    ) -> AppState {
        let c_options: web_sys::CredentialRequestOptions = rcr.into();
        let promise = window()
            .navigator()
            .credentials()
            .get_with_options(&c_options)
            .expect_throw("Unable to create promise");
        let fut = JsFuture::from(promise);
        // Wait on the promise, when complete it will issue a callback.
        ctx.link().send_future(async move {
            match fut.await {
                Ok(jsval) => {
                    let w_rpkc = web_sys::PublicKeyCredential::from(jsval);
                    // Serialise the web_sys::pkc into the webauthn proto version, ready to
                    // handle/transmit.
                    let pkc = PublicKeyCredential::from(w_rpkc);
                    // start the fetch routine to post to the server
                    match Self::authenticate_complete(pkc).await {
                        Ok(v) => v,
                        // If an error occured, convert it as needed
                        Err(v) => v.into(),
                    }
                }
                Err(e) => {
                    console::log!(format!("error -> {e:?}").as_str());
                    AppMsg::Error(format!("{e:?}"))
                }
            }
        });
        AppState::Waiting
    }

    // 9. Submit the signed result to the server. If it was correct we will get
    // 200 ok.
    async fn authenticate_complete(pkc: PublicKeyCredential) -> Result<AppMsg, FetchError> {
        console::log!(format!("pkc -> {pkc:?}").as_str());

        let req_jsvalue = serde_json::to_string(&pkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise pkc");

        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::SameOrigin);
        opts.set_body(&req_jsvalue);

        let request = Request::new_with_str_and_init("/login_finish", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            Ok(AppMsg::AuthenticateSuccess)
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            Ok(AppMsg::Error(emsg))
        }
    }

    // 10. Render that the authentication was a success
    fn view_success(&self, _ctx: &Context<Self>) -> Html {
        html! {
          <>
            <main>
              <p>{ "It Worked! 🎉" }</p>
            </main>
          </>
        }
    }

    // In other cases, we render an error.
    fn view_error(&self, _ctx: &Context<Self>, msg: &str) -> Html {
        html! {
          <>
            <main>
                <h3>{ "Oh No ~" }</h3>
                <p>{ msg }</p>
            </main>
          </>
        }
    }
}

// =====
// Various glue and stubs to process and route the events and states. I have
// tried to keep this as minimal as possible, and push all the logic and workflows
// to the above, but this still needs to exist.

fn get_value_from_element_id(id: &str) -> Option<String> {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|element| element.value())
}

pub fn document() -> Document {
    window().document().expect("Unable to retrieve document")
}

pub fn window() -> Window {
    web_sys::window().expect("Unable to retrieve window")
}

#[derive(Debug)]
enum AppState {
    Init,
    Waiting,
    Login,
    Success,
    Error(String),
}

#[derive(Debug)]
enum AppMsg {
    Register,
    BeginRegisterChallenge(CreationChallengeResponse),
    RegisterSuccess,
    Authenticate,
    BeginAuthenticateChallenge(RequestChallengeResponse),
    AuthenticateSuccess,
    Error(String),
}

struct App {
    state: AppState,
    last_username: String,
}

impl Component for App {
    type Message = AppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        App {
            state: AppState::Init,
            last_username: "".to_string(),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let mut state_change = match (&self.state, msg) {
            (AppState::Init, AppMsg::Register) => self.update_start_register(ctx),
            (AppState::Waiting, AppMsg::BeginRegisterChallenge(ccr)) => {
                self.update_register_challenge(ctx, ccr)
            }
            (AppState::Waiting, AppMsg::RegisterSuccess) => AppState::Login,
            (AppState::Login, AppMsg::Authenticate) => self.update_start_authenticate(ctx),
            (AppState::Waiting, AppMsg::BeginAuthenticateChallenge(rcr)) => {
                self.update_authenticate_challenge(ctx, rcr)
            }
            (AppState::Waiting, AppMsg::AuthenticateSuccess) => AppState::Success,
            (_, AppMsg::Error(msg)) => {
                console::log!(msg.as_str());
                AppState::Error(msg)
            }
            (s, m) => {
                let msg = format!("Invalid State Transition -> {s:?}, {m:?}");
                console::log!(msg.as_str());
                AppState::Error(msg)
            }
        };
        std::mem::swap(&mut self.state, &mut state_change);
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            AppState::Init => self.view_register(ctx),
            AppState::Waiting => self.view_waiting(ctx),
            AppState::Login => self.view_authenticate(ctx),
            AppState::Success => self.view_success(ctx),
            AppState::Error(msg) => self.view_error(ctx, msg),
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("oauth2::rendered");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchError {
    err: JsValue,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.err, f)
    }
}

impl Error for FetchError {}

impl From<JsValue> for FetchError {
    fn from(value: JsValue) -> Self {
        Self { err: value }
    }
}

impl FetchError {
    pub fn as_string(&self) -> String {
        self.err.as_string().unwrap_or_else(|| "null".to_string())
    }
}

impl From<FetchError> for AppMsg {
    fn from(fe: FetchError) -> Self {
        AppMsg::Error(fe.as_string())
    }
}

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<App>();
    Ok(())
}
