use crate::error::*;
use crate::utils;

use gloo::console;
use yew::prelude::*;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use webauthn_rs_demo_shared::*;

#[derive(Debug, Clone)]
enum ChallengeState {
    Waiting,
    Presented(RequestChallengeResponse),
    Cancelled
}

#[derive(Debug, Clone)]
enum ConduiTestState {
    Init,
    Waiting,
    Main(ChallengeState),
    LoginSuccess,
    Error(String),
}

#[derive(Debug)]
pub struct ConduiTest {
    state: ConduiTestState,
}

#[derive(Debug)]
pub enum AppMsg {
    Main,
    Register,
    BeginRegisterChallenge(web_sys::CredentialCreationOptions),
    CompleteRegisterChallenge(JsValue),
    RegisterSuccess,
    BeginLoginChallenge(RequestChallengeResponse),
    CompleteLoginChallenge(JsValue),
    LoginSuccess,
    Error(String),
    ErrorCode(ResponseError),
    Cancelled,
}

impl From<FetchError> for AppMsg {
    fn from(fe: FetchError) -> Self {
        AppMsg::ErrorCode(ResponseError::UnknownError(fe.as_string()))
    }
}

impl Component for ConduiTest {
    type Message = AppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        ConduiTest {
            state: ConduiTestState::Init,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!(&format!("{:?} {:?}", self.state, msg));
        let mut state_change = match (&self.state, msg) {
            (_, AppMsg::Error(msg)) => {
                console::log!(format!("error -> {:?}", msg).as_str());
                ConduiTestState::Error(msg)
            }
            (_, AppMsg::ErrorCode(e_code)) => {
                let msg = format!("{:?}", e_code);
                console::log!(&msg);
                ConduiTestState::Error(msg)
            }
            (_, AppMsg::Main) |
            (ConduiTestState::Waiting, AppMsg::RegisterSuccess) => ConduiTestState::Main(ChallengeState::Waiting),
            (ConduiTestState::Main(_), AppMsg::Register) => {
                let username = utils::get_value_from_element_id("autofocus").expect("No username");

                if username == "" {
                    ctx.link().send_message(AppMsg::Error(
                        "A username must be provided".to_string(),
                    ));
                    return false;
                }

                console::log!(format!("username   -> {:?}", username).as_str());
                ctx.link().send_future(async {
                    match Self::register_begin(username).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                ConduiTestState::Waiting
            }
            (ConduiTestState::Waiting, AppMsg::BeginRegisterChallenge(ccr)) => {
                console::log!(format!("ccr -> {:?}", ccr));
                let promise = utils::window()
                    .navigator()
                    .credentials()
                    .create_with_options(&ccr)
                    .expect("Unable to create promise");
                let fut = JsFuture::from(promise);

                ctx.link().send_future(async {
                    match fut.await {
                        Ok(data) => AppMsg::CompleteRegisterChallenge(data),
                        Err(e) => {
                            console::log!(format!("error -> {:?}", e).as_str());
                            AppMsg::Error(format!("error -> {:?}", e))
                        }
                    }
                });
                ConduiTestState::Waiting
            }
            (ConduiTestState::Waiting, AppMsg::CompleteRegisterChallenge(jsval)) => {
                ctx.link().send_future(async {
                    match Self::register_complete(
                        web_sys::PublicKeyCredential::from(jsval),
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                ConduiTestState::Waiting
            }

            (ConduiTestState::Main(ChallengeState::Waiting), AppMsg::BeginLoginChallenge(mut ccr)) => {
                // Setup conditional mediation.
                ccr.mediation = Mediation::Conditional;

                // No state change, we are just triggering a callback.
                ConduiTestState::Main(ChallengeState::Presented(ccr))
            }
            (ConduiTestState::Main(_), AppMsg::CompleteLoginChallenge(jsv)) => {
                ctx.link().send_future(async {
                    match Self::login_complete(web_sys::PublicKeyCredential::from(jsv))
                        .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // the user did something so now we are waiting.
                ConduiTestState::Waiting
            }
            (ConduiTestState::Waiting, AppMsg::LoginSuccess) => ConduiTestState::LoginSuccess,
            (ConduiTestState::Main(_), AppMsg::Cancelled) => ConduiTestState::Main(ChallengeState::Cancelled),
            (s, m) => {
                let msg = format!("Invalid State Transition -> {:?}, {:?}", s, m);
                console::log!(msg.as_str());
                ConduiTestState::Error(msg)
            }
        };
        std::mem::swap(&mut self.state, &mut state_change);
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            ConduiTestState::Waiting => {
                html! {
                  <main class="text-center form-signin h-100">
                    <div class="vert-center">
                      <div class="spinner-border text-dark" role="status">
                        <span class="visually-hidden">{ "Loading..." }</span>
                      </div>
                    </div>
                  </main>
                }
            }
            ConduiTestState::Init => self.view_begin(ctx),
            ConduiTestState::Main(_) => self.view_main(ctx),
            ConduiTestState::LoginSuccess => self.view_success(ctx),
            ConduiTestState::Error(msg) => self.view_error(ctx, &msg),
        }
    }

    fn rendered(&mut self, ctx: &Context<Self>, _first_render: bool) {
        console::log!("oauth2::rendered");
        crate::utils::autofocus("autofocus");
        match &self.state {
            ConduiTestState::Main(ChallengeState::Waiting) => {
                // Because of course this doesn't fucking work right.
                /*
                let promise = is_conditional_mediation_available();
                console::log!(format!("{:?}", promise).as_str());
                let fut = JsFuture::from(promise);
                // We are on the main page, lets try to trigger a conditional UI challenge ...
                ctx.link().send_future(async {
                    let x = fut.await;
                    console::log!(format!("{:?}", x).as_str());

                    if x.ok().and_then(|v| v.as_bool()) == Some(true) {
                        console::log!("conditional mediation is available");
                        match Self::conditional_login_begin().await {
                            Ok(v) => v,
                            Err(v) => v.into(),
                        }
                    } else {
                        console::log!("conditional mediation is NOT available");
                        AppMsg::Error("Condition Mediation is NOT available on this platform".to_string())
                    }
                });
                */
                ctx.link().send_future(async {
                    console::log!("we hope conditional mediation is available!");
                    match Self::conditional_login_begin().await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            ConduiTestState::Main(ChallengeState::Presented(ccr)) => {
                let c_options: web_sys::CredentialRequestOptions = ccr.clone().into();
                console::log!(format!("raw c_options {:?}", c_options).as_str());

                let promise = utils::window()
                    .navigator()
                    .credentials()
                    .get_with_options(&c_options)
                    .expect("Unable to create promise");
                let fut = JsFuture::from(promise);

                ctx.link().send_future(async {
                    console::log!("Started future for navigator cred get");
                    match fut.await {
                        Ok(data) => {
                            console::log!(format!("nav cred get data -> {:?}", data).as_str());
                            AppMsg::CompleteLoginChallenge(data)
                        }
                        Err(e) => {
                            console::log!(format!("nav cred get error -> {:?}", e).as_str());
                            AppMsg::Cancelled
                        }
                    }
                });
            }
            ConduiTestState::Main(ChallengeState::Cancelled) => {
                console::log!("Condui dialog canceled or errored");
            }
            _ => {}
        }
    }
}

/*
#[wasm_bindgen(inline_js = "export async function is_conditional_mediation_available() {
    PublicKeyCredential.isConditionalMediationAvailable()
}")]
extern "C" {
    fn is_conditional_mediation_available() -> js_sys::Promise;
}
*/


impl ConduiTest {
    /*
    fn do_registration(&mut self, ctx: &Context<Self>, settings: RegisterWithSettings) {
        ctx.link().send_future(async move {
            match Self::register_begin(settings).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
    }

    fn do_auth(&mut self, ctx: &Context<Self>, settings: AuthenticateWithSettings) {
        ctx.link().send_future(async move {
            match Self::login_begin(settings).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
    }
    */

    fn view_main(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="form-description">
              <main class="text-center form-signin">
                  <div class="form-floating">
                    <input id="autofocus" type="text" name="name" autocomplete="username webauthn" class="form-control" />
                    <label for="autofocus">{ "Username" }</label>
                  </div>
                  <div class="form-floating">
                    <input type="password" name="password" autocomplete="current-password webauthn" class="form-control"/>
                    <label for="password">{ "Password:" }</label>
                  </div>
                  <button type="button" class="btn btn-lg btn-primary"
                    onclick={ ctx.link().callback(|_| AppMsg::Register) }>
                    { "Register Credential" }</button>
              </main>
            </div>
        }
    }

    fn view_begin(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="form-description">
              <main class="h-100">
                <div class="vert-center">
                  <div>
                    <p>
                    {"This will conduct a compatability test of your authenticator (security token) to determine how it works with Conditional UI." }
                    </p>
                    <p>
                    { "Due to the nature of this test, it will consume space on your authenticator, which may leave it unable to register to new websites in some cases" }
                    </p>
                    <p>
                    { "You should be absolutely sure before you proceed with this test" }
                    </p>

                    <div class="text-center">
                      <button type="button" class="btn btn-lg btn-primary" data-bs-toggle="modal" data-bs-target="#exampleModalDefault">
                        { "Begin Conditional UI Test" }
                      </button>
                    </div>
                  </div>
                </div>
              </main>

              <div class="modal fade" id="exampleModalDefault" tabindex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                  <div class="modal-content">
                    <div class="modal-header">
                      <h5 class="modal-title" id="exampleModalLabel">{ "Are You Sure?" }</h5>
                      <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                      <div class="container-fluid">
                        <div class="row">
                          <p>
                          { "Are you sure you want to proceed with this test?" }
                          </p>
                          <p>
                          { "Some authenticators can NEVER remove the credentials created during this test without fully reseting the device." }
                          </p>
                          <p>
                          { "This may prevent you signing up and using this device with other websites in the future." }
                          </p>
                        </div>
                      </div>
                    </div>
                    <div class="modal-footer">
                      <button type="button" class="btn btn-success" data-bs-dismiss="modal">{ "Cancel - Leave for Safety" }</button>
                      <button type="button" class="btn btn-danger"
                        data-bs-dismiss="modal"
                        onclick={ ctx.link().callback(|_| AppMsg::Main) }>
                        { "Yes, I Am Sure" }</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
        }
    }

    fn view_success(&self, ctx: &Context<Self>) -> Html {
        html! {
          <>
            <div class="form-description">
              <div>
                <h3>
                  {" Success! "}
                </h3>
              </div>
            </div>
            <main class="text-center form-signin">
              <button class="btn btn-lg btn-primary"
                  onclick={ ctx.link().callback(|_| AppMsg::Main) }>
                  { "Continue Conditional Ui Test" }
              </button>
            </main>
          </>
        }
    }

    fn view_error(&self, ctx: &Context<Self>, msg: &str) -> Html {
        html! {
          <>
            <div class="form-description">
              <div>
                <h3>
                  {" Error! "}
                </h3>
                <h2>
                  {"🥺 We weren't expecting this!" }
                </h2>
                <p>{ msg }</p>
              </div>
            </div>
            <main class="text-center form-signin">
              <button class="btn btn-lg btn-primary"
                  onclick={ ctx.link().callback(|_| AppMsg::Main) }>
                  { "Continue Conditional Ui Test" }
              </button>
            </main>
          </>
        }
    }

    async fn register_begin(
        username: String,
    ) -> Result<AppMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        let dest = format!("/condui/register_start/{}", username);
        let request = Request::new_with_str_and_init(&dest, &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let ccr: CreationChallengeResponse = jsval.into_serde().unwrap_throw();
            let c_options = ccr.into();
            Ok(AppMsg::BeginRegisterChallenge(c_options))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "No error message".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn register_complete(
        data: web_sys::PublicKeyCredential,
    ) -> Result<AppMsg, FetchError> {
        console::log!("register_complete()");

        let rpkc = RegisterPublicKeyCredential::from(data);
        console::log!(format!("rpkc -> {:?}", rpkc).as_str());

        let req_jsvalue = serde_json::to_string(&rpkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise rpkc");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/condui/register_finish", &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        console::log!(format!("resp_value -> {:?}", resp_value).as_str());
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            Ok(AppMsg::RegisterSuccess)
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "No error message".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn conditional_login_begin() -> Result<AppMsg, FetchError> {
        console::log!("conditional_login_begin()");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        let request = Request::new_with_str_and_init("/condui/login_start", &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        console::log!("conditional_login_begin() req sent");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Unable to get response");
        let status = resp.status();

        console::log!("conditional_login_begin() status");

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            console::log!(format!("conditional_login_begin() {:?}", jsval).as_str());
            let ccr: Result<RequestChallengeResponse, _> = jsval.into_serde();
            console::log!(format!("conditional_login_begin() {:?}", ccr).as_str());
            let ccr = ccr.expect_throw("Failed to deserialise");
            Ok(AppMsg::BeginLoginChallenge(ccr))
            // let c_options = ccr.into();
            // Ok(AppMsg::BeginLoginChallenge(c_options))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "No error message".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn login_complete(
        data: web_sys::PublicKeyCredential,
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

        let request = Request::new_with_str_and_init("/condui/login_finish", &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap_throw();
        let status = resp.status();

        if status == 200 {
            Ok(AppMsg::LoginSuccess)
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "No error message".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }
}
