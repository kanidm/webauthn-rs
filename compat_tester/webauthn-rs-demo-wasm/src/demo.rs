use crate::error::*;
use crate::utils;

use gloo::console;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use webauthn_rs_demo_shared::*;
use yew::prelude::*;

// JsValue(NotAllowedError: The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client. undefined)

#[derive(Debug)]
pub struct Demo {
    state: DemoState,
    reg_settings: RegisterWithType,
    last_username: String,
}

#[derive(Debug)]
pub enum DemoState {
    Waiting,
    Register,
    Login,
    LoginSuccess,
    Error(String),
}

#[derive(Debug)]
pub enum AppMsg {
    // This can probably go ...
    Register,
    BeginRegisterChallenge(web_sys::CredentialCreationOptions, String),
    CompleteRegisterChallenge(JsValue, String),
    RegisterSuccess,
    Login,
    BeginLoginChallenge(web_sys::CredentialRequestOptions, String),
    CompleteLoginChallenge(JsValue, String),
    LoginSuccess,
    // Errors
    Error(Option<String>),
    ErrorCode(ResponseError),
}

impl From<FetchError> for AppMsg {
    fn from(fe: FetchError) -> Self {
        AppMsg::Error(Some(fe.as_string()))
    }
}

impl Demo {
    async fn register_begin(
        username: String,
        settings: RegisterWithType,
    ) -> Result<AppMsg, FetchError> {
        let req_jsvalue = serde_json::to_string(&settings)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise settings");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let dest = format!("/demo/register_start/{}", username);
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
            Ok(AppMsg::BeginRegisterChallenge(c_options, username))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string();
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn register_complete(
        data: web_sys::PublicKeyCredential,
        username: String,
    ) -> Result<AppMsg, FetchError> {
        console::log!("register_complete()");

        let client_extensions = data.get_client_extension_results();
        console::log!(format!("client_extensions -> {:?}", client_extensions));

        let rpkc = RegisterPublicKeyCredential::from(data);
        console::log!(format!("rpkc -> {:?}", rpkc).as_str());

        let req_jsvalue = serde_json::to_string(&rpkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise rpkc");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let dest = format!("/demo/register_finish/{}", username);
        let request = Request::new_with_str_and_init(&dest, &opts)?;

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
            let emsg = text.as_string();
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn login_begin(
        username: String,
        settings: AuthenticateWithType,
    ) -> Result<AppMsg, FetchError> {
        let req_jsvalue = serde_json::to_string(&settings)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise settings");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let dest = format!("/demo/login_start/{}", username);
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
            let ccr: RequestChallengeResponse = jsval.into_serde().unwrap_throw();
            let c_options = ccr.into();
            Ok(AppMsg::BeginLoginChallenge(c_options, username))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string();
            Ok(AppMsg::Error(emsg))
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

        let dest = format!("/demo/login_finish/{}", username);
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
            Ok(AppMsg::LoginSuccess)
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string();
            Ok(AppMsg::Error(emsg))
        }
    }

    fn view_register(&self, ctx: &Context<Self>) -> Html {
        let last_username = self.last_username.clone();

        html! {
          <>
            <div class="form-description">
              <div>
                <p>
                  { "Webauthn is a modern, passwordless method of securely authenticating to a website. You can test registering and then authenticating with Webauthn here!" }
                </p>
                <p>
                  { "A Webauthn credential uses strong cryptography to identify you to a site. The cryptographic key is contained in a secure device like a yubikey, a trusted platform module, or your phones secure enclave. Even when you use a finger print or a pin with your credential, that biometric or pin data never leaves your device. "}
                </p>
              </div>
            </div>
            <main class="text-center form-signin">
              <h3 class="h3 mb-3 fw-normal">{ "Register a Webauthn Credential" }</h3>
              <form
                    onsubmit={ ctx.link().callback(|e: FocusEvent| {
                    console::log!("prevent_default()");
                    e.prevent_default();
                    AppMsg::Register
                } ) }
                action="javascript:void(0);"
              >
                <div class="form-floating">
                  <input id="autofocus" type="text" class="form-control" value={ last_username } />
                  <label for="autofocus">{ "Username" }</label>
                </div>
                <button type="button" class="btn btn-lg btn-secondary" data-bs-toggle="modal" data-bs-target="#exampleModalDefault">
                  { "Change Webauthn Settings" }
                </button>
                <button class="btn btn-lg btn-primary" type="submit">
                    { "Begin Registration" }
                </button>
              </form>
            </main>

            <div class="modal fade" id="exampleModalDefault" tabindex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">
              <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="exampleModalLabel">{ "Webauthn Settings" }</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                  <div class="modal-body">
                    <div class="container-fluid">
                      <div class="row">
                        <p>
                        { "Change settings of the credential that will be registered" }
                        </p>
                      </div>
                      <div class="row">
                        <table class="table">
                          <tbody>
                            <tr>
                              <td>{ "Credential Type" }</td>
                              <td>
                                <select class="form-select" id="credential_type">
                                  <option selected=true value="pk">{ "Passkey" }</option>
                                  <option value="pl">{ "Passwordless" }</option>
                                  <option value="sk">{ "Security Key" }</option>
                                </select>
                              </td>
                            </tr>

                            <tr>
                              <td>{ "Attestation Level" }</td>
                              <td>
                                <select class="form-select" id="strict_attestation_required">
                                  <option selected=true value="n">{ "None" }</option>
                                  <option value="a">{ "Any Known Manufacturer" }</option>
                                  <option value="s">{ "Strict" }</option>
                                </select>
                              </td>
                            </tr>

                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal">{ "Save changes" }</button>
                  </div>
                </div>
              </div>
            </div>
          </>
        }
    }

    fn view_login(&self, ctx: &Context<Self>) -> Html {
        let last_username = self.last_username.clone();
        html! {
          <>
            <div class="form-description">
              <div>
                <p>
                  { "Now try to authenticate! See what happens if you change the username or use a different credential" }
                </p>
              </div>
            </div>
            <main class="text-center form-signin">
              <h3 class="h3 mb-3 fw-normal">{ "Authenticate with Webauthn" }</h3>
              <form
                    onsubmit={ ctx.link().callback(|e: FocusEvent| {
                    console::log!("prevent_default()");
                    e.prevent_default();
                    AppMsg::Login
                } ) }
                action="javascript:void(0);"
              >
                <div class="form-floating">
                  <input id="autofocus" type="text" class="form-control" value={ last_username } />
                  <label for="autofocus">{ "Username" }</label>
                </div>
                <button class="btn btn-lg btn-primary" type="submit">
                    { "Authenticate" }
                </button>
              </form>
            </main>
          </>
        }
    }

    fn view_login_success(&self, ctx: &Context<Self>) -> Html {
        let last_username = self.last_username.clone();
        html! {
          <>
            <div class="form-description">
              <div>
                <h3>
                  {" Success! 🎉 " }
                </h3>
                <p>
                  { "See what happens if you use a different username, or a different credential" }
                </p>
                <p>
                  { "Or you can go back and register new credentials to see how they work" }
                </p>
              </div>
            </div>
            <main class="text-center form-signin">
              <h3 class="h3 mb-3 fw-normal">{ "Authenticate with Webauthn" }</h3>
              <form
                    onsubmit={ ctx.link().callback(|e: FocusEvent| {
                    console::log!("prevent_default()");
                    e.prevent_default();
                    AppMsg::Login
                } ) }
                action="javascript:void(0);"
              >
                <div class="form-floating">
                  <input id="autofocus" type="text" class="form-control" value={ last_username } />
                  <label for="autofocus">{ "Username" }</label>
                </div>
              <button class="btn btn-lg btn-secondary"
                  onclick={ ctx.link().callback(|_| AppMsg::Register) }>
                  { "Back to Register" }
              </button>
                <button class="btn btn-lg btn-primary" type="submit">
                    { "Authenticate" }
                </button>
              </form>
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
                  onclick={ ctx.link().callback(|_| AppMsg::Register) }>
                  { "Back to Register" }
              </button>
            </main>
          </>
        }
    }
}

impl Component for Demo {
    type Message = AppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        Demo {
            state: DemoState::Register,
            reg_settings: RegisterWithType::Passkey,
            last_username: String::default(),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let mut state_change = match (&self.state, msg) {
            (_, AppMsg::Error(None)) => {
                let msg = "No error message available".to_string();
                console::log!(&msg);
                DemoState::Error(msg)
            }
            (_, AppMsg::Error(Some(msg))) => {
                console::log!(format!("fetch task error -> {:?}", msg).as_str());
                DemoState::Error(msg)
            }
            (_, AppMsg::ErrorCode(e_code)) => {
                let msg = format!("{:?}", e_code);
                console::log!(&msg);
                DemoState::Error(msg)
            }
            // Rego
            (DemoState::Register, AppMsg::Register) => {
                let username = utils::get_value_from_element_id("autofocus").expect("No username");

                if username == "" {
                    ctx.link().send_message(AppMsg::Error(Some(
                        "A username must be provided".to_string(),
                    )));
                    return false;
                }

                self.last_username = username.clone();
                // Build the settings that we'll be using.

                let attest_req =
                    utils::get_select_value_from_element_id("strict_attestation_required")
                        .and_then(|v| match v.as_str() {
                            "s" => Some(AttestationLevel::Strict),
                            "a" => Some(AttestationLevel::AnyKnown),
                            _ => None,
                        })
                        .unwrap_or(AttestationLevel::None);

                let settings = utils::get_select_value_from_element_id("credential_type")
                    .and_then(|v| match v.as_str() {
                        "pk" => Some(RegisterWithType::Passkey),
                        "sk" => Some(RegisterWithType::SecurityKey(attest_req)),
                        "pl" => Some(RegisterWithType::Passwordless(attest_req)),
                        _ => None,
                    })
                    .unwrap_or(RegisterWithType::Passkey);

                console::log!(format!("cred_type  -> {:?}", settings).as_str());
                console::log!(format!("username   -> {:?}", username).as_str());

                self.reg_settings = settings.clone();

                ctx.link().send_future(async {
                    match Self::register_begin(username, settings).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                DemoState::Waiting
            }
            (_, AppMsg::Register) => DemoState::Register,
            (DemoState::Waiting, AppMsg::BeginRegisterChallenge(ccr, username)) => {
                console::log!(format!("ccr -> {:?}", ccr));
                let promise = utils::window()
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
                            AppMsg::Error(Some(format!("error -> {:?}", e)))
                        }
                    }
                });
                DemoState::Waiting
            }
            (DemoState::Waiting, AppMsg::CompleteRegisterChallenge(jsval, username)) => {
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
                DemoState::Waiting
            }
            (DemoState::Waiting, AppMsg::RegisterSuccess) => DemoState::Login,
            // Loggo
            (DemoState::LoginSuccess, AppMsg::Login) | (DemoState::Login, AppMsg::Login) => {
                let username = utils::get_value_from_element_id("autofocus").expect("No username");
                if username == "" {
                    ctx.link().send_message(AppMsg::Error(Some(
                        "A username must be provided".to_string(),
                    )));
                    return false;
                }
                self.last_username = username.clone();

                let settings: AuthenticateWithType = (&self.reg_settings).into();

                console::log!(format!("login -> {:?}", username).as_str());
                ctx.link().send_future(async {
                    match Self::login_begin(username, settings).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                DemoState::Waiting
            }
            (DemoState::Waiting, AppMsg::BeginLoginChallenge(cro, username)) => {
                console::log!(format!("cro -> {:?}", cro).as_str());
                let promise = utils::window()
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
                            AppMsg::Error(Some(format!("error -> {:?}", e)))
                        }
                    }
                });
                DemoState::Waiting
            }
            (DemoState::Waiting, AppMsg::CompleteLoginChallenge(jsv, username)) => {
                ctx.link().send_future(async {
                    match Self::login_complete(web_sys::PublicKeyCredential::from(jsv), username)
                        .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                DemoState::Waiting
            }
            (DemoState::Waiting, AppMsg::LoginSuccess) => DemoState::LoginSuccess,
            (s, m) => {
                let msg = format!("Invalid State Transition -> {:?}, {:?}", s, m);
                console::log!(msg.as_str());
                DemoState::Error(msg)
            }
        };
        std::mem::swap(&mut self.state, &mut state_change);
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            DemoState::Waiting => {
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
            DemoState::Register => self.view_register(ctx),
            DemoState::Login => self.view_login(ctx),
            DemoState::LoginSuccess => self.view_login_success(ctx),
            DemoState::Error(msg) => self.view_error(ctx, &msg),
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus("autofocus");
        console::log!("oauth2::rendered");
    }
}
