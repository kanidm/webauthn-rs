use crate::error::*;
use crate::utils;

use gloo::console;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, Request, RequestInit, RequestMode, Response};
use webauthn_rs_demo_shared::*;
use webauthn_rs_proto::wasm::PublicKeyCredentialExt;
use yew::prelude::*;

// JsValue(NotAllowedError: The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client. undefined)

#[derive(Debug)]
pub struct Demo {
    state: DemoState,
    ctap2_supported: bool,
    reg_settings: RegisterWithType,
    last_username: String,
    abort_controller: AbortController,
}

#[derive(Debug, Clone)]
pub enum ConduiState {
    Waiting,
    Presented(web_sys::CredentialRequestOptions),
    Cancelled,
}

#[derive(Debug, Clone)]
pub enum DemoState {
    Waiting,
    Register,
    Login(ConduiState),
    LoginSuccess(ConduiState),
    Error(String),
}

#[derive(Debug)]
pub enum AppMsg {
    SetCtap2Support { ctap2_supported: bool },
    // This can probably go ...
    Register,
    BeginRegisterChallenge(web_sys::CredentialCreationOptions, String),
    CompleteRegisterChallenge(JsValue, String),
    RegisterSuccess,
    Login,
    ConduiChallengeReady(web_sys::CredentialRequestOptions),
    BeginLoginChallenge(web_sys::CredentialRequestOptions, String),
    CompleteConduiChallenge(JsValue),
    CompleteLoginChallenge(JsValue, String),
    ConduiCancelled,
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
        reg_type: RegisterWithType,
    ) -> Result<AppMsg, FetchError> {
        let reg_start = RegisterStart {
            username: username.to_owned(),
            reg_type,
        };

        let req_jsvalue =
            serde_wasm_bindgen::to_value(&reg_start).expect_throw("Failed to serialise settings");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/demo/register_start", &opts)?;

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
            let ccr: CreationChallengeResponse =
                serde_wasm_bindgen::from_value(jsval).unwrap_throw();
            let c_options = ccr.into();
            Ok(AppMsg::BeginRegisterChallenge(c_options, username))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = serde_wasm_bindgen::from_value(jsval).unwrap_throw();
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

        let reg_finish = RegisterFinish { username, rpkc };
        let req_jsvalue =
            serde_wasm_bindgen::to_value(&reg_finish).expect("Failed to serialise rpkc");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/demo/register_finish", &opts)?;

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
            let err: ResponseError = serde_wasm_bindgen::from_value(jsval).unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string();
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn conditional_login_begin() -> Result<AppMsg, FetchError> {
        console::log!("conditional_login_begin()");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        let request = Request::new_with_str_and_init("/demo/condui_login_start", &opts)?;

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
            let ccr: Result<RequestChallengeResponse, _> = serde_wasm_bindgen::from_value(jsval);
            console::log!(format!("conditional_login_begin() {:?}", ccr).as_str());
            let ccr = ccr.expect_throw("Failed to deserialise");
            let c_options = ccr.into();
            Ok(AppMsg::ConduiChallengeReady(c_options))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = serde_wasm_bindgen::from_value(jsval).unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string();
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn conditional_login_complete(
        data: web_sys::PublicKeyCredential,
    ) -> Result<AppMsg, FetchError> {
        console::log!(format!("pkc -> {:?}", data).as_str());
        let pkc = PublicKeyCredential::from(data);
        console::log!(format!("rp pkc -> {:?}", pkc).as_str());

        let req_jsvalue = serde_wasm_bindgen::to_value(&pkc).expect("Failed to serialise pkc");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/demo/condui_login_finish", &opts)?;

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
            let err: ResponseError = serde_wasm_bindgen::from_value(jsval).unwrap_throw();
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
        auth_type: AuthenticateWithType,
    ) -> Result<AppMsg, FetchError> {
        let auth_start = AuthenticateStart {
            username: username.to_owned(),
            auth_type,
        };

        let req_jsvalue =
            serde_wasm_bindgen::to_value(&auth_start).expect_throw("Failed to serialise settings");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/demo/login_start", &opts)?;

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
            let ccr: RequestChallengeResponse =
                serde_wasm_bindgen::from_value(jsval).unwrap_throw();
            let c_options = ccr.into();
            Ok(AppMsg::BeginLoginChallenge(c_options, username))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = serde_wasm_bindgen::from_value(jsval).unwrap_throw();
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
        let auth_finish = AuthenticateFinish { username, pkc };

        let req_jsvalue =
            serde_wasm_bindgen::to_value(&auth_finish).expect("Failed to serialise pkc");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/demo/login_finish", &opts)?;

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
            let err: ResponseError = serde_wasm_bindgen::from_value(jsval).unwrap_throw();
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

        let ctap2_support = if self.ctap2_supported {
            html! {
                <></>
            }
        } else {
            html! {
                <p>
                  { "⚠️ Your browser appears to lack support for CTAP2. This site may not perform as expected." }
                </p>
            }
        };

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
              { ctap2_support }
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
                                  <option value="pl">{ "Attested Passkey" }</option>
                                  <option value="sk">{ "Security Key" }</option>
                                </select>
                              </td>
                            </tr>

                            <tr>
                              <td>{ "Attestation Level" }</td>
                              <td>
                                <select class="form-select" id="strict_attestation_required">
                                  <option selected=true value="n">{ "None" }</option>
                                  <option value="a">{ "Any Known FIDO Device" }</option>
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
                  <input id="autofocus" type="text" name="name" autocomplete="webauthn" class="form-control" value={ last_username } />
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

    fn create(ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());

        // Fire off the check for ctap2 support.
        match PublicKeyCredentialExt::is_external_ctap2_securitykey_supported() {
            Ok(promise) => {
                ctx.link().send_future(async {
                    let x = wasm_bindgen_futures::JsFuture::from(promise).await;

                    console::log!(format!("{:?}", x).as_str());

                    match x.map(|i| i.as_bool()) {
                        Ok(Some(true)) => AppMsg::SetCtap2Support {
                            ctap2_supported: true,
                        },
                        Ok(Some(false)) => AppMsg::SetCtap2Support {
                            ctap2_supported: false,
                        },
                        Ok(None) => AppMsg::SetCtap2Support {
                            ctap2_supported: true,
                        },
                        Err(e) => {
                            console::log!(format!("isctap2 error {:?}", e).as_str());
                            AppMsg::SetCtap2Support {
                                ctap2_supported: true,
                            }
                        }
                    }
                });
            }
            Err(e) => {
                console::log!(format!("isExternalCTAP2SecurityKeySupported() does not exist in this browser - assuming ctap2 is supported - error {:?}", e).as_str());
            }
        };

        Demo {
            state: DemoState::Register,
            ctap2_supported: true,
            reg_settings: RegisterWithType::Passkey,
            last_username: String::default(),
            abort_controller: AbortController::new().expect("Failed to build abort controller"),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let mut state_change = match (&self.state, msg) {
            (state, AppMsg::SetCtap2Support { ctap2_supported }) => {
                self.ctap2_supported = ctap2_supported;
                state.clone()
            }
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
                            "a" => Some(AttestationLevel::AnyKnownFido),
                            _ => None,
                        })
                        .unwrap_or(AttestationLevel::None);

                let reg_type = utils::get_select_value_from_element_id("credential_type")
                    .and_then(|v| match v.as_str() {
                        "pk" => Some(RegisterWithType::Passkey),
                        "sk" => Some(RegisterWithType::SecurityKey(attest_req)),
                        "pl" => Some(RegisterWithType::AttestedPasskey(attest_req)),
                        _ => None,
                    })
                    .unwrap_or(RegisterWithType::Passkey);

                self.reg_settings = reg_type.clone();
                console::log!(format!("register_settings -> {reg_type:?}").as_str());

                // End anything dangling.
                self.abort_controller.abort();

                ctx.link().send_future(async {
                    match Self::register_begin(username, reg_type).await {
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
            (DemoState::Waiting, AppMsg::RegisterSuccess) => DemoState::Login(ConduiState::Waiting),
            // Loggo
            (DemoState::LoginSuccess(_), AppMsg::Login) | (DemoState::Login(_), AppMsg::Login) => {
                let username = utils::get_value_from_element_id("autofocus").expect("No username");
                if username == "" {
                    ctx.link().send_message(AppMsg::Error(Some(
                        "A username must be provided".to_string(),
                    )));
                    return false;
                }
                self.last_username = username.clone();

                let auth_type: AuthenticateWithType = (&self.reg_settings).into();

                // End anything dangling from condui
                self.abort_controller.abort();

                console::log!(format!("login -> {:?}", username).as_str());
                ctx.link().send_future(async {
                    match Self::login_begin(username, auth_type).await {
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

            (DemoState::Waiting, AppMsg::LoginSuccess) => {
                DemoState::LoginSuccess(ConduiState::Waiting)
            }
            // Condui handlers
            (DemoState::Login(ConduiState::Waiting), AppMsg::ConduiChallengeReady(cro)) => {
                // No state change, we are just triggering a callback.
                DemoState::Login(ConduiState::Presented(cro))
            }
            (DemoState::LoginSuccess(ConduiState::Waiting), AppMsg::ConduiChallengeReady(cro)) => {
                // No state change, we are just triggering a callback.
                DemoState::LoginSuccess(ConduiState::Presented(cro))
            }
            (DemoState::Login(ConduiState::Presented(_)), AppMsg::CompleteConduiChallenge(jsv))
            | (
                DemoState::LoginSuccess(ConduiState::Presented(_)),
                AppMsg::CompleteConduiChallenge(jsv),
            ) => {
                ctx.link().send_future(async {
                    match Self::conditional_login_complete(web_sys::PublicKeyCredential::from(jsv))
                        .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // the user did something so now we are waiting.
                DemoState::Waiting
            }

            (DemoState::Login(_), AppMsg::ConduiCancelled) => {
                DemoState::Login(ConduiState::Cancelled)
            }
            (DemoState::LoginSuccess(_), AppMsg::ConduiCancelled) => {
                DemoState::LoginSuccess(ConduiState::Cancelled)
            }
            (state, AppMsg::ConduiCancelled) => state.clone(),
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
            DemoState::Login(_) => self.view_login(ctx),
            DemoState::LoginSuccess(_) => self.view_login_success(ctx),
            DemoState::Error(msg) => self.view_error(ctx, &msg),
        }
    }

    fn rendered(&mut self, ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus("autofocus");
        console::log!("rendered");

        // At this point we need to check if condui is possible.
        match &mut self.state {
            DemoState::Login(ConduiState::Waiting)
            | DemoState::LoginSuccess(ConduiState::Waiting) => {
                match PublicKeyCredentialExt::is_conditional_mediation_available() {
                    Ok(promise) => ctx.link().send_future(async {
                        let x = wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();

                        console::log!(format!("{:?}", x).as_str());

                        if x.as_bool() == Some(true) {
                            console::log!("conditional mediation is available");
                            match Self::conditional_login_begin().await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        } else {
                            console::log!("conditional mediation is NOT available");
                            AppMsg::ConduiCancelled
                        }
                    }),
                    Err(e) => {
                        console::log!(format!("isConditionalMediationAvailable() does not exist in this browser. Assuming unsupported. error {:?}", e).as_str());
                    }
                };
            }
            DemoState::Login(ConduiState::Presented(c_options))
            | DemoState::LoginSuccess(ConduiState::Presented(c_options)) => {
                console::log!(format!("raw c_options {:?}", c_options).as_str());

                // Setup the abort controller.
                let mut abort_controller =
                    AbortController::new().expect("Failed to build abort controller");

                std::mem::swap(&mut self.abort_controller, &mut abort_controller);
                let abort_signal = self.abort_controller.signal();

                c_options.signal(&abort_signal);

                let promise = utils::window()
                    .navigator()
                    .credentials()
                    .get_with_options(&c_options)
                    .expect("Unable to create promise");
                let fut = JsFuture::from(promise);

                ctx.link().send_future(async {
                    console::log!("Started future for navigator cred get");
                    // Im not sure if we select! over this, if we can cancel this future / promise
                    // or not.
                    match fut.await {
                        Ok(data) => {
                            console::log!(format!("nav cred get data -> {:?}", data).as_str());
                            AppMsg::CompleteConduiChallenge(data)
                        }
                        Err(e) => {
                            console::log!(format!("nav cred get error -> {:?}", e).as_str());
                            AppMsg::ConduiCancelled
                        }
                    }
                });
            }
            _ => {}
        }
    }
}
