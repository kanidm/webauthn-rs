use crate::error::*;
use crate::utils;

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

#[derive(Debug)]
pub enum Demo {
    Waiting,
    Register,
    Login,
    Error( Option<String> ),
}

#[derive(Debug)]
pub enum AppMsg {
    // This can probably go ...
    // UserNameInput(String),
    Register,
    BeginRegisterChallenge(web_sys::CredentialCreationOptions, String),
    CompleteRegisterChallenge(JsValue, String),
    RegisterSuccess,
    Login,
    BeginLoginChallenge(web_sys::CredentialRequestOptions, String),
    CompleteLoginChallenge(JsValue, String),
    LoginSuccess,
    // Errors
    Error(String),
}

impl From<FetchError> for AppMsg {
    fn from(fe: FetchError) -> Self {
        AppMsg::Error(fe.as_string())
    }
}

impl Demo {
    async fn register_begin(username: String) -> Result<AppMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        let dest = format!("/challenge/register/{}", username);
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
            Ok(AppMsg::Error(emsg))
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

        let dest = format!("/register/{}", username);
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
            Ok(AppMsg::RegisterSuccess)
        } else {
            let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    async fn login_begin(username: String) -> Result<AppMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        let dest = format!("/challenge/login/{}", username);
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

        let dest = format!("/login/{}", username);
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
            Ok(AppMsg::LoginSuccess)
        } else {
            let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(AppMsg::Error(emsg))
        }
    }

    fn view_register(&self, ctx: &Context<Self>) -> Html {
        html! {
                  <>
                    <div class="form-description">
                      <div>
                        <p>
                          { "Webauthn is a modern, passwordless method of securely authenticating to a website." }
                        </p>
                        <p>
                          { "A Webauthn credential uses strong cryptography to identify you to a site. The cryptographic key is contained in a secure device like a yubikey, a trusted platform module, or your phones secure enclave. Even when you use a finger print or a pin with your credential, that biometric or pin data never leaves your device. "}
                        </p>
                        <p>
                          { "You can test registering and then authenticating with Webauthn here!" }
                        </p>
                      </div>
                    </div>
                    <main class="text-center form-signin">
                      <h3 class="h3 mb-3 fw-normal">{ "Register a Webauthn Credential" }</h3>
                      <div class="form-floating">
                        <input id="username" type="text" class="form-control" value="" />
                        <label for="username">{ "Username" }</label>
                      </div>
                      <button type="button" class="btn btn-lg btn-secondary" data-bs-toggle="modal" data-bs-target="#exampleModalDefault">
                        { "Change Webauthn Settings" }
                      </button>
                      <button class="btn btn-lg btn-primary"
                          onclick={ ctx.link().callback(|_| AppMsg::Register) }>
                          { "Begin Registration" }
                      </button>
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
                                <td>{ "User Verification Required" }</td>
                                <td>
                                  <input class="form-check-input" type="checkbox" value="" id="invalidCheck3" />
                                </td>
                              </tr>
                              <tr>
                                <td>{ "Attestation" }</td>
                                <td>
                                  <select class="form-select" id="validationServer04">
                                    <option selected=true value="">{ "None" }</option>
                                    <option>{ "Indirect" }</option>
                                    <option>{ "Direct" }</option>
                                  </select>
                                </td>
                              </tr>
                              <tr>
                                <td>{ "Attachment" }</td>
                                <td>
                                  <select class="form-select" id="validationServer04">
                                    <option selected=true value="">{ "Any" }</option>
                                    <option>{ "Platform" }</option>
                                    <option>{ "Roaming" }</option>
                                  </select>
                                </td>
                              </tr>
                              <tr>
                                <td>{ "Algorithm" }</td>
                                <td>
                                  <div class="row">
                                    <div class="col">
                                      { "ES256" }
                                    </div>
                                    <div class="col">
                                      <input class="form-check-input" type="checkbox" value="ES256" id="invalidCheck3" checked=true />
                                    </div>
                                  </div>
                                  <div class="row">
                                    <div class="col">
                                      { "RS256" }
                                    </div>
                                    <div class="col">
                                      <input class="form-check-input" type="checkbox" value="RS256" id="invalidCheck3" />
                                    </div>
                                  </div>
            
                                </td>
                              </tr>
            
            
                            </tbody>
                          </table>
                        </div>
            
                      </div>
            
                          </div>
                          <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{ "Reset Settings" }</button>
                            <button type="button" class="btn btn-primary">{ "Save changes" }</button>
                          </div>
                        </div>
                      </div>
                    </div>

                  </>
                }
    }
}

impl Component for Demo {
    type Message = AppMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        Demo::Register
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let mut state_change = match (&self, msg) {
            (_, AppMsg::Error(msg)) => {
                console::log!(format!("fetch task error -> {:?}", msg).as_str());
                Demo::Error( Some(msg) )
            }
            /*
            AppMsg::UserNameInput(mut username) => {
                std::mem::swap(&mut self.username, &mut username);
            }
            */
            // Rego
            (Demo::Register, AppMsg::Register) => {
                let username = utils::get_value_from_element_id("username")
                    .expect("No username");
                console::log!(format!("register -> {:?}", username).as_str());
                ctx.link().send_future(async {
                    match Self::register_begin(username).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                Demo::Waiting
            }
            (Demo::Waiting, AppMsg::BeginRegisterChallenge(ccr, username)) => {
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
                            AppMsg::Error(format!("error -> {:?}", e))
                        }
                    }
                });
                Demo::Waiting
            }
            (Demo::Waiting, AppMsg::CompleteRegisterChallenge(jsval, username)) => {
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
                Demo::Waiting
            }
            // Loggo
            (Demo::Login, AppMsg::Login) => {
                let username = utils::get_value_from_element_id("username")
                    .expect("No username");
                console::log!(format!("login -> {:?}", username).as_str());
                ctx.link().send_future(async {
                    match Self::login_begin(username).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                Demo::Waiting
            }
            (Demo::Waiting, AppMsg::BeginLoginChallenge(cro, username)) => {
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
                                AppMsg::Error(format!("error -> {:?}", e))
                            }
                        }
                    });
                Demo::Waiting
            }
            (Demo::Waiting, AppMsg::CompleteLoginChallenge(jsv, username)) => {
                ctx.link().send_future(async {
                    match Self::login_complete(web_sys::PublicKeyCredential::from(jsv), username)
                        .await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                Demo::Waiting
            }
            (s, m) => {
                let msg = format!("Invalid State Transition -> {:?}, {:?}", s, m);
                console::log!(msg.as_str());
                Demo::Error(Some(msg))
            }
        };
        std::mem::swap(self, &mut state_change);
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match self {
            Demo::Waiting => {
                html! {
                  <main class="text-center form-signin h-100">
                    <div class="vert-center">
                      <h1>{ ". . ." }</h1>
                    </div>
                  </main>
                }
            }
            Demo::Register => {
                self.view_register(ctx)
            }
            Demo::Login => {
                unimplemented!();
            }
            Demo::Error(msg) => {
                unimplemented!();
            }
        }
    }
}

/*
<div>
    <input id="username" type="text" class="form-control" value={ username }
        oninput={ ctx.link().callback(|e: InputEvent| AppMsg::UserNameInput(utils::get_value_from_input_event(e))) } />
    <button type="button" class="btn btn-dark" onclick={ ctx.link().callback(|_| AppMsg::Register) }>{" Register "}</button>
    <button type="button" class="btn btn-dark" onclick={ ctx.link().callback(|_| AppMsg::Login) }>{" Login "}</button>
</div>
*/
