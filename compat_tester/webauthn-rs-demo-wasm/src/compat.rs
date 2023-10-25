use crate::error::*;
use crate::utils;

use gloo::console;
// use gloo::timers;
// timers::future::TimeoutFuture::new(1_000).await;
use yew::prelude::*;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use webauthn_rs_demo_shared::*;

/*
 * We want to test:
 * Direct Attest: Discouraged
 * Indirect Attest: Discouraged
 * None Attest: Discouraged
 * None Attest - remove the previous enc algo
 * Auth - use the discouraged as above, see if we get UV=true?
 * None Attest - preferred,
 * Auth - use the discouraged as above, see if we get UV=true?
 * None Attest - required
 * If reg -> is req during auth
 *
 */

#[derive(Debug)]
enum CompatTestState {
    Init,
    Step(u32),
    Complete,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
enum CompatTestStep {
    DirectAttest1 = 1,
    IndirectAttest1 = 2,
    NoneAttest1 = 3,
    AuthDiscouraged = 4,
    AuthDiscouragedConsistent = 5,
    // Some devices can only store one cred-per-domain, so this checks if
    // that's the case.
    NoneAttest2 = 6,
    AuthMultipleCredentials = 7,
    FallBackAlg = 8,
    UvPreferred = 9,
    AuthPreferred = 10,
    AuthPreferredConsistent = 11,
    UvRequired = 12,
    AuthRequired = 13,
    ExtnUvmSupported = 14,
    ExtnCredProtectSupported = 15,
    ExtnHmacSecretSupported = 16,
    Complete = 17,
}

impl From<u32> for CompatTestStep {
    fn from(v: u32) -> Self {
        match v {
            1 => CompatTestStep::DirectAttest1,
            2 => CompatTestStep::IndirectAttest1,
            3 => CompatTestStep::NoneAttest1,
            4 => CompatTestStep::AuthDiscouraged,
            5 => CompatTestStep::AuthDiscouragedConsistent,
            6 => CompatTestStep::NoneAttest2,
            7 => CompatTestStep::AuthMultipleCredentials,
            8 => CompatTestStep::FallBackAlg,
            9 => CompatTestStep::UvPreferred,
            10 => CompatTestStep::AuthPreferred,
            11 => CompatTestStep::AuthPreferredConsistent,
            12 => CompatTestStep::UvRequired,
            13 => CompatTestStep::AuthRequired,
            14 => CompatTestStep::ExtnUvmSupported,
            15 => CompatTestStep::ExtnCredProtectSupported,
            16 => CompatTestStep::ExtnHmacSecretSupported,
            17 => CompatTestStep::Complete,
            _ => panic!("Unknown variant!"),
        }
    }
}

impl CompatTestStep {
    fn next(&self) -> Self {
        if matches!(self, CompatTestStep::Complete) {
            CompatTestStep::Complete
        } else {
            Self::from((*self as u32) + 1)
        }
    }
}

fn reg_extensions_full() -> RequestRegistrationExtensions {
    RequestRegistrationExtensions {
        cred_protect: Some(CredProtect {
            credential_protection_policy:
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
            enforce_credential_protection_policy: Some(false),
        }),
        uvm: Some(true),
        cred_props: Some(true),
        min_pin_length: Some(true),
        hmac_create_secret: Some(true),
    }
}

fn auth_extensions_full() -> RequestAuthenticationExtensions {
    RequestAuthenticationExtensions {
        appid: None,
        uvm: Some(true),
        hmac_get_secret: None,
    }
}

#[derive(Debug)]
pub struct CompatTest {
    state: CompatTestState,
    step: CompatTestStep,
    results: CompatTestResults,
    show_next: bool,
}

#[derive(Debug)]
pub enum AppMsg {
    Ignore,
    Begin,
    ResultsToClipboard,
    BeginRegisterChallenge(CreationChallengeResponse),
    CompleteRegisterChallenge(RegisterPublicKeyCredential),
    RegisterSuccess(RegistrationSuccess),

    BeginLoginChallenge(RequestChallengeResponse),
    CompleteLoginChallenge(PublicKeyCredential),
    LoginSuccess(AuthenticationSuccess),

    ErrorCode(ResponseError),
}

impl From<FetchError> for AppMsg {
    fn from(fe: FetchError) -> Self {
        AppMsg::ErrorCode(ResponseError::UnknownError(fe.as_string()))
    }
}

impl Component for CompatTest {
    type Message = AppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!(format!("create").as_str());
        CompatTest {
            state: CompatTestState::Init,
            // state: CompatTestState::Complete,
            step: CompatTestStep::DirectAttest1,
            // step: CompatTestStep::NoneAttest1,
            results: CompatTestResults::default(),
            show_next: false,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!(&format!("{:?} {:?}", self.step, msg));
        match msg {
            AppMsg::Ignore => {
                match self.step {
                    // Triggers the complete view when done.
                    CompatTestStep::Complete => {
                        self.state = CompatTestState::Complete;
                    }
                    _ => {
                        self.show_next = true;
                    }
                }
            }
            AppMsg::ResultsToClipboard => {
                // Not yet supported, see: https://docs.rs/web-sys/latest/web_sys/struct.Clipboard.html
                let data = serde_json::to_string(&self.results)
                    .expect_throw("Failed to serialise results");

                let promise = utils::clipboard().write_text(&data);
                let fut = JsFuture::from(promise);

                ctx.link().send_future(async move {
                    match fut.await {
                        Ok(_) => {
                            console::log!("Wrote to clipboard!");
                        }
                        Err(e) => {
                            console::log!(&format!("Unable to access clipboard -> {:?}", e));
                        }
                    };
                    AppMsg::Ignore
                });
            }
            AppMsg::Begin => {
                self.show_next = false;
                match self.step {
                    CompatTestStep::DirectAttest1 => {
                        // Set the initial test results to failure.
                        self.results.direct_attest_1 = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "compatuser".to_string(),
                                uv: Some(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                                algorithm: Some(COSEAlgorithm::secure_algs()),
                                attestation: Some(AttestationConveyancePreference::Direct),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::IndirectAttest1 => {
                        // Set the initial test results to failure.
                        self.results.indirect_attest_1 = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "compatuser".to_string(),
                                uv: Some(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                                algorithm: Some(COSEAlgorithm::secure_algs()),
                                attestation: Some(AttestationConveyancePreference::Indirect),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::NoneAttest1 => {
                        // Set the initial test results to failure.
                        self.results.none_attest_1 = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "compatuser".to_string(),
                                uv: Some(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                                algorithm: Some(COSEAlgorithm::all_possible_algs()),
                                attestation: Some(AttestationConveyancePreference::None),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::NoneAttest2 => {
                        // Set the initial test results to failure.
                        self.results.none_attest_2 = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "another_user".to_string(),
                                uv: Some(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                                algorithm: Some(COSEAlgorithm::all_possible_algs()),
                                attestation: Some(AttestationConveyancePreference::None),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::FallBackAlg => {
                        // Look back at the previous test
                        let algs =
                            if let Some(alg) = self.results.none_attest_1.get_credential_alg() {
                                // What alg was used?
                                // Remove it from the list.
                                let mut algs = COSEAlgorithm::all_possible_algs();
                                algs.retain(|a| a != alg);
                                algs
                            } else {
                                // Skip
                                self.step = self.step.next();
                                ctx.link().send_message(AppMsg::Begin);
                                return false;
                            };

                        /*
                        if true {
                            self.step = self.step.next();
                            ctx.link().send_message(AppMsg::Begin);
                            return false;
                        }
                        */

                        self.results.fallback_alg = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "compatuser".to_string(),
                                uv: Some(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                                algorithm: Some(algs),
                                attestation: Some(AttestationConveyancePreference::None),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::UvPreferred => {
                        // Set the initial test results to failure.
                        self.results.uvpreferred = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "compatuser".to_string(),
                                uv: Some(UserVerificationPolicy::Preferred),
                                algorithm: Some(COSEAlgorithm::secure_algs()),
                                attestation: Some(AttestationConveyancePreference::None),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::UvRequired => {
                        // Set the initial test results to failure.
                        self.results.uvrequired = CTestAttestState::failed();
                        // Start the process!
                        self.do_registration(
                            ctx,
                            RegisterWithSettings {
                                username: "compatuser".to_string(),
                                uv: Some(UserVerificationPolicy::Required),
                                algorithm: Some(COSEAlgorithm::secure_algs()),
                                attestation: Some(AttestationConveyancePreference::None),
                                attachment: None,
                                extensions: Some(reg_extensions_full()),
                            },
                        );
                    }
                    CompatTestStep::AuthDiscouraged => {
                        if let Some(cred_id) = self.results.none_attest_1.get_credential_id() {
                            self.results.authdiscouraged = CTestAuthState::failed();
                            let use_cred_id = Some(cred_id.clone());
                            self.do_auth(
                                ctx,
                                AuthenticateWithSettings {
                                    username: "compatuser".to_string(),
                                    use_cred_id,
                                    uv: Some(UserVerificationPolicy::Discouraged_DO_NOT_USE),
                                    extensions: Some(auth_extensions_full()),
                                },
                            );
                        } else {
                            // Skip
                            self.results.authdiscouraged = CTestAuthState::FailedPrerequisite;
                            self.step = self.step.next();
                            ctx.link().send_message(AppMsg::Begin);
                            return false;
                        };
                    }
                    CompatTestStep::AuthMultipleCredentials => {
                        let mut skip = true;

                        if let Some(cred_1_id) = self.results.none_attest_1.get_credential_id() {
                            if let Some(cred_2_id) = self.results.none_attest_2.get_credential_id()
                            {
                                self.results.authmultiple = CTestAuthState::failed();
                                if cred_1_id != cred_2_id {
                                    let use_cred_id = Some(cred_1_id.clone());
                                    self.do_auth(
                                        ctx,
                                        AuthenticateWithSettings {
                                            username: "compatuser".to_string(),
                                            use_cred_id,
                                            uv: None,
                                            extensions: Some(auth_extensions_full()),
                                        },
                                    );
                                    skip = false;
                                } else {
                                    self.results
                                        .authmultiple
                                        .set_err(ResponseError::CredentialIdAreIdentical);
                                }
                            }
                        }
                        // Skip
                        if skip {
                            self.results.authmultiple = CTestAuthState::FailedPrerequisite;
                            self.step = self.step.next();
                            ctx.link().send_message(AppMsg::Begin);
                            return false;
                        }
                    }
                    CompatTestStep::AuthDiscouragedConsistent => {
                        if let Some(rs) = self.results.none_attest_1.get_reg_result() {
                            if let Some(aus) = self.results.authdiscouraged.get_auth_result() {
                                if aus.uv == rs.uv {
                                    self.results.authdiscouraged_consistent =
                                        CTestSimpleState::Passed;
                                } else {
                                    self.results.authdiscouraged_consistent =
                                        CTestSimpleState::Warning;
                                }
                                self.step = self.step.next();
                                ctx.link().send_message(AppMsg::Begin);
                                return true;
                            }
                        }
                        // Skip
                        self.results.authdiscouraged_consistent =
                            CTestSimpleState::FailedPrerequisite;
                        self.step = self.step.next();
                        ctx.link().send_message(AppMsg::Begin);
                        return false;
                    }
                    CompatTestStep::AuthPreferred => {
                        if let Some(cred_id) = self.results.uvpreferred.get_credential_id() {
                            self.results.authpreferred = CTestAuthState::failed();
                            let use_cred_id = Some(cred_id.clone());
                            self.do_auth(
                                ctx,
                                AuthenticateWithSettings {
                                    username: "compatuser".to_string(),
                                    use_cred_id,
                                    uv: Some(UserVerificationPolicy::Preferred),
                                    extensions: Some(auth_extensions_full()),
                                },
                            );
                        } else {
                            // Skip
                            self.results.authpreferred = CTestAuthState::FailedPrerequisite;
                            self.step = self.step.next();
                            ctx.link().send_message(AppMsg::Begin);
                            return false;
                        };
                    }
                    CompatTestStep::AuthPreferredConsistent => {
                        if let Some(rs) = self.results.uvpreferred.get_reg_result() {
                            if let Some(aus) = self.results.authpreferred.get_auth_result() {
                                if aus.uv == rs.uv {
                                    self.results.authpreferred_consistent =
                                        CTestSimpleState::Passed;
                                } else {
                                    self.results.authpreferred_consistent =
                                        CTestSimpleState::Failed;
                                }
                                self.step = self.step.next();
                                ctx.link().send_message(AppMsg::Begin);
                                return true;
                            }
                        }
                        // Skip
                        self.results.authpreferred_consistent =
                            CTestSimpleState::FailedPrerequisite;
                        self.step = self.step.next();
                        ctx.link().send_message(AppMsg::Begin);
                        return false;
                    }
                    CompatTestStep::AuthRequired => {
                        if let Some(cred_id) = self.results.uvrequired.get_credential_id() {
                            self.results.authrequired = CTestAuthState::failed();
                            let use_cred_id = Some(cred_id.clone());
                            self.do_auth(
                                ctx,
                                AuthenticateWithSettings {
                                    username: "compatuser".to_string(),
                                    use_cred_id,
                                    uv: Some(UserVerificationPolicy::Required),
                                    extensions: Some(auth_extensions_full()),
                                },
                            );
                        } else {
                            // Skip
                            self.results.authrequired = CTestAuthState::FailedPrerequisite;
                            self.step = self.step.next();
                            ctx.link().send_message(AppMsg::Begin);
                            return false;
                        };
                    }
                    CompatTestStep::ExtnUvmSupported => {
                        self.results.extn_uvm_supported = CTestSimpleState::FailedPrerequisite;
                        self.step = self.step.next();
                        ctx.link().send_message(AppMsg::Begin);
                        return false;
                    }
                    CompatTestStep::ExtnCredProtectSupported => {
                        if let Some(rs) = self.results.direct_attest_1.get_reg_result() {
                            console::log!(&format!("{:?}", rs.extensions));

                            if matches!(rs.extensions.cred_protect, ExtnState::Set(_)) {
                                self.results.extn_credprotect_supported = CTestSimpleState::Passed
                            } else {
                                self.results.extn_credprotect_supported = CTestSimpleState::Failed
                            }
                        } else {
                            self.results.extn_credprotect_supported =
                                CTestSimpleState::FailedPrerequisite;
                        }

                        self.step = self.step.next();
                        ctx.link().send_message(AppMsg::Begin);
                        return false;
                    }
                    CompatTestStep::ExtnHmacSecretSupported => {
                        if let Some(rs) = self.results.direct_attest_1.get_reg_result() {
                            console::log!(&format!("{:?}", rs.extensions));
                            if matches!(rs.extensions.hmac_create_secret, ExtnState::Set(true)) {
                                self.results.extn_hmacsecret_supported = CTestSimpleState::Passed
                            } else {
                                self.results.extn_hmacsecret_supported = CTestSimpleState::Failed
                            }
                        } else {
                            self.results.extn_hmacsecret_supported =
                                CTestSimpleState::FailedPrerequisite;
                        }

                        self.step = self.step.next();
                        ctx.link().send_message(AppMsg::Begin);
                        return false;
                    }
                    CompatTestStep::Complete => {
                        self.state = CompatTestState::Complete;
                        return true;
                    }
                };
                // Set our step
                self.state = CompatTestState::Step(self.step as u32);
            }
            AppMsg::BeginRegisterChallenge(ccr) => {
                // Stash a copy of the ccr
                match self.step {
                    CompatTestStep::DirectAttest1 => {
                        self.results.direct_attest_1.save_ccr(&ccr);
                    }
                    CompatTestStep::IndirectAttest1 => {
                        self.results.indirect_attest_1.save_ccr(&ccr);
                    }
                    CompatTestStep::NoneAttest1 => {
                        self.results.none_attest_1.save_ccr(&ccr);
                    }
                    CompatTestStep::NoneAttest2 => {
                        self.results.none_attest_2.save_ccr(&ccr);
                    }
                    CompatTestStep::FallBackAlg => {
                        self.results.fallback_alg.save_ccr(&ccr);
                    }
                    CompatTestStep::UvPreferred => {
                        self.results.uvpreferred.save_ccr(&ccr);
                    }
                    CompatTestStep::UvRequired => {
                        self.results.uvrequired.save_ccr(&ccr);
                    }
                    CompatTestStep::AuthDiscouraged
                    | CompatTestStep::AuthPreferred
                    | CompatTestStep::AuthRequired
                    | CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::AuthMultipleCredentials
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {
                        console::log!("INVALID STATE!!!");
                    }
                };

                let c_options: web_sys::CredentialCreationOptions = ccr.into();
                let promise = utils::window()
                    .navigator()
                    .credentials()
                    .create_with_options(&c_options)
                    .expect_throw("Unable to create promise");
                let fut = JsFuture::from(promise);

                ctx.link().send_future(async move {
                    match fut.await {
                        Ok(jsval) => {
                            let w_rpkc = web_sys::PublicKeyCredential::from(jsval);
                            let rpkc = RegisterPublicKeyCredential::from(w_rpkc);
                            AppMsg::CompleteRegisterChallenge(rpkc)
                        }
                        Err(e) => {
                            console::log!(format!("error -> {:?}", e).as_str());
                            AppMsg::ErrorCode(ResponseError::NavigatorError(format!("{:?}", e)))
                        }
                    }
                });
            }
            AppMsg::CompleteRegisterChallenge(rpkc) => {
                match self.step {
                    CompatTestStep::DirectAttest1 => {
                        self.results.direct_attest_1.save_rpkc(&rpkc);
                    }
                    CompatTestStep::IndirectAttest1 => {
                        self.results.indirect_attest_1.save_rpkc(&rpkc);
                    }
                    CompatTestStep::NoneAttest1 => {
                        self.results.none_attest_1.save_rpkc(&rpkc);
                    }
                    CompatTestStep::NoneAttest2 => {
                        self.results.none_attest_2.save_rpkc(&rpkc);
                    }
                    CompatTestStep::FallBackAlg => {
                        self.results.fallback_alg.save_rpkc(&rpkc);
                    }
                    CompatTestStep::UvPreferred => {
                        self.results.uvpreferred.save_rpkc(&rpkc);
                    }
                    CompatTestStep::UvRequired => {
                        self.results.uvrequired.save_rpkc(&rpkc);
                    }
                    CompatTestStep::AuthDiscouraged
                    | CompatTestStep::AuthPreferred
                    | CompatTestStep::AuthRequired
                    | CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::AuthMultipleCredentials
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {
                        console::log!("INVALID STATE!!!");
                    }
                };

                ctx.link().send_future(async {
                    match Self::register_complete(rpkc).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            AppMsg::RegisterSuccess(rs) => {
                match self.step {
                    CompatTestStep::DirectAttest1 => {
                        self.results.direct_attest_1.set_success(rs);
                    }
                    CompatTestStep::IndirectAttest1 => {
                        self.results.indirect_attest_1.set_success(rs);
                    }
                    CompatTestStep::NoneAttest1 => {
                        self.results.none_attest_1.set_success(rs);
                    }
                    CompatTestStep::NoneAttest2 => {
                        self.results.none_attest_2.set_success(rs);
                    }
                    CompatTestStep::FallBackAlg => {
                        self.results.fallback_alg.set_success(rs);
                    }
                    CompatTestStep::UvPreferred => {
                        self.results.uvpreferred.set_success(rs);
                    }
                    CompatTestStep::UvRequired => {
                        if rs.uv {
                            self.results.uvrequired.set_success(rs);
                        } else {
                            self.results
                                .uvrequired
                                .set_err(ResponseError::UserNotVerified);
                        }
                    }
                    CompatTestStep::AuthDiscouraged
                    | CompatTestStep::AuthPreferred
                    | CompatTestStep::AuthRequired
                    | CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::AuthMultipleCredentials
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {
                        console::log!("INVALID STATE!!!");
                    }
                };
                self.step = self.step.next();
                ctx.link().send_message(AppMsg::Ignore);
            }
            AppMsg::BeginLoginChallenge(rcr) => {
                match self.step {
                    CompatTestStep::AuthDiscouraged => {
                        self.results.authdiscouraged.save_rcr(&rcr);
                    }
                    CompatTestStep::AuthPreferred => {
                        self.results.authpreferred.save_rcr(&rcr);
                    }
                    CompatTestStep::AuthRequired => {
                        self.results.authrequired.save_rcr(&rcr);
                    }
                    CompatTestStep::AuthMultipleCredentials => {
                        self.results.authmultiple.save_rcr(&rcr);
                    }
                    CompatTestStep::DirectAttest1
                    | CompatTestStep::IndirectAttest1
                    | CompatTestStep::NoneAttest1
                    | CompatTestStep::NoneAttest2
                    | CompatTestStep::FallBackAlg
                    | CompatTestStep::UvPreferred
                    | CompatTestStep::UvRequired
                    | CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {
                        console::log!("INVALID STATE!!!");
                    }
                }

                let c_options: web_sys::CredentialRequestOptions = rcr.into();
                let promise = utils::window()
                    .navigator()
                    .credentials()
                    .get_with_options(&c_options)
                    .expect_throw("Unable to create promise");
                let fut = JsFuture::from(promise);

                ctx.link().send_future(async move {
                    match fut.await {
                        Ok(jsval) => {
                            let w_pkc = web_sys::PublicKeyCredential::from(jsval);
                            let pkc = PublicKeyCredential::from(w_pkc);
                            AppMsg::CompleteLoginChallenge(pkc)
                        }
                        Err(e) => {
                            console::log!(format!("error -> {:?}", e).as_str());
                            AppMsg::ErrorCode(ResponseError::NavigatorError(format!("{:?}", e)))
                        }
                    }
                });
            }
            AppMsg::CompleteLoginChallenge(pkc) => {
                match self.step {
                    CompatTestStep::AuthDiscouraged => {
                        self.results.authdiscouraged.save_pkc(&pkc);
                    }
                    CompatTestStep::AuthPreferred => {
                        self.results.authpreferred.save_pkc(&pkc);
                    }
                    CompatTestStep::AuthRequired => {
                        self.results.authrequired.save_pkc(&pkc);
                    }
                    CompatTestStep::AuthMultipleCredentials => {
                        self.results.authmultiple.save_pkc(&pkc);
                    }
                    CompatTestStep::DirectAttest1
                    | CompatTestStep::IndirectAttest1
                    | CompatTestStep::NoneAttest1
                    | CompatTestStep::NoneAttest2
                    | CompatTestStep::FallBackAlg
                    | CompatTestStep::UvPreferred
                    | CompatTestStep::UvRequired
                    | CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {
                        console::log!("INVALID STATE!!!");
                    }
                }
                ctx.link().send_future(async {
                    match Self::login_complete(pkc).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            AppMsg::LoginSuccess(aus) => {
                match self.step {
                    CompatTestStep::AuthDiscouraged => {
                        self.results.authdiscouraged.set_success(aus);
                    }
                    CompatTestStep::AuthPreferred => {
                        self.results.authpreferred.set_success(aus);
                    }
                    CompatTestStep::AuthRequired => {
                        self.results.authrequired.set_success(aus);
                    }
                    CompatTestStep::AuthMultipleCredentials => {
                        self.results.authmultiple.set_success(aus);
                    }
                    CompatTestStep::DirectAttest1
                    | CompatTestStep::IndirectAttest1
                    | CompatTestStep::NoneAttest1
                    | CompatTestStep::NoneAttest2
                    | CompatTestStep::FallBackAlg
                    | CompatTestStep::UvPreferred
                    | CompatTestStep::UvRequired
                    | CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {
                        console::log!("INVALID STATE!!!");
                    }
                }
                self.step = self.step.next();
                ctx.link().send_message(AppMsg::Ignore);
            }
            AppMsg::ErrorCode(err) => {
                match self.step {
                    CompatTestStep::DirectAttest1 => {
                        self.results.direct_attest_1.set_err(err);
                    }
                    CompatTestStep::IndirectAttest1 => {
                        self.results.indirect_attest_1.set_err(err);
                    }
                    CompatTestStep::NoneAttest1 => {
                        self.results.none_attest_1.set_err(err);
                    }
                    CompatTestStep::NoneAttest2 => {
                        self.results.none_attest_2.set_err(err);
                    }
                    CompatTestStep::FallBackAlg => {
                        match err {
                            ResponseError::NavigatorError(_) => {
                                // This generally means that there is no fallback algo, so we only warn here.
                                self.results.fallback_alg.set_warn(err)
                            }
                            ResponseError::COSEKeyEDUnsupported => {
                                // Means that ED keys are the fallback and we don't support it.
                                self.results.fallback_alg.set_warn(err)
                            }
                            _ => self.results.fallback_alg.set_err(err),
                        }
                    }
                    CompatTestStep::UvPreferred => {
                        self.results.uvpreferred.set_err(err);
                    }
                    CompatTestStep::UvRequired => {
                        match err {
                            ResponseError::NavigatorError(_) => {
                                // This generally means that the browser de-selected the credential
                                // since it can't do uv.
                                self.results.uvrequired.set_warn(err)
                            }
                            _ => self.results.uvrequired.set_err(err),
                        }
                    }
                    CompatTestStep::AuthDiscouraged => {
                        self.results.authdiscouraged.set_err(err);
                    }
                    CompatTestStep::AuthMultipleCredentials => {
                        match err {
                            ResponseError::NavigatorError(_) => {
                                // Very likely we are on an ipad, and it can't proceed because the
                                // credential that we want to use here no longer exists.
                                self.results.authmultiple.set_warn(err)
                            }
                            _ => self.results.authmultiple.set_err(err),
                        }
                    }
                    CompatTestStep::AuthPreferred => {
                        self.results.authpreferred.set_err(err);
                    }
                    CompatTestStep::AuthRequired => {
                        self.results.authrequired.set_err(err);
                    }
                    CompatTestStep::AuthDiscouragedConsistent
                    | CompatTestStep::AuthPreferredConsistent
                    | CompatTestStep::ExtnUvmSupported
                    | CompatTestStep::ExtnCredProtectSupported
                    | CompatTestStep::ExtnHmacSecretSupported
                    | CompatTestStep::Complete => {}
                };
                self.step = self.step.next();
                ctx.link().send_message(AppMsg::Ignore);
            }
        };
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match self.state {
            CompatTestState::Init => self.view_begin(ctx),
            CompatTestState::Step(step) => self.view_step(ctx, step),
            CompatTestState::Complete => self.view_complete(ctx),
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus("autofocus");
        console::log!("oauth2::rendered");
    }
}

impl CompatTest {
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

    fn view_issue_link(&self) -> Html {
        let mut url = url::Url::parse("https://github.com/kanidm/webauthn-rs/issues/new")
            .expect_throw("Failed to parse static url");

        url.query_pairs_mut()
            .append_pair("title", "Compatibility Test Failure")
            .append_pair(
                "body",
                r#"
Please add any extra details here:

* Browser version
* Type of authenticator hardware
* Any other details that may help

```
<please paste the details json here>
```
            "#,
            );

        html! {
          <div class="vert-center w-100">
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
              { "An error occured in your test. If possible, please " }
              <a href={ url.as_str().to_string() } class="alert-link" rel="noopener noreferrer" target="_blank">{ "open an issue" }</a>
            </div>
          </div>
        }
    }

    fn view_complete(&self, ctx: &Context<Self>) -> Html {
        let data =
            serde_json::to_string_pretty(&self.results).expect_throw("Failed to serialise results");

        console::log!(&format!("{:?}", self.results));
        html! {
            <div class="form-description">
              <main class="h-100">
                <div class="text-center">
                <h1>{ "Test Complete" }</h1>
                </div>
                { if self.results.did_err() {
                    self.view_issue_link()
                } else {
                  html! { <></> }
                } }
                <div class="vert-center w-100">
                  <table class="table table-striped">
                    <thead>
                    <tr>
                      <th scope="col">{ "#" }</th>
                      <th scope="col">{ "Name" }</th>
                      <th scope="col">{ "Result" }</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                      <th scope="row">{ "1" }</th>
                      <td>{ "Direct Attestation" }</td>
                      <td>{ self.results.direct_attest_1.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "2" }</th>
                      <td>{ "Indirect Attestation" }</td>
                      <td>{ self.results.indirect_attest_1.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "3" }</th>
                      <td>{ "None Attestation 1 + UV Discouraged" }</td>
                      <td>{ self.results.none_attest_1.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "4" }</th>
                      <td>{ "Auth UV Discouraged" }</td>
                      <td>{ self.results.authdiscouraged.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "5" }</th>
                      <td>{ "Auth UV Discouraged Consistent" }</td>
                      <td>{ self.results.authdiscouraged_consistent.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "6" }</th>
                      <td>{ "None Attestation 2 + UV Discouraged" }</td>
                      <td>{ self.results.none_attest_2.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "7" }</th>
                      <td>{ "Multiple User Credentials Allowed" }</td>
                      <td>{ self.results.authmultiple.to_result() }</td>
                    </tr>

                    <tr>
                      <th scope="row">{ "8" }</th>
                      <td>{ "Fallback Algorithm" }</td>
                      <td>{ self.results.fallback_alg.to_result() }</td>
                    </tr>

                    <tr>
                      <th scope="row">{ "9" }</th>
                      <td>{ "Register UserVerification Preferred" }</td>
                      <td>{ self.results.uvpreferred.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "10" }</th>
                      <td>{ "Auth UV Preferred" }</td>
                      <td>{ self.results.authpreferred.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "11" }</th>
                      <td>{ "Auth UV Preferred Consistent" }</td>
                      <td>{ self.results.authpreferred_consistent.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "12" }</th>
                      <td>{ "Register UserVerification Required" }</td>
                      <td>{ self.results.uvrequired.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "13" }</th>
                      <td>{ "Auth UV Required" }</td>
                      <td>{ self.results.authrequired.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "14" }</th>
                      <td>{ "Extension uvm supported (Attestation Only)" }</td>
                      <td>{ self.results.extn_uvm_supported.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "15" }</th>
                      <td>{ "Extension credProtect supported (Attestation Only)" }</td>
                      <td>{ self.results.extn_credprotect_supported.to_result() }</td>
                    </tr>
                    <tr>
                      <th scope="row">{ "16" }</th>
                      <td>{ "Extension hmac-secret supported (Attestation Only)" }</td>
                      <td>{ self.results.extn_hmacsecret_supported.to_result() }</td>
                    </tr>

                    </tbody>
                  </table>
                </div>
                <div class="vert-center w-100" style="padding-bottom: 10px;">
                  <button class="btn btn-lg btn-info"
                      onclick={ ctx.link().callback(|_| AppMsg::ResultsToClipboard) }>
                      { "Copy Detailed Results to Clipboard" }
                  </button>
                </div>
                <div class="w-100 accordion" id="accordionExample">
                  <div class="accordion-item">
                    <h4 class="accordion-header" id="headingThree">
                      <button class="accordion-button collapsed" type="button"
                        data-bs-toggle="collapse" data-bs-target="#collapseThree"
                        aria-expanded="false" aria-controls="collapseThree">
                        { "Details (JSON)" }
                      </button>
                    </h4>
                    <div id="collapseThree" class="accordion-collapse collapse"
                      aria-labelledby="headingThree" data-bs-parent="#accordionExample">
                      <div class="accordion-body">
                        <pre>{ data }</pre>
                      </div>
                    </div>
                  </div>
                </div>
              </main>
            </div>
        }
    }

    fn view_step(&self, ctx: &Context<Self>, step: u32) -> Html {
        html! {
          <main class="text-center form-signin h-100">
            <div class="vert-center">
              { if self.show_next {
                html! {
                  <form
                    onsubmit={ ctx.link().callback(|e: FocusEvent| {
                        console::log!("prevent_default()");
                        e.prevent_default();
                        AppMsg::Begin
                    } ) }
                    action="javascript:void(0);"
                  >
                    <button id="autofocus" class="btn btn-lg btn-primary" type="submit">{ "Next Test" }</button>
                  </form>
                }
              } else {
                  html! {
                    <h1>{ format!("{} of {}", step, (CompatTestStep::Complete as u32) - 1 ) }</h1>
                  }
              } }
            </div>
          </main>
        }
    }

    fn view_begin(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="form-description">
              <main class="h-100">
                <div class="vert-center">
                  <div>
                    <p>
                    {" This will conduct a compatability test of your authenticator (security token) to determine if it is compatible with Webauthn RS." }
                    </p>
                    <p>
                    { "During this test your authenticator will prompt your to authenticate and interact with it a number of times." }
                    </p>
                    <p>
                    { "You may also be requested to configure a PIN or Biometrics on your authenticator. If you do NOT wish for this to happen, do NOT run this test." }
                    </p>
                    <p>
                    { "Please know that and PIN or Biometrics you configure never leave your security token, and are not accessible to the Webauthn RS site." }
                    </p>
                    <p>
                    { "If you have multiple authenticators available, you MUST ensure that you only use a single one of them during the test until completed." }
                    </p>
                    <div class="text-center">
                      <form
                        onsubmit={ ctx.link().callback(|e: FocusEvent| {
                            console::log!("prevent_default()");
                            e.prevent_default();
                            AppMsg::Begin
                        } ) }
                        action="javascript:void(0);"
                      >
                        <button id="autofocus" class="btn btn-lg btn-primary" type="submit">{ "Begin Compatibility Test" }</button>
                      </form>
                    </div>
                  </div>
                </div>
              </main>
            </div>
        }
    }

    async fn register_begin(settings: RegisterWithSettings) -> Result<AppMsg, FetchError> {
        let req_jsvalue = serde_json::to_string(&settings)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise settings");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/compat/register_start", &opts)?;

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
            Ok(AppMsg::BeginRegisterChallenge(ccr))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(String::default);
            Ok(AppMsg::ErrorCode(ResponseError::UnknownError(emsg)))
        }
    }

    async fn register_complete(rpkc: RegisterPublicKeyCredential) -> Result<AppMsg, FetchError> {
        console::log!(format!("rpkc -> {:?}", rpkc).as_str());

        let req_jsvalue = serde_json::to_string(&rpkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise rpkc");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/compat/register_finish", &opts)?;

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
            let rs: RegistrationSuccess = jsval.into_serde().unwrap_throw();
            console::log!(format!("rs -> {:?}", rs).as_str());
            Ok(AppMsg::RegisterSuccess(rs))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(String::default);
            Ok(AppMsg::ErrorCode(ResponseError::UnknownError(emsg)))
        }
    }

    async fn login_begin(settings: AuthenticateWithSettings) -> Result<AppMsg, FetchError> {
        let req_jsvalue = serde_json::to_string(&settings)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise settings");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/compat/login_start", &opts)?;

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
            Ok(AppMsg::BeginLoginChallenge(ccr))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(String::default);
            Ok(AppMsg::ErrorCode(ResponseError::UnknownError(emsg)))
        }
    }

    async fn login_complete(pkc: PublicKeyCredential) -> Result<AppMsg, FetchError> {
        console::log!(format!("pkc -> {:?}", pkc).as_str());

        let req_jsvalue = serde_json::to_string(&pkc)
            .map(|s| JsValue::from(&s))
            .expect("Failed to serialise pkc");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/compat/login_finish", &opts)?;

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
            let aus: AuthenticationSuccess = jsval.into_serde().unwrap_throw();
            console::log!(format!("aus -> {:?}", aus).as_str());
            Ok(AppMsg::LoginSuccess(aus))
        } else if status == 400 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let err: ResponseError = jsval.into_serde().unwrap_throw();
            Ok(AppMsg::ErrorCode(err))
        } else {
            // let headers = resp.headers();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(String::default);
            Ok(AppMsg::ErrorCode(ResponseError::UnknownError(emsg)))
        }
    }
}
