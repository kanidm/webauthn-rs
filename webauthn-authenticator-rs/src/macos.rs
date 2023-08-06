use crate::{AuthenticatorBackend, Url, WebauthnCError};
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

mod sys {
    use swift_rs::{swift, SRString};

    swift!(pub fn perform_register(options: SRString) -> SRString);
    swift!(pub fn perform_auth(options: SRString) -> SRString);

    #[derive(serde::Deserialize)]
    pub enum Result<T> {
        #[serde(rename = "data")]
        Data(T),
        #[serde(rename = "error")]
        Error(String),
    }
}

/// Authenticator backend for MacOS ASAuthorization API.
#[derive(Default)]
pub struct MacOS {}

impl AuthenticatorBackend for MacOS {
    /// Perform a registration action using the ASAuthorization API.
    fn perform_register(
        &mut self,
        _origin: Url,
        options: PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let result =
            unsafe { sys::perform_register(serde_json::to_string(&options)?.as_str().into()) };

        match serde_json::from_str::<sys::Result<RegisterPublicKeyCredential>>(result.as_str())? {
            sys::Result::Data(data) => Ok(data),
            sys::Result::Error(s) => Err(WebauthnCError::ASAuthorization(s)),
        }
    }

    /// Perform an authentication action using the ASAuthorization API.
    fn perform_auth(
        &mut self,
        _origin: Url,
        options: PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        let result = unsafe { sys::perform_auth(serde_json::to_string(&options)?.as_str().into()) };

        match serde_json::from_str::<sys::Result<PublicKeyCredential>>(result.as_str())? {
            sys::Result::Data(data) => Ok(data),
            sys::Result::Error(s) => Err(WebauthnCError::ASAuthorization(s)),
        }
    }
}
