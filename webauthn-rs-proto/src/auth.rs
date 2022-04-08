//! Types related to authentication (Assertion)

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};

use crate::extensions::{AuthenticationExtensionsClientOutputs, RequestAuthenticationExtensions};
use crate::options::*;

/// The requested options for the authentication
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    /// The challenge that should be signed by the authenticator.
    pub challenge: Base64UrlSafeData,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The timeout for the authenticator in case of no interaction.
    pub timeout: Option<u32>,
    /// The relying party ID.
    pub rp_id: String,
    /// The set of credentials that are allowed to sign this challenge.
    pub allow_credentials: Vec<AllowCredentials>,
    /// The verification policy the browser will request.
    pub user_verification: UserVerificationPolicy,
    /// extensions.
    pub extensions: Option<RequestAuthenticationExtensions>,
}

/// A JSON serializable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestChallengeResponse {
    /// The options.
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[cfg(feature = "wasm")]
impl Into<web_sys::CredentialRequestOptions> for RequestChallengeResponse {
    fn into(self) -> web_sys::CredentialRequestOptions {
        use js_sys::{Array, Object, Uint8Array};
        use wasm_bindgen::JsValue;

        let chal = Uint8Array::from(self.public_key.challenge.0.as_slice());
        let allow_creds: Array = self
            .public_key
            .allow_credentials
            .iter()
            .map(|ac| {
                let obj = Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &JsValue::from_str(ac.type_.as_str()))
                    .unwrap();

                js_sys::Reflect::set(&obj, &"id".into(), &Uint8Array::from(ac.id.0.as_slice()))
                    .unwrap();

                if let Some(transports) = &ac.transports {
                    let tarray: Array = transports
                        .iter()
                        .map(|trs| JsValue::from_serde(trs).unwrap())
                        .collect();

                    js_sys::Reflect::set(&obj, &"transports".into(), &tarray).unwrap();
                }

                obj
            })
            .collect();

        let jsv = JsValue::from_serde(&self).unwrap();

        let pkcco = js_sys::Reflect::get(&jsv, &"publicKey".into()).unwrap();
        js_sys::Reflect::set(&pkcco, &"challenge".into(), &chal).unwrap();

        js_sys::Reflect::set(&pkcco, &"allowCredentials".into(), &allow_creds).unwrap();

        web_sys::CredentialRequestOptions::from(jsv)
    }
}

/// <https://w3c.github.io/webauthn/#authenticatorassertionresponse>
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthenticatorAssertionResponseRaw {
    /// Raw authenticator data.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Base64UrlSafeData,

    /// Signed client data.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,

    /// Signature
    pub signature: Base64UrlSafeData,

    /// Optional userhandle.
    #[serde(rename = "userHandle")]
    pub user_handle: Option<Base64UrlSafeData>,
}

/// A client response to an authentication challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by authentication to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PublicKeyCredential {
    /// The credential Id, likely base64
    pub id: String,
    /// The binary of the credential id.
    #[serde(rename = "rawId")]
    pub raw_id: Base64UrlSafeData,
    /// The authenticator response.
    pub response: AuthenticatorAssertionResponseRaw,
    /// Unsigned Client processed extensions.
    #[serde(default)]
    pub extensions: AuthenticationExtensionsClientOutputs,
    /// The authenticator type.
    #[serde(rename = "type")]
    pub type_: String,
}

#[cfg(feature = "wasm")]
impl From<web_sys::PublicKeyCredential> for PublicKeyCredential {
    fn from(data: web_sys::PublicKeyCredential) -> PublicKeyCredential {
        use js_sys::Uint8Array;

        let data_raw_id =
            Uint8Array::new(&js_sys::Reflect::get(&data, &"rawId".into()).unwrap()).to_vec();

        let data_response = js_sys::Reflect::get(&data, &"response".into()).unwrap();

        let data_response_authenticator_data = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"authenticatorData".into()).unwrap(),
        )
        .to_vec();

        let data_response_signature =
            Uint8Array::new(&js_sys::Reflect::get(&data_response, &"signature".into()).unwrap())
                .to_vec();

        let data_response_user_handle =
            &js_sys::Reflect::get(&data_response, &"userHandle".into()).unwrap();
        let data_response_user_handle = if data_response_user_handle.is_undefined() {
            None
        } else {
            Some(Uint8Array::new(data_response_user_handle).to_vec())
        };

        let data_response_client_data_json = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"clientDataJSON".into()).unwrap(),
        )
        .to_vec();

        let data_extensions = data.get_client_extension_results();

        // Base64 it

        let data_raw_id_b64 = Base64UrlSafeData(data_raw_id);
        let data_response_client_data_json_b64 = Base64UrlSafeData(data_response_client_data_json);
        let data_response_authenticator_data_b64 =
            Base64UrlSafeData(data_response_authenticator_data);
        let data_response_signature_b64 = Base64UrlSafeData(data_response_signature);

        let data_response_user_handle_b64 = data_response_user_handle.map(|d| Base64UrlSafeData(d));

        PublicKeyCredential {
            id: format!("{}", data_raw_id_b64),
            raw_id: data_raw_id_b64,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: data_response_authenticator_data_b64,
                client_data_json: data_response_client_data_json_b64,
                signature: data_response_signature_b64,
                user_handle: data_response_user_handle_b64,
            },
            extensions: data_extensions.into(),
            type_: "public-key".to_string(),
        }
    }
}
