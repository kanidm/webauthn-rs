//! Types related to attestation (Registration)

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};

use crate::extensions::{RegistrationExtensionsClientOutputs, RequestRegistrationExtensions};
use crate::options::*;

/// <https://w3c.github.io/webauthn/#dictionary-makecredentialoptions>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    /// The relying party
    pub rp: RelyingParty,
    /// The user.
    pub user: User,
    /// The one-time challenge for the credential to sign.
    pub challenge: Base64UrlSafeData,
    /// The set of cryptographic types allowed by this server.
    pub pub_key_cred_params: Vec<PubKeyCredParams>,

    /// The timeout for the authenticator to stop accepting the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    /// The requested attestation level from the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,

    /// Credential ID's that are excluded from being able to be registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    /// Criteria defining which authenticators may be used in this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,

    /// Non-standard extensions that may be used by the browser/authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<RequestRegistrationExtensions>,
}

/// A JSON serializable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationChallengeResponse {
    /// The options.
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[cfg(feature = "wasm")]
impl From<CreationChallengeResponse> for web_sys::CredentialCreationOptions {
    fn from(ccr: CreationChallengeResponse) -> Self {
        use js_sys::Uint8Array;
        use wasm_bindgen::JsValue;

        let chal = Uint8Array::from(ccr.public_key.challenge.0.as_slice());
        let userid = Uint8Array::from(ccr.public_key.user.id.0.as_slice());

        let jsv = JsValue::from_serde(&ccr).unwrap();

        let pkcco = js_sys::Reflect::get(&jsv, &"publicKey".into()).unwrap();
        js_sys::Reflect::set(&pkcco, &"challenge".into(), &chal).unwrap();

        let user = js_sys::Reflect::get(&pkcco, &"user".into()).unwrap();
        js_sys::Reflect::set(&user, &"id".into(), &userid).unwrap();

        if let Some(extensions) = ccr.public_key.extensions {
            if let Some(cred_blob) = extensions.cred_blob {
                let exts = js_sys::Reflect::get(&pkcco, &"extensions".into()).unwrap();
                let cred_blob = Uint8Array::from(cred_blob.0.as_ref());
                js_sys::Reflect::set(&exts, &"credBlob".into(), &cred_blob).unwrap();
            }
        }
        web_sys::CredentialCreationOptions::from(jsv)
    }
}

/// <https://w3c.github.io/webauthn/#authenticatorattestationresponse>
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AuthenticatorAttestationResponseRaw {
    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject>
    #[serde(rename = "attestationObject")]
    pub attestation_object: Base64UrlSafeData,

    /// <https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson>
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,

    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-gettransports>
    #[serde(default)]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// A client response to a registration challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by registration to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
/// <https://w3c.github.io/webauthn/#iface-pkcredential>
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterPublicKeyCredential {
    /// The id of the PublicKey credential, likely in base64.
    ///
    /// This is NEVER actually
    /// used in a real registration, because the true credential ID is taken from the
    /// attestation data.
    pub id: String,
    /// The id of the credential, as binary.
    ///
    /// This is NEVER actually
    /// used in a real registration, because the true credential ID is taken from the
    /// attestation data.
    #[serde(rename = "rawId")]
    pub raw_id: Base64UrlSafeData,
    /// <https://w3c.github.io/webauthn/#dom-publickeycredential-response>
    pub response: AuthenticatorAttestationResponseRaw,
    /// The type of credential.
    #[serde(rename = "type")]
    pub type_: String,
    /// Unsigned Client processed extensions.
    #[serde(default)]
    pub extensions: RegistrationExtensionsClientOutputs,
}

#[cfg(feature = "wasm")]
impl From<web_sys::PublicKeyCredential> for RegisterPublicKeyCredential {
    fn from(data: web_sys::PublicKeyCredential) -> RegisterPublicKeyCredential {
        use js_sys::Uint8Array;

        // is_user_verifying_platform_authenticator_available

        // AuthenticatorAttestationResponse has getTransports but web_sys isn't exposing it?
        let transports = None;

        // First, we have to b64 some data here.
        // data.raw_id
        let data_raw_id =
            Uint8Array::new(&js_sys::Reflect::get(&data, &"rawId".into()).unwrap()).to_vec();

        let data_response = js_sys::Reflect::get(&data, &"response".into()).unwrap();
        let data_response_attestation_object = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"attestationObject".into()).unwrap(),
        )
        .to_vec();

        let data_response_client_data_json = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"clientDataJSON".into()).unwrap(),
        )
        .to_vec();

        let data_extensions = data.get_client_extension_results();

        // Now we can convert to the base64 values for json.
        let data_raw_id_b64 = Base64UrlSafeData(data_raw_id);

        let data_response_attestation_object_b64 =
            Base64UrlSafeData(data_response_attestation_object);

        let data_response_client_data_json_b64 = Base64UrlSafeData(data_response_client_data_json);

        RegisterPublicKeyCredential {
            id: format!("{}", data_raw_id_b64),
            raw_id: data_raw_id_b64,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: data_response_attestation_object_b64,
                client_data_json: data_response_client_data_json_b64,
                transports,
            },
            type_: "public-key".to_string(),
            extensions: data_extensions.into(),
        }
    }
}
