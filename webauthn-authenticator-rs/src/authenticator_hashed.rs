//! Specialized alternative traits for authenticator backends.
#[cfg(feature = "ctap2")]
use std::collections::BTreeMap;

#[cfg(any(feature = "ctap2", feature = "crypto"))]
use base64urlsafedata::Base64UrlSafeData;

#[cfg(feature = "ctap2")]
use serde_cbor_2::{ser::to_vec_packed, Value};
#[cfg(any(all(doc, not(doctest)), feature = "crypto"))]
use url::Url;
#[cfg(feature = "ctap2")]
use webauthn_rs_proto::PublicKeyCredentialDescriptor;
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2"))]
use crate::ctap2::commands::{
    GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest, MakeCredentialResponse,
};
use crate::error::WebauthnCError;
#[cfg(any(all(doc, not(doctest)), feature = "crypto"))]
use crate::{
    crypto::compute_sha256,
    util::{creation_to_clientdata, get_to_clientdata},
    AuthenticatorBackend,
};

/// [AuthenticatorBackend] with a `client_data_hash` parameter, for proxying
/// requests.
///
/// **Note:** unless you're proxying autentication requests, use the
/// [AuthenticatorBackend] trait instead. There is an implementation of
/// [AuthenticatorBackend] for `T: AuthenticatorBackendHashedClientData`.
///
/// Normally, [AuthenticatorBackend] takes the `origin` and `options.challenge`
/// parameters, serialises it to JSON, and then hashes it to produce
/// `client_data_hash`, which the authenticator signs. That JSON and the
/// signature are returned to the relying party, which it can check contain
/// expected values and are signed correctly.
///
/// This doesn't work when proxying an authenticator, where an initiator (web
/// browser) has *already* produced a `client_data_hash` for the authenticator
/// to sign, and changing it will cause the authenticator to sign something else
/// (and fail verification).
///
/// This trait instead takes a `client_data_hash` directly, and ignores the
/// `options.challenge` parameter. The downside is that this *can't* return a
/// `client_data_json` (the value is unknown), because the authenticator
/// wouldn't normally get a `client_data_json`.
///
/// This is similar to
/// [`BrowserPublicKeyCredentialCreationOptions.Builder.setClientDataHash()`][0]
/// on Android (Google Play Services FIDO API), which Chromium uses to proxy
/// caBLE requests (which only contain `client_data_json`) to an authenticator
/// stored in the device's secure element.
///
/// [AuthenticatorBackendHashedClientData] provides a [AuthenticatorBackend]
/// implementation – so backends should only implement **one** of those APIs,
/// preferring to implement [AuthenticatorBackendHashedClientData] if possible.
///
/// This interface won't be feasiable to implement on all platforms. For
/// example, Windows' Webauthn API takes a `client_data_json` and always hashes
/// it, and Apple's Passkey API takes `relyingPartyIdentifier` (origin) and
/// `challenge` parameters and generates the `client_data_json` for you.
///
/// Most clients should prefer to use the [AuthenticatorBackend] trait.
///
/// **See also:** [perform_register_with_request], [perform_auth_with_request]
///
/// [0]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/api/common/BrowserPublicKeyCredentialCreationOptions.Builder#public-browserpublickeycredentialcreationoptions.builder-setclientdatahash-byte[]-clientdatahash
pub trait AuthenticatorBackendHashedClientData {
    fn perform_register(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError>;

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError>;
}

#[cfg(any(all(doc, not(doctest)), feature = "crypto"))]
/// This provides a [AuthenticatorBackend] implementation for
/// [AuthenticatorBackendHashedClientData] implementations.
///
/// This implementation creates and hashes the `client_data_json`, and inserts
/// it back into the response type as normal.
impl<T: AuthenticatorBackendHashedClientData> AuthenticatorBackend for T {
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let client_data = creation_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();
        let mut cred = self.perform_register(client_data_hash, options, timeout_ms)?;
        cred.response.client_data_json = Base64UrlSafeData(client_data);

        Ok(cred)
    }

    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        let client_data = get_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();
        let mut cred = self.perform_auth(client_data_hash, options, timeout_ms)?;
        cred.response.client_data_json = Base64UrlSafeData(client_data);
        Ok(cred)
    }
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2"))]
/// Performs a registration request, using a [MakeCredentialRequest].
///
/// All PIN/UV auth parameters will be ignored, and are processed by
/// [AuthenticatorBackendHashedClientData] in the usual way.
///
/// Returns a [MakeCredentialResponse] as `Vec<u8>` on success. The message may
/// not be identical to what the authenticator actually returned, as it is
/// subject to deserialisation and conversion to and from another structure used
/// by [AuthenticatorBackend].
pub fn perform_register_with_request(
    backend: &mut impl AuthenticatorBackendHashedClientData,
    request: MakeCredentialRequest,
    timeout_ms: u32,
) -> Result<Vec<u8>, WebauthnCError> {
    let options = PublicKeyCredentialCreationOptions {
        rp: request.rp,
        user: request.user,
        challenge: Base64UrlSafeData(vec![]),
        pub_key_cred_params: request.pub_key_cred_params,
        timeout: Some(timeout_ms),
        exclude_credentials: Some(request.exclude_list),
        // TODO
        attestation: None,
        authenticator_selection: None,
        extensions: None,
    };
    let client_data_hash = request.client_data_hash;

    let cred: RegisterPublicKeyCredential =
        backend.perform_register(client_data_hash, options, timeout_ms)?;

    // attestation_object is a MakeCredentialResponse, with string keys
    // rather than u32, we need to convert it.
    let resp: MakeCredentialResponse =
        serde_cbor_2::de::from_slice(cred.response.attestation_object.0.as_slice())
            .map_err(|_| WebauthnCError::Cbor)?;

    // Write value with u32 keys
    let resp: BTreeMap<u32, Value> = resp.into();
    to_vec_packed(&resp).map_err(|_| WebauthnCError::Cbor)
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2"))]
/// Performs an authentication request, using a [GetAssertionRequest].
///
/// All PIN/UV auth parameters will be ignored, and are processed by
/// [AuthenticatorBackendHashedClientData] in the usual way.
///
/// Returns a [GetAssertionResponse] as `Vec<u8>` on success. The message may
/// not be identical to what the authenticator actually returned, as it is
/// subject to deserialisation and conversion to and from another structure used
/// by [AuthenticatorBackend].
pub fn perform_auth_with_request(
    backend: &mut impl AuthenticatorBackendHashedClientData,
    request: GetAssertionRequest,
    timeout_ms: u32,
) -> Result<Vec<u8>, WebauthnCError> {
    let options = PublicKeyCredentialRequestOptions {
        challenge: Base64UrlSafeData(vec![]),
        timeout: Some(timeout_ms),
        rp_id: request.rp_id,
        allow_credentials: request.allow_list,
        // TODO
        user_verification: webauthn_rs_proto::UserVerificationPolicy::Preferred,
        extensions: None,
    };

    let cred = backend.perform_auth(request.client_data_hash, options, timeout_ms)?;
    let resp = GetAssertionResponse {
        credential: Some(PublicKeyCredentialDescriptor {
            type_: cred.type_,
            id: cred.raw_id,
            transports: None,
        }),
        auth_data: Some(cred.response.authenticator_data.0),
        signature: Some(cred.response.signature.0),
        number_of_credentials: None,
        user_selected: None,
        large_blob_key: None,
    };

    // Write value with u32 keys
    let resp: BTreeMap<u32, Value> = resp.into();
    to_vec_packed(&resp).map_err(|_| WebauthnCError::Cbor)
}
