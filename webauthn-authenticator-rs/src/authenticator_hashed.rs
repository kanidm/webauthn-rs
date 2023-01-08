//! Specialized alternative traits for authenticator backends.
use std::collections::BTreeMap;

use base64urlsafedata::Base64UrlSafeData;
use serde_cbor::{ser::to_vec_packed, Value};
use url::Url;
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
};

use crate::{
    ctap2::commands::{
        GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest, MakeCredentialResponse,
    },
    error::WebauthnCError,
    util::{compute_sha256, creation_to_clientdata, get_to_clientdata},
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
        serde_cbor::de::from_slice(cred.response.attestation_object.0.as_slice())
            .map_err(|_| WebauthnCError::Cbor)?;

    // Write value with u32 keys
    let resp: BTreeMap<u32, Value> = resp.into();
    to_vec_packed(&resp).map_err(|_| WebauthnCError::Cbor)
}

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

#[cfg(test)]
#[allow(clippy::panic)]
mod test {
    use openssl::{hash::MessageDigest, rand::rand_bytes, sign::Verifier, x509::X509};
    use webauthn_rs_core::proto::COSEKey;
    use webauthn_rs_proto::{AllowCredentials, PubKeyCredParams, RelyingParty, User};

    use crate::{
        ctap2::{commands::value_to_vec_u8, CBORResponse},
        softtoken::SoftToken,
    };

    use super::*;

    #[test]
    fn perform_register_auth_with_command() {
        let _ = tracing_subscriber::fmt::try_init();
        let (mut soft_token, _) = SoftToken::new().unwrap();
        let mut client_data_hash = vec![0; 32];
        let mut user_id = vec![0; 16];
        rand_bytes(&mut client_data_hash).unwrap();
        rand_bytes(&mut user_id).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: client_data_hash.clone(),
            rp: RelyingParty {
                name: "example.com".to_string(),
                id: "example.com".to_string(),
            },
            user: User {
                id: Base64UrlSafeData(user_id),
                name: "sampleuser".to_string(),
                display_name: "Sample User".to_string(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -257,
                },
            ],
            exclude_list: vec![],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let response = perform_register_with_request(&mut soft_token, request, 10000).unwrap();

        // All keys should be ints
        let m: Value = serde_cbor::from_slice(response.as_slice()).unwrap();
        let m = if let Value::Map(m) = m {
            m
        } else {
            panic!("unexpected type")
        };
        assert!(m.keys().all(|k| matches!(k, Value::Integer(_))));

        // Try to deserialise the MakeCredentialResponse again
        let response =
            <MakeCredentialResponse as CBORResponse>::try_from(response.as_slice()).unwrap();
        trace!(?response);

        // Run packed attestation verification
        // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
        let mut att_stmt = if let Value::Map(m) = response.att_stmt.unwrap() {
            m
        } else {
            panic!("unexpected type");
        };
        trace!(?att_stmt);
        let signature = value_to_vec_u8(
            att_stmt.remove(&Value::Text("sig".to_string())).unwrap(),
            "att_stmt.sig",
        )
        .unwrap();

        // Extract attestation certificate
        let x5c = if let Value::Array(v) = att_stmt.remove(&Value::Text("x5c".to_string())).unwrap()
        {
            v
        } else {
            panic!("Unexpected type");
        };
        let x5c = value_to_vec_u8(x5c[0].to_owned(), "x5c[0]").unwrap();
        let verification_cert = X509::from_der(&x5c).unwrap();
        let pubkey = verification_cert.public_key().unwrap();

        // Reconstruct verification data (auth_data + client_data_hash)
        let mut verification_data =
            value_to_vec_u8(response.auth_data.unwrap(), "verification_data").unwrap();
        let auth_data_len = verification_data.len();
        verification_data.reserve(client_data_hash.len());
        verification_data.extend_from_slice(&client_data_hash);

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
        assert!(verifier
            .verify_oneshot(&signature, &verification_data)
            .unwrap());

        // https://www.w3.org/TR/webauthn-2/#attestation-object
        let cred_id_off = /* rp_id_hash */ 32 + /* flags */ 1 + /* counter */ 4 + /* aaguid */ 16;
        let cred_id_len = u16::from_be_bytes(
            (&verification_data[cred_id_off..cred_id_off + 2])
                .try_into()
                .unwrap(),
        ) as usize;
        let cred_id = Base64UrlSafeData(
            (verification_data[cred_id_off + 2..cred_id_off + 2 + cred_id_len]).to_vec(),
        );

        // Future assertions are signed with this COSEKey
        let cose_key: Value = serde_cbor::from_slice(
            &verification_data[cred_id_off + 2 + cred_id_len..auth_data_len],
        )
        .unwrap();
        let cose_key = COSEKey::try_from(&cose_key).unwrap();

        rand_bytes(&mut client_data_hash).unwrap();
        let request = GetAssertionRequest {
            client_data_hash: client_data_hash.clone(),
            rp_id: "example.com".to_string(),
            allow_list: vec![AllowCredentials {
                type_: "public-key".to_string(),
                id: cred_id.to_owned(),
                transports: None,
            }],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
        };
        trace!(?request);

        let response = perform_auth_with_request(&mut soft_token, request, 10000).unwrap();
        let response =
            <GetAssertionResponse as CBORResponse>::try_from(response.as_slice()).unwrap();
        trace!(?response);

        // Check correct matching credential
        assert_eq!(response.credential.unwrap().id, cred_id);

        // Check the signature
        let signature = response.signature.unwrap();
        let mut verification_data = response.auth_data.unwrap();
        verification_data.reserve(client_data_hash.len());
        verification_data.extend_from_slice(&client_data_hash);

        assert!(cose_key
            .verify_signature(&signature, &verification_data)
            .unwrap());
    }
}
