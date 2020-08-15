#![allow(non_snake_case)]

//! JSON Protocol Structs and representations for communication with authenticators
//! and clients.

use std::collections::BTreeMap;
use std::convert::TryFrom;

use crate::base64_data::Base64UrlSafeData;
use crate::crypto;
use crate::error::*;

use serde::{Deserialize, Serialize};

/// Representation of a UserId
pub type UserId = Vec<u8>;

/// Representation of a device counter
pub type Counter = u32;

/// Representation of an AAGUID
/// https://www.w3.org/TR/webauthn/#aaguid
pub type Aaguid = Vec<u8>;

/// A challenge issued by the server. This contains a set of random bytes
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Challenge(pub Vec<u8>);

impl Into<Base64UrlSafeData> for Challenge {
    fn into(self) -> Base64UrlSafeData {
        Base64UrlSafeData(self.0)
    }
}

impl From<Base64UrlSafeData> for Challenge {
    fn from(d: Base64UrlSafeData) -> Self {
        Challenge(d.0)
    }
}

/// A credential ID type. At the moment this is a vector of bytes, but
/// it could also be a future change for this to be base64 string instead.
///
/// If changed, this would likely be a major library version change.
pub type CredentialID = Vec<u8>;

/// A user's authenticator credential. It contains an id, the public key
/// and a counter of how many times the authenticator has been used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// The ID of this credential.
    pub cred_id: CredentialID,
    /// The public key of this credential
    pub cred: crypto::COSEKey,
    /// The counter for this credential
    pub counter: u32,
}

impl Credential {
    pub(crate) fn new(acd: &AttestedCredentialData, ck: crypto::COSEKey, counter: u32) -> Self {
        Credential {
            cred_id: acd.credential_id.clone(),
            cred: ck,
            counter,
        }
    }
}

impl PartialEq<Credential> for Credential {
    fn eq(&self, c: &Credential) -> bool {
        self.cred_id == c.cred_id
    }
}

/// Defines the User Authenticator Verification policy. This is documented
/// https://w3c.github.io/webauthn/#enumdef-userverificationrequirement, and each
/// variant lists it's effects.
///
/// To be clear, Verification means that the Authenticator perform extra or supplementary
/// interfaction with the user to verify who they are. An example of this is Apple Touch Id
/// required a fingerprint to be verified, or a yubico device requiring a pin in addition to
/// a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin where touch is
/// the only interaction - we only verify a user is present, but we don't have extra details
/// to the legitimacy of that user.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationPolicy {
    /// Require User Verification bit to be set, and fail the registration or authentication
    /// if false. If the authenticator is not able to perform verification, it may not be
    /// usable with this policy.
    Required,
    /// Prefer User Verification bit to be set, and yolo the registration or authentication
    /// if false. This means if the authenticator can perform verification, do it, but don't
    /// mind if not.
    ///
    /// WARNING: This setting is effectively useless. Either you *want* user verification
    /// so require `Required`, or you do not want it, so use `Discouraged`. This setting
    /// will prompt users for verification, but without enforcing that it is present.
    ///
    /// As a result, this setting is effectively `Discouraged` and should be AVOIDED.
    Preferred,
    /// Request that no verification is performed, and fail if it is. This is intended to
    /// minimise user interaction in workflows, but is potentially a security risk to use.
    Discouraged,
}

// These are the primary communication structures you will need to handle.
pub(crate) type JSONExtensions = BTreeMap<String, String>;

/// Relying Party Entity
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    pub(crate) name: String,
    pub(crate) id: String,
}

/// User Entity
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub(crate) id: Base64UrlSafeData,
    pub(crate) name: String,
    pub(crate) display_name: String,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct PubKeyCredParams {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    // Should this be a diff size?
    pub(crate) alg: i64,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct AllowCredentials {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    pub(crate) id: String,
    /// https://www.w3.org/TR/webauthn/#transport
    /// may be usb, nfc, ble, internal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) transports: Option<Vec<String>>,
}

/// https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub(crate) rp: RelyingParty,
    pub(crate) user: User,
    pub(crate) challenge: Base64UrlSafeData,
    pub(crate) pub_key_cred_params: Vec<PubKeyCredParams>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) timeout: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attestation: Option<AttestationConveyancePreference>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authenticator_selection: Option<AuthenticatorSelectionCriteria>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extensions: Option<JSONExtensions>,
}

/// https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    /// https://www.w3.org/TR/webauthn/#attachment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authenticator_attachment: Option<AuthenticatorAttachment>,

    /// https://www.w3.org/TR/webauthn/#resident-credential
    pub(crate) require_resident_key: bool,

    pub(crate) user_verification: UserVerificationPolicy,
}

/// The authenticator attachment hint. This is NOT enforced, and is only used
/// to help a user select a relevant authenticator type.
///
/// https://www.w3.org/TR/webauthn/#attachment
#[derive(Debug, Copy, Clone, Serialize)]
pub enum AuthenticatorAttachment {
    /// https://www.w3.org/TR/webauthn/#attachment
    #[serde(rename = "platform")]
    Platform,
    /// https://www.w3.org/TR/webauthn/#attachment
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none
    None,

    /// WARNING: This allows the user to choose if they send a attestation
    /// to your service. You either want this (use `Direct`) or do not (use `None`).
    /// This option is effectively the same as `None` and should be AVOIDED.
    /// https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect
    Indirect,

    /// https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct
    Direct,
}

/// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    type_: String,
    id: Base64UrlSafeData,
    transports: Option<Vec<AuthenticatorTransport>>,
}

impl PublicKeyCredentialDescriptor {
    /// Constructed from a byte array
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            type_: "public-key".to_string(),
            id: Base64UrlSafeData(bytes),
            transports: None,
        }
    }
}

/// https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(unused)]
pub enum AuthenticatorTransport {
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb
    Usb,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc
    Nfc,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble
    Ble,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal
    Internal,
}

/// A JSON serialisable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationChallengeResponse {
    pub(crate) public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicKeyCredentialRequestOptions {
    challenge: Base64UrlSafeData,
    timeout: u32,
    rp_id: String,
    allow_credentials: Vec<AllowCredentials>,
    user_verification: UserVerificationPolicy,
    extensions: Option<JSONExtensions>,
}

/// A JSON serialisable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize)]
pub struct RequestChallengeResponse {
    publicKey: PublicKeyCredentialRequestOptions,
}

impl RequestChallengeResponse {
    pub(crate) fn new(
        challenge: Challenge,
        timeout: u32,
        relaying_party: String,
        allow_credentials: Vec<AllowCredentials>,
        user_verification_policy: UserVerificationPolicy,
    ) -> Self {
        RequestChallengeResponse {
            publicKey: PublicKeyCredentialRequestOptions {
                challenge: challenge.into(),
                timeout,
                rp_id: relaying_party,
                allow_credentials,
                user_verification: user_verification_policy,
                extensions: None,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CollectedClientData {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    pub(crate) challenge: Base64UrlSafeData,
    pub(crate) origin: String,
    pub(crate) tokenBinding: Option<TokenBinding>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TokenBinding {
    pub status: String,
    pub id: Option<String>,
}

// Should this be tryfrom
impl TryFrom<&Vec<u8>> for CollectedClientData {
    type Error = WebauthnError;
    fn try_from(data: &Vec<u8>) -> Result<CollectedClientData, WebauthnError> {
        let ccd: CollectedClientData =
            serde_json::from_slice(&data).map_err(|e| WebauthnError::ParseJSONFailure(e))?;

        Ok(ccd)
    }
}

#[derive(Debug)]
pub(crate) struct AttestedCredentialData {
    pub(crate) aaguid: Aaguid,
    pub(crate) credential_id: CredentialID,
    pub(crate) credential_pk: serde_cbor::Value,
}

// https://w3c.github.io/webauthn/#sctn-attestation
#[derive(Debug)]
pub(crate) struct AuthenticatorData {
    pub(crate) rp_id_hash: Vec<u8>,
    // pub(crate) flags: u8,
    pub(crate) counter: u32,
    pub(crate) user_present: bool,
    pub(crate) user_verified: bool,
    pub(crate) acd: Option<AttestedCredentialData>,
    // pub(crate) extensions: Option<CBORExtensions>,
    pub(crate) extensions: Option<()>,
}

fn cbor_parser(i: &[u8]) -> nom::IResult<&[u8], serde_cbor::Value> {
    let v: serde_cbor::Value = serde_cbor::from_slice(&i[0..])
        .map_err(|_| nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(1))))?;

    // Now re-encode it to find the length ... yuk.
    let encoded = serde_cbor::to_vec(&v)
        .map_err(|_| nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(2))))?;
    // Finally we know the cred len
    let cred_len = encoded.len();

    Ok((&i[cred_len..], v))
}

named!( extensions_parser<&[u8], ()>,
    // Just throw the bytes into cbor?
    do_parse!(
        (())
    )
);

named!( acd_parser<&[u8], AttestedCredentialData>,
    do_parse!(
        aaguid: take!(16) >>
        cred_id_len: u16!(nom::Endianness::Big) >>
        cred_id: take!(cred_id_len) >>
        cred_pk: cbor_parser >>
        (AttestedCredentialData {
            aaguid: aaguid.to_vec(),
            credential_id: cred_id.to_vec(),
            credential_pk: cred_pk,
        })
    )
);

named!( authenticator_data_flags<&[u8], (bool, bool, bool, bool)>,
    bits!(
        do_parse!(
            exten_pres: map!(take_bits!(u8, 1), |i| i != 0)  >>
            acd_pres: map!(take_bits!(u8, 1), |i| i != 0) >>
            take_bits!(u8, 1) >>
            take_bits!(u8, 1) >>
            take_bits!(u8, 1) >>
            u_ver: map!(take_bits!(u8, 1), |i| i != 0) >>
            take_bits!(u8, 1) >>
            u_pres: map!(take_bits!(u8, 1), |i| i != 0) >>
            ((exten_pres, acd_pres, u_ver, u_pres))
        )
    )
);

named!( authenticator_data_parser<&[u8], AuthenticatorData>,
    do_parse!(
        rp_id_hash: take!(32) >>
        data_flags: authenticator_data_flags >>
        counter: u32!(nom::Endianness::Big) >>
        acd: cond!(data_flags.1, acd_parser) >>
        extensions: cond!(data_flags.0, extensions_parser) >>
        (AuthenticatorData {
            rp_id_hash: rp_id_hash.to_vec(),
            counter: counter,
            user_verified: data_flags.2,
            user_present: data_flags.3,
            acd: acd,
            extensions: extensions,
        })
    )
);

impl TryFrom<&Vec<u8>> for AuthenticatorData {
    type Error = WebauthnError;
    fn try_from(auth_data_bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        authenticator_data_parser(auth_data_bytes.as_slice())
            .map_err(|_| WebauthnError::ParseNOMFailure)
            .map(|(_, ad)| ad)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttestationObjectInner<'a> {
    pub(crate) auth_data: &'a [u8],
    pub(crate) fmt: String,
    pub(crate) att_stmt: serde_cbor::Value,
}

#[derive(Debug)]
pub(crate) struct AttestationObject {
    pub(crate) auth_data: AuthenticatorData,
    pub(crate) auth_data_bytes: Vec<u8>,
    pub(crate) fmt: String,
    // https://w3c.github.io/webauthn/#generating-an-attestation-object
    pub(crate) att_stmt: serde_cbor::Value,
}

impl TryFrom<&[u8]> for AttestationObject {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<AttestationObject, WebauthnError> {
        let aoi: AttestationObjectInner =
            serde_cbor::from_slice(&data).map_err(|e| WebauthnError::ParseCBORFailure(e))?;
        let auth_data_bytes: Vec<u8> = aoi.auth_data.iter().map(|b| *b).collect();

        let auth_data = AuthenticatorData::try_from(&auth_data_bytes)?;

        // Yay! Now we can assemble a reasonably sane structure.
        Ok(AttestationObject {
            fmt: aoi.fmt.clone(),
            auth_data,
            auth_data_bytes,
            att_stmt: aoi.att_stmt.clone(),
        })
    }
}

/// https://w3c.github.io/webauthn/#authenticatorattestationresponse
#[derive(Debug, Deserialize)]
pub struct AuthenticatorAttestationResponseRaw {
    /// https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
    #[serde(rename = "attestationObject")]
    pub attestation_object: Base64UrlSafeData,

    /// https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
}

pub(crate) struct AuthenticatorAttestationResponse {
    pub(crate) attestation_object: AttestationObject,
    pub(crate) client_data_json: CollectedClientData,
    pub(crate) client_data_json_bytes: Vec<u8>,
}

impl TryFrom<&AuthenticatorAttestationResponseRaw> for AuthenticatorAttestationResponse {
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAttestationResponseRaw) -> Result<Self, Self::Error> {
        let ccdj = CollectedClientData::try_from(aarr.client_data_json.as_ref())?;
        let ao = AttestationObject::try_from(aarr.attestation_object.as_ref())?;

        Ok(AuthenticatorAttestationResponse {
            attestation_object: ao,
            client_data_json: ccdj,
            client_data_json_bytes: aarr.client_data_json.clone().into(),
        })
    }
}

/// A client response to a registration challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by registration to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
/// https://w3c.github.io/webauthn/#iface-pkcredential
#[derive(Debug, Deserialize)]
pub struct RegisterPublicKeyCredential {
    pub(crate) id: String,

    #[serde(rename = "rawId")]
    pub(crate) raw_id: Base64UrlSafeData,

    /// https://w3c.github.io/webauthn/#dom-publickeycredential-response
    pub response: AuthenticatorAttestationResponseRaw,

    #[serde(rename = "type")]
    pub(crate) type_: String,
}

#[derive(Debug)]
pub(crate) struct AuthenticatorAssertionResponse {
    pub(crate) authenticator_data: AuthenticatorData,
    pub(crate) authenticator_data_bytes: Vec<u8>,
    pub(crate) client_data: CollectedClientData,
    pub(crate) client_data_bytes: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) user_handle: Option<Vec<u8>>,
}

impl TryFrom<&AuthenticatorAssertionResponseRaw> for AuthenticatorAssertionResponse {
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAssertionResponseRaw) -> Result<Self, Self::Error> {
        Ok(AuthenticatorAssertionResponse {
            authenticator_data: AuthenticatorData::try_from(aarr.authenticator_data.as_ref())?,
            authenticator_data_bytes: aarr.authenticator_data.clone().into(),
            client_data: CollectedClientData::try_from(aarr.client_data_json.as_ref())?,
            client_data_bytes: aarr.client_data_json.clone().into(),
            signature: aarr.signature.clone().into(),
            user_handle: aarr.user_handle.clone().map(|uh| uh.into()),
        })
    }
}

// https://w3c.github.io/webauthn/#authenticatorassertionresponse
#[derive(Debug, Deserialize)]
pub(crate) struct AuthenticatorAssertionResponseRaw {
    #[serde(rename = "authenticatorData")]
    pub(crate) authenticator_data: Base64UrlSafeData,

    #[serde(rename = "clientDataJSON")]
    pub(crate) client_data_json: Base64UrlSafeData,

    pub(crate) signature: Base64UrlSafeData,

    #[serde(rename = "userHandle")]
    pub(crate) user_handle: Option<Base64UrlSafeData>,
}

/// A client response to an authentication challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by authentication to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
#[derive(Debug, Deserialize)]
pub struct PublicKeyCredential {
    pub(crate) id: String,
    #[serde(rename = "rawId")]
    pub(crate) raw_id: Base64UrlSafeData,
    pub(crate) response: AuthenticatorAssertionResponseRaw,
    #[serde(rename = "type")]
    pub(crate) type_: String,
}

#[cfg(test)]
mod tests {
    use super::{AttestationObject, RegisterPublicKeyCredential};
    use serde_json;
    use std::convert::TryFrom;

    #[test]
    fn deserialise_register_response() {
        let x = r#"
        {   "id":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw",
            "rawId":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw",
            "response":{
                "attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU-CNhi_5_oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ-aF5-lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp_wStyvOkTd4NlWHW8rQ",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwZENXRDJWamRMSVkzN2VSYTVfazdhS3BqdkF2VmNOY04ycVozMjk0blpVIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
            },
            "type":"public-key"
        }
        "#;
        let _y: RegisterPublicKeyCredential = serde_json::from_str(x).unwrap();
    }

    #[test]
    fn deserialise_AttestationObject() {
        let raw_ao = base64::decode(
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQCgxaVISCxE+DrcxP5/+aPM88CTI+04J+o61SK6mnepjGZYv062AbtydzWmbAxF00VSAyp0ImP94uoy+0y7w9yilAQIDJiABIVggGT9woA+UoX+jBxuiHQpdkm0kCVh75WTj3TXl4zLJuzoiWCBKiCneKgWJgWiwrZedNwl06GTaXyaGrYS4bPbBraInyg=="
        ).unwrap();

        let _ao = AttestationObject::try_from(raw_ao.as_slice()).unwrap();
    }
    // Add tests for when the objects are too short.
}
