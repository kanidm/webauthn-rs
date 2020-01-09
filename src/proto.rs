#![allow(non_snake_case)]

//! JSON Protocol Structs and representations for communication with authenticators
//! and clients.

use std::collections::BTreeMap;
use std::convert::TryFrom;

use crate::crypto;
use crate::error::*;

/// Representation of a UserId. This is currently a type alias to "String".
pub type UserId = String;

/// A challenge issued by the server. This contains a set of random bytes
/// which should always be kept private. This type can be serialised or
/// deserialised by serde as required for your storage needs.
#[derive(Clone, Serialize, Deserialize)]
pub struct Challenge(pub Vec<u8>);

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            base64::encode_mode(&self.0, base64::Base64Mode::Standard)
        )
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            base64::encode_mode(&self.0, base64::Base64Mode::Standard)
        )
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
            counter: counter,
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
pub enum UserVerificationPolicy {
    /// Require User Verification bit to be set, and fail the registration or authentication
    /// if false. If the authenticator is not able to perform verification, it may not be
    /// usable with this policy.
    Required,
    /// Prefer User Verification bit to be set, and yolo the registration or authentication
    /// if false. This means if the authenticator can perform verification, do it, but don't
    /// mind if not.
    Preferred,
    /// Request that no verification is performed, and fail if it is. This is intended to
    /// minimise user interaction in workflows, but is potentially a security risk to use.
    Discouraged,
}

impl ToString for UserVerificationPolicy {
    fn to_string(&self) -> String {
        match self {
            UserVerificationPolicy::Required => "required".to_string(),
            UserVerificationPolicy::Preferred => "preferred".to_string(),
            UserVerificationPolicy::Discouraged => "discouraged".to_string(),
        }
    }
}

// These are the primary communication structures you will need to handle.

pub(crate) type CBORExtensions = serde_cbor::Value;
pub(crate) type JSONExtensions = BTreeMap<String, String>;

#[derive(Debug, Serialize)]
struct RelayingParty {
    name: String,
}

#[derive(Debug, Serialize)]
struct User {
    id: String,
    name: String,
    displayName: String,
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
}

#[derive(Debug, Serialize)]
struct PublicKeyCredentialCreationOptions {
    // https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
    rp: RelayingParty,
    user: User,
    // Should this just be bytes?
    challenge: String,
    pubKeyCredParams: Vec<PubKeyCredParams>,
    timeout: u32,
    attestation: String,
    // excludeCredentials
    // authenticatorSelection
    // See get_extensions for typing details here.
    // I suspect it's actually a map in json.
    extensions: Option<JSONExtensions>,
    userVerification: String,
}

/// A JSON serialisable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize)]
pub struct CreationChallengeResponse {
    publicKey: PublicKeyCredentialCreationOptions,
}

impl CreationChallengeResponse {
    pub(crate) fn new(
        relaying_party: String,
        user_id: String,
        user_name: String,
        user_display_name: String,
        challenge: String,
        pkcp: Vec<PubKeyCredParams>,
        timeout: u32,
        userVerificationPolicy: UserVerificationPolicy,
    ) -> CreationChallengeResponse {
        CreationChallengeResponse {
            publicKey: PublicKeyCredentialCreationOptions {
                rp: RelayingParty {
                    name: relaying_party,
                },
                user: User {
                    id: user_id,
                    name: user_name,
                    displayName: user_display_name,
                },
                challenge: challenge,
                pubKeyCredParams: pkcp,
                timeout: timeout,
                attestation: "direct".to_string(),
                extensions: None,
                userVerification: userVerificationPolicy.to_string(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct PublicKeyCredentialRequestOptions {
    challenge: String,
    timeout: u32,
    rpId: String,
    allowCredentials: Vec<AllowCredentials>,
    userVerification: String,
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
        challenge: String,
        timeout: u32,
        relaying_party: String,
        allowCredentials: Vec<AllowCredentials>,
        userVerificationPolicy: UserVerificationPolicy,
    ) -> Self {
        RequestChallengeResponse {
            publicKey: PublicKeyCredentialRequestOptions {
                challenge: challenge,
                timeout: timeout,
                rpId: relaying_party,
                allowCredentials: allowCredentials,
                userVerification: userVerificationPolicy.to_string(),
                extensions: None,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct CollectedClientData {
    pub(crate) type_: String,
    pub(crate) challenge: Vec<u8>,
    pub(crate) origin: String,
    pub(crate) tokenBinding: Option<TokenBinding>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CollectedClientDataRaw {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
    pub tokenBinding: Option<TokenBinding>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TokenBinding {
    pub status: String,
    pub id:Option<String>
}

// Should this be tryfrom
impl TryFrom<&Vec<u8>> for CollectedClientData {
    type Error = WebauthnError;
    fn try_from(data: &Vec<u8>) -> Result<CollectedClientData, WebauthnError> {
        let ccdr: CollectedClientDataRaw =
            serde_json::from_slice(&data).map_err(|e| WebauthnError::ParseJSONFailure(e))?;

        let chal_vec: Vec<u8> = base64::decode_mode(&ccdr.challenge, base64::Base64Mode::Standard)
            .or(base64::decode_mode(
                &ccdr.challenge,
                base64::Base64Mode::UrlSafe,
            ))
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;

        Ok(CollectedClientData {
            type_: ccdr.type_.clone(),
            challenge: chal_vec,
            origin: ccdr.origin.clone(),
            tokenBinding: ccdr.tokenBinding.clone(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct AttestedCredentialData {
    pub(crate) aaguid: Vec<u8>,
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
    fn try_from(authDataBytes: &Vec<u8>) -> Result<Self, Self::Error> {
        authenticator_data_parser(authDataBytes.as_slice())
            .map_err(|_| WebauthnError::ParseNOMFailure)
            .map(|(_, ad)| ad)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AttestationObjectInner<'a> {
    pub(crate) authData: &'a [u8],
    pub(crate) fmt: String,
    pub(crate) attStmt: serde_cbor::Value,
}

#[derive(Debug)]
pub(crate) struct AttestationObject {
    pub(crate) authData: AuthenticatorData,
    pub(crate) authDataBytes: Vec<u8>,
    pub(crate) fmt: String,
    // https://w3c.github.io/webauthn/#generating-an-attestation-object
    pub(crate) attStmt: serde_cbor::Value,
}

impl TryFrom<&String> for AttestationObject {
    type Error = WebauthnError;

    fn try_from(data: &String) -> Result<AttestationObject, WebauthnError> {
        // println!("data: {:?}", data);
        let attest_data_vec: Vec<u8> = base64::decode_mode(&data, base64::Base64Mode::Standard)
            .or(base64::decode_mode(&data, base64::Base64Mode::UrlSafe))
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;

        // println!("attest_data_vec: {:?}", attest_data_vec);
        let aoi: AttestationObjectInner = serde_cbor::from_slice(&attest_data_vec)
            .map_err(|e| WebauthnError::ParseCBORFailure(e))?;
        let authDataBytes: Vec<u8> = aoi.authData.iter().map(|b| *b).collect();

        let authData = AuthenticatorData::try_from(&authDataBytes)?;

        // Yay! Now we can assemble a reasonably sane structure.
        Ok(AttestationObject {
            fmt: aoi.fmt.clone(),
            authData: authData,
            authDataBytes: authDataBytes,
            attStmt: aoi.attStmt.clone(),
        })
    }
}

// https://w3c.github.io/webauthn/#authenticatorattestationresponse
#[derive(Debug, Deserialize)]
pub(crate) struct AuthenticatorAttestationResponseRaw {
    pub(crate) attestationObject: String,
    pub(crate) clientDataJSON: String,
}

pub(crate) struct AuthenticatorAttestationResponse {
    pub(crate) attestation_object: AttestationObject,
    pub(crate) client_data_json: CollectedClientData,
    pub(crate) client_data_json_bytes: Vec<u8>,
}

impl TryFrom<&AuthenticatorAttestationResponseRaw> for AuthenticatorAttestationResponse {
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAttestationResponseRaw) -> Result<Self, Self::Error> {
        let ccdjr = base64::decode(aarr.clientDataJSON.as_str())
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;

        let ccdj = CollectedClientData::try_from(&ccdjr)?;
        let ao = AttestationObject::try_from(&aarr.attestationObject)?;

        Ok(AuthenticatorAttestationResponse {
            attestation_object: ao,
            client_data_json: ccdj,
            client_data_json_bytes: ccdjr,
        })
    }
}

/// A client response to a registration challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by registration to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
#[derive(Debug, Deserialize)]
pub struct RegisterPublicKeyCredential {
    // See standard PublicKeyCredential and Credential
    // https://w3c.github.io/webauthn/#iface-pkcredential
    id: String,
    rawId: String,
    pub(crate) response: AuthenticatorAttestationResponseRaw,
    #[serde(rename = "type")]
    type_: String,
    // discovery
    // identifier
    // clientExtensionsResults
}

#[derive(Debug)]
pub(crate) struct AuthenticatorAssertionResponse {
    pub(crate) authenticatorData: AuthenticatorData,
    // I think we need this for sig?
    pub(crate) authenticatorDataBytes: Vec<u8>,
    pub(crate) clientDataJSON: CollectedClientData,
    pub(crate) clientDataJSONBytes: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) userHandle: Option<String>,
}

impl TryFrom<&AuthenticatorAssertionResponseRaw> for AuthenticatorAssertionResponse {
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAssertionResponseRaw) -> Result<Self, Self::Error> {
        let ccdjr = base64::decode(aarr.clientDataJSON.as_str())
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;
        let adr = base64::decode(aarr.authenticatorData.as_str())
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;
        let sigr = base64::decode(aarr.signature.as_str())
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;

        // Do we need to deconstruct this first?

        Ok(AuthenticatorAssertionResponse {
            authenticatorData: AuthenticatorData::try_from(&adr)?,
            authenticatorDataBytes: adr,
            clientDataJSON: CollectedClientData::try_from(&ccdjr)?,
            clientDataJSONBytes: ccdjr,
            signature: sigr,
            userHandle: aarr.userHandle.clone(),
        })
    }
}

// https://w3c.github.io/webauthn/#authenticatorassertionresponse
#[derive(Debug, Deserialize)]
pub(crate) struct AuthenticatorAssertionResponseRaw {
    authenticatorData: String,
    clientDataJSON: String,
    signature: String,
    userHandle: Option<String>,
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
    // Why can't we parse this?
    //
    // pub rawId: &'a [u8],
    pub(crate) rawId: String,
    pub(crate) response: AuthenticatorAssertionResponseRaw,
    #[serde(rename = "type")]
    pub(crate) type_: String,
    pub(crate) discovery: Option<String>,
    pub(crate) identifier: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{AttestationObject, RegisterPublicKeyCredential};
    use serde_json;
    use std::convert::TryFrom;

    #[test]
    fn deserialise_register_response() {
        let x = r#"
        {"id":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw","rawId":"4oiUggKcrpRIlB+cFzFbfkx/BNeM7UAnz3wO7ZpT4I2GL/n+g8TICyJTHg11l0wyc+VkQUVnJ0yM08+1D5oXnw==","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU+CNhi/5/oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ+aF5+lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp/wStyvOkTd4NlWHW8rQ==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwZENXRDJWamRMSVkzN2VSYTVfazdhS3BqdkF2VmNOY04ycVozMjk0blpVIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"},"type":"public-key"}
        "#;
        let _y: RegisterPublicKeyCredential = serde_json::from_str(x).unwrap();
    }

    #[test]
    fn deserialise_AttestationObject() {
        let raw_ao = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQCgxaVISCxE+DrcxP5/+aPM88CTI+04J+o61SK6mnepjGZYv062AbtydzWmbAxF00VSAyp0ImP94uoy+0y7w9yilAQIDJiABIVggGT9woA+UoX+jBxuiHQpdkm0kCVh75WTj3TXl4zLJuzoiWCBKiCneKgWJgWiwrZedNwl06GTaXyaGrYS4bPbBraInyg==".to_string();

        let _ao = AttestationObject::try_from(&raw_ao).unwrap();
        // println!("{:?}", ao);
    }
    // Add tests for when the objects are too short.
}
