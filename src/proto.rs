#![allow(non_snake_case)]
// Implementations of the Webauthn protocol structures
// that can be json encoded and used by other
// applications.

use byteorder::{BigEndian, ByteOrder};
use std::collections::BTreeMap;
use std::convert::TryFrom;

use super::error::*;

// These are the three primary communication structures you will
// need to handle.

pub type CredentialID = Vec<u8>;
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
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    // Should this be a diff size?
    pub(crate) alg: i64,
}

#[derive(Debug, Serialize, Clone)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    pub(crate) id: String,
}

// https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
#[derive(Debug, Serialize)]
struct PublicKeyCredentialCreationOptions {
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
}

#[derive(Debug, Serialize)]
pub struct CreationChallengeResponse {
    publicKey: PublicKeyCredentialCreationOptions,
}

impl CreationChallengeResponse {
    pub fn new(
        relaying_party: String,
        user_id: String,
        user_name: String,
        user_display_name: String,
        challenge: String,
        pkcp: Vec<PubKeyCredParams>,
        timeout: u32,
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
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialRequestOptions {
    challenge: String,
    timeout: u32,
    rpId: String,
    allowCredentials: Vec<AllowCredentials>,
    userVerification: String,
    extensions: Option<JSONExtensions>,
}

#[derive(Debug, Serialize)]
pub struct RequestChallengeResponse {
    publicKey: PublicKeyCredentialRequestOptions,
}

impl RequestChallengeResponse {
    pub fn new(
        challenge: String,
        timeout: u32,
        relaying_party: String,
        allowCredentials: Vec<AllowCredentials>,
        userVerification: Option<String>,
    ) -> Self {
        RequestChallengeResponse {
            publicKey: PublicKeyCredentialRequestOptions {
                challenge: challenge,
                timeout: timeout,
                rpId: relaying_party,
                allowCredentials: allowCredentials,
                userVerification: match userVerification {
                    Some(s) => s,
                    None => "preferred".to_string(),
                },
                extensions: None,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct CollectedClientData {
    pub type_: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub tokenBinding: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CollectedClientDataRaw {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
    pub tokenBinding: Option<String>,
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
    pub aaguid: Vec<u8>,
    pub credential_id: CredentialID,
    pub credential_pk: serde_cbor::Value,
}

// https://w3c.github.io/webauthn/#sctn-attestation
#[derive(Debug)]
pub(crate) struct AuthenticatorData {
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
    pub user_present: bool,
    pub user_verified: bool,
    pub extensions: Option<CBORExtensions>,
    pub acd: Option<AttestedCredentialData>,
}

impl TryFrom<&Vec<u8>> for AuthenticatorData {
    type Error = WebauthnError;
    fn try_from(authDataBytes: &Vec<u8>) -> Result<Self, Self::Error> {
        println!("data: {:?}", authDataBytes);
        if authDataBytes.len() < 37 {
            return Err(WebauthnError::ParseInsufficentBytesAvailable);
        }

        // Now from the aoi, create the other structs.
        let rp_id_hash: Vec<u8> = authDataBytes[0..32].into();
        let flags: u8 = authDataBytes[32];
        // From RFC:
        // flags:   [ Exten | Auth | 0 | 0 | 0 | UVer | 0 | UPres ]
        //        7                                                 0
        let user_present = (flags & (1 << 0)) != 0;
        let user_verified = (flags & (1 << 2)) != 0;
        let acd_present = (flags & (1 << 6)) != 0;
        let extensions_present = (flags & (1 << 7)) != 0;
        let counter: u32 = BigEndian::read_u32(&authDataBytes[33..37]);

        // Get all remaining bytes. This is both the acd and extensions.
        //
        let acd_extension_bytes: Vec<u8> = authDataBytes[37..].into();

        let (exten_offset, acd) = if acd_present {
            // TODO: Harden this to be sure we have enough bytes!!!
            let aaguid: Vec<u8> = acd_extension_bytes[0..16].into();
            let cred_id_len: usize = BigEndian::read_u16(&acd_extension_bytes[16..18]) as usize;
            // Now this tells us how much to read from for the credential ID.

            let cred_id_end = 18 + cred_id_len;
            let cred_id: Vec<u8> = acd_extension_bytes[18..cred_id_end].into();

            // let cred_pk: Vec<u8> = acd_extension_bytes[cred_id_end..].into();
            let cred_pk: serde_cbor::Value =
                serde_cbor::from_slice(&acd_extension_bytes[cred_id_end..])
                    .map_err(|e| WebauthnError::ParseCBORFailure(e))?;

            // Now re-encode it to find the length ... yuk.
            let encoded =
                serde_cbor::to_vec(&cred_pk).map_err(|e| WebauthnError::ParseCBORFailure(e))?;
            // Finally we know the cred len
            let cred_len = encoded.len();

            // Now to get the extension offset we have:
            // [ aaguid   | id len | cred_id     | cred_pk     ][ extensions             ]
            //    0 -> 15   16, 17   18 + id_len   cred_id_end    cred_len + cred_id_end
            let exten_offset = cred_len + cred_id_end;

            (
                exten_offset,
                Some(AttestedCredentialData {
                    aaguid: aaguid,
                    credential_id: cred_id,
                    credential_pk: cred_pk,
                }),
            )
        } else {
            (0, None)
        };

        // TODO: Harden this to be sure we have enough bytes!!!
        let extensions: Option<serde_cbor::Value> = if acd_present && extensions_present {
            Some(
                serde_cbor::from_slice(&acd_extension_bytes[exten_offset..])
                    .map_err(|e| WebauthnError::ParseCBORFailure(e))?,
            )
        } else {
            None
        };

        Ok(AuthenticatorData {
            rp_id_hash: rp_id_hash,
            flags: flags,
            counter: counter,
            user_present: user_present,
            user_verified: user_verified,
            extensions: extensions,
            acd: acd,
        })
    }
}

#[derive(Debug, Deserialize)]
// pub(crate) struct AttestationObject<'a> {
pub struct AttestationObjectInner<'a> {
    pub authData: &'a [u8],
    pub fmt: String,
    pub attStmt: serde_cbor::Value,
}

#[derive(Debug)]
pub(crate) struct AttestationObject {
    pub authData: AuthenticatorData,
    pub authDataBytes: Vec<u8>,
    pub fmt: String,
    // https://w3c.github.io/webauthn/#generating-an-attestation-object
    pub attStmt: serde_cbor::Value,
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
pub struct AuthenticatorAttestationResponseRaw {
    pub attestationObject: String,
    pub clientDataJSON: String,
}

pub(crate) struct AuthenticatorAttestationResponse {
    pub attestation_object: AttestationObject,
    pub client_data_json: CollectedClientData,
    pub client_data_json_bytes: Vec<u8>,
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

// See standard PublicKeyCredential and Credential
// https://w3c.github.io/webauthn/#iface-pkcredential

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    id: String,
    rawId: String,
    pub response: AuthenticatorAttestationResponseRaw,
    #[serde(rename = "type")]
    type_: String,
    // discovery
    // identifier
    // clientExtensionsResults
}

#[derive(Debug)]
pub(crate) struct AuthenticatorAssertionResponse {
    pub authenticatorData: AuthenticatorData,
    // I think we need this for sig?
    pub authenticatorDataBytes: Vec<u8>,
    pub clientDataJSON: CollectedClientData,
    pub clientDataJSONBytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub userHandle: Option<String>,
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
pub struct AuthenticatorAssertionResponseRaw {
    authenticatorData: String,
    clientDataJSON: String,
    signature: String,
    userHandle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyCredential {
    pub id: String,
    // Why can't we parse this?
    //
    // pub rawId: &'a [u8],
    pub rawId: String,
    pub response: AuthenticatorAssertionResponseRaw,
    #[serde(rename = "type")]
    pub type_: String,
    pub discovery: Option<String>,
    pub identifier: Option<String>,
}

/*
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub publicKey: PublicKeyCredential,
}
*/

#[cfg(test)]
mod tests {
    use super::{AttestationObject, RegisterResponse};
    use serde_json;
    use std::convert::TryFrom;

    #[test]
    fn deserialise_register_response() {
        let x = r#"
        {"id":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw","rawId":"4oiUggKcrpRIlB+cFzFbfkx/BNeM7UAnz3wO7ZpT4I2GL/n+g8TICyJTHg11l0wyc+VkQUVnJ0yM08+1D5oXnw==","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU+CNhi/5/oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ+aF5+lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp/wStyvOkTd4NlWHW8rQ==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwZENXRDJWamRMSVkzN2VSYTVfazdhS3BqdkF2VmNOY04ycVozMjk0blpVIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"},"type":"public-key"}
        "#;
        let y: RegisterResponse = serde_json::from_str(x).unwrap();
    }

    #[test]
    fn deserialise_AttestationObject() {
        let raw_ao = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQCgxaVISCxE+DrcxP5/+aPM88CTI+04J+o61SK6mnepjGZYv062AbtydzWmbAxF00VSAyp0ImP94uoy+0y7w9yilAQIDJiABIVggGT9woA+UoX+jBxuiHQpdkm0kCVh75WTj3TXl4zLJuzoiWCBKiCneKgWJgWiwrZedNwl06GTaXyaGrYS4bPbBraInyg==".to_string();

        let ao = AttestationObject::try_from(&raw_ao).unwrap();
        println!("{:?}", ao);
    }
    // Add tests for when the objects are too short.
}
