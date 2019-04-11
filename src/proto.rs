#![allow(non_snake_case)]
// Implementations of the Webauthn protocol structures
// that can be json encoded and used by other
// applications.

use byteorder::{BigEndian, ByteOrder};

// These are the three primary communication structures you will
// need to handle.

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
    pub(crate) alg: i16,
}

#[derive(Debug, Serialize, Clone)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    pub(crate) id: String,
}

#[derive(Debug, Serialize)]
struct PublicKey {
    challenge: String,
    rp: RelayingParty,
    user: User,
    pubKeyCredParams: Vec<PubKeyCredParams>,
    allowCredentials: Vec<AllowCredentials>,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    publicKey: PublicKey,
}

impl ChallengeResponse {
    pub fn new(
        challenge: String,
        relaying_party: String,
        user_id: String,
        user_name: String,
        user_display_name: String,
        pkcp: Vec<PubKeyCredParams>,
        ac: Vec<AllowCredentials>,
    ) -> ChallengeResponse {
        ChallengeResponse {
            publicKey: PublicKey {
                challenge: challenge,
                rp: RelayingParty {
                    name: relaying_party,
                },
                user: User {
                    id: user_id,
                    name: user_name,
                    displayName: user_display_name,
                },
                pubKeyCredParams: pkcp,
                allowCredentials: ac,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CollectedClientData {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
    // tokenBinding,
}

// Should this be tryfrom
impl From<&String> for CollectedClientData {
    fn from(data: &String) -> CollectedClientData {
        let client_data_vec: Vec<u8> = 
            base64::decode(data)
            .unwrap();

        serde_json::from_slice(&client_data_vec)
            .unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct Extensions {
}

#[derive(Debug)]
pub(crate) struct AttestedCredentialData {
    aaguid: Vec<u8>,
    credential_id: Vec<u8>,
    credential_pk: Vec<u8>,
}

// https://w3c.github.io/webauthn/#sctn-attestation
#[derive(Debug)]
pub(crate) struct AuthenticatorData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    counter: u32,
    user_present: bool,
    user_verified: bool,
    extensions: Option<Extensions>,
    acd: Option<AttestedCredentialData>,
}

#[derive(Debug, Deserialize)]
// pub(crate) struct AttestationObject<'a> {
pub struct AttestationObjectInner<'a> {
    pub fmt: String,
    pub authData: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct AttestationObject {
    pub fmt: String,
    pub authData: AuthenticatorData,
}

impl From<&String> for AttestationObject {
    fn from(data: &String) -> AttestationObject {
        let attest_data_vec: Vec<u8> =
            base64::decode(&data)
            .unwrap();
        let aoi: AttestationObjectInner = serde_cbor::from_slice(&attest_data_vec)
            .unwrap();

        // TODO: Actually length check everything !!!
        // Like holy shit, check it!!!

        // Now from the aoi, create the other structs.
        let rp_id_hash: Vec<u8> = aoi.authData[0..32].into();
        let flags: u8 = aoi.authData[32];
        // From RFC:
        // flags:   [ Exten | Auth | 0 | 0 | 0 | UVer | 0 | UPres ]
        //        7                                                 0
        let user_present = (flags & (1 << 0)) != 0;
        let user_verified = (flags & (1 << 2)) != 0;
        let acd_present = (flags & (1 << 6)) != 0;
        let extensions_present = (flags & (1 << 7)) != 0;
        let counter: u32 = BigEndian::read_u32(&aoi.authData[33..37]);

        // Get all remaining bytes.
        let acd_extension_bytes: Vec<u8> = aoi.authData[37..].into();

        let acd = if acd_present {
            let aaguid: Vec<u8> = acd_extension_bytes[0..16].into();
            let cred_id_len: usize = BigEndian::read_u16(&acd_extension_bytes[16..18]) as usize;
            // Now this tells us how much to read from for the credential ID.

            let cred_id_end = 18 + cred_id_len;
            let cred_id: Vec<u8> = acd_extension_bytes[18..cred_id_end].into();
            let cred_pk: Vec<u8> = acd_extension_bytes[cred_id_end..].into();

            Some(AttestedCredentialData {
                aaguid: aaguid,
                credential_id: cred_id,
                credential_pk: cred_pk,
            })
        } else {
            None
        };

        // For now there seems to be no clear way to determine the extsions (if) they exist.
        let extensions = None;

        // Yay! Now we can assemble a reasonably sane structure.
        AttestationObject {
            fmt: aoi.fmt.clone(),
            authData: AuthenticatorData {
                rp_id_hash: rp_id_hash,
                flags: flags,
                counter: counter,
                user_present: user_present,
                user_verified: user_verified,
                extensions: extensions,
                acd: acd
            }
        }
    }
}


// https://w3c.github.io/webauthn/#authenticatorattestationresponse
#[derive(Debug, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub attestationObject: String,
    pub clientDataJSON: String
}

// See standard PublicKeyCredential and Credential
// https://w3c.github.io/webauthn/#iface-pkcredential

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    id: String,
    rawId: String,
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    type_: String,
    // discovery
    // identifier
    // clientExtensionsResults
}

#[derive(Debug, Deserialize)]
pub struct AuthenticatorResponse {
    authenticatorData: String,
    clientDataJSON: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    response: AuthenticatorResponse,
}

#[cfg(test)]
mod tests {
    use super::{RegisterResponse, AttestationObject};
    use serde_json;

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


        let ao = AttestationObject::from(&raw_ao);
        println!("{:?}", ao);

    }

}
