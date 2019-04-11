// Implementations of the Webauthn protocol structures
// that can be json encoded and used by other
// applications.

// These are the three primary communication structures you will
// need to handle.
#![allow(non_snake_case)]

#[derive(Debug, Serialize, Deserialize)]
struct RelayingParty {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    displayName: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    type_: String,
    alg: i16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    type_: String,
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicKey {
    challenge: String,
    rp: RelayingParty,
    user: User,
    pubKeyCredParams: Vec<PubKeyCredParams>,
    allowCredentials: Vec<AllowCredentials>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsResponse {
    attestationObject: String,
    clientDataJSON: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    id: String,
    rawId: String,
    response: CredentialsResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {}

#[cfg(test)]
mod tests {
    use super::RegisterResponse;
    use serde_json;

    #[test]
    fn deserialise() {
        let x = r#"
        {"id":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw","rawId":"4oiUggKcrpRIlB+cFzFbfkx/BNeM7UAnz3wO7ZpT4I2GL/n+g8TICyJTHg11l0wyc+VkQUVnJ0yM08+1D5oXnw==","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU+CNhi/5/oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ+aF5+lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp/wStyvOkTd4NlWHW8rQ==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwZENXRDJWamRMSVkzN2VSYTVfazdhS3BqdkF2VmNOY04ycVozMjk0blpVIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"},"type":"public-key"}
        "#;
        let y: RegisterResponse = serde_json::from_str(x).unwrap();
    }
}
