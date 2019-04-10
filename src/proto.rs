// Implementations of the Webauthn protocol structures
// that can be json encoded and used by other
// applications.

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
    type_: String,
    alg: i16,
}

#[derive(Debug, Serialize, Clone)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    type_: String,
    id: String,
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

#[derive(Debug, Serialize)]
struct RegisterResponse {}

#[derive(Debug, Serialize)]
struct LoginRequest {}
