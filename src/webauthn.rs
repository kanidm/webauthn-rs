use super::proto::*;
use rand::prelude::*;
use std::collections::BTreeMap;

// Can this ever change?
const CHALLENGE_SIZE_BYTES: usize = 32;


pub enum Algorithm {
    ALG_ECDSA_SHA256,
}

impl From<&Algorithm> for i16 {
    fn from(a: &Algorithm) -> i16 {
        match a {
            ALG_ECDSA_SHA256 => -7,
        }
    }
}

type UserId = String;
type CredID = String;

#[derive(Clone)]
struct Challenge(Vec<u8>);

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}


// We have to remember the challenges we issued, so keep a reference ...

pub struct Webauthn {
    rng: StdRng,
    chals: BTreeMap<UserId, Challenge>,
    creds: BTreeMap<UserId, Vec<CredID>>,
    rp: String,
    pkcp: Vec<PubKeyCredParams>,
}

impl Webauthn {
    pub fn new(rp: String, alg: Vec<Algorithm>) -> Self {
        Webauthn {
            rng: StdRng::from_entropy(),
            chals: BTreeMap::new(),
            creds: BTreeMap::new(),
            rp: rp,
            pkcp: alg.iter().map(|a| {
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: a.into(),
                }
            }).collect(),
        }
    }

    pub fn generate_challenge(
        &mut self,
        username: UserId,
    ) -> ChallengeResponse {
        let chal = Challenge(
            (0..CHALLENGE_SIZE_BYTES)
                .map(|_| self.rng.gen())
                .collect::<Vec<u8>>(),
        );

        // Get the user's existing creds if any.

        let uc = self.creds.get(username.as_str());
        let ac = match uc {
            Some(creds) => {
                creds.iter()
                .map(|cred_id| {
                    AllowCredentials {
                        type_: "public-key".to_string(),
                        id: cred_id.clone(),
                    }
                }).collect()
            }
            None => {
                Vec::new()
            }
        };

        println!("Challenge for {} -> {:?}", username, chal);
        println!("Creds for {} -> {:?}", username, ac);

        let c = ChallengeResponse::new(
            chal.to_string(),
            self.rp.clone(),
            username.clone(),
            username.clone(),
            username.clone(),
            self.pkcp.clone(),
            ac,
        );
        self.chals.insert(username, chal);
        c
    }

    pub fn register_credential(&mut self, reg: RegisterResponse) -> Option<()> {
        println!("{:?}", reg);

        // Decode the client data json
        let client_data = CollectedClientData::from(&reg.response.clientDataJSON);

        println!("{:?}", client_data);

        if client_data.type_ != "webauthn.create" {
            println!("Invalid client_data type");
            return None;
        }

        // assert the challenge is as we issued it.
        // assert the origin matches our origin.

        // get the attetstation object
        // cbor decode


        let attest_data = AttestationObject::from(&reg.response.attestationObject);
        println!("{:?}", attest_data);

        // Store the cred Id associated to the user.

        None
    }

    pub fn verify_credential(&self, lgn: LoginRequest) -> Option<()> {
        println!("{:?}", lgn);

        None
    }
}
