use super::proto::*;
use rand::prelude::*;
use std::collections::BTreeMap;

// Can this ever change?
const CHALLENGE_SIZE_BYTES: usize = 32;

type UserId = String;

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
    rp: String,
    pkcp: Vec<PubKeyCredParams>,
    ac: Vec<AllowCredentials>,
}

impl Webauthn {
    pub fn new(rp: String) -> Self {
        Webauthn {
            rng: StdRng::from_entropy(),
            chals: BTreeMap::new(),
            rp: rp,
            pkcp: Vec::new(),
            ac: Vec::new(),
        }
    }

    pub fn generate_challenge(&mut self, username: String) -> ChallengeResponse {
        let chal = Challenge(
            (0..CHALLENGE_SIZE_BYTES)
                .map(|_| self.rng.gen())
                .collect::<Vec<u8>>(),
        );

        println!("Challenge for {} -> {:?}", username, chal);

        let c = ChallengeResponse::new(
            chal.to_string(),
            self.rp.clone(),
            username.clone(),
            username.clone(),
            username.clone(),
            self.pkcp.clone(),
            self.ac.clone(),
        );
        self.chals.insert(username, chal);
        c
    }
}
