use actix::prelude::*;
use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::error::WebauthnError;
use webauthn_rs::proto::{
    CreationChallengeResponse, Credential, CredentialID, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, UserId,
};
use webauthn_rs::{AuthenticationState, RegistrationState, Webauthn};

use lru::LruCache;
use std::collections::BTreeMap;

const CHALLENGE_CACHE_SIZE: usize = 256;

pub struct WebauthnActor {
    wan: Webauthn<WebauthnEphemeralConfig>,
    reg_chals: LruCache<UserId, RegistrationState>,
    auth_chals: LruCache<UserId, AuthenticationState>,
    creds: BTreeMap<UserId, BTreeMap<CredentialID, Credential>>,
}

impl Actor for WebauthnActor {
    type Context = Context<Self>;
}

impl WebauthnActor {
    pub fn new(config: WebauthnEphemeralConfig) -> Self {
        WebauthnActor {
            wan: Webauthn::new(config),
            reg_chals: LruCache::new(CHALLENGE_CACHE_SIZE),
            auth_chals: LruCache::new(CHALLENGE_CACHE_SIZE),
            creds: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct ChallengeRegister {
    pub username: String,
}

impl Message for ChallengeRegister {
    type Result = Result<CreationChallengeResponse, WebauthnError>;
}

impl Handler<ChallengeRegister> for WebauthnActor {
    type Result = Result<CreationChallengeResponse, WebauthnError>;

    fn handle(&mut self, msg: ChallengeRegister, _: &mut Self::Context) -> Self::Result {
        debug!("handle ChallengeRegister -> {:?}", msg);
        let (ccr, rs) = self.wan.generate_challenge_register(&msg.username, None)?;
        self.reg_chals.put(msg.username, rs);
        Ok(ccr)
    }
}

#[derive(Debug)]
pub struct ChallengeAuthenticate {
    pub username: String,
}

impl Message for ChallengeAuthenticate {
    type Result = Result<RequestChallengeResponse, WebauthnError>;
}

impl Handler<ChallengeAuthenticate> for WebauthnActor {
    type Result = Result<RequestChallengeResponse, WebauthnError>;

    fn handle(&mut self, msg: ChallengeAuthenticate, _: &mut Self::Context) -> Self::Result {
        debug!("handle ChallengeAuthenticate -> {:?}", msg);

        let creds = match self.creds.get(&msg.username) {
            Some(creds) => Some(creds.iter().map(|(_, v)| v.clone()).collect()),
            None => None,
        }
        .ok_or(WebauthnError::CredentialRetrievalError)?;

        let (acr, st) = self
            .wan
            .generate_challenge_authenticate(&msg.username, creds, None)?;
        self.auth_chals.put(msg.username, st);
        Ok(acr)
    }
}

#[derive(Debug)]
pub struct Register {
    pub username: String,
    pub reg: RegisterPublicKeyCredential,
}

impl Message for Register {
    type Result = Result<(), WebauthnError>;
}

impl Handler<Register> for WebauthnActor {
    type Result = Result<(), WebauthnError>;

    fn handle(&mut self, msg: Register, _: &mut Self::Context) -> Self::Result {
        debug!("handle Register -> {:?}", msg);

        let Register { username, reg } = msg;

        let rs = self
            .reg_chals
            .pop(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        self.wan
            .register_credential(reg, rs, |cred_id| match self.creds.get(&username) {
                Some(ucreds) => Ok(ucreds.contains_key(cred_id)),
                None => Ok(false),
            })
            .map(|cred| {
                match self.creds.get_mut(&username) {
                    Some(v) => {
                        let cred_id = cred.cred_id.clone();
                        v.insert(cred_id, cred);
                    }
                    None => {
                        let mut t = BTreeMap::new();
                        let credential_id = cred.cred_id.clone();
                        t.insert(credential_id, cred);
                        self.creds.insert(username, t);
                    }
                };
                ()
            })
    }
}

#[derive(Debug)]
pub struct Authenticate {
    pub username: String,
    pub lgn: PublicKeyCredential,
}

impl Message for Authenticate {
    type Result = Result<(), WebauthnError>;
}

impl Handler<Authenticate> for WebauthnActor {
    type Result = Result<(), WebauthnError>;

    fn handle(&mut self, msg: Authenticate, _: &mut Self::Context) -> Self::Result {
        debug!("handle Authenticate -> {:?}", msg);
        let Authenticate { lgn, username } = msg;
        let st = self
            .auth_chals
            .pop(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        self.wan.authenticate_credential(lgn, st).map(|r| {
            r.map(|(cred_id, counter)| {
                match self.creds.get_mut(&username) {
                    Some(v) => {
                        let mut c = v.remove(&cred_id).unwrap();
                        c.counter = counter;
                        v.insert(cred_id.clone(), c);
                        Ok(())
                    }
                    None => {
                        // Invalid state but not end of world ...
                        Err(())
                    }
                }
            });
            ()
        })
    }
}
