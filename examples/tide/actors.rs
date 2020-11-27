use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::error::WebauthnError;
use webauthn_rs::proto::{
    CreationChallengeResponse, Credential, CredentialID, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, UserId, UserVerificationPolicy,
};
use webauthn_rs::{AuthenticationState, RegistrationState, Webauthn};

use lru::LruCache;
use std::collections::BTreeMap;
use std::sync::Mutex;

type WebauthnResult<T> = core::result::Result<T, WebauthnError>;

const CHALLENGE_CACHE_SIZE: usize = 256;

pub struct WebauthnActor {
    wan: Webauthn<WebauthnEphemeralConfig>,
    reg_chals: Mutex<LruCache<UserId, RegistrationState>>,
    auth_chals: Mutex<LruCache<UserId, AuthenticationState>>,
    creds: Mutex<BTreeMap<UserId, BTreeMap<CredentialID, Credential>>>,
}

impl WebauthnActor {
    pub fn new(config: WebauthnEphemeralConfig) -> Self {
        WebauthnActor {
            wan: Webauthn::new(config),
            reg_chals: Mutex::new(LruCache::new(CHALLENGE_CACHE_SIZE)),
            auth_chals: Mutex::new(LruCache::new(CHALLENGE_CACHE_SIZE)),
            creds: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn challenge_register(
        &self,
        username: String,
    ) -> WebauthnResult<CreationChallengeResponse> {
        tide::log::debug!("handle ChallengeRegister -> {:?}", username);
        let (ccr, rs) = self
            .wan
            .generate_challenge_register(&username, Some(UserVerificationPolicy::Required))?;
        self.reg_chals
            .lock()
            .unwrap()
            .put(username.into_bytes(), rs);
        tide::log::debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok(ccr)
    }

    pub async fn challenge_authenticate(
        &self,
        username: &String,
    ) -> WebauthnResult<RequestChallengeResponse> {
        tide::log::debug!("handle ChallengeAuthenticate -> {:?}", username);

        let creds = match self
            .creds
            .lock()
            .unwrap()
            .get(&username.as_bytes().to_vec())
        {
            Some(creds) => Some(creds.iter().map(|(_, v)| v.clone()).collect()),
            None => None,
        }
        .ok_or(WebauthnError::CredentialRetrievalError)?;

        let (acr, st) = self.wan.generate_challenge_authenticate(creds)?;
        self.auth_chals
            .lock()
            .unwrap()
            .put(username.as_bytes().to_vec(), st);
        tide::log::debug!("complete ChallengeAuthenticate -> {:?}", acr);
        Ok(acr)
    }

    pub async fn register(
        &self,
        username: &String,
        reg: &RegisterPublicKeyCredential,
    ) -> WebauthnResult<()> {
        tide::log::debug!(
            "handle Register -> (username: {:?}, reg: {:?})",
            username,
            reg
        );

        let username = username.as_bytes().to_vec();

        let rs = self
            .reg_chals
            .lock()
            .unwrap()
            .pop(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        let r = self
            .wan
            .register_credential(reg, rs, |cred_id| {
                match self.creds.lock().unwrap().get_mut(&username) {
                    Some(ucreds) => Ok(ucreds.contains_key(cred_id)),
                    None => Ok(false),
                }
            })
            .map(|cred| {
                let mut creds = self.creds.lock().unwrap();
                match creds.get_mut(&username) {
                    Some(v) => {
                        let cred_id = cred.cred_id.clone();
                        v.insert(cred_id, cred);
                    }
                    None => {
                        let mut t = BTreeMap::new();
                        let credential_id = cred.cred_id.clone();
                        t.insert(credential_id, cred);
                        creds.insert(username, t);
                    }
                };
                tide::log::debug!("{:?}", self.creds);
                ()
            });
        tide::log::debug!("complete Register -> {:?}", r);
        r
    }

    pub async fn authenticate(
        &self,
        username: &String,
        lgn: &PublicKeyCredential,
    ) -> WebauthnResult<()> {
        tide::log::debug!(
            "handle Authenticate -> (username: {:?}, lgn: {:?})",
            username,
            lgn
        );

        let username = username.as_bytes().to_vec();

        let st = self
            .auth_chals
            .lock()
            .unwrap()
            .pop(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        let r = self.wan.authenticate_credential(lgn, st).map(|r| {
            r.map(|(cred_id, counter)| {
                match self.creds.lock().unwrap().get_mut(&username) {
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
        });
        tide::log::debug!("complete Authenticate -> {:?}", r);
        r
    }
}
