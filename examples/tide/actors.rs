use webauthn_rs::error::WebauthnError;
use webauthn_rs::proto::{
    CreationChallengeResponse, Credential, CredentialID, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, UserId, UserVerificationPolicy,
};
use webauthn_rs::{
    ephemeral::WebauthnEphemeralConfig,
    proto::{RequestAuthenticationExtensions, RequestRegistrationExtensions},
};
use webauthn_rs::{AuthenticationState, RegistrationState, Webauthn};

use async_std::sync::Mutex;
use lru::LruCache;
use std::collections::BTreeMap;

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

        let exts = RequestRegistrationExtensions::builder()
            .cred_blob(vec![0xde, 0xad, 0xbe, 0xef])
            .build();

        let (ccr, rs) = self.wan.generate_challenge_register_options(
            username.as_bytes().to_vec(),
            username.to_string(),
            username.to_string(),
            None,
            Some(UserVerificationPolicy::Discouraged),
            Some(exts),
        )?;
        // .generate_challenge_register(&username, Some(UserVerificationPolicy::Discouraged))?;
        self.reg_chals.lock().await.put(username.into_bytes(), rs);
        tide::log::debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok(ccr)
    }

    pub async fn challenge_authenticate(
        &self,
        username: &String,
    ) -> WebauthnResult<RequestChallengeResponse> {
        tide::log::debug!("handle ChallengeAuthenticate -> {:?}", username);

        let creds = match self.creds.lock().await.get(&username.as_bytes().to_vec()) {
            Some(creds) => Some(creds.iter().map(|(_, v)| v.clone()).collect()),
            None => None,
        }
        .ok_or(WebauthnError::CredentialRetrievalError)?;

        let exts = RequestAuthenticationExtensions::builder()
            .get_cred_blob(true)
            .build();

        // let (acr, st) = self.wan.generate_challenge_authenticate(creds)?;
        let (acr, st) = self
            .wan
            .generate_challenge_authenticate_options(creds, Some(exts))?;
        self.auth_chals
            .lock()
            .await
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
            .await
            .pop(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        let mut creds = self.creds.lock().await;
        let r = match creds.get_mut(&username) {
            Some(ucreds) => self
                .wan
                .register_credential(reg, &rs, |cred_id| Ok(ucreds.contains_key(cred_id)))
                .map(|cred| {
                    let cred_id = cred.0.cred_id.clone();
                    ucreds.insert(cred_id, cred.0);
                }),
            None => {
                let r = self
                    .wan
                    .register_credential(reg, &rs, |_| Ok(false))
                    .map(|cred| {
                        let mut t = BTreeMap::new();
                        let credential_id = cred.0.cred_id.clone();
                        t.insert(credential_id, cred.0);
                        creds.insert(username, t);
                    });
                tide::log::debug!("{:?}", self.creds);
                r
            }
        };
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
            .await
            .pop(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;

        let mut creds = self.creds.lock().await;
        let r = self
            .wan
            .authenticate_credential(lgn, &st)
            .map(|(cred_id, auth_data)| {
                let _ = match creds.get_mut(&username) {
                    Some(v) => {
                        let mut c = v.remove(cred_id).unwrap();
                        c.counter = auth_data.counter;
                        v.insert(cred_id.clone(), c);
                        Ok(())
                    }
                    None => {
                        // Invalid state but not end of world ...
                        Err(())
                    }
                };
                ()
            });
        tide::log::debug!("complete Authenticate -> {:?}", r);
        r
    }
}
