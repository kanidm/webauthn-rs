//! An implementation of an Ephemeral (in-memory) webauthn configuration provider
//! This stores all challenges and credentials in memory - IE they are lost on
//! service restart. It's only really useful for demo-sites, testing and as an
//! example/reference implementation of the WebauthnConfig trait.
use lru::LruCache;
use std::collections::BTreeMap;

use crate::proto::{Challenge, Credential, CredentialID, UserId};
use crate::WebauthnConfig;

const CHALLENGE_CACHE_SIZE: usize = 256;

/// An implementation of an Ephemeral (in-memory) webauthn configuration provider
/// This stores all challenges and credentials in memory - IE they are lost on
/// service restart. It's only really useful for demo-sites, testing and as an
/// example/reference implementation of the WebauthnConfig trait.
pub struct WebauthnEphemeralConfig {
    chals: LruCache<UserId, Challenge>,
    creds: BTreeMap<UserId, BTreeMap<CredentialID, Credential>>,
    rp_name: String,
    rp_id: String,
    rp_origin: String,
}

impl std::fmt::Debug for WebauthnEphemeralConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "WebauthnEphemeralConfig{{ chals -> {{???}}, creds: {:?}, rp_name: {:?}, rp_id: {:?}, rp_origin: {:?} }}",
            self.creds, self.rp_name, self.rp_id, self.rp_origin)
    }
}

impl WebauthnConfig for WebauthnEphemeralConfig {
    /// Returns the relying party name. See the trait documentation for more.
    fn get_relying_party_name(&self) -> String {
        self.rp_name.clone()
    }

    /// Returns the relying party id. See the trait documentation for more.
    fn get_relying_party_id(&self) -> String {
        self.rp_id.clone()
    }

    /// Persist a challenge associated to a userId. See the trait documentation for more.
    fn persist_challenge(&mut self, userid: UserId, challenge: Challenge) -> Result<(), ()> {
        self.chals.put(userid, challenge);
        Ok(())
    }

    /// Retrieve a challenge associated to a userId. See the trait documentation for more.
    fn retrieve_challenge(&mut self, userid: &UserId) -> Option<Challenge> {
        self.chals.pop(userid)
    }

    /// Assert if a credential related to a userId exists. See the trait documentation for more.
    fn does_exist_credential(&self, userid: &UserId, cred: &Credential) -> Result<bool, ()> {
        match self.creds.get(userid) {
            Some(creds) => Ok(creds.contains_key(&cred.cred_id)),
            None => Ok(false),
        }
    }

    /// Persist a credential related to a userId. See the trait documentation for more.
    fn persist_credential(&mut self, userid: UserId, cred: Credential) -> Result<(), ()> {
        match self.creds.get_mut(&userid) {
            Some(v) => {
                let cred_id = cred.cred_id.clone();
                v.insert(cred_id, cred);
            }
            None => {
                let mut t = BTreeMap::new();
                let credential_id = cred.cred_id.clone();
                t.insert(credential_id, cred);
                self.creds.insert(userid, t);
            }
        };
        Ok(())
    }

    /// Update a credentials counter. See the trait documentation for more.
    fn credential_update_counter(
        &mut self,
        userid: &UserId,
        cred: &Credential,
        counter: u32,
    ) -> Result<(), ()> {
        match self.creds.get_mut(userid) {
            Some(v) => {
                let cred_id = cred.cred_id.clone();
                let _ = v.remove(&cred_id);
                let mut c = cred.clone();
                c.counter = counter;
                v.insert(cred_id, c);
                Ok(())
            }
            None => {
                // Invalid state but not end of world ...
                Err(())
            }
        }
    }

    /// Report an invalid credential counter. See the trait documentation for more.
    fn credential_report_invalid_counter(
        &mut self,
        userid: &UserId,
        cred: &Credential,
        _counter: u32,
    ) -> Result<(), ()> {
        match self.creds.get_mut(userid) {
            Some(v) => {
                v.remove(&cred.cred_id);
                Ok(())
            }
            None => {
                // Invalid state but not end of world ...
                Err(())
            }
        }
    }

    /// Retrieve the credentials associated to a userId. See the trait documentation for more.
    fn retrieve_credentials(&self, userid: &UserId) -> Option<Vec<&Credential>> {
        match self.creds.get(userid) {
            Some(creds) => {
                Some(creds.iter()
                    .map(|(_, v)| v)
                    .collect())
            }
            None => None,
        }
    }

    /// Retrieve the relying party origin. See the trait documentation for more.
    fn get_origin(&self) -> &String {
        &self.rp_origin
    }
}

impl WebauthnEphemeralConfig {
    /// Create a new Webauthn Ephemeral instance. This requires a provided relying party
    /// name, origin and id. See the trait documentation for more detail on relying party
    /// name, origin and id.
    pub fn new(rp_name: &str, rp_origin: &str, rp_id: &str) -> Self {
        WebauthnEphemeralConfig {
            chals: LruCache::new(CHALLENGE_CACHE_SIZE),
            creds: BTreeMap::new(),
            rp_name: rp_name.to_string(),
            rp_id: rp_id.to_string(),
            rp_origin: rp_origin.to_string(),
        }
    }
}
