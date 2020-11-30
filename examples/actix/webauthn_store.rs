use std::collections::BTreeMap;

use webauthn_rs::{AuthenticationState, RegistrationState, proto::{Credential, CredentialID, UserId}};

pub trait WebauthnChallengeStore<ChallengeState> {
    fn add(&mut self, user_id: &UserId, state: ChallengeState);
    fn pop(&mut self, user_id: &UserId) -> Option<ChallengeState>;
}

pub trait WebauthnCredentialStore {
    fn add_creds(&mut self, user_id: &UserId, credential_id: CredentialID, credential: Credential);
    fn for_user(&self, user_id: &UserId) -> Option<Vec<Credential>>;
    fn set_counter(&mut self, user_id: &UserId, cred_id: CredentialID, counter: u32);
}

pub struct MemCredentialStore {
    credentials: BTreeMap<UserId, BTreeMap<CredentialID, Credential>>,
}

impl MemCredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: BTreeMap::new(),
        }
    }
}

impl WebauthnCredentialStore for MemCredentialStore {
    fn add_creds(&mut self, user_id: &UserId, credential_id: CredentialID, credential: Credential) {
        if !self.credentials.contains_key(user_id) {
            self.credentials.insert(user_id.clone(), BTreeMap::new());
        }

        // TODO: Do good error handling, don't be as lazy as me
        let user_credential_store = self.credentials.get_mut(user_id).unwrap();
        user_credential_store.insert(credential_id, credential);
    }

    fn for_user(&self, user_id: &UserId) -> Option<Vec<Credential>> {
        match self.credentials.get(user_id) {
            Some(creds) => Some(creds.iter().map(|(_, v)| v.clone()).collect()),
            None => None,
        }
    }

    fn set_counter(&mut self, user_id: &UserId, cred_id: CredentialID, counter: u32) {
        // TODO: Do good error handling, don't be as lazy as me
        let user_tree = self.credentials.get_mut(user_id).unwrap();
        let mut c = user_tree.remove(&cred_id).unwrap();
        c.counter = counter;
        user_tree.insert(cred_id, c);
    }
}

pub struct RegisterChallengeStore {
    challenges: BTreeMap<UserId, RegistrationState>,
}

impl RegisterChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: BTreeMap::new(),
        }
    }
}

impl WebauthnChallengeStore<RegistrationState> for RegisterChallengeStore {
    fn add(&mut self, user_id: &UserId, state: RegistrationState) {
        self.challenges.insert(user_id.clone(), state);
    }

    fn pop(&mut self, user_id: &UserId) -> Option<RegistrationState> {
        match self.challenges.get(user_id) {
            Some(state) => Some(state.to_owned()),
            None => None,
        }
    }
}

pub struct AuthChallengeStore {
    challenges: BTreeMap<UserId, AuthenticationState>,
}

impl AuthChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: BTreeMap::new(),
        }
    }
}

impl WebauthnChallengeStore<AuthenticationState> for AuthChallengeStore {
    fn add(&mut self, user_id: &UserId, state: AuthenticationState) {
        self.challenges.insert(user_id.clone(), state);
    }

    fn pop(&mut self, user_id: &UserId) -> Option<AuthenticationState> {
        match self.challenges.get(user_id) {
            Some(state) => Some(state.to_owned()),
            None => None,
        }
    }
}
