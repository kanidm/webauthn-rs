use concread::CowCell;
use std::collections::BTreeMap;
use webauthn_rs::prelude::*;

#[derive(Clone, Default)]
pub struct UserData {
    pub name_to_id: BTreeMap<String, Uuid>,
    pub passkeys: BTreeMap<Uuid, Vec<Passkey>>,
    pub registrations: BTreeMap<Uuid, PasskeyRegistration>,
}

pub struct DemoState {
    pub webauthn: Webauthn,
    pub users: CowCell<UserData>,
}

impl DemoState {
    pub fn new(webauthn: Webauthn) -> Self {
        Self {
            webauthn,
            users: Default::default(),
        }
    }
}
