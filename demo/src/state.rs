use concread::CowCell;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct UserAccount {
    pub created: OffsetDateTime,
    pub passkeys: Vec<Passkey>,
}

impl UserAccount {
    pub fn new(passkey: Passkey) -> Self {
        Self {
            created: OffsetDateTime::now_utc(),
            passkeys: vec![passkey],
        }
    }
}

#[derive(Clone, Default)]
pub struct UserData {
    pub name_to_id: BTreeMap<String, Uuid>,
    pub accounts: BTreeMap<Uuid, UserAccount>,
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

    // TODO: memory management; removing excessive entries.
}
