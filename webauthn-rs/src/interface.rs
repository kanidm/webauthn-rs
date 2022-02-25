use serde::{Deserialize, Serialize};

use webauthn_rs_core::interface::RegistrationState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationCa {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationCaList {
    cas: Vec<AttestationCa>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: Option<AttestationCaList>,
}

// SecurityKey

// PasswordlessKey
