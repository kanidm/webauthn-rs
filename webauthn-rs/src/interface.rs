use serde::{Deserialize, Serialize};

use webauthn_rs_core::interface::{AttestationCaList, AuthenticationState, RegistrationState};
use webauthn_rs_core::proto::Credential;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: Option<AttestationCaList>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKey {
    pub(crate) cred: Credential,
}

// PasswordlessKey

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordlessKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: Option<AttestationCaList>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordlessKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordlessKey {
    pub(crate) cred: Credential,
}
