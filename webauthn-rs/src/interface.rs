//! Types that are expected to be serialised in applications using [crate::Webauthn]

use serde::{Deserialize, Serialize};

use webauthn_rs_core::interface::{AttestationCaList, AuthenticationState, RegistrationState};
use webauthn_rs_core::proto::{Credential, CredentialID};

/// An in progress registration session for a [SecurityKey].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: Option<AttestationCaList>,
}

/// An in progress authentication session for a [SecurityKey].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A Security Key for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKey {
    pub(crate) cred: Credential,
}

impl SecurityKey {
    /// Retrieve a reference to this Security Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Post authentication, update this credentials counter.
    pub fn update_credential_counter(&mut self, counter: u32) {
        self.cred.counter = counter
    }
}

// PasswordlessKey

/// An in progress registration session for a [PasswordlessKey].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordlessKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: Option<AttestationCaList>,
}

/// An in progress registration session for a [PasswordlessKey].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordlessKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A passwordless key for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordlessKey {
    pub(crate) cred: Credential,
}

impl PasswordlessKey {
    /// Retrieve a reference to this Passwordless Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Post authentication, update this credentials counter.
    pub fn update_credential_counter(&mut self, counter: u32) {
        self.cred.counter = counter
    }
}
