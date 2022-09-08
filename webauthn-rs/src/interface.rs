//! Types that are expected to be serialised in applications using [crate::Webauthn]

use serde::{Deserialize, Serialize};

use webauthn_rs_core::interface::{
    AttestationCaList, AuthenticationResult, AuthenticationState, RegistrationState,
};
use webauthn_rs_core::proto::{COSEAlgorithm, Credential, CredentialID, ParsedAttestation};

/// An in progress registration session for a [Passkey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
pub struct PasskeyRegistration {
    pub(crate) rs: RegistrationState,
}

/// An in progress authentication session for a [Passkey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
pub struct PasskeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A Passkey for a user.
///
/// These can be safely serialised and deserialised from a database for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub(crate) cred: Credential,
}

impl Passkey {
    /// Retrieve a reference to this Pass Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Retrieve the type of cryptographic algorithm used by this key
    pub fn cred_algorithm(&self) -> &COSEAlgorithm {
        &self.cred.cred.type_
    }

    /// Post authentication, update this credentials properties.
    ///
    /// To determine if this is required, you can inspect the result of
    /// `authentication_result.needs_update()`. Counter intuitively, most passkeys
    /// will never need their properties updated! This is because passkeys lack an
    /// internal device activation counter (due to their synchronisation), and the
    /// backup-state flags are rarely if ever changed.
    ///
    /// If the credential_id does not match, None is returned.
    /// If the cred id matches and the credential is updated, Some(true) is returned.
    /// If the cred id matches, but the credential is not changed, Some(false) is returned.
    pub fn update_credential(&mut self, res: &AuthenticationResult) -> Option<bool> {
        if res.cred_id() == self.cred_id() {
            let mut changed = false;
            if res.counter() > self.cred.counter {
                self.cred.counter = res.counter();
                changed = true;
            }

            if res.backup_state() != self.cred.backup_state {
                self.cred.backup_state = res.backup_state();
                changed = true;
            }

            if res.backup_eligible() != self.cred.backup_eligible {
                // MUST be false -> true
                assert!(!self.cred.backup_eligible);
                assert!(res.backup_eligible());
                self.cred.backup_eligible = res.backup_eligible();
                changed = true;
            }

            Some(changed)
        } else {
            None
        }
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Passkey> for Credential {
    fn from(pk: Passkey) -> Self {
        pk.cred
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Credential> for Passkey {
    /// Convert a generic webauthn credential into a Passkey
    fn from(cred: Credential) -> Self {
        Passkey { cred }
    }
}

impl PartialEq for Passkey {
    fn eq(&self, other: &Self) -> bool {
        self.cred.cred_id == other.cred.cred_id
    }
}

// PasswordlessKey

/// An in progress registration session for a [PasswordlessKey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[cfg(feature = "preview-features")]
pub struct PasswordlessKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: AttestationCaList,
}

/// An in progress authentication session for a [PasswordlessKey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[cfg(feature = "preview-features")]
pub struct PasswordlessKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A passwordless key for a user
///
/// These can be safely serialised and deserialised from a database for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "preview-features")]
pub struct PasswordlessKey {
    pub(crate) cred: Credential,
}

#[cfg(feature = "preview-features")]
impl PasswordlessKey {
    /// Retrieve a reference to this Passwordless Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Retrieve the type of cryptographic algorithm used by this key
    pub fn cred_algorithm(&self) -> &COSEAlgorithm {
        &self.cred.cred.type_
    }

    /// Retrieve a reference to the attestation used during this [`Credential`]'s
    /// registration. This can tell you information about the manufacterer and
    /// what type of credential it is.
    pub fn attestation(&self) -> &ParsedAttestation {
        &self.cred.attestation
    }

    /// Post authentication, update this credentials properties.
    ///
    /// To determine if this is required, you can inspect the result of
    /// `authentication_result.needs_update()`. Generally this will always
    /// be true as this class of key will maintain an activation counter which
    /// allows (limited) protection against device cloning.
    ///
    /// If the credential_id does not match, None is returned. If the cred id matches
    /// and the credential is updated, Some(true) is returned. If the cred id
    /// matches, but the credential is not changed, Some(false) is returned.
    pub fn update_credential(&mut self, res: &AuthenticationResult) -> Option<bool> {
        if res.cred_id() == self.cred_id() {
            let mut changed = false;
            if res.counter() > self.cred.counter {
                self.cred.counter = res.counter();
                changed = true;
            }

            if res.backup_state() != self.cred.backup_state {
                self.cred.backup_state = res.backup_state();
                changed = true;
            }

            Some(changed)
        } else {
            None
        }
    }
}

#[cfg(feature = "danger-credential-internals")]
#[cfg(feature = "preview-features")]
impl From<PasswordlessKey> for Credential {
    fn from(pk: PasswordlessKey) -> Self {
        pk.cred
    }
}

#[cfg(feature = "danger-credential-internals")]
#[cfg(feature = "preview-features")]
impl From<Credential> for PasswordlessKey {
    /// Convert a generic webauthn credential into a Passkey
    fn from(cred: Credential) -> Self {
        PasswordlessKey { cred }
    }
}

/// An in progress registration session for a [SecurityKey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
pub struct SecurityKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: Option<AttestationCaList>,
}

/// An in progress authentication session for a [SecurityKey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
pub struct SecurityKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A Security Key for a user.
///
/// These can be safely serialised and deserialised from a database for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityKey {
    pub(crate) cred: Credential,
}

impl SecurityKey {
    /// Retrieve a reference to this Security Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Retrieve the type of cryptographic algorithm used by this key
    pub fn cred_algorithm(&self) -> &COSEAlgorithm {
        &self.cred.cred.type_
    }

    /// Retrieve a reference to the attestation used during this [`Credential`]'s
    /// registration. This can tell you information about the manufacterer and
    /// what type of credential it is.
    pub fn attestation(&self) -> &ParsedAttestation {
        &self.cred.attestation
    }

    /// Post authentication, update this credentials properties.
    ///
    /// To determine if this is required, you can inspect the result of
    /// `authentication_result.needs_update()`. Generally this will always
    /// be true as this class of key will maintain an activation counter which
    /// allows (limited) protection against device cloning.
    ///
    /// If the credential_id does not match, None is returned. If the cred id matches
    /// and the credential is updated, Some(true) is returned. If the cred id
    /// matches, but the credential is not changed, Some(false) is returned.
    pub fn update_credential(&mut self, res: &AuthenticationResult) -> Option<bool> {
        if res.cred_id() == self.cred_id() {
            let mut changed = false;
            if res.counter() > self.cred.counter {
                self.cred.counter = res.counter();
                changed = true;
            }

            if res.backup_state() != self.cred.backup_state {
                self.cred.backup_state = res.backup_state();
                changed = true;
            }

            Some(changed)
        } else {
            None
        }
    }
}

impl PartialEq for SecurityKey {
    fn eq(&self, other: &Self) -> bool {
        self.cred.cred_id == other.cred.cred_id
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<SecurityKey> for Credential {
    fn from(sk: SecurityKey) -> Self {
        sk.cred
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Credential> for SecurityKey {
    /// Convert a generic webauthn credential into a security key
    fn from(cred: Credential) -> Self {
        SecurityKey { cred }
    }
}

/// An in progress registration session for a [DeviceKey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[cfg(feature = "resident-key-support")]
pub struct DeviceKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: AttestationCaList,
}

/// An in progress authentication session for a [DeviceKey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[cfg(feature = "resident-key-support")]
pub struct DeviceKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A device key belonging to a user
///
/// These can be safely serialised and deserialised from a database for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "resident-key-support")]
pub struct DeviceKey {
    pub(crate) cred: Credential,
}

#[cfg(feature = "resident-key-support")]
impl DeviceKey {
    /// Retrieve a reference to this Resident Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Retrieve the type of cryptographic algorithm used by this key
    pub fn cred_algorithm(&self) -> &COSEAlgorithm {
        &self.cred.cred.type_
    }

    /// Retrieve a reference to the attestation used during this [`Credential`]'s
    /// registration. This can tell you information about the manufacterer and
    /// what type of credential it is.
    pub fn attestation(&self) -> &ParsedAttestation {
        &self.cred.attestation
    }

    /// Post authentication, update this credentials properties.
    ///
    /// To determine if this is required, you can inspect the result of
    /// `authentication_result.needs_update()`. Generally this will always
    /// be true as this class of key will maintain an activation counter which
    /// allows (limited) protection against device cloning.
    ///
    /// If the credential_id does not match, None is returned. If the cred id matches
    /// and the credential is updated, Some(true) is returned. If the cred id
    /// matches, but the credential is not changed, Some(false) is returned.
    pub fn update_credential(&mut self, res: &AuthenticationResult) -> Option<bool> {
        if res.cred_id() == self.cred_id() {
            let mut changed = false;
            if res.counter() > self.cred.counter {
                self.cred.counter = res.counter();
                changed = true;
            }

            if res.backup_state() != self.cred.backup_state {
                self.cred.backup_state = res.backup_state();
                changed = true;
            }

            Some(changed)
        } else {
            None
        }
    }
}

#[cfg(feature = "resident-key-support")]
impl PartialEq for DeviceKey {
    fn eq(&self, other: &Self) -> bool {
        self.cred.cred_id == other.cred.cred_id
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<DeviceKey> for Credential {
    fn from(dk: DeviceKey) -> Self {
        dk.cred
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Credential> for DeviceKey {
    /// Convert a generic webauthn credential into a security key
    fn from(cred: Credential) -> Self {
        DeviceKey { cred }
    }
}

/// An in progress authentication session for a [DiscoverableKey]. [Passkey] and [DeviceKey]
/// can be used with these workflows.
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly weaken the
/// security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to achieve this
/// see the [crate#allow-serialising-registration-and-authentication-state] level documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[cfg(feature = "preview-features")]
pub struct DiscoverableAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// A key that can be used in discoverable workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "preview-features")]
pub struct DiscoverableKey {
    pub(crate) cred: Credential,
}

#[cfg(feature = "preview-features")]
impl From<&DeviceKey> for DiscoverableKey {
    fn from(k: &DeviceKey) -> Self {
        DiscoverableKey {
            cred: k.cred.clone(),
        }
    }
}

#[cfg(feature = "preview-features")]
impl From<&Passkey> for DiscoverableKey {
    fn from(k: &Passkey) -> Self {
        DiscoverableKey {
            cred: k.cred.clone(),
        }
    }
}
