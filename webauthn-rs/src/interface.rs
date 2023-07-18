//! Types that are expected to be serialised in applications using [crate::Webauthn]

use serde::{Deserialize, Serialize};

use webauthn_rs_core::interface::{
    AttestationCaList, AuthenticationResult, AuthenticationState, RegistrationState,
};
use webauthn_rs_core::proto::{
    COSEAlgorithm, COSEKey, Credential, CredentialID, ParsedAttestation,
};

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
#[allow(missing_docs)]
pub struct PasskeyRegistration {
    pub rs: RegistrationState,
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
#[allow(missing_docs)]
pub struct PasskeyAuthentication {
    pub ast: AuthenticationState,
}

/// A Passkey for a user. A passkey is a term that covers all possible authenticators that may exist.
/// These could be roaming credentials such as Apple's Account back passkeys, they could be a users
/// Yubikey, a Windows Hello TPM, or even a password manager softtoken.
///
/// Passkeys *may* opportunistically have some properties such as discoverability (residence). This
/// is not a guarantee since enforcing residence on devices like yubikeys that have limited storage
/// and no administration of resident keys may break the device.
///
/// These can be safely serialised and deserialised from a database for persistance.
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

    /// Retrieve a reference to this Passkey's credential public key.
    pub fn get_public_key(&self) -> &COSEKey {
        &self.cred.cred
    }

    /// Post authentication, update this credentials properties.
    ///
    /// To determine if this is required, you can inspect the result of
    /// `authentication_result.needs_update()`. Counter intuitively, most passkeys
    /// will never need their properties updated! This is because many passkeys lack an
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

// AttestedPasskey

/// An in progress registration session for a [AttestedPasskey].
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
pub struct AttestedPasskeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: AttestationCaList,
}

/// An in progress authentication session for a [AttestedPasskey].
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
pub struct AttestedPasskeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// An attested passkey for a user. This is a specialisation of [Passkey] as you can
/// limit the make and models of authenticators that a user may register. Additionally
/// these keys will always enforce userverification.
///
/// These can be safely serialised and deserialised from a database for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "preview-features")]
pub struct AttestedPasskey {
    pub(crate) cred: Credential,
}

#[cfg(feature = "preview-features")]
impl AttestedPasskey {
    /// Retrieve a reference to this AttestedPasskey Key's credential ID.
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

#[cfg(all(feature = "danger-credential-internals", feature = "preview-features"))]
impl From<AttestedPasskey> for Credential {
    fn from(pk: AttestedPasskey) -> Self {
        pk.cred
    }
}

#[cfg(all(feature = "danger-credential-internals", feature = "preview-features"))]
impl From<Credential> for AttestedPasskey {
    /// Convert a generic webauthn credential into a Passkey
    fn from(cred: Credential) -> Self {
        AttestedPasskey { cred }
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

/// A Security Key for a user. These are the legacy "second factor" method of security tokens.
///
/// You should avoid this type in favour of [Passkey] or [AttestedPasskey]
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

/// An in progress registration session for a [AttestedResidentKey].
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
pub struct AttestedResidentKeyRegistration {
    pub(crate) rs: RegistrationState,
    pub(crate) ca_list: AttestationCaList,
}

/// An in progress authentication session for a [AttestedResidentKey].
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
pub struct AttestedResidentKeyAuthentication {
    pub(crate) ast: AuthenticationState,
}

/// An attested resident key belonging to a user. These are a specialisation of [AttestedPasskey] where
/// the devices in use can be attested. In addition this type enforces keys to be resident on the
/// authenticator.
///
/// Since most authenticators have very limited key residence support, this should only be used in
/// tightly controlled enterprise environments where you have strict access over the makes and models
/// of keys in use.
///
/// Key residence is *not* a security property. The general reason for the usage of key residence is
/// to allow the device to identify the user in addition to authenticating them.
///
/// These can be safely serialised and deserialised from a database for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "resident-key-support")]
pub struct AttestedResidentKey {
    pub(crate) cred: Credential,
}

#[cfg(feature = "resident-key-support")]
impl AttestedResidentKey {
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
impl PartialEq for AttestedResidentKey {
    fn eq(&self, other: &Self) -> bool {
        self.cred.cred_id == other.cred.cred_id
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<AttestedResidentKey> for Credential {
    fn from(dk: AttestedResidentKey) -> Self {
        dk.cred
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Credential> for AttestedResidentKey {
    /// Convert a generic webauthn credential into a security key
    fn from(cred: Credential) -> Self {
        AttestedResidentKey { cred }
    }
}

/// An in progress authentication session for a [DiscoverableKey]. [Passkey] and [AttestedResidentKey]
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

/// A key that can be used in discoverable workflows. Within this library [Passkey]s may be
/// discoverable on an opportunistic bases, and [AttestedResidentKey]s will always be discoverable.
///
/// Generally this is used as part of conditional ui which allows autofill of discovered
/// credentials in username fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "preview-features")]
pub struct DiscoverableKey {
    pub(crate) cred: Credential,
}

#[cfg(feature = "preview-features")]
impl From<&AttestedResidentKey> for DiscoverableKey {
    fn from(k: &AttestedResidentKey) -> Self {
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
