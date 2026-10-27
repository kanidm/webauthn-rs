#[cfg(feature = "attestation")]
use crate::interface::AttestedPasskey;
#[cfg(feature = "resident-key-support")]
use crate::interface::AttestedResidentKey;
#[cfg(feature = "conditional-ui")]
use crate::interface::DiscoverableKey;
use crate::interface::{Passkey, SecurityKey};
use webauthn_rs_core::proto::Credential;

/// Internal trait for things that accept a reference to [Credential].
///
/// We don't want to freely expose a wrapped [Credential], so we use this instead of [`AsRef`].
///
/// This trait is not to be implemented or used outside this crate. If you need to access a wrapped
/// [Credential] from outside of this crate, enable the `danger-credential-internals` feature.
pub trait CredentialRef {
    /// Get a reference to [Credential].
    fn credential(&self) -> &Credential;
}

impl CredentialRef for Credential {
    #[inline]
    fn credential(&self) -> &Credential {
        &self
    }
}

impl CredentialRef for &Credential {
    #[inline]
    fn credential(&self) -> &Credential {
        &self
    }
}

macro_rules! impl_credentialref {
    ($t: ty) => {
        impl crate::private::CredentialRef for &$t {
            #[inline]
            fn credential(&self) -> &Credential {
                &self.cred
            }
        }

        impl crate::private::CredentialRef for $t {
            #[inline]
            fn credential(&self) -> &Credential {
                &self.cred
            }
        }
    };
}

#[cfg(feature = "attestation")]
impl_credentialref!(AttestedPasskey);
#[cfg(feature = "resident-key-support")]
impl_credentialref!(AttestedResidentKey);
#[cfg(feature = "conditional-ui")]
impl_credentialref!(DiscoverableKey);
impl_credentialref!(Passkey);
impl_credentialref!(SecurityKey);
