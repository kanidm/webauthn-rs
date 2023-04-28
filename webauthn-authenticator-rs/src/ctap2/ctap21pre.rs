use std::ops::{Deref, DerefMut};

use crate::{transport::Token, ui::UiCallback};

use super::{
    commands::GetInfoResponse, ctap21_bio::BiometricAuthenticatorInfo, Ctap20Authenticator,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use super::commands::PrototypeBioEnrollmentRequest;

/// CTAP 2.1-PRE protocol implementation.
///
/// This contains only CTAP 2.1-PRE-specific functionality. All CTAP 2.0
/// functionality is avaliable via a [Deref] to [Ctap20Authenticator].
#[derive(Debug)]
pub struct Ctap21PreAuthenticator<'a, T: Token, U: UiCallback> {
    authenticator: Ctap20Authenticator<'a, T, U>,
}

/// For backwards compatibility, pretend to be a
/// [CTAP 2.0 authenticator][Ctap20Authenticator].
impl<'a, T: Token, U: UiCallback> Deref for Ctap21PreAuthenticator<'a, T, U> {
    type Target = Ctap20Authenticator<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        &self.authenticator
    }
}

impl<'a, T: Token, U: UiCallback> DerefMut for Ctap21PreAuthenticator<'a, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.authenticator
    }
}

impl<'a, T: Token, U: UiCallback> Ctap21PreAuthenticator<'a, T, U> {
    pub(super) fn new(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self {
        Self {
            authenticator: Ctap20Authenticator::new(info, token, ui_callback),
        }
    }
}

impl<'a, T: Token, U: UiCallback> BiometricAuthenticatorInfo<U>
    for Ctap21PreAuthenticator<'a, T, U>
{
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    type RequestType = PrototypeBioEnrollmentRequest;

    #[inline]
    fn biometrics(&self) -> Option<bool> {
        self.info.ctap21pre_biometrics()
    }
}
