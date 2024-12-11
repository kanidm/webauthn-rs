use std::ops::{Deref, DerefMut};

use crate::{transport::Token, ui::UiCallback};

use super::{
    commands::GetInfoResponse, ctap21_bio::BiometricAuthenticatorInfo,
    ctap21_cred::CredentialManagementAuthenticatorInfo, internal::CtapAuthenticatorVersion,
    Ctap20Authenticator,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use super::commands::{PrototypeBioEnrollmentRequest, PrototypeCredentialManagementRequest};

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

impl<T: Token, U: UiCallback> DerefMut for Ctap21PreAuthenticator<'_, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.authenticator
    }
}

impl<'a, T: Token, U: UiCallback> CtapAuthenticatorVersion<'a, T, U>
    for Ctap21PreAuthenticator<'a, T, U>
{
    const VERSION: &'static str = "FIDO_2_1_PRE";
    fn new_with_info(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self {
        Self {
            authenticator: Ctap20Authenticator::new_with_info(info, token, ui_callback),
        }
    }
}

impl<T: Token, U: UiCallback> BiometricAuthenticatorInfo<U> for Ctap21PreAuthenticator<'_, T, U> {
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    type RequestType = PrototypeBioEnrollmentRequest;

    #[inline]
    fn biometrics(&self) -> Option<bool> {
        self.info.ctap21pre_biometrics()
    }
}

impl<T: Token, U: UiCallback> CredentialManagementAuthenticatorInfo<U>
    for Ctap21PreAuthenticator<'_, T, U>
{
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    type RequestType = PrototypeCredentialManagementRequest;

    #[inline]
    fn supports_credential_management(&self) -> bool {
        self.info.ctap21pre_credential_management()
    }
}
