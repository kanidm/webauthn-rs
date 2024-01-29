use async_trait::async_trait;

use crate::{
    prelude::WebauthnCError,
    transport::{
        yubikey::{YubiKeyConfig, YubiKeyToken},
        Token,
    },
    ui::UiCallback,
};

use super::Ctap20Authenticator;

/// YubiKey vendor-specific commands.
///
/// ## Warning
///
/// These commands currently operate on *any* [`Ctap20Authenticator`][], and do
/// not filter to just YubiKey devices. Due to the nature of CTAP
/// vendor-specific commands, this may cause unexpected or undesirable behaviour
/// on other vendors' keys.
///
/// Protocol notes are in [`crate::transport::yubikey`].
#[async_trait]
pub trait YubiKeyAuthenticator {
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError>;
}

#[async_trait]
impl<'a, T: Token + YubiKeyToken, U: UiCallback> YubiKeyAuthenticator
    for Ctap20Authenticator<'a, T, U>
{
    #[inline]
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError> {
        self.token.get_yubikey_config().await
    }
}
