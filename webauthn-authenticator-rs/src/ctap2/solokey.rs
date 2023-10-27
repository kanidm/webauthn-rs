use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    prelude::WebauthnCError, transport::solokey::SoloKeyToken, transport::Token, ui::UiCallback,
};

use super::Ctap20Authenticator;

/// SoloKey (Trussed) vendor-specific commands.
///
/// ## Warning
///
/// These commands currently operate on *any* [`Ctap20Authenticator`][], and do
/// not filter to just SoloKey/Trussed devices. Due to the nature of CTAP
/// vendor-specific commands, this may cause unexpected or undesirable behaviour
/// on other vendors' keys.
///
/// Protocol notes are in [`crate::transport::solokey`].
#[async_trait]
pub trait SoloKeyAuthenticator {
    /// Gets a SoloKey's lock (secure boot) status.
    async fn get_solokey_lock(&mut self) -> Result<bool, WebauthnCError>;

    /// Gets some random bytes from a SoloKey.
    async fn get_solokey_random(&mut self) -> Result<[u8; 57], WebauthnCError>;

    /// Gets a SoloKey's UUID.
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError>;

    /// Gets a SoloKey's firmware version.
    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError>;
}

#[async_trait]
impl<'a, T: Token + SoloKeyToken, U: UiCallback> SoloKeyAuthenticator
    for Ctap20Authenticator<'a, T, U>
{
    #[inline]
    async fn get_solokey_lock(&mut self) -> Result<bool, WebauthnCError> {
        self.token.get_solokey_lock().await
    }

    #[inline]
    async fn get_solokey_random(&mut self) -> Result<[u8; 57], WebauthnCError> {
        self.token.get_solokey_random().await
    }

    #[inline]
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError> {
        self.token.get_solokey_uuid().await
    }

    #[inline]
    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError> {
        self.token.get_solokey_version().await
    }
}
