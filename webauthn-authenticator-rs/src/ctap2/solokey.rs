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
    /// Gets the device-specific UUID of a SoloKey token.
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError>;

    /// Gets the version of a SoloKey token.
    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError>;
}

#[async_trait]
impl<'a, T: Token + SoloKeyToken, U: UiCallback> SoloKeyAuthenticator
    for Ctap20Authenticator<'a, T, U>
{
    #[inline]
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError> {
        self.token.get_solokey_uuid().await
    }

    #[inline]
    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError> {
        self.token.get_solokey_version().await
    }
}
