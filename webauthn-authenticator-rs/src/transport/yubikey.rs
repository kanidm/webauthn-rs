//! YubiKey vendor-specific commands.
//!
//! ## USB HID
//!
//! Commands are sent on a `U2FHIDFrame` level, and values are bitwise-OR'd
//! with `transport::TYPE_INIT` (0x80).
//!
//! Command | Description | Request | Response
//! ------- | ----------- | ------- | --------
//!
//! ## NFC
//!
//! ## References
//!
use async_trait::async_trait;

use crate::prelude::WebauthnCError;

use super::AnyToken;

#[cfg(all(feature = "usb", feature = "vendor-yubikey"))]
pub(crate) const CMD_GET_CONFIG: u8 = super::TYPE_INIT | 0x42;

/// See [`YubiKeyAuthenticator`](crate::ctap2::YubiKeyAuthenticator).
#[async_trait]
pub trait YubiKeyToken {
    /// See [`SoloKeyAuthenticator::get_solokey_lock()`](crate::ctap2::SoloKeyAuthenticator::get_solokey_lock).
    async fn get_yubikey_config(&mut self) -> Result<bool, WebauthnCError>;
}

#[async_trait]
#[allow(clippy::unimplemented)]
impl YubiKeyToken for AnyToken {
    async fn get_yubikey_config(&mut self) -> Result<bool, WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_yubikey_config().await,
        }
    }
}
