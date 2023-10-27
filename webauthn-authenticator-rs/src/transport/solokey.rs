//! SoloKey (Trussed) vendor-specific commands.
//!
//! ## USB HID
//!
//! Commands are sent on a `U2FHIDFrame` level, and values are bitwise-OR'd
//! with `transport::TYPE_INIT` (0x80).
//!
//! Command | Description | Request | Response
//! ------- | ----------- | ------- | --------
//! `0x51`  | Update      | _none_ to reboot into update mode, `01` to be "destructive" | _none_
//! `0x53`  | Reboot      | _none_  | _none_
//! `0x60`  | Get random bytes | _none_ | 57 bytes of randomness
//! `0x61`  | Get version | _none_  | Version ID as `u32`
//! `0x62`  | Get device UUID | _none_ | Big-endian UUID (16 bytes)
//! `0x63`  | Get lock state | _none_ | `0` for unlocked "hacker edition" devices, `1` if locked
//!
//! ## NFC
//!
//! Admin app AID: `A0 00 00 08 47 00 00 00 01`
//!
//! ## References
//!
//! * [`solo2-cli` Admin commands][0]
//! * [SoloKeys `admin-app` commands][1]
//!
//! [0]: https://github.com/solokeys/solo2-cli/blob/main/src/apps/admin.rs
//! [1]: https://github.com/solokeys/admin-app/blob/main/src/admin.rs
use async_trait::async_trait;
use uuid::Uuid;

use crate::prelude::WebauthnCError;

use super::AnyToken;

#[cfg(all(feature = "usb", feature = "vendor-solokey"))]
pub(crate) const CMD_RANDOM: u8 = super::TYPE_INIT | 0x60;

#[cfg(all(feature = "usb", feature = "vendor-solokey"))]
pub(crate) const CMD_VERSION: u8 = super::TYPE_INIT | 0x61;

#[cfg(all(feature = "usb", feature = "vendor-solokey"))]
pub(crate) const CMD_UUID: u8 = super::TYPE_INIT | 0x62;

#[cfg(all(feature = "usb", feature = "vendor-solokey"))]
pub(crate) const CMD_LOCK: u8 = super::TYPE_INIT | 0x63;

/// See [`SoloKeyAuthenticator`](crate::ctap2::SoloKeyAuthenticator).
#[async_trait]
pub trait SoloKeyToken {
    /// See [`SoloKeyAuthenticator::get_solokey_lock()`](crate::ctap2::SoloKeyAuthenticator::get_solokey_lock).
    async fn get_solokey_lock(&mut self) -> Result<bool, WebauthnCError>;

    /// See [`SoloKeyAuthenticator::get_solokey_random()`](crate::ctap2::SoloKeyAuthenticator::get_solokey_random).
    async fn get_solokey_random(&mut self) -> Result<[u8; 57], WebauthnCError>;

    /// See [`SoloKeyAuthenticator::get_solokey_version()`](crate::ctap2::SoloKeyAuthenticator::get_solokey_version).
    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError>;

    /// See [`SoloKeyAuthenticator::get_solokey_uuid()`](crate::ctap2::SoloKeyAuthenticator::get_solokey_uuid).
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError>;
}

#[async_trait]
#[allow(clippy::unimplemented)]
impl SoloKeyToken for AnyToken {
    async fn get_solokey_lock(&mut self) -> Result<bool, WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_solokey_lock().await,
        }
    }

    async fn get_solokey_random(&mut self) -> Result<[u8; 57], WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_solokey_random().await,
        }
    }

    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_solokey_version().await,
        }
    }

    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_solokey_uuid().await,
        }
    }
}
