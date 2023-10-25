use async_trait::async_trait;
use uuid::Uuid;

use crate::prelude::WebauthnCError;

use super::AnyToken;

#[cfg(all(feature = "usb", feature = "vendor-solokey"))]
pub const CMD_UUID: u8 = super::TYPE_INIT | 0x62;

#[async_trait]
pub trait SoloKeyToken {
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError>;
}

#[async_trait]
impl SoloKeyToken for AnyToken {
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
