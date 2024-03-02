use async_trait::async_trait;

#[cfg(all(feature = "usb", feature = "vendor-yubikey"))]
use crate::transport::yubikey::CMD_GET_CONFIG;

use crate::{
    prelude::WebauthnCError,
    transport::{
        types::{U2FError, U2FHID_ERROR},
        yubikey::{YubiKeyConfig, YubiKeyToken},
    },
    usb::{framing::U2FHIDFrame, USBToken},
};

#[async_trait]
impl YubiKeyToken for USBToken {
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: CMD_GET_CONFIG,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await?;

        let r = self.recv_one().await?;
        match r.cmd {
            CMD_GET_CONFIG => YubiKeyConfig::from_bytes(r.data.as_slice()),
            U2FHID_ERROR => Err(U2FError::from(r.data.as_slice()).into()),
            _ => Err(WebauthnCError::UnexpectedState),
        }
    }
}
