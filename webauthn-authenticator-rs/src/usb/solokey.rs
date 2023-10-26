use async_trait::async_trait;
use uuid::Uuid;

#[cfg(all(feature = "usb", feature = "vendor-solokey"))]
use crate::transport::solokey::{CMD_LOCK, CMD_RANDOM, CMD_UUID, CMD_VERSION};

use crate::{
    prelude::WebauthnCError,
    transport::{
        solokey::SoloKeyToken,
        types::{U2FError, U2FHID_ERROR},
    },
    usb::{framing::U2FHIDFrame, USBToken},
};

#[async_trait]
impl SoloKeyToken for USBToken {
    async fn get_solokey_lock(&mut self) -> Result<bool, WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: CMD_LOCK,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await?;

        let r = self.recv_one().await?;
        match r.cmd {
            CMD_LOCK => {
                if r.len != 1 || r.data.len() != 1 {
                    return Err(WebauthnCError::InvalidMessageLength);
                }

                Ok(r.data[0] != 0)
            }

            U2FHID_ERROR => Err(U2FError::from(r.data.as_slice()).into()),

            _ => Err(WebauthnCError::UnexpectedState),
        }
    }

    async fn get_solokey_random(&mut self) -> Result<[u8; 57], WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: CMD_RANDOM,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await?;

        let r = self.recv_one().await?;
        match r.cmd {
            CMD_RANDOM => r
                .data
                .try_into()
                .map_err(|_| WebauthnCError::InvalidMessageLength),

            U2FHID_ERROR => Err(U2FError::from(r.data.as_slice()).into()),

            _ => Err(WebauthnCError::UnexpectedState),
        }
    }

    async fn get_solokey_version(&mut self) -> Result<u32, WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: CMD_VERSION,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await?;

        let r = self.recv_one().await?;
        match r.cmd {
            CMD_VERSION => {
                let u = u32::from_be_bytes(
                    r.data
                        .try_into()
                        .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                );

                Ok(u)
            }

            U2FHID_ERROR => Err(U2FError::from(r.data.as_slice()).into()),

            _ => Err(WebauthnCError::UnexpectedState),
        }
    }

    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: CMD_UUID,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await?;

        let r = self.recv_one().await?;
        match r.cmd {
            CMD_UUID => {
                if r.len != 16 || r.data.len() != 16 {
                    return Err(WebauthnCError::InvalidMessageLength);
                }

                let u = Uuid::from_bytes(
                    r.data
                        .try_into()
                        .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                );

                Ok(u)
            }

            U2FHID_ERROR => Err(U2FError::from(r.data.as_slice()).into()),

            _ => Err(WebauthnCError::UnexpectedState),
        }
    }
}
