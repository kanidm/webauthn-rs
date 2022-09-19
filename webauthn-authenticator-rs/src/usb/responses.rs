//! All [Response] frame types, used by FIDO tokens over USB HID.
use crate::error::WebauthnCError;
use crate::transport::iso7816::ISO7816ResponseAPDU;
use crate::usb::framing::U2FHIDFrame;
use crate::usb::*;

/// Response type [U2FHID_INIT]
#[derive(Debug)]
pub struct InitResponse {
    pub nonce: Vec<u8>,
    /// Allocated channel identifier
    pub cid: u32,
    /// U2F protocol version (2)
    protocol_version: u8,
    device_version_major: u8,
    device_version_minor: u8,
    device_version_build: u8,
    capabilities: u8,
}

impl InitResponse {
    /// `true` if the device suports CTAPv1 / U2F protocol
    pub fn supports_ctap1(&self) -> bool {
        self.capabilities & CAPABILITY_NMSG == 0
    }

    /// `true` if the device suports CTAPv2 / CBOR protocol
    pub fn supports_ctap2(&self) -> bool {
        self.capabilities & CAPABILITY_CBOR > 0
    }
}

impl TryFrom<&[u8]> for InitResponse {
    type Error = ();
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 17 {
            return Err(());
        }

        let (nonce, d) = d.split_at(8);
        let nonce = nonce.to_vec();
        let (cid, d) = d.split_at(4);
        let cid = cid.try_into().map(u32::from_be_bytes).or(Err(()))?;

        Ok(InitResponse {
            nonce,
            cid,
            protocol_version: d[0],
            device_version_major: d[1],
            device_version_minor: d[2],
            device_version_build: d[3],
            capabilities: d[4],
        })
    }
}

/// CTAPv2 CBOR message
#[derive(Debug, PartialEq)]
pub struct CBORResponse {
    /// Status code
    pub status: u8,
    /// Data payload
    pub data: Vec<u8>,
}

impl TryFrom<&[u8]> for CBORResponse {
    type Error = ();
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 1 {
            return Err(());
        }
        Ok(Self {
            status: d[0],
            data: d[1..].to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum U2FError {
    None,
    InvalidCommand,
    InvalidParameter,
    InvalidMessageLength,
    InvalidMessageSequencing,
    MessageTimeout,
    ChannelBusy,
    ChannelRequiresLock,
    SyncCommandFailed,
    Unspecified,
    Unknown,
}

impl From<u8> for U2FError {
    fn from(v: u8) -> Self {
        match v {
            0x00 => U2FError::None,
            0x01 => U2FError::InvalidCommand,
            0x02 => U2FError::InvalidParameter,
            0x03 => U2FError::InvalidMessageLength,
            0x04 => U2FError::InvalidMessageSequencing,
            0x05 => U2FError::MessageTimeout,
            0x06 => U2FError::ChannelBusy,
            0x0a => U2FError::ChannelRequiresLock,
            0x0b => U2FError::SyncCommandFailed,
            0x7f => U2FError::Unspecified,
            _ => U2FError::Unknown,
        }
    }
}

impl From<&[u8]> for U2FError {
    fn from(d: &[u8]) -> Self {
        if d.len() >= 1 {
            U2FError::from(d[0])
        } else {
            U2FError::Unknown
        }
    }
}

/// Type for parsing all responses from a FIDO token.
#[derive(Debug)]
pub enum Response {
    Init(InitResponse),
    Msg(ISO7816ResponseAPDU),
    Cbor(CBORResponse),
    Error(U2FError),
    Unknown,
}

/// Parser for a response [U2FHIDFrame].
///
/// The frame must be complete (ie: all fragments received) before parsing.
impl TryFrom<&U2FHIDFrame> for Response {
    type Error = WebauthnCError;

    fn try_from(f: &U2FHIDFrame) -> Result<Response, WebauthnCError> {
        if !f.complete() {
            error!("cannot parse incomplete frame");
            return Err(WebauthnCError::Internal);
        }

        let b = &f.data[..];
        Ok(match f.cmd {
            U2FHID_INIT => InitResponse::try_from(b)
                .map(Response::Init)
                .unwrap_or(Response::Unknown),
            U2FHID_MSG => ISO7816ResponseAPDU::try_from(b)
                .map(Response::Msg)
                .unwrap_or(Response::Unknown),
            U2FHID_CBOR => CBORResponse::try_from(b)
                .map(Response::Cbor)
                .unwrap_or(Response::Unknown),
            U2FHID_ERROR => Response::Error(U2FError::from(b)),
            _ => Response::Unknown,
        })
    }
}
