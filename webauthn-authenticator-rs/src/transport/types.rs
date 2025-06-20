use super::TYPE_INIT;
use crate::error::{CtapError, WebauthnCError};

#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
use super::iso7816::ISO7816ResponseAPDU;

pub const U2FHID_PING: u8 = TYPE_INIT | 0x01;
#[cfg(any(doc, feature = "bluetooth"))]
pub const BTLE_KEEPALIVE: u8 = TYPE_INIT | 0x02;
pub const U2FHID_MSG: u8 = TYPE_INIT | 0x03;
#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
pub const U2FHID_INIT: u8 = TYPE_INIT | 0x06;
#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
pub const U2FHID_WINK: u8 = TYPE_INIT | 0x08;
#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
pub const U2FHID_CBOR: u8 = TYPE_INIT | 0x10;
#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
pub const U2FHID_CANCEL: u8 = TYPE_INIT | 0x11;
#[cfg(any(all(doc, not(doctest)), feature = "usb"))]
pub const U2FHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b;
#[cfg(any(doc, feature = "bluetooth"))]
pub const BTLE_CANCEL: u8 = TYPE_INIT | 0x3e;
pub const U2FHID_ERROR: u8 = TYPE_INIT | 0x3f;

/// Type for parsing all responses from a BTLE or USB FIDO token.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    #[cfg(any(all(doc, not(doctest)), feature = "usb"))]
    Init(crate::usb::InitResponse),
    Ping(Vec<u8>),
    #[cfg(any(all(doc, not(doctest)), feature = "usb"))]
    Msg(ISO7816ResponseAPDU),
    #[cfg(any(all(doc, not(doctest)), feature = "usb"))]
    Wink,
    Cbor(CBORResponse),
    Error(U2FError),
    KeepAlive(KeepAliveStatus),
    Unknown,
}

/// CTAPv2 CBOR message
#[derive(Debug, PartialEq, Eq)]
pub struct CBORResponse {
    /// Status code
    pub status: CtapError,
    /// Data payload
    pub data: Vec<u8>,
}

impl TryFrom<&[u8]> for CBORResponse {
    type Error = WebauthnCError;
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.is_empty() {
            return Err(WebauthnCError::MessageTooShort);
        }
        Ok(Self {
            status: d[0].into(),
            data: d[1..].to_vec(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeepAliveStatus {
    Processing,
    UserPresenceNeeded,
    Unknown(u8),
}

impl From<u8> for KeepAliveStatus {
    fn from(v: u8) -> Self {
        use KeepAliveStatus::*;
        match v {
            1 => Processing,
            2 => UserPresenceNeeded,
            v => Unknown(v),
        }
    }
}

impl From<&[u8]> for KeepAliveStatus {
    fn from(d: &[u8]) -> Self {
        if !d.is_empty() {
            Self::from(d[0])
        } else {
            Self::Unknown(0)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
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
        if !d.is_empty() {
            U2FError::from(d[0])
        } else {
            U2FError::Unknown
        }
    }
}
