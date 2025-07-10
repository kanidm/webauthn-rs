//! Authenticator errors.

use std::sync::PoisonError;

pub type Result<T> = std::result::Result<T, WebauthnCError>;

/// Client error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebauthnCError {
    #[error("A JSON parsing failure has occurred")]
    Json,
    #[error("A CBOR parsing failure has occurred")]
    Cbor,
    #[error("An unknown failure has occurred")]
    Unknown,
    #[error("A security failure has occurred")]
    Security,
    #[error("Not supported")]
    NotSupported,
    #[error("A platform authenticator failure has occurred")]
    PlatformAuthenticator,
    #[error("An internal failure has occurred")]
    Internal,
    #[error("A parser (nom) failure has occurred")]
    ParseNOMFailure,
    #[error("OpenSSL error: {0}")]
    OpenSSL(String),
    #[error("An APDU construction failure has occurred")]
    ApduConstruction,
    #[error("An APDU transmission failure has occurred")]
    ApduTransmission,
    #[error("Invalid algorithm")]
    InvalidAlgorithm,
    #[error("Invalid assertion")]
    InvalidAssertion,
    #[error("Invalid registration")]
    InvalidRegistration,
    #[error("The message was too large")]
    MessageTooLarge,
    #[error("The message was too short")]
    MessageTooShort,
    #[error("The message had an unexpected length")]
    InvalidMessageLength,
    #[error("Cancelled")]
    Cancelled,
    #[error("CTAP error: {0:?}")]
    Ctap(CtapError),
    #[error("The PIN was too short")]
    PinTooShort,
    #[error("The PIN was too long")]
    PinTooLong,
    #[error("The PIN contained a null byte (`\0`)")]
    PinContainsNull,
    #[error("No token was selected")]
    NoSelectedToken,
    #[error("The authenticator did not provide a required field; this may indicate a bug in this library, or in the authenticator")]
    MissingRequiredField,
    #[error("The provided friendly name was too long")]
    FriendlyNameTooLong,
    #[cfg(feature = "usb")]
    #[error("HID error: {0}")]
    HidError(fido_hid_rs::HidError),
    #[cfg(feature = "nfc")]
    #[error("PC/SC error: {0}")]
    PcscError(pcsc::Error),
    #[error("No HID devices were detected; this may indicate a permissions issue")]
    NoHidDevices,
    /// See [PoisonError]; generally indicates that a method holding a prior lock on the mutex failed.
    #[error("Poisoned mutex")]
    PoisonedMutex,
    #[error("The checksum of the value was incorrect")]
    Checksum,
    #[error("The card reported as a PC/SC storage card, rather than a smart card")]
    StorageCard,
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("Invalid caBLE URL")]
    InvalidCableUrl,
    #[cfg(feature = "cable")]
    #[error("Base10 decoding error: {0:?}")]
    Base10(crate::cable::DecodeError),
    #[error("Bluetooth error: {0}")]
    BluetoothError(String),
    #[error("No Bluetooth adapter")]
    NoBluetoothAdapter,
    #[error(
        "Attempt to communicate with an authenticator for which the connection has been closed"
    )]
    Closed,
    #[error("Websocket error: {0}")]
    WebsocketError(String),
    #[error("The value of the nonce for this object has exceeded the limit")]
    NonceOverflow,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("User verification was required, but is not available for this authenticator; you may need to set a PIN, or use a different authenticator")]
    UserVerificationRequired,
    #[error("The library is in an unexpected state; this could indicate that something has not been initialised correctly, or that the authenticator is sending unexpected messages")]
    UnexpectedState,
    #[cfg(feature = "usb")]
    #[error("U2F error: {0:?}")]
    U2F(crate::transport::types::U2FError),
}

#[cfg(feature = "nfc")]
impl From<pcsc::Error> for WebauthnCError {
    fn from(e: pcsc::Error) -> Self {
        Self::PcscError(e)
    }
}

#[cfg(feature = "usb")]
impl From<fido_hid_rs::HidError> for WebauthnCError {
    fn from(e: fido_hid_rs::HidError) -> Self {
        Self::HidError(e)
    }
}

impl<T> From<PoisonError<T>> for WebauthnCError {
    fn from(_: PoisonError<T>) -> Self {
        Self::PoisonedMutex
    }
}

#[cfg(feature = "ctap2")]
impl From<crate::transport::iso7816::Error> for WebauthnCError {
    fn from(v: crate::transport::iso7816::Error) -> Self {
        use crate::transport::iso7816::Error::*;
        match v {
            ResponseTooShort => WebauthnCError::MessageTooShort,
            DataTooLong => WebauthnCError::MessageTooLarge,
            _ => WebauthnCError::Internal,
        }
    }
}

#[cfg(feature = "crypto")]
impl From<openssl::error::ErrorStack> for WebauthnCError {
    fn from(v: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(v.to_string())
    }
}

impl From<std::io::Error> for WebauthnCError {
    fn from(v: std::io::Error) -> Self {
        Self::IoError(v.to_string())
    }
}

#[cfg(feature = "cable")]
impl From<crate::cable::DecodeError> for WebauthnCError {
    fn from(v: crate::cable::DecodeError) -> Self {
        Self::Base10(v)
    }
}

#[cfg(feature = "cable")]
impl From<tokio_tungstenite::tungstenite::error::Error> for WebauthnCError {
    fn from(v: tokio_tungstenite::tungstenite::error::Error) -> Self {
        Self::WebsocketError(v.to_string())
    }
}

#[cfg(any(feature = "bluetooth", feature = "cable"))]
impl From<btleplug::Error> for WebauthnCError {
    fn from(v: btleplug::Error) -> Self {
        use btleplug::Error::*;
        match v {
            PermissionDenied => WebauthnCError::PermissionDenied,
            _ => Self::BluetoothError(v.to_string()),
        }
    }
}

#[cfg(feature = "usb")]
impl From<crate::transport::types::U2FError> for WebauthnCError {
    fn from(value: crate::transport::types::U2FError) -> Self {
        Self::U2F(value)
    }
}

/// FIDO CTAP-2.x error.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#error-responses>
#[derive(Debug, PartialEq, Eq)]
pub enum CtapError {
    /// Indicates successful response.
    Ok,
    /// The command is not a valid CTAP command.
    Ctap1InvalidCommand,
    /// The command included an invalid parameter.
    Ctap1InvalidParameter,
    /// Invalid message or item length.
    Ctap1InvalidLength,
    /// Invalid message sequencing.
    Ctap1InvalidSeq,
    /// Message timed out.
    Ctap1Timeout,
    /// Channel busy. Client SHOULD retry the request after a short delay.
    /// Note that the client MAY abort the transaction if the command is no longer relevant.
    Ctap1ChannelBusy,
    /// Command not allowed on this cid.
    Ctap1LockRequired,
    /// Command not allowed on this cid.
    Ctap1InvalidChannel,
    Ctap2CborUnexpectedType,
    Ctap2InvalidCBOR,
    Ctap2MissingParameter,
    Ctap2LimitExceeded,
    Ctap2FingerprintDatabaseFull,
    Ctap2LargeBlobStorageFull,
    Ctap2CredentialExcluded,
    Ctap2Processing,
    Ctap2InvalidCredential,
    Ctap2UserActionPending,
    Ctap2OperationPending,
    Ctap2NoOperations,
    Ctap2UnsupportedAlgorithm,
    Ctap2OperationDenied,
    Ctap2KeyStoreFull,
    Ctap2UnsupportedOption,
    Ctap2InvalidOption,
    Ctap2KeepAliveCancel,
    Ctap2NoCredentials,
    Ctap2UserActionTimeout,
    Ctap2NotAllowed,
    Ctap2PinInvalid,
    Ctap2PinBlocked,
    Ctap2PinAuthInvalid,
    Ctap2PinAuthBlocked,
    Ctap2PinNotSet,
    Ctap2PUATRequired,
    Ctap2PinPolicyViolation,
    Ctap2RequestTooLarge,
    Ctap2ActionTimeout,
    Ctap2UserPresenceRequired,
    Ctap2UserVerificationBlocked,
    Ctap2IntegrityFailure,
    Ctap2InvalidSubcommand,
    Ctap2UserVerificationInvalid,
    Ctap2UnauthorizedPermission,
    Ctap1Unspecified,
    Ctap2LastError,
    /// The error code was unknown
    Unknown(u8),
}

impl CtapError {
    pub fn is_ok(&self) -> bool {
        *self == CtapError::Ok
    }
}

impl From<u8> for CtapError {
    fn from(e: u8) -> Self {
        use CtapError::*;
        match e {
            0x00 => Ok,
            0x01 => Ctap1InvalidCommand,
            0x02 => Ctap1InvalidParameter,
            0x03 => Ctap1InvalidLength,
            0x04 => Ctap1InvalidSeq,
            0x05 => Ctap1Timeout,
            0x06 => Ctap1ChannelBusy,
            0x0a => Ctap1LockRequired,
            0x0b => Ctap1InvalidChannel,
            0x11 => Ctap2CborUnexpectedType,
            0x12 => Ctap2InvalidCBOR,
            0x14 => Ctap2MissingParameter,
            0x15 => Ctap2LimitExceeded,
            0x17 => Ctap2FingerprintDatabaseFull,
            0x18 => Ctap2LargeBlobStorageFull,
            0x19 => Ctap2CredentialExcluded,
            0x21 => Ctap2Processing,
            0x22 => Ctap2InvalidCredential,
            0x23 => Ctap2UserActionPending,
            0x24 => Ctap2OperationPending,
            0x25 => Ctap2NoOperations,
            0x26 => Ctap2UnsupportedAlgorithm,
            0x27 => Ctap2OperationDenied,
            0x28 => Ctap2KeyStoreFull,
            0x2b => Ctap2UnsupportedOption,
            0x2c => Ctap2InvalidOption,
            0x2d => Ctap2KeepAliveCancel,
            0x2e => Ctap2NoCredentials,
            0x2f => Ctap2UserActionTimeout,
            0x30 => Ctap2NotAllowed,
            0x31 => Ctap2PinInvalid,
            0x32 => Ctap2PinBlocked,
            0x33 => Ctap2PinAuthInvalid,
            0x34 => Ctap2PinAuthBlocked,
            0x35 => Ctap2PinNotSet,
            0x36 => Ctap2PUATRequired,
            0x37 => Ctap2PinPolicyViolation,
            0x39 => Ctap2RequestTooLarge,
            0x3a => Ctap2ActionTimeout,
            0x3b => Ctap2UserPresenceRequired,
            0x3c => Ctap2UserVerificationBlocked,
            0x3d => Ctap2IntegrityFailure,
            0x3e => Ctap2InvalidSubcommand,
            0x3f => Ctap2UserVerificationInvalid,
            0x40 => Ctap2UnauthorizedPermission,
            0x7f => Ctap1Unspecified,
            0xdf => Ctap2LastError,
            e => Unknown(e),
        }
    }
}

impl From<CtapError> for u8 {
    fn from(e: CtapError) -> Self {
        use CtapError::*;
        match e {
            Ok => 0x00,
            Ctap1InvalidCommand => 0x01,
            Ctap1InvalidParameter => 0x02,
            Ctap1InvalidLength => 0x03,
            Ctap1InvalidSeq => 0x04,
            Ctap1Timeout => 0x05,
            Ctap1ChannelBusy => 0x06,
            Ctap1LockRequired => 0x0a,
            Ctap1InvalidChannel => 0x0b,
            Ctap2CborUnexpectedType => 0x11,
            Ctap2InvalidCBOR => 0x12,
            Ctap2MissingParameter => 0x14,
            Ctap2LimitExceeded => 0x15,
            Ctap2FingerprintDatabaseFull => 0x17,
            Ctap2LargeBlobStorageFull => 0x18,
            Ctap2CredentialExcluded => 0x19,
            Ctap2Processing => 0x21,
            Ctap2InvalidCredential => 0x22,
            Ctap2UserActionPending => 0x23,
            Ctap2OperationPending => 0x24,
            Ctap2NoOperations => 0x25,
            Ctap2UnsupportedAlgorithm => 0x26,
            Ctap2OperationDenied => 0x27,
            Ctap2KeyStoreFull => 0x28,
            Ctap2UnsupportedOption => 0x2b,
            Ctap2InvalidOption => 0x2c,
            Ctap2KeepAliveCancel => 0x2d,
            Ctap2NoCredentials => 0x2e,
            Ctap2UserActionTimeout => 0x2f,
            Ctap2NotAllowed => 0x30,
            Ctap2PinInvalid => 0x31,
            Ctap2PinBlocked => 0x32,
            Ctap2PinAuthInvalid => 0x33,
            Ctap2PinAuthBlocked => 0x34,
            Ctap2PinNotSet => 0x35,
            Ctap2PUATRequired => 0x36,
            Ctap2PinPolicyViolation => 0x37,
            Ctap2RequestTooLarge => 0x39,
            Ctap2ActionTimeout => 0x3a,
            Ctap2UserPresenceRequired => 0x3b,
            Ctap2UserVerificationBlocked => 0x3c,
            Ctap2IntegrityFailure => 0x3d,
            Ctap2InvalidSubcommand => 0x3e,
            Ctap2UserVerificationInvalid => 0x3f,
            Ctap2UnauthorizedPermission => 0x40,
            Ctap1Unspecified => 0x7f,
            Ctap2LastError => 0xdf,
            Unknown(e) => e,
        }
    }
}

impl From<CtapError> for WebauthnCError {
    fn from(e: CtapError) -> Self {
        Self::Ctap(e)
    }
}
