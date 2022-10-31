use crate::transport::iso7816::Error;

#[derive(Debug, PartialEq)]
pub enum WebauthnCError {
    Json,
    Cbor,
    Unknown,
    Security,
    NotSupported,
    PlatformAuthenticator,
    Internal,
    ParseNOMFailure,
    OpenSSL(String),
    ApduConstruction,
    ApduTransmission,
    InvalidAlgorithm,
    InvalidAssertion,
    MessageTooLarge,
    MessageTooShort,
    Cancelled,
    Ctap(CtapError),
    InvalidPin,
    NoSelectedToken,
    #[cfg(feature = "nfc")]
    PcscError(pcsc::Error),
}

#[cfg(feature = "nfc")]
impl From<pcsc::Error> for WebauthnCError {
    fn from(e: pcsc::Error) -> Self {
        Self::PcscError(e)
    }
}

impl From<Error> for WebauthnCError {
    fn from(v: Error) -> Self {
        match v {
            Error::ResponseTooShort => WebauthnCError::MessageTooShort,
            Error::DataTooLong => WebauthnCError::MessageTooLarge,
            _ => WebauthnCError::Internal,
        }
    }
}

impl From<openssl::error::ErrorStack> for WebauthnCError {
    fn from(v: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(v.to_string())
    }
}

/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#error-responses>
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

impl From<CtapError> for WebauthnCError {
    fn from(e: CtapError) -> Self {
        Self::Ctap(e)
    }
}
