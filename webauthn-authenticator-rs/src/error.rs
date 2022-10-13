use crate::transport::iso7816::Error;

#[derive(Debug, PartialEq, Eq)]
pub enum WebauthnCError {
    Json,
    Cbor,
    Unknown,
    Security,
    NotSupported,
    PlatformAuthenticator,
    Internal,
    ParseNOMFailure,
    OpenSSL,
    ApduConstruction,
    ApduTransmission,
    InvalidAlgorithm,
    InvalidAssertion,
    MessageTooLarge,
    MessageTooShort,
    Ctap(CtapError),
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

#[derive(Debug, PartialEq, Eq)]
pub enum CtapError {
    Ok,
    Ctap1InvalidCommand,
    Ctap1InvalidParameter,
    // TODO
    Ctap2CborUnexpectedType,
    // CTAP2_ERR_PIN_AUTH_INVALID
    Ctap2PinInvalid,
    Ctap2PinBlocked,
    Ctap2PinAuthInvalid,
    Ctap2PinAuthBlocked,
    Ctap2PUATRequired,
    UNKNOWN(u8),
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
            0x11 => Ctap2CborUnexpectedType,
            0x31 => Ctap2PinInvalid,
            0x32 => Ctap2PinBlocked,
            0x33 => Ctap2PinAuthInvalid,
            0x34 => Ctap2PinAuthBlocked,
            0x36 => Ctap2PUATRequired,
            e => UNKNOWN(e),
        }
    }
}

impl From<CtapError> for WebauthnCError {
    fn from(e: CtapError) -> Self {
        Self::Ctap(e)
    }
}
