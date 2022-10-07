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
    CTAP1_ERR_INVALID_COMMAND,
    CTAP1_ERR_INVALID_PARAMETER,
    // TODO
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
    // CTAP2_ERR_PIN_AUTH_INVALID
    Ctap2PinAuthInvalid,
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
            0x01 => CTAP1_ERR_INVALID_COMMAND,
            0x02 => CTAP1_ERR_INVALID_PARAMETER,
            0x11 => CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            0x33 => Ctap2PinAuthInvalid,
            e => UNKNOWN(e),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CtapOrWebauthnCError {
    Ctap(CtapError),
    Webauthn(WebauthnCError),
}

impl From<CtapError> for CtapOrWebauthnCError {
    fn from(e: CtapError) -> Self {
        CtapOrWebauthnCError::Ctap(e)
    }
}

impl From<WebauthnCError> for CtapOrWebauthnCError {
    fn from(e: WebauthnCError) -> Self {
        CtapOrWebauthnCError::Webauthn(e)
    }
}
