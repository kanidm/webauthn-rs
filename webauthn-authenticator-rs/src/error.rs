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
    OpenSSL(String),
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

impl From<openssl::error::ErrorStack> for WebauthnCError {
    fn from(v: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(v.to_string())
    }
}
