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
