#[derive(Debug)]
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
    ApduTransmission,
    InvalidAlgorithm,
    InvalidAssertion,
}
