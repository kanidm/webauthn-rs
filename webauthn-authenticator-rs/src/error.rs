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
    ApduConstruction,
    ApduTransmission,
    InvalidAlgorithm,
    InvalidAssertion,
}
