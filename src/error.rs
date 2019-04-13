use base64::DecodeError as b64DecodeError;
use serde_cbor::error::Error as CBORError;
use serde_json::error::Error as JSONError;

#[derive(Debug)]
pub enum WebauthnError {
    InvalidClientDataType,
    MismatchedChallenge,
    InvalidRPOrigin,
    InvalidRPIDHash,
    UserNotPresent,
    UserNotVerified,
    InvalidExtensions,
    InvalidAttestationFormat,
    MissingAttestationCredentialData,
    AttestationFailure,
    AttestationNotSupported,

    AttestationStatementMapInvalid,
    AttestationStatementSigMissing,
    AttestationStatementSigInvalid,

    ParseBase64Failure(b64DecodeError),
    ParseCBORFailure(CBORError),
    ParseJSONFailure(JSONError),
    ParseInsufficentBytesAvailable,
}
