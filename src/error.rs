use base64::Base64Error as b64DecodeError;
use openssl::error::ErrorStack as OpenSSLErrorStack;
use serde_cbor::error::Error as CBORError;
use serde_json::error::Error as JSONError;

#[derive(Debug)]
pub enum WebauthnError {
    InvalidClientDataType,
    MismatchedChallenge,
    ChallengeNotFound,
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
    AttestationStatementX5CMissing,
    AttestationStatementX5CInvalid,
    AttestationTrustFailure,

    CertificatePublicKeyInvalid,

    ParseBase64Failure(b64DecodeError),
    ParseCBORFailure(CBORError),
    ParseJSONFailure(JSONError),
    ParseInsufficentBytesAvailable,
    OpenSSLError(OpenSSLErrorStack),
    OpenSSLErrorNoCurveName,

    COSEKeyInvalidCBORValue,
    COSEKeyInvalidType,
    COSEKeyECDSAXYInvalid,
    COSEKeyECDSAInvalidCurve,
    COSEKeyECDSAContentType,
    COSEKeyInvalid,

    CredentialExistCheckError,
    CredentialAlreadyExists,
    CredentialPersistenceError,
    CredentialNotFound,

    TrustFailure,
}
