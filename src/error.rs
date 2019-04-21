//! Possible errors that may occur during Webauthn Operation processing

use base64::Base64Error as b64DecodeError;
use openssl::error::ErrorStack as OpenSSLErrorStack;
use serde_cbor::error::Error as CBORError;
use serde_json::error::Error as JSONError;
// use nom::Err as NOMError;

/// Possible errors that may occur during Webauthn Operation proessing.
#[derive(Debug)]
pub enum WebauthnError {
    /// The JSON from the client did not indicate webauthn.<method> correctly.
    InvalidClientDataType,
    /// The client response challenge differs from the latest challenge issued to
    /// the userId.
    MismatchedChallenge,
    /// There are no challenges associated to the UserId.
    ChallengeNotFound,
    /// The clients relying party origin does not match our servers information
    InvalidRPOrigin,
    /// The clients relying party id hash does not match the hash of our
    /// relying party id.
    InvalidRPIDHash,
    /// The user present bit is not set, and required.
    UserNotPresent,
    /// The user verified bit is not set, and required by policy.
    UserNotVerified,
    /// The extensions are unknown to this server.
    InvalidExtensions,
    /// The required attestation data is not present in the response.
    MissingAttestationCredentialData,
    /// The attestation format requested is not able to be processed
    /// by this server - please report an issue to add the attestation format.
    AttestationNotSupported,

    /// A failure occured in persisting the Challenge data.
    ChallengePersistenceError,

    /// The attestation statement map is not valid.
    AttestationStatementMapInvalid,
    /// The attestation statement signature is not present.
    AttestationStatementSigMissing,
    /// The attestation statement signature is not valid.
    AttestationStatementSigInvalid,
    /// The attestation statement x5c (trust root) is not present.
    AttestationStatementX5CMissing,
    /// The attestation statement x5c (trust root) is not valid.
    AttestationStatementX5CInvalid,
    /// The attestation trust could not be established.
    AttestationTrustFailure,

    /// The X5C trust root is not a valid algorithm for signing.
    CertificatePublicKeyInvalid,

    /// A base64 parser failure has occured
    ParseBase64Failure(b64DecodeError),
    /// A CBOR parser failure has occured
    ParseCBORFailure(CBORError),
    /// A JSON parser failure has occured
    ParseJSONFailure(JSONError),
    /// A NOM parser failure has occured.
    ParseNOMFailure,
    /// In parsing the attestation object, there was insufficent data
    ParseInsufficentBytesAvailable,
    /// An openSSL Error has occured
    OpenSSLError(OpenSSLErrorStack),
    /// The requested OpenSSL curve is not supported by OpenSSL.
    OpenSSLErrorNoCurveName,

    /// The COSEKey contains invalid CBOR which can not be processed.
    COSEKeyInvalidCBORValue,
    /// The COSEKey type is not supported by this implementation.
    COSEKeyInvalidType,
    /// The COSEKey contains invalid X/Y coordinate data.
    COSEKeyECDSAXYInvalid,
    /// The COSEKey uses a curve that is not supported by this implementation.
    COSEKeyECDSAInvalidCurve,
    /// The COSEKey contains invalid cryptographic algorithm request.
    COSEKeyECDSAContentType,

    /// The credential exist check failed
    CredentialExistCheckError,
    /// The credential already exists
    CredentialAlreadyExists,
    /// The credential was not able to be persisted
    CredentialPersistenceError,
    /// The credential was not able to be retrieved
    CredentialRetrievalError,
    /// The credential requested could not be found.
    CredentialNotFound,
    /// The credential may have be compromised and should be inspected.
    CredentialPossibleCompromise,
    /// The credential counter could not be updated.
    CredentialCounterUpdateFailure,

    /// The trust path could not be established.
    TrustFailure,

    /// Authentication has failed.
    AuthenticationFailure,
}
