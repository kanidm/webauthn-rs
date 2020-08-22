//! Possible errors that may occur during Webauthn Operation processing

use base64::DecodeError as b64DecodeError;
use openssl::error::ErrorStack as OpenSSLErrorStack;
use serde_cbor::error::Error as CBORError;
use serde_json::error::Error as JSONError;
// use nom::Err as NOMError;

/// Possible errors that may occur during Webauthn Operation proessing.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum WebauthnError {
    #[error("The JSON from the client did not indicate webauthn.<method> correctly")]
    InvalidClientDataType,

    #[error(
        "The client response challenge differs from the latest challenge issued to the userId"
    )]
    MismatchedChallenge,

    #[error("There are no challenges associated to the UserId")]
    ChallengeNotFound,

    #[error("The clients relying party origin does not match our servers information")]
    InvalidRPOrigin,

    #[error("The clients relying party id hash does not match the hash of our relying party id")]
    InvalidRPIDHash,

    #[error("The user present bit is not set, and required")]
    UserNotPresent,

    #[error("The user verified bit is not set, and required by policy")]
    UserNotVerified,

    #[error("The user verified even through discouragement")]
    UserVerifiedWhenDiscouraged,

    #[error("The extensions are unknown to this server")]
    InvalidExtensions,

    #[error("The required attestation data is not present in the response")]
    MissingAttestationCredentialData,

    #[error("The attestation format requested is not able to be processed by this server - please report an issue to add the attestation format")]
    AttestationNotSupported,

    #[error("A failure occured in persisting the Challenge data")]
    ChallengePersistenceError,

    #[error("The attestation statement map is not valid")]
    AttestationStatementMapInvalid,

    #[error("The attestation statement signature is not present")]
    AttestationStatementSigMissing,

    #[error("The attestation statement signature is not valid")]
    AttestationStatementSigInvalid,

    #[error("The attestation statement version is not present")]
    AttestationStatementVerMissing,

    #[error("The attestation statement version is not valid")]
    AttestationStatementVerInvalid,

    #[error("The attestation statement version not supported")]
    AttestationStatementVerUnsupported,

    #[error("The attestation statement x5c (trust root) is not present")]
    AttestationStatementX5CMissing,

    #[error("The attestation statement x5c (trust root) is not valid")]
    AttestationStatementX5CInvalid,

    #[error("The attestation statement algorithmm is not present")]
    AttestationStatementAlgMissing,

    #[error("The attestation statement certinfo is not present")]
    AttestationStatementCertInfoMissing,

    #[error("The attestation statement pubarea is not present")]
    AttestationStatementPubAreaMissing,

    #[error("The attestation statement alg does not match algorithm of the credentialPublicKey in authenticatorData")]
    AttestationStatementAlgMismatch,

    #[error("The attestation statement alg does not match algorithm of the credentialPublicKey in authenticatorData")]
    AttestationStatementAlgInvalid,

    #[error("The attestation trust could not be established")]
    AttestationTrustFailure,

    #[error("The attestation Certificates OID 1.3.6.1.4.1.45724.1.1.4 aaguid does not match the aaguid of the token")]
    AttestationCertificateAAGUIDMismatch,

    #[error("The attestation created by the tpm is not correct")]
    AttestationTpmStInvalid,

    #[error("The tpm attestation and key algorithms do not match")]
    AttestationTpmPubareaMismatch,

    #[error("The tpm attestation extradata is missing or invalid")]
    AttestationTpmExtraDataInvalid,

    #[error("The tpm attestation extradata does not match the hash of the verification data")]
    AttestationTpmExtraDataMismatch,

    #[error("The tpm requested hash over pubarea is unknown")]
    AttestationTpmPubareaHashUnknown,

    #[error("The tpm requested hash over pubarea is invalid")]
    AttestationTpmPubareaHashInvalid,

    #[error("The tpms attest certify structure is invalid")]
    AttestationTpmAttestCertifyInvalid,

    #[error("The requirements of https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements are not met by this attestation certificate")]
    AttestationCertificateRequirementsNotMet,

    #[error("The X5C trust root is not a valid algorithm for signing")]
    CertificatePublicKeyInvalid,

    #[error("A base64 parser failure has occurred")]
    ParseBase64Failure(#[from] b64DecodeError),

    #[error("A CBOR parser failure has occurred")]
    ParseCBORFailure(#[from] CBORError),

    #[error("A JSON parser failure has occurred")]
    ParseJSONFailure(#[from] JSONError),

    #[error("A NOM parser failure has occurred")]
    ParseNOMFailure,

    #[error("In parsing the attestation object, there was insufficient data")]
    ParseInsufficentBytesAvailable,

    #[error("An openSSL Error has occured")]
    OpenSSLError(#[from] OpenSSLErrorStack),

    #[error("The requested OpenSSL curve is not supported by OpenSSL")]
    OpenSSLErrorNoCurveName,

    #[error("The COSEKey contains invalid CBOR which can not be processed")]
    COSEKeyInvalidCBORValue,

    #[error("The COSEKey type is not supported by this implementation")]
    COSEKeyInvalidType,

    #[error("The COSEKey contains invalid ECDSA X/Y coordinate data")]
    COSEKeyECDSAXYInvalid,

    #[error("The COSEKey contains invalid RSA modulus/exponent data")]
    COSEKeyRSANEInvalid,

    #[error("The COSEKey uses a curve that is not supported by this implementation")]
    COSEKeyECDSAInvalidCurve,

    #[error("The COSEKey contains invalid cryptographic algorithm request")]
    COSEKeyECDSAContentType,

    #[error("The credential exist check failed")]
    CredentialExistCheckError,

    #[error("The credential already exists")]
    CredentialAlreadyExists,

    #[error("The credential was not able to be persisted")]
    CredentialPersistenceError,

    #[error("The credential was not able to be retrieved")]
    CredentialRetrievalError,

    #[error("The credential requested could not be found")]
    CredentialNotFound,

    #[error("The credential may have be compromised and should be inspected")]
    CredentialPossibleCompromise,

    #[error("The credential counter could not be updated")]
    CredentialCounterUpdateFailure,

    #[error("The provided call back failed to allow reporting the credential failure")]
    CredentialCompromiseReportFailure,

    #[error("The trust path could not be established")]
    TrustFailure,

    #[error("Authentication has failed")]
    AuthenticationFailure,
}
