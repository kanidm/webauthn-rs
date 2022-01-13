use serde::{Deserialize, Serialize};
use webauthn_rs::error::WebauthnError;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RegisterWithSettings {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ResponseError {
    InvalidClientDataType,
    MismatchedChallenge,
    ChallengeNotFound,
    InvalidRPOrigin,
    InvalidRPIDHash,
    UserNotPresent,
    UserNotVerified,
    InvalidExtensions,
    AuthenticatorDataMissingExtension,
    MissingAttestationCredentialData,
    AttestationNotSupported,
    ChallengePersistenceError,
    AttestationStatementMapInvalid,
    AttestationStatementSigMissing,
    AttestationStatementSigInvalid,
    AttestationStatementVerMissing,
    AttestationStatementVerInvalid,
    AttestationStatementVerUnsupported,
    AttestationStatementX5CMissing,
    AttestationStatementX5CInvalid,
    AttestationStatementAlgMissing,
    AttestationStatementCertInfoMissing,
    AttestationStatementPubAreaMissing,
    AttestationStatementAlgMismatch,
    AttestationStatementAlgInvalid,
    AttestationTrustFailure,
    AttestationCertificateAAGUIDMismatch,
    AttestationTpmStInvalid,
    AttestationTpmPubAreaMismatch,
    AttestationTpmExtraDataInvalid,
    AttestationTpmExtraDataMismatch,
    AttestationTpmPubAreaHashUnknown,
    AttestationTpmPubAreaHashInvalid,
    AttestationTpmAttestCertifyInvalid,
    AttestationCertificateRequirementsNotMet,
    CertificatePublicKeyInvalid,
    ParseBase64Failure,
    ParseCBORFailure,
    ParseJSONFailure,
    ParseNOMFailure,
    ParseInsufficientBytesAvailable,
    OpenSSLError,
    OpenSSLErrorNoCurveName,
    COSEKeyInvalidCBORValue,
    COSEKeyInvalidType,
    COSEKeyECDSAXYInvalid,
    COSEKeyRSANEInvalid,
    COSEKeyECDSAInvalidCurve,
    COSEKeyInvalidAlgorithm,
    CredentialExistCheckError,
    CredentialAlreadyExists,
    CredentialPersistenceError,
    CredentialRetrievalError,
    CredentialNotFound,
    CredentialAlteredAlgFromRequest,
    CredentialExcludedFromRequest,
    CredentialPossibleCompromise,
    CredentialCounterUpdateFailure,
    CredentialCompromiseReportFailure,
    TrustFailure,
    AuthenticationFailure,
    InconsistentUserVerificationPolicy,
    InvalidUsername,
    ECDSACurveInvalidNid,
    AttestationCredentialSubjectKeyMismatch,
    CredentialCrossOrigin,
    SessionStateInvalid,
    UnknownError(String),
}

impl From<WebauthnError> for ResponseError {
    fn from(value: WebauthnError) -> Self {
        match value {
            WebauthnError::InvalidClientDataType => Self::InvalidClientDataType,
            WebauthnError::MismatchedChallenge => Self::MismatchedChallenge,
            WebauthnError::ChallengeNotFound => Self::ChallengeNotFound,
            WebauthnError::InvalidRPOrigin => Self::InvalidRPOrigin,
            WebauthnError::InvalidRPIDHash => Self::InvalidRPIDHash,
            WebauthnError::UserNotPresent => Self::UserNotPresent,
            WebauthnError::UserNotVerified => Self::UserNotVerified,
            WebauthnError::InvalidExtensions => Self::InvalidExtensions,
            WebauthnError::AuthenticatorDataMissingExtension => {
                Self::AuthenticatorDataMissingExtension
            }
            WebauthnError::MissingAttestationCredentialData => {
                Self::MissingAttestationCredentialData
            }
            WebauthnError::AttestationNotSupported => Self::AttestationNotSupported,
            WebauthnError::ChallengePersistenceError => Self::ChallengePersistenceError,
            WebauthnError::AttestationStatementMapInvalid => Self::AttestationStatementMapInvalid,
            WebauthnError::AttestationStatementSigMissing => Self::AttestationStatementSigMissing,
            WebauthnError::AttestationStatementSigInvalid => Self::AttestationStatementSigInvalid,
            WebauthnError::AttestationStatementVerMissing => Self::AttestationStatementVerMissing,
            WebauthnError::AttestationStatementVerInvalid => Self::AttestationStatementVerInvalid,
            WebauthnError::AttestationStatementVerUnsupported => {
                Self::AttestationStatementVerUnsupported
            }
            WebauthnError::AttestationStatementX5CMissing => Self::AttestationStatementX5CMissing,
            WebauthnError::AttestationStatementX5CInvalid => Self::AttestationStatementX5CInvalid,
            WebauthnError::AttestationStatementAlgMissing => Self::AttestationStatementAlgMissing,
            WebauthnError::AttestationStatementCertInfoMissing => {
                Self::AttestationStatementCertInfoMissing
            }
            WebauthnError::AttestationStatementPubAreaMissing => {
                Self::AttestationStatementPubAreaMissing
            }
            WebauthnError::AttestationStatementAlgMismatch => Self::AttestationStatementAlgMismatch,
            WebauthnError::AttestationStatementAlgInvalid => Self::AttestationStatementAlgInvalid,
            WebauthnError::AttestationTrustFailure => Self::AttestationTrustFailure,
            WebauthnError::AttestationCertificateAAGUIDMismatch => {
                Self::AttestationCertificateAAGUIDMismatch
            }
            WebauthnError::AttestationTpmStInvalid => Self::AttestationTpmStInvalid,
            WebauthnError::AttestationTpmPubAreaMismatch => Self::AttestationTpmPubAreaMismatch,
            WebauthnError::AttestationTpmExtraDataInvalid => Self::AttestationTpmExtraDataInvalid,
            WebauthnError::AttestationTpmExtraDataMismatch => Self::AttestationTpmExtraDataMismatch,
            WebauthnError::AttestationTpmPubAreaHashUnknown => {
                Self::AttestationTpmPubAreaHashUnknown
            }
            WebauthnError::AttestationTpmPubAreaHashInvalid => {
                Self::AttestationTpmPubAreaHashInvalid
            }
            WebauthnError::AttestationTpmAttestCertifyInvalid => {
                Self::AttestationTpmAttestCertifyInvalid
            }
            WebauthnError::AttestationCertificateRequirementsNotMet => {
                Self::AttestationCertificateRequirementsNotMet
            }
            WebauthnError::CertificatePublicKeyInvalid => Self::CertificatePublicKeyInvalid,
            WebauthnError::ParseBase64Failure(_) => Self::ParseBase64Failure,
            WebauthnError::ParseCBORFailure(_) => Self::ParseCBORFailure,
            WebauthnError::ParseJSONFailure(_) => Self::ParseJSONFailure,
            WebauthnError::ParseNOMFailure => Self::ParseNOMFailure,
            WebauthnError::ParseInsufficientBytesAvailable => Self::ParseInsufficientBytesAvailable,
            WebauthnError::OpenSSLErrorNoCurveName => Self::OpenSSLErrorNoCurveName,
            WebauthnError::COSEKeyInvalidCBORValue => Self::COSEKeyInvalidCBORValue,
            WebauthnError::COSEKeyInvalidType => Self::COSEKeyInvalidType,
            WebauthnError::COSEKeyECDSAXYInvalid => Self::COSEKeyECDSAXYInvalid,
            WebauthnError::COSEKeyRSANEInvalid => Self::COSEKeyRSANEInvalid,
            WebauthnError::COSEKeyECDSAInvalidCurve => Self::COSEKeyECDSAInvalidCurve,
            WebauthnError::COSEKeyInvalidAlgorithm => Self::COSEKeyInvalidAlgorithm,
            WebauthnError::CredentialExistCheckError => Self::CredentialExistCheckError,
            WebauthnError::CredentialAlreadyExists => Self::CredentialAlreadyExists,
            WebauthnError::CredentialPersistenceError => Self::CredentialPersistenceError,
            WebauthnError::CredentialRetrievalError => Self::CredentialRetrievalError,
            WebauthnError::CredentialNotFound => Self::CredentialNotFound,
            WebauthnError::CredentialAlteredAlgFromRequest => Self::CredentialAlteredAlgFromRequest,
            WebauthnError::CredentialExcludedFromRequest => Self::CredentialExcludedFromRequest,
            WebauthnError::CredentialPossibleCompromise => Self::CredentialPossibleCompromise,
            WebauthnError::CredentialCounterUpdateFailure => Self::CredentialCounterUpdateFailure,
            WebauthnError::CredentialCompromiseReportFailure => {
                Self::CredentialCompromiseReportFailure
            }
            WebauthnError::TrustFailure => Self::TrustFailure,
            WebauthnError::AuthenticationFailure => Self::AuthenticationFailure,
            WebauthnError::InconsistentUserVerificationPolicy => {
                Self::InconsistentUserVerificationPolicy
            }
            WebauthnError::InvalidUsername => Self::InvalidUsername,
            WebauthnError::ECDSACurveInvalidNid => Self::ECDSACurveInvalidNid,
            WebauthnError::AttestationCredentialSubjectKeyMismatch => {
                Self::AttestationCredentialSubjectKeyMismatch
            }
            WebauthnError::CredentialCrossOrigin => Self::CredentialCrossOrigin,
            _ => Self::UnknownError(format!("{:?}", value)),
            // WebauthnError::OpenSSLError(_)                                                                                =>      Self::OpenSSLError,
        }
    }
}
