#![deny(warnings)]
#![warn(unused_extern_crates)]

use base64urlsafedata::HumanBinaryData;
use serde::{Deserialize, Serialize};
#[cfg(feature = "core")]
use webauthn_rs_core::error::WebauthnError;

pub use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticationExtensions, AuthenticatorAttachment,
    COSEAlgorithm, CreationChallengeResponse, CredProtect, CredentialProtectionPolicy, ExtnState,
    Mediation, PublicKeyCredential, RegisterPublicKeyCredential, RegisteredExtensions,
    RequestAuthenticationExtensions, RequestChallengeResponse, RequestRegistrationExtensions,
    UserVerificationPolicy,
};

pub type CredentialID = HumanBinaryData;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum AttestationLevel {
    None,
    AnyKnownFido,
    Strict,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterStart {
    pub username: String,
    pub reg_type: RegisterWithType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RegisterWithType {
    Passkey,
    AttestedPasskey(AttestationLevel),
    SecurityKey(AttestationLevel),
    // Device(bool),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterFinish {
    pub username: String,
    pub rpkc: RegisterPublicKeyCredential,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthenticateStart {
    pub username: String,
    pub auth_type: AuthenticateWithType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthenticateFinish {
    pub username: String,
    pub pkc: PublicKeyCredential,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthenticateWithType {
    Passkey,
    AttestedPasskey,
    SecurityKey,
    // Device
}

impl From<&RegisterWithType> for AuthenticateWithType {
    fn from(regsettings: &RegisterWithType) -> AuthenticateWithType {
        match regsettings {
            RegisterWithType::Passkey => AuthenticateWithType::Passkey,
            RegisterWithType::AttestedPasskey(_) => AuthenticateWithType::AttestedPasskey,
            RegisterWithType::SecurityKey(_) => AuthenticateWithType::SecurityKey,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RegisterWithSettings {
    pub username: String,
    pub uv: Option<UserVerificationPolicy>,
    pub algorithm: Option<Vec<COSEAlgorithm>>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub attachment: Option<AuthenticatorAttachment>,
    pub extensions: Option<RequestRegistrationExtensions>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistrationSuccess {
    pub cred_id: CredentialID,
    // pub cred: Credential,
    pub uv: bool,
    pub alg: COSEAlgorithm,
    // pub counter: u32,
    pub extensions: RegisteredExtensions,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthenticateWithSettings {
    pub username: String,
    pub use_cred_id: Option<CredentialID>,
    pub uv: Option<UserVerificationPolicy>,
    pub extensions: Option<RequestAuthenticationExtensions>,
}

impl From<&RegisterWithSettings> for AuthenticateWithSettings {
    fn from(regsettings: &RegisterWithSettings) -> AuthenticateWithSettings {
        let use_cred_id = None;
        let uv = regsettings.uv;
        let extensions = None;
        let username = regsettings.username.clone();

        AuthenticateWithSettings {
            username,
            use_cred_id,
            uv,
            extensions,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthenticationSuccess {
    pub cred_id: CredentialID,
    pub uv: bool,
    // pub counter: u32,
    pub extensions: AuthenticationExtensions,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub enum CTestAttestState {
    #[default]
    NotTested,
    Passed {
        rs: RegistrationSuccess,
        ccr: CreationChallengeResponse,
        rpkc: RegisterPublicKeyCredential,
    },
    Warning {
        err: ResponseError,
        ccr: Option<CreationChallengeResponse>,
        rpkc: Option<RegisterPublicKeyCredential>,
    },
    Failed {
        err: ResponseError,
        ccr: Option<CreationChallengeResponse>,
        rpkc: Option<RegisterPublicKeyCredential>,
    },
}

impl CTestAttestState {
    pub fn failed() -> Self {
        CTestAttestState::Failed {
            err: ResponseError::IncompleteTest,
            ccr: None,
            rpkc: None,
        }
    }

    pub fn to_result(&self) -> String {
        match self {
            CTestAttestState::NotTested => "🥑 ".to_string(),
            CTestAttestState::Passed { .. } => "✅ ".to_string(),
            CTestAttestState::Failed { .. } => "❌ ".to_string(),
            CTestAttestState::Warning { .. } => "⚠️  ".to_string(),
        }
    }

    pub fn set_warn(&mut self, err: ResponseError) {
        let mut n_self = match self {
            CTestAttestState::Failed {
                err: ResponseError::IncompleteTest,
                ccr,
                rpkc,
                ..
            } => CTestAttestState::Warning {
                err,
                ccr: ccr.clone(),
                rpkc: rpkc.clone(),
            },
            _ => panic!("Invalid State"),
        };
        std::mem::swap(self, &mut n_self);
    }

    pub fn set_err(&mut self, mut n_err: ResponseError) {
        match self {
            CTestAttestState::Failed { err, .. } => {
                std::mem::swap(err, &mut n_err);
            }
            _ => panic!("Invalid State"),
        }
    }

    pub fn save_ccr(&mut self, n_ccr: &CreationChallengeResponse) {
        match self {
            CTestAttestState::Failed { ccr, .. } => {
                *ccr = Some(n_ccr.clone());
            }
            _ => panic!("Invalid State"),
        }
    }

    pub fn save_rpkc(&mut self, n_rpkc: &RegisterPublicKeyCredential) {
        match self {
            CTestAttestState::Failed { rpkc, .. } => {
                *rpkc = Some(n_rpkc.clone());
            }
            _ => panic!("Invalid State"),
        }
    }

    pub fn set_success(&mut self, rs: RegistrationSuccess) {
        let mut n_self = match self {
            CTestAttestState::Failed {
                err: ResponseError::IncompleteTest,
                ccr: Some(ccr),
                rpkc: Some(rpkc),
                ..
            } => CTestAttestState::Passed {
                rs,
                ccr: ccr.clone(),
                rpkc: rpkc.clone(),
            },
            _ => panic!("Invalid State"),
        };
        std::mem::swap(self, &mut n_self);
    }

    pub fn get_credential_id(&self) -> Option<&CredentialID> {
        match self {
            CTestAttestState::Passed { rs, .. } => Some(&rs.cred_id),
            _ => None,
        }
    }

    pub fn get_credential_alg(&self) -> Option<&COSEAlgorithm> {
        match self {
            CTestAttestState::Passed { rs, .. } => Some(&rs.alg),
            _ => None,
        }
    }

    pub fn get_reg_result(&self) -> Option<&RegistrationSuccess> {
        match self {
            CTestAttestState::Passed { rs, .. } => Some(rs),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub enum CTestAuthState {
    #[default]
    NotTested,
    FailedPrerequisite,
    Passed {
        aus: AuthenticationSuccess,
        rcr: RequestChallengeResponse,
        pkc: PublicKeyCredential,
    },
    Warning {
        err: ResponseError,
        rcr: Option<RequestChallengeResponse>,
        pkc: Option<PublicKeyCredential>,
    },
    Failed {
        err: ResponseError,
        rcr: Option<RequestChallengeResponse>,
        pkc: Option<PublicKeyCredential>,
    },
}

impl CTestAuthState {
    pub fn failed() -> Self {
        CTestAuthState::Failed {
            err: ResponseError::IncompleteTest,
            rcr: None,
            pkc: None,
        }
    }

    pub fn to_result(&self) -> String {
        match self {
            CTestAuthState::NotTested => "🥑 ".to_string(),
            CTestAuthState::FailedPrerequisite => "⏭ ".to_string(),
            CTestAuthState::Passed { .. } => "✅ ".to_string(),
            CTestAuthState::Failed { .. } => "❌ ".to_string(),
            CTestAuthState::Warning { .. } => "⚠️  ".to_string(),
        }
    }

    pub fn save_rcr(&mut self, n_rcr: &RequestChallengeResponse) {
        match self {
            CTestAuthState::Failed { rcr, .. } => {
                *rcr = Some(n_rcr.clone());
            }
            _ => panic!("Invalid State"),
        }
    }

    pub fn save_pkc(&mut self, n_pkc: &PublicKeyCredential) {
        match self {
            CTestAuthState::Failed { pkc, .. } => {
                *pkc = Some(n_pkc.clone());
            }
            _ => panic!("Invalid State"),
        }
    }

    pub fn set_warn(&mut self, err: ResponseError) {
        let mut n_self = match self {
            CTestAuthState::Failed {
                err: ResponseError::IncompleteTest,
                rcr,
                pkc,
            } => CTestAuthState::Warning {
                err,
                rcr: rcr.clone(),
                pkc: pkc.clone(),
            },
            _ => panic!("Invalid State"),
        };
        std::mem::swap(self, &mut n_self);
    }

    pub fn set_err(&mut self, mut n_err: ResponseError) {
        match self {
            CTestAuthState::Failed { err, .. } => {
                std::mem::swap(err, &mut n_err);
            }
            _ => panic!("Invalid State"),
        }
    }

    pub fn set_success(&mut self, aus: AuthenticationSuccess) {
        let mut n_self = match self {
            CTestAuthState::Failed {
                err: ResponseError::IncompleteTest,
                rcr: Some(rcr),
                pkc: Some(pkc),
            } => CTestAuthState::Passed {
                aus,
                rcr: rcr.clone(),
                pkc: pkc.clone(),
            },
            _ => panic!("Invalid State"),
        };
        std::mem::swap(self, &mut n_self);
    }

    pub fn get_auth_result(&self) -> Option<&AuthenticationSuccess> {
        match self {
            CTestAuthState::Passed { aus, .. } => Some(aus),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub enum CTestSimpleState {
    #[default]
    NotTested,
    FailedPrerequisite,
    Passed,
    Warning,
    Failed,
}

impl CTestSimpleState {
    pub fn failed() -> CTestSimpleState {
        CTestSimpleState::Failed
    }

    pub fn to_result(&self) -> String {
        match self {
            CTestSimpleState::NotTested => "🥑 ".to_string(),
            CTestSimpleState::FailedPrerequisite => "⏭ ".to_string(),
            CTestSimpleState::Passed => "✅ ".to_string(),
            CTestSimpleState::Failed => "❌ ".to_string(),
            CTestSimpleState::Warning => "⚠️  ".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CompatTestResults {
    pub direct_attest_1: CTestAttestState,
    pub indirect_attest_1: CTestAttestState,
    pub none_attest_1: CTestAttestState,
    pub authdiscouraged: CTestAuthState,
    pub authdiscouraged_consistent: CTestSimpleState,
    pub none_attest_2: CTestAttestState,
    pub authmultiple: CTestAuthState,

    pub fallback_alg: CTestAttestState,
    pub uvpreferred: CTestAttestState,
    pub authpreferred: CTestAuthState,
    pub authpreferred_consistent: CTestSimpleState,
    pub uvrequired: CTestAttestState,
    pub authrequired: CTestAuthState,
    pub extn_uvm_supported: CTestSimpleState,
    pub extn_credprotect_supported: CTestSimpleState,
    pub extn_hmacsecret_supported: CTestSimpleState,
}

impl CompatTestResults {
    pub fn did_err(&self) -> bool {
        matches!(self.direct_attest_1, CTestAttestState::Failed { .. })
            || matches!(self.indirect_attest_1, CTestAttestState::Failed { .. })
            || matches!(self.none_attest_1, CTestAttestState::Failed { .. })
            || matches!(self.fallback_alg, CTestAttestState::Failed { .. })
            || matches!(self.uvpreferred, CTestAttestState::Failed { .. })
            || matches!(self.uvrequired, CTestAttestState::Failed { .. })
    }
}

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
    COSEKeyEDUnsupported,
    COSEKeyECDSAXYInvalid,
    COSEKeyRSANEInvalid,
    COSEKeyECDSAInvalidCurve,
    COSEKeyEDDSAInvalidCurve,
    COSEKeyInvalidAlgorithm,
    CredentialMayNotBeHardwareBound,
    CredentialInsecureCryptography,
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
    NavigatorError(String),
    UnknownError(String),
    IncompleteTest,
    CredentialIdAreIdentical,
}

#[cfg(feature = "core")]
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
            WebauthnError::COSEKeyEDUnsupported => Self::COSEKeyEDUnsupported,
            WebauthnError::COSEKeyECDSAXYInvalid => Self::COSEKeyECDSAXYInvalid,
            WebauthnError::COSEKeyRSANEInvalid => Self::COSEKeyRSANEInvalid,
            WebauthnError::COSEKeyECDSAInvalidCurve => Self::COSEKeyECDSAInvalidCurve,
            WebauthnError::COSEKeyInvalidAlgorithm => Self::COSEKeyInvalidAlgorithm,

            WebauthnError::CredentialMayNotBeHardwareBound => Self::CredentialMayNotBeHardwareBound,
            WebauthnError::CredentialInsecureCryptography => Self::CredentialInsecureCryptography,
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
            #[allow(unreachable_patterns)]
            _ => Self::UnknownError(format!("{value:?}")),
            // WebauthnError::OpenSSLError(_)                                                                                =>      Self::OpenSSLError,
        }
    }
}
