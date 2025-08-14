//! This library implements support to cryptographically verify, parse, validate and post-process
//! the content of the FIDO Metadata Service. The FIDO Metadata Service acts like a "certificate
//! transparency" registry, defining the certification state of hardware authenticators (such as
//! Yubikeys, Windows Hello, Feitan and more). These Metadata describe the features, certification
//! state, signing CA's and more about these devices.
//!
//! 2022-08-12 - FIDO's Metadata currently has a number of data entry errors - due to this, certain
//! authenticator models will NOT be presented or listed when these errors are severe enough.

#![deny(warnings)]
#![warn(unused_extern_crates)]
// #![warn(missing_docs)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

pub mod mds;
pub mod patch;
pub mod query;

use crate::mds::AuthenticatorStatus;
use crate::mds::AuthenticatorTransport;
use crate::mds::FidoDevice as RawFidoDevice;
use crate::mds::FidoMds as RawFidoMds;
use crate::mds::MetadataStatement as RawMetadataStatement;
use crate::mds::StatusReport as RawStatusReport;
use crate::mds::UserVerificationMethod as RawUserVerificationMethod;
use crate::mds::VerificationMethodAndCombinations;
use crate::mds::MultiDeviceCredentialSupport;
use crate::mds::{
    AttestationType, AuthenticationAlgorithm, AuthenticatorGetInfo, BiometricAccuracyDescriptor,
    CodeAccuracyDescriptor, EcdaaAnchor, ExtensionDescriptor, KeyProtection,
    PatternAccuracyDescriptor, ProtocolFamily, PublicKeyAlg,
};

use crate::query::{AttrValueAssertion, Query};

use webauthn_attestation_ca::{AttestationCaList, AttestationCaListBuilder};

use base64::{engine::general_purpose::STANDARD, Engine};
use compact_jwt::JwtError;
use std::cmp::Ordering;
use std::fmt;
use std::rc;
use std::str::FromStr;
use tracing::{debug, error, info, trace, warn};

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;
use uuid::Uuid;

pub const FIDO_MDS_URL: &str = "https://mds.fidoalliance.org/";

/// A status report for an authenticator. This describes the specific state of this device and
/// it's FIDO certification status. The effective date acts as a publishing time, where if the
/// effective date is `None` it is considered 'the latest report'.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReport {
    /// This device is NOT certified by FIDO.
    NotFidoCertified {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device at the firmware version or lower can have user verification bypassed allowing
    /// malware to access the device.
    UserVerificationBypass {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or lower firmware version this relates to.
        authenticator_version: u32,
        /// A url describing the report.
        url: Option<String>,
    },
    /// The attestation key of this device has been compromised, allowing anyone to impersonate these
    /// devices.
    AttestationKeyCompromise {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
        /// The Base64 DER encoded certificate that has been compromised. If `None` assume
        /// all related certificates are compromised, and the device is untrustworthy.
        certificate: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// The private keys of this device can be compromised by malware / software on a machine that
    /// interacts with the device.
    UserKeyRemoteCompromise {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
        /// A url describing the report.
        url: Option<String>,
    },
    /// The private keys of this device can be compromised and extracted by someone with physical
    /// possession. This may or may not be a destructive process.
    UserKeyPhysicalCompromise {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
        /// A url describing the report.
        url: Option<String>,
    },
    /// An update exists for this device. You *should* recommend that users update this device
    /// before proceeding.
    UpdateAvailable {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has had it's certification revoked and can not be trusted.
    Revoked {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
        /// A url describing the report.
        url: Option<String>,
    },
    /// The vendor have submitted a self-completed compliance checklist, but FIDO have not
    /// performed the certification themself. If in doubt, do not trust this device.
    SelfAssertionSubmitted {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: u32,
    },
    /// This device has been certified by FIDO at Level 1
    FidoCertified {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has been certified by FIDO at Level 1
    FidoCertifiedL1 {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has been certified by FIDO at Level 1 Plus
    FidoCertifiedL1Plus {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has been certified by FIDO at Level 2
    FidoCertifiedL2 {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has been certified by FIDO at Level 2 Plus
    FidoCertifiedL2Plus {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has been certified by FIDO at Level 3
    FidoCertifiedL3 {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
    /// This device has been certified by FIDO at Level 3 Plus
    FidoCertifiedL3Plus {
        /// Date of the report. If `None` it is considered "up to date".
        effective_date: Option<String>,
        /// The exact or greater firmware version this relates to.
        authenticator_version: Option<u32>,
        /// A description of the authenticator
        certification_descriptor: Option<String>,
        /// FIDO Alliance Certificate Number
        certificate_number: Option<String>,
        /// Authenticator Certification Policy
        certification_policy_version: Option<String>,
        /// Security Requirements Version
        certification_requirements_version: Option<String>,
        /// A url describing the report.
        url: Option<String>,
    },
}

impl TryFrom<RawStatusReport> for StatusReport {
    type Error = ();

    fn try_from(raw_sr: RawStatusReport) -> Result<Self, Self::Error> {
        match raw_sr {
            RawStatusReport {
                status: AuthenticatorStatus::NotFidoCertified,
                effective_date,
                authenticator_version,
                url,
                ..
            } => Ok(StatusReport::NotFidoCertified {
                effective_date,
                authenticator_version: authenticator_version.unwrap_or(0),
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::SelfAssertionSubmitted,
                effective_date,
                authenticator_version: Some(authenticator_version),
                ..
            } => Ok(StatusReport::SelfAssertionSubmitted {
                effective_date,
                authenticator_version,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::UserVerificationBypass,
                effective_date,
                authenticator_version: Some(authenticator_version),
                url,
                ..
            } => Ok(StatusReport::UserVerificationBypass {
                effective_date,
                authenticator_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::AttestationKeyCompromise,
                effective_date,
                authenticator_version: Some(authenticator_version),
                certificate,
                url,
                ..
            } => Ok(StatusReport::AttestationKeyCompromise {
                effective_date,
                authenticator_version,
                certificate,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::UserKeyRemoteCompromise,
                effective_date,
                authenticator_version: Some(authenticator_version),
                url,
                ..
            } => Ok(StatusReport::UserKeyRemoteCompromise {
                effective_date,
                authenticator_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::UserKeyPhysicalCompromise,
                effective_date,
                authenticator_version: Some(authenticator_version),
                url,
                ..
            } => Ok(StatusReport::UserKeyPhysicalCompromise {
                effective_date,
                authenticator_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::Revoked,
                effective_date,
                authenticator_version: Some(authenticator_version),
                url,
                ..
            } => Ok(StatusReport::Revoked {
                effective_date,
                authenticator_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::UpdateAvailable,
                effective_date,
                authenticator_version: Some(authenticator_version),
                url,
                ..
            } => Ok(StatusReport::UpdateAvailable {
                effective_date,
                authenticator_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertified,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertified {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertifiedL1,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertifiedL1 {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertifiedL1Plus,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertifiedL1Plus {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertifiedL2,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertifiedL2 {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertifiedL2Plus,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertifiedL2Plus {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertifiedL3,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertifiedL3 {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            RawStatusReport {
                status: AuthenticatorStatus::FidoCertifiedL3Plus,
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
                ..
            } => Ok(StatusReport::FidoCertifiedL3Plus {
                effective_date,
                authenticator_version,
                certification_descriptor,
                certificate_number,
                certification_policy_version,
                certification_requirements_version,
                url,
            }),
            sr => {
                warn!("Invalid Status Report - {:?}", sr);
                Err(())
            }
        }
    }
}

impl PartialEq<AuthenticatorStatus> for StatusReport {
    fn eq(&self, other: &AuthenticatorStatus) -> bool {
        // Looks nicer code style wise this way.
        #[allow(clippy::match_like_matches_macro)]
        match (self, other) {
            (StatusReport::NotFidoCertified { .. }, AuthenticatorStatus::NotFidoCertified)
            | (
                StatusReport::SelfAssertionSubmitted { .. },
                AuthenticatorStatus::SelfAssertionSubmitted,
            )
            | (
                StatusReport::UserVerificationBypass { .. },
                AuthenticatorStatus::UserVerificationBypass,
            )
            | (
                StatusReport::AttestationKeyCompromise { .. },
                AuthenticatorStatus::AttestationKeyCompromise,
            )
            | (
                StatusReport::UserKeyRemoteCompromise { .. },
                AuthenticatorStatus::UserKeyRemoteCompromise,
            )
            | (
                StatusReport::UserKeyPhysicalCompromise { .. },
                AuthenticatorStatus::UserKeyPhysicalCompromise,
            )
            | (StatusReport::Revoked { .. }, AuthenticatorStatus::Revoked)
            | (StatusReport::UpdateAvailable { .. }, AuthenticatorStatus::UpdateAvailable)
            | (StatusReport::FidoCertified { .. }, AuthenticatorStatus::FidoCertified)
            | (StatusReport::FidoCertifiedL1 { .. }, AuthenticatorStatus::FidoCertifiedL1)
            | (
                StatusReport::FidoCertifiedL1Plus { .. },
                AuthenticatorStatus::FidoCertifiedL1Plus,
            )
            | (StatusReport::FidoCertifiedL2 { .. }, AuthenticatorStatus::FidoCertifiedL2)
            | (
                StatusReport::FidoCertifiedL2Plus { .. },
                AuthenticatorStatus::FidoCertifiedL2Plus,
            )
            | (StatusReport::FidoCertifiedL3 { .. }, AuthenticatorStatus::FidoCertifiedL3)
            | (
                StatusReport::FidoCertifiedL3Plus { .. },
                AuthenticatorStatus::FidoCertifiedL3Plus,
            ) => true,
            _ => false,
        }
    }
}

impl StatusReport {
    /// Retrieve the effective date of this report
    pub fn effective_date(&self) -> Option<&str> {
        match self {
            StatusReport::NotFidoCertified { effective_date, .. }
            | StatusReport::UserVerificationBypass { effective_date, .. }
            | StatusReport::AttestationKeyCompromise { effective_date, .. }
            | StatusReport::UserKeyRemoteCompromise { effective_date, .. }
            | StatusReport::UserKeyPhysicalCompromise { effective_date, .. }
            | StatusReport::UpdateAvailable { effective_date, .. }
            | StatusReport::Revoked { effective_date, .. }
            | StatusReport::SelfAssertionSubmitted { effective_date, .. }
            | StatusReport::FidoCertified { effective_date, .. }
            | StatusReport::FidoCertifiedL1 { effective_date, .. }
            | StatusReport::FidoCertifiedL1Plus { effective_date, .. }
            | StatusReport::FidoCertifiedL2 { effective_date, .. }
            | StatusReport::FidoCertifiedL2Plus { effective_date, .. }
            | StatusReport::FidoCertifiedL3 { effective_date, .. }
            | StatusReport::FidoCertifiedL3Plus { effective_date, .. } => effective_date.as_deref(),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            StatusReport::NotFidoCertified { .. } => "Not FIDO Certified",
            StatusReport::UserVerificationBypass { .. } => "⚠️  User Verification Bypass",
            StatusReport::AttestationKeyCompromise { .. } => "⚠️  Attestation Key Compromise",
            StatusReport::UserKeyRemoteCompromise { .. } => "⚠️  User Key Remote Compromise",
            StatusReport::UserKeyPhysicalCompromise { .. } => "⚠️  User Key Physical Compromise",
            StatusReport::UpdateAvailable { .. } => "⚠️  Update Available",
            StatusReport::Revoked { .. } => "⚠️  Revoked",
            StatusReport::SelfAssertionSubmitted { .. } => "Self Assertion",
            StatusReport::FidoCertified { .. } | StatusReport::FidoCertifiedL1 { .. } => {
                "FIDO Certified - L1"
            }
            StatusReport::FidoCertifiedL1Plus { .. } => "FIDO Certified - L1 Plus",
            StatusReport::FidoCertifiedL2 { .. } => "FIDO Certified - L2",
            StatusReport::FidoCertifiedL2Plus { .. } => "FIDO Certified - L2 Plus",
            StatusReport::FidoCertifiedL3 { .. } => "FIDO Certified - L3",
            StatusReport::FidoCertifiedL3Plus { .. } => "FIDO Certified - L3 Plus",
        }
    }

    pub(crate) fn numeric(&self) -> u8 {
        match self {
            StatusReport::NotFidoCertified { .. }
            | StatusReport::UserVerificationBypass { .. }
            | StatusReport::AttestationKeyCompromise { .. }
            | StatusReport::UserKeyRemoteCompromise { .. }
            | StatusReport::UserKeyPhysicalCompromise { .. }
            | StatusReport::UpdateAvailable { .. }
            | StatusReport::Revoked { .. }
            | StatusReport::SelfAssertionSubmitted { .. } => 0,
            StatusReport::FidoCertified { .. } | StatusReport::FidoCertifiedL1 { .. } => 10,
            StatusReport::FidoCertifiedL1Plus { .. } => 11,
            StatusReport::FidoCertifiedL2 { .. } => 20,
            StatusReport::FidoCertifiedL2Plus { .. } => 21,
            StatusReport::FidoCertifiedL3 { .. } => 30,
            StatusReport::FidoCertifiedL3Plus { .. } => 31,
        }
    }

    fn gte(&self, level: &AuthenticatorStatus) -> bool {
        self.numeric() >= level.numeric()
    }
}

impl PartialOrd for StatusReport {
    fn partial_cmp(&self, other: &StatusReport) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StatusReport {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.effective_date(), other.effective_date()) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

/// An identifier of a user verification method. Some methods may contain an internal descriptor
/// which provides information about certification or details of the user verification method.
#[derive(Debug, Clone, Hash, PartialEq)]
pub enum UserVerificationMethod {
    /// No user verification is required
    None,
    /// Physical interaction is required i.e. touching the device. The identity of whom touched
    /// the device is NOT asserted, only that *someone* touched it.
    PresenceInternal,
    /// A passcode was entered internally to the device, i.e. a self contained PIN entry pad embedded
    /// into the device.
    PasscodeInternal(Option<CodeAccuracyDescriptor>),
    /// A password was supplied to the device from an external source, i.e. a PIN entry dialog in
    /// a browser, that then supplied the PIN to the device.
    PasscodeExternal(Option<CodeAccuracyDescriptor>),
    /// A fingerprint reader that is built into the device.
    FingerprintInternal(Option<BiometricAccuracyDescriptor>),
    /// A Handprint reader that is built into the device.
    HandprintInternal(Option<BiometricAccuracyDescriptor>),
    /// A Handprint reader that is built into the device.
    EyeprintInternal(Option<BiometricAccuracyDescriptor>),
    /// A Voiceprint reader that is built into the device.
    VoiceprintInternal(Option<BiometricAccuracyDescriptor>),
    /// A Faceprint reader that is built into the device.
    FaceprintInternal(Option<BiometricAccuracyDescriptor>),
    /// Unknown - No definition is available.
    LocationInternal,
    /// A pattern was entered internally to the device, i.e. a 3x3 grid of dots on a display that the
    /// user traces over on a touch screen.
    PatternInternal(Option<PatternAccuracyDescriptor>),
}

impl FromStr for UserVerificationMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(UserVerificationMethod::None),
            "presence" => Ok(UserVerificationMethod::PresenceInternal),
            "pin_internal" | "passcode_internal" => {
                Ok(UserVerificationMethod::PasscodeInternal(None))
            }
            "pin_external" | "passcode_external" => {
                Ok(UserVerificationMethod::PasscodeExternal(None))
            }
            "fingerprint_internal" | "fprint_internal" | "fprint" => {
                Ok(UserVerificationMethod::FingerprintInternal(None))
            }
            "handprint_internal" | "hprint_internal" | "hprint" => {
                Ok(UserVerificationMethod::HandprintInternal(None))
            }
            "eyeprint_internal" | "eprint_internal" | "eprint" => {
                Ok(UserVerificationMethod::EyeprintInternal(None))
            }
            "voiceprint_internal" | "vprint_internal" | "vprint" => {
                Ok(UserVerificationMethod::VoiceprintInternal(None))
            }
            "faceprint_internal" | "face_internal" | "face" => {
                Ok(UserVerificationMethod::FaceprintInternal(None))
            }
            "pattern_internal" | "pattern" => Ok(UserVerificationMethod::PatternInternal(None)),
            _ => Err(()),
        }
    }
}

impl fmt::Display for UserVerificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserVerificationMethod::None => write!(f, "None"),
            UserVerificationMethod::PresenceInternal => write!(f, "PresenceInternal"),
            UserVerificationMethod::PasscodeInternal(Some(cad)) => write!(
                f,
                "PasscodeInternal ( base: {}, min_length: {}, max_retries: {:?}, slowdown: {:?} )",
                cad.base, cad.min_length, cad.max_retries, cad.block_slowdown
            ),
            UserVerificationMethod::PasscodeInternal(None) => {
                write!(f, "PasscodeInternal (unknown limits)")
            }
            UserVerificationMethod::PasscodeExternal(Some(cad)) => write!(
                f,
                "PasscodeExternal ( base: {}, min_length: {}, max_retries: {:?}, slowdown: {:?} )",
                cad.base, cad.min_length, cad.max_retries, cad.block_slowdown
            ),
            UserVerificationMethod::PasscodeExternal(None) => {
                write!(f, "PasscodeExternal (unknown limits)")
            }
            UserVerificationMethod::FingerprintInternal(_) => write!(f, "FingerprintInternal"),
            UserVerificationMethod::HandprintInternal(_) => write!(f, "HandprintInternal"),
            UserVerificationMethod::EyeprintInternal(_) => write!(f, "EyeprintInternal"),
            UserVerificationMethod::VoiceprintInternal(_) => write!(f, "VoiceprintInternal"),
            UserVerificationMethod::FaceprintInternal(_) => write!(f, "FaceprintInternal"),
            UserVerificationMethod::LocationInternal => write!(f, "LocationInternal"),
            UserVerificationMethod::PatternInternal(_) => write!(f, "PatternInternal"),
        }
    }
}

impl TryFrom<VerificationMethodAndCombinations> for UserVerificationMethod {
    type Error = ();

    fn try_from(uvmac: VerificationMethodAndCombinations) -> Result<Self, Self::Error> {
        let VerificationMethodAndCombinations {
            user_verification_method,
            ca_desc,
            ba_desc,
            pa_desc,
        } = uvmac;

        match (user_verification_method, ca_desc, ba_desc, pa_desc) {
            (RawUserVerificationMethod::None, None, None, None) => Ok(UserVerificationMethod::None),
            (RawUserVerificationMethod::PresenceInternal, None, None, None) => {
                Ok(UserVerificationMethod::PresenceInternal)
            }
            (RawUserVerificationMethod::PasscodeInternal, ca_desc, None, None) => {
                Ok(UserVerificationMethod::PasscodeInternal(ca_desc))
            }
            (RawUserVerificationMethod::PasscodeExternal, ca_desc, None, None) => {
                Ok(UserVerificationMethod::PasscodeExternal(ca_desc))
            }
            (RawUserVerificationMethod::FingerprintInternal, None, ba_desc, None) => {
                Ok(UserVerificationMethod::FingerprintInternal(ba_desc))
            }
            (RawUserVerificationMethod::HandprintInternal, None, ba_desc, None) => {
                Ok(UserVerificationMethod::HandprintInternal(ba_desc))
            }
            (RawUserVerificationMethod::EyeprintInternal, None, ba_desc, None) => {
                Ok(UserVerificationMethod::EyeprintInternal(ba_desc))
            }
            (RawUserVerificationMethod::VoiceprintInternal, None, ba_desc, None) => {
                Ok(UserVerificationMethod::VoiceprintInternal(ba_desc))
            }
            (RawUserVerificationMethod::FaceprintInternal, None, ba_desc, None) => {
                Ok(UserVerificationMethod::FaceprintInternal(ba_desc))
            }
            (RawUserVerificationMethod::LocationInternal, None, None, None) => {
                Ok(UserVerificationMethod::LocationInternal)
            }
            (RawUserVerificationMethod::PatternInternal, None, None, pa_desc) => {
                Ok(UserVerificationMethod::PatternInternal(pa_desc))
            }
            // RawUserVerificationMethod::All
            r => {
                warn!("Invalid UVM - {:?}", r);
                Err(())
            }
        }
    }
}

#[derive(Debug, Clone)]
enum FidoDevice {
    Uaf(UAF),
    U2F(U2F),
    FIDO2(FIDO2),
}

/// A metadata statement describing a UAF device.
#[derive(Debug, Clone)]
pub struct UAF {
    /// The AAID that uniquely identifies this device.
    pub aaid: String,
    /// A description of the device in English
    pub description: String,
    /// Descriptions of the device, mapped from language to description.
    pub alternative_descriptions: BTreeMap<String, String>,
    /// The latest firmware version of the device.
    pub authenticator_version: u32,
    /// The supported cryptographic algorithms this device supports.
    pub authentication_algorithms: Vec<AuthenticationAlgorithm>,
    /// The encoding of the devices public key when registered
    pub public_key_alg_and_encodings: Vec<PublicKeyAlg>,
    /// The types of attestation format that device may provide
    pub attestation_types: Vec<AttestationType>,
    /// A matrix of user verification methods this device supports. The outer matrix is
    /// a list of `OR` methods, the inner list is `AND` methods. For example, consider:
    ///
    ///
    /// [
    ///     [
    ///         { uvm: None }
    ///     ],
    ///     // OR
    ///     [
    ///         { uvm: PresenceInternal }
    ///     ],
    ///     // OR
    ///     [
    ///         { uvm: PresenceInternal },
    ///         { uvm: PasscodeExternal },
    ///     ],
    /// ]
    ///
    ///
    /// This is a common configuration found on many devices where it supports signatures with
    /// no verification, signatures with touch-only, and signatures with touch and a passcode. These
    /// bits are represented via the User Presence and User Verification booleans inside of the
    /// attested credential data. Webauthn for example will always require at least presence.
    pub user_verification_details: Vec<Vec<UserVerificationMethod>>,
    /// The methods of supported private key protection this device supports.
    pub key_protection: Vec<KeyProtection>,
    /// If this device is restricted to only sign FIDO signature assertions. If `false` the device
    /// may be used to sign any arbitrary data. If `true` the device may only be used with FIDO
    /// (Webauthn) requests.
    pub is_key_restricted: bool,
    /// If `true` the device requires user verification for each operation it performs. If `false`
    /// the device may cache the user verification for a short time. Consider a token that requires
    /// a PIN - it may cache this for a small amount of time so that the user only requires presence.
    pub is_fresh_user_verification_required: bool,
    /// A list of DER root certificates that may have signed this model of authenticators attestation.
    pub attestation_root_certificates: Vec<Vec<u8>>,
    /// A list of ECDAA root anchors that may have signed this model of authenticators attestation.
    pub ecdaa_trust_anchors: Vec<EcdaaAnchor>,
    /// A list of extensions that this device supports.
    pub supported_extensions: Vec<ExtensionDescriptor>,
    /// If supported, the output of CTAP2.0+ authenticatorGetInfo command from a "factory new" device.
    pub authenticator_get_info: Option<AuthenticatorGetInfo>,
    /// A list of status reports about this device.
    pub status_reports: BTreeSet<StatusReport>,
    /// The time this device was last updated.
    pub time_of_last_status_change: String,
}

/// A metadata statement describing a U2F device.
#[derive(Debug, Clone)]
pub struct U2F {
    /// A list of attestation certificate keys that identify sub-models of this device.
    pub attestation_certificate_key_identifiers: Vec<String>,
    /// A description of the device in English
    pub description: String,
    /// Descriptions of the device, mapped from language to description.
    pub alternative_descriptions: BTreeMap<String, String>,
    /// The latest firmware version of the device.
    pub authenticator_version: u32,
    /// The supported cryptographic algorithms this device supports.
    pub authentication_algorithms: Vec<AuthenticationAlgorithm>,
    /// The encoding of the devices public key when registered
    pub public_key_alg_and_encodings: Vec<PublicKeyAlg>,
    /// The types of attestation format that device may provide
    pub attestation_types: Vec<AttestationType>,
    /// A matrix of user verification methods this device supports. The outer matrix is
    /// a list of `OR` methods, the inner list is `AND` methods. For example, consider:
    ///
    ///
    /// [
    ///     [
    ///         { uvm: None }
    ///     ],
    ///     // OR
    ///     [
    ///         { uvm: PresenceInternal }
    ///     ],
    ///     // OR
    ///     [
    ///         { uvm: PresenceInternal },
    ///         { uvm: PasscodeExternal },
    ///     ],
    /// ]
    ///
    ///
    /// This is a common configuration found on many devices where it supports signatures with
    /// no verification, signatures with touch-only, and signatures with touch and a passcode. These
    /// bits are represented via the User Presence and User Verification booleans inside of the
    /// attested credential data. Webauthn for example will always require at least presence.
    pub user_verification_details: Vec<Vec<UserVerificationMethod>>,
    /// The methods of supported private key protection this device supports.
    pub key_protection: Vec<KeyProtection>,
    /// If this device is restricted to only sign FIDO signature assertions. If `false` the device
    /// may be used to sign any arbitrary data. If `true` the device may only be used with FIDO
    /// (Webauthn) requests.
    pub is_key_restricted: bool,
    /// If `true` the device requires user verification for each operation it performs. If `false`
    /// the device may cache the user verification for a short time. Consider a token that requires
    /// a PIN - it may cache this for a small amount of time so that the user only requires presence.
    pub is_fresh_user_verification_required: bool,
    /// A list of DER root certificates that may have signed this model of authenticators attestation.
    pub attestation_root_certificates: Vec<Vec<u8>>,
    /// A list of ECDAA root anchors that may have signed this model of authenticators attestation.
    pub ecdaa_trust_anchors: Vec<EcdaaAnchor>,
    /// A list of extensions that this device supports.
    pub supported_extensions: Vec<ExtensionDescriptor>,
    /// If supported, the output of CTAP2.0+ authenticatorGetInfo command from a "factory new" device.
    pub authenticator_get_info: Option<AuthenticatorGetInfo>,
    /// A list of status reports about this device.
    pub status_reports: BTreeSet<StatusReport>,
    /// The time this device was last updated.
    pub time_of_last_status_change: String,
}

impl fmt::Display for U2F {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

/// A metadata statement describing a FIDO2 device.
#[derive(Debug, Clone)]
pub struct FIDO2 {
    /// The AAGUID (UUID, Universally Unique IDentifier) that identifies this device.
    pub aaguid: Uuid,
    /// A description of the device in English
    pub description: String,
    /// Descriptions of the device, mapped from language to description.
    pub alternative_descriptions: BTreeMap<String, String>,
    /// The latest firmware version of the device.
    pub authenticator_version: u32,
    /// The supported cryptographic algorithms this device supports.
    pub authentication_algorithms: Vec<AuthenticationAlgorithm>,
    /// The encoding of the devices public key when registered
    pub public_key_alg_and_encodings: Vec<PublicKeyAlg>,
    /// The types of attestation format that device may provide
    pub attestation_types: Vec<AttestationType>,
    /// A matrix of user verification methods this device supports. The outer matrix is
    /// a list of `OR` methods, the inner list is `AND` methods. For example, consider:
    ///
    ///
    /// [
    ///     [
    ///         { uvm: None }
    ///     ],
    ///     // OR
    ///     [
    ///         { uvm: PresenceInternal }
    ///     ],
    ///     // OR
    ///     [
    ///         { uvm: PresenceInternal },
    ///         { uvm: PasscodeExternal },
    ///     ],
    /// ]
    ///
    ///
    /// This is a common configuration found on many devices where it supports signatures with
    /// no verification, signatures with touch-only, and signatures with touch and a passcode. These
    /// bits are represented via the User Presence and User Verification booleans inside of the
    /// attested credential data. Webauthn for example will always require at least presence.
    pub user_verification_details: Vec<Vec<UserVerificationMethod>>,
    /// The methods of supported private key protection this device supports.
    pub key_protection: Vec<KeyProtection>,
    /// If this device is restricted to only sign FIDO signature assertions. If `false` the device
    /// may be used to sign any arbitrary data. If `true` the device may only be used with FIDO
    /// (Webauthn) requests.
    pub is_key_restricted: bool,
    /// If `true` the device requires user verification for each operation it performs. If `false`
    /// the device may cache the user verification for a short time. Consider a token that requires
    /// a PIN - it may cache this for a small amount of time so that the user only requires presence.
    pub is_fresh_user_verification_required: bool,
    /// A list of DER root certificates that may have signed this model of authenticators attestation.
    pub attestation_root_certificates: Vec<Vec<u8>>,
    /// A list of ECDAA root anchors that may have signed this model of authenticators attestation.
    pub ecdaa_trust_anchors: Vec<EcdaaAnchor>,
    /// A list of extensions that this device supports.
    pub supported_extensions: Vec<ExtensionDescriptor>,
    /// If supported, the output of CTAP2.0+ authenticatorGetInfo command from a "factory new" device.
    pub authenticator_get_info: Option<AuthenticatorGetInfo>,
    /// A list of status reports about this device.
    pub status_reports: BTreeSet<StatusReport>,
    /// The time this device was last updated.
    pub time_of_last_status_change: String,
    /// These data as supplied from FIDO is inconsistent for this device, and may contain omissions
    /// or errors. In some cases the webauthn-rs project has patched these data to correct these
    /// which is indicated by the "patched" flag.
    pub inconsistent_data: bool,
    /// These data have been patched by the webauthn-rs project to repair flaws in the MDS that
    /// are provided by FIDO. These patches are created by the project observing the device and
    /// providing this.
    pub patched_data: bool,
    /// If the device supports multiple credentials
    pub multi_device_credential_support: MultiDeviceCredentialSupport,
}

impl fmt::Display for FIDO2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.aaguid, self.description)
    }
}

impl FIDO2 {
    fn query_attr(&self, ava: &AttrValueAssertion) -> bool {
        match ava {
            AttrValueAssertion::AaguidEq(u) => self.aaguid == *u,
            AttrValueAssertion::DescriptionEq(s) => &self.description == s,
            AttrValueAssertion::DescriptionCnt(s) => self
                .description
                .to_lowercase()
                .contains(s.to_lowercase().as_str()),
            AttrValueAssertion::StatusEq(s) => self
                .status_reports
                .last()
                .map(|sr| sr == s)
                .unwrap_or(false),
            AttrValueAssertion::StatusGte(s) => self.status_reports.iter().any(|sr| sr.gte(s)),
            AttrValueAssertion::StatusLt(s) => self.status_reports.iter().any(|sr| !sr.gte(s)),
            AttrValueAssertion::TransportEq(t) => self
                .authenticator_get_info
                .as_ref()
                .map(|agi| agi.transports.contains(t))
                .unwrap_or(false),
            AttrValueAssertion::UserVerificationCnt(u) => self
                .user_verification_details
                .iter()
                .flat_map(|and| and.iter())
                .any(|uvd| std::mem::discriminant(uvd) == std::mem::discriminant(u)),
        }
    }

    fn query_match(&self, q: &Query) -> bool {
        match q {
            Query::Op(ava) => self.query_attr(ava),
            Query::And(a, b) => self.query_match(a) && self.query_match(b),
            Query::Or(a, b) => self.query_match(a) || self.query_match(b),
            Query::Not(a) => !self.query_match(a),
        }
    }
}

impl TryFrom<RawFidoDevice> for FidoDevice {
    type Error = ();

    fn try_from(rawdevice: RawFidoDevice) -> Result<Self, Self::Error> {
        let RawFidoDevice {
            aaid,
            aaguid,
            attestation_certificate_key_identifiers,
            metadata_statement,
            biometric_status_reports,
            status_reports,
            time_of_last_status_change,
            rogue_list_url: _,
            rogue_list_hash: _,
        } = rawdevice;

        if aaid != metadata_statement.aaid {
            warn!(
                "Inconsistent aaid {:?} != {:?}",
                aaid, metadata_statement.aaid
            );
            return Err(());
        }

        if aaguid != metadata_statement.aaguid {
            warn!(
                "Inconsistent aaguid {:?} != {:?}",
                aaguid, metadata_statement.aaguid
            );
            return Err(());
        }

        if attestation_certificate_key_identifiers
            != metadata_statement.attestation_certificate_key_identifiers
        {
            warn!(
                "Inconsistent aki {:?} != {:?}",
                attestation_certificate_key_identifiers,
                metadata_statement.attestation_certificate_key_identifiers
            );
            return Err(());
        }

        if !biometric_status_reports.is_empty() {
            debug!(?biometric_status_reports);
        }

        let mut invalid_metadata = false;
        let mut inconsistent_data = false;
        let mut patched_data = false;

        // We deconstruct the MDS because there are a bunch of duplicate
        // types / values that we want to expose.
        let RawMetadataStatement {
            legal_header: _,
            upv: _,
            aaid: _,
            aaguid: _,
            attestation_certificate_key_identifiers: _,
            description,
            alternative_descriptions,
            authenticator_version,
            protocol_family,
            schema: _,
            authentication_algorithms,
            public_key_alg_and_encodings,
            attestation_types,
            mut user_verification_details,
            key_protection,
            is_key_restricted,
            is_fresh_user_verification_required,
            matcher_protection: _,
            crypto_strength: _,
            attachment_hint: _,
            tc_display: _,
            tc_display_content_type: _,
            tc_display_png_characteristics: _,
            attestation_root_certificates,
            ecdaa_trust_anchors,
            icon: _,
            supported_extensions,
            mut authenticator_get_info,
            multi_device_credential_support,
        } = metadata_statement;

        let mut status_reports: BTreeSet<_> = status_reports
            .into_iter()
            .filter_map(|sr| {
                sr.try_into()
                    .map_err(|_| {
                        warn!(
                            "Invalid Status Report located in: {:?}, {:?}, {:?}",
                            aaid, aaguid, attestation_certificate_key_identifiers
                        );
                        invalid_metadata = true;
                    })
                    .ok()
            })
            .collect();

        if let Some(status_report) = patch::mds_deny_insecure_authenticators(aaguid) {
            status_reports.insert(status_report);
        }

        let attestation_root_certificates = attestation_root_certificates.into_iter()
            .filter_map(|cert| {
                let trim_cert = cert.trim();
                if trim_cert != cert {
                    warn!(
                        "Invalid attestation root certificate - leading/trailing whitespace: {:?}, {:?}, {:?}",
                        aaid, aaguid, attestation_certificate_key_identifiers
                    );
                    inconsistent_data = true;
                    None
                } else {
                    match STANDARD.decode(trim_cert) {
                        Ok(der) => Some(der),
                        Err(e) => {
                            warn!(
                                "Invalid attestation root certificate - invalid base64 {:?} : {:?}, {:?}, {:?}",
                                e,
                                aaid, aaguid, attestation_certificate_key_identifiers
                            );
                            invalid_metadata = true;
                            None
                        }
                    }
                }
            })
            .collect();

        if patch::mds_user_verification_method_code_accuracy_descriptor(
            &mut user_verification_details,
        ) {
            info!(
                "Device was patched for invalid code accuracy descriptior on presence: {:?}, {:?}, {:?}",
                aaid, aaguid, attestation_certificate_key_identifiers
            );
            inconsistent_data = true;
            patched_data = true;
        }

        if patch::mds_user_verification_method_invalid_all_present(&mut user_verification_details) {
            info!(
                "Device was patched for uvm 'all', which violates fido's standards: {:?}, {:?}, {:?}",
                aaid, aaguid, attestation_certificate_key_identifiers
            );
            inconsistent_data = true;
            patched_data = true;
        }

        // debug!("{:#?}", user_verification_details);

        let mut user_verification_details: Vec<Vec<_>> = user_verification_details.into_iter()
            .map(|inner| {
                inner.into_iter()
                    .filter_map(|uvm| {
                        uvm.try_into()
                            .map_err(|_e| {
                                warn!(
                                    "Invalid user verification details located in: {:?}, {:?}, {:?}",
                                    aaid, aaguid, attestation_certificate_key_identifiers
                                );
                                assert!(aaguid.is_none());
                                invalid_metadata = true;
                            })
                            .ok()

                    })
                    .collect()
            })
            .collect();

        match patch::user_verification_method(aaguid, &user_verification_details) {
            Ok(None) => {
                // No patching needed.
            }
            Ok(Some(mut uvm_patch)) => {
                // Patch provided
                inconsistent_data = true;
                patched_data = true;
                std::mem::swap(&mut uvm_patch, &mut user_verification_details)
            }
            Err(_e) => {
                error!("Unable to patch user verification methods. This is a bug and should be reported. https://github.com/kanidm/webauthn-rs/issues");
            }
        }

        for uvm_and in user_verification_details.iter() {
            if uvm_and.contains(&UserVerificationMethod::None) && uvm_and.len() != 1 {
                debug!(?user_verification_details);
                debug!(?description);
                warn!(
                    "Illogical user verification method located in - None may not exist with other UVM: {:?}, {:?}, {:?}",
                    aaid, aaguid, attestation_certificate_key_identifiers
                );
                invalid_metadata = true;
            }
        }

        // There are multiple devices that have no authenticator get info, and instead rely on
        // other fields in the metadata to do the work for them. In these cases, we should actually
        // make the AGI is None since it's only populated by the fido MDS and not a true mds.

        let agi_invalid = if let Some(agi) = authenticator_get_info.as_ref() {
            agi.extensions.is_empty()
                && agi.pin_uv_auth_protocols.is_empty()
                && agi.transports.is_empty()
                && agi.algorithms.is_empty()
        } else {
            false
        };

        if agi_invalid {
            authenticator_get_info = None;
            info!(
                "Device was patched for invalid authenticator get info that was not collected from a real device: {:?}, {:?}, {:?}",
                aaid, aaguid, attestation_certificate_key_identifiers
            );
            patched_data = true;
            inconsistent_data = true;
        }

        if let Some(agi) = authenticator_get_info.as_ref() {
            if !supported_extensions.is_empty() {
                let agi_extn: BTreeSet<_> = agi.extensions.iter().map(|s| s.as_str()).collect();
                let sup_extn: BTreeSet<_> =
                    supported_extensions.iter().map(|s| s.id.as_str()).collect();

                for sup_missing in agi_extn.difference(&sup_extn) {
                    warn!(
                        "Inconsistent supported extension descriptor {} in - {:?}, {:?}, {:?}",
                        sup_missing, aaid, aaguid, attestation_certificate_key_identifiers
                    );
                    inconsistent_data = true;
                }

                for agi_missing in sup_extn.difference(&agi_extn) {
                    warn!(
                        "Inconsistent authenticator_get_info extension descriptor {} in - {:?}, {:?}, {:?}",
                        agi_missing,
                        aaid, aaguid, attestation_certificate_key_identifiers
                    );
                    inconsistent_data = true;
                }
            }
        }

        if let Some(aaguid) = aaguid.as_ref() {
            if authenticator_get_info.is_none() {
                warn!("FIDO2 Device missing authenticator info - {:?}", aaguid);
                invalid_metadata = true;
            }
        }

        if invalid_metadata {
            return Err(());
        }

        match (
            protocol_family,
            aaid,
            aaguid,
            attestation_certificate_key_identifiers,
        ) {
            (ProtocolFamily::Uaf, Some(aaid), None, _) => Ok(FidoDevice::Uaf(UAF {
                aaid,
                description,
                alternative_descriptions,
                authenticator_version,
                authentication_algorithms,
                public_key_alg_and_encodings,
                attestation_types,
                user_verification_details,
                key_protection,
                is_key_restricted,
                is_fresh_user_verification_required,
                attestation_root_certificates,
                ecdaa_trust_anchors,
                supported_extensions,
                authenticator_get_info,
                status_reports,
                time_of_last_status_change,
            })),
            (ProtocolFamily::Fido2, None, Some(aaguid), _) => Ok(FidoDevice::FIDO2(FIDO2 {
                aaguid,
                description,
                alternative_descriptions,
                authenticator_version,
                authentication_algorithms,
                public_key_alg_and_encodings,
                attestation_types,
                user_verification_details,
                key_protection,
                is_key_restricted,
                is_fresh_user_verification_required,
                attestation_root_certificates,
                ecdaa_trust_anchors,
                supported_extensions,
                authenticator_get_info,
                status_reports,
                time_of_last_status_change,
                inconsistent_data,
                patched_data,
                multi_device_credential_support,
            })),
            (ProtocolFamily::U2f, None, None, Some(aki)) => Ok(FidoDevice::U2F(U2F {
                attestation_certificate_key_identifiers: aki,
                description,
                alternative_descriptions,
                authenticator_version,
                authentication_algorithms,
                public_key_alg_and_encodings,
                attestation_types,
                user_verification_details,
                key_protection,
                is_key_restricted,
                is_fresh_user_verification_required,
                attestation_root_certificates,
                ecdaa_trust_anchors,
                supported_extensions,
                authenticator_get_info,
                status_reports,
                time_of_last_status_change,
            })),
            r => {
                warn!(
                    "Invalid device aaid/aaguid, may not be a valid metadata statement {:?}",
                    r
                );
                Err(())
            }
        }
    }
}

/// The set of parsed and validated FIDO Metadata
#[derive(Debug, Clone)]
pub struct FidoMds {
    /// The set of FIDO2 device metadata that exists within the Metadata Statement, indexed by their
    /// aaguid / uuid.
    pub fido2: Vec<rc::Rc<FIDO2>>,
    /// The set of (legacy) UAF device metadata that exists within the Metadata Statement.
    pub uaf: Vec<UAF>,
    /// The set of (legacy) U2f device metadata that exists within the Metadata Statement.
    pub u2f: Vec<rc::Rc<U2F>>,
}

impl From<RawFidoMds> for FidoMds {
    fn from(rawmds: RawFidoMds) -> Self {
        let mut fido2 = Vec::new();
        let mut uaf = Vec::new();
        let mut u2f = Vec::new();

        rawmds
            .entries
            .into_iter()
            .filter_map(|device| device.try_into().ok())
            .for_each(|fd| match fd {
                FidoDevice::Uaf(dev) => uaf.push(dev),
                FidoDevice::U2F(dev) => {
                    // let akis = dev.attestation_certificate_key_identifiers.clone();
                    let dev = rc::Rc::new(dev);

                    u2f.push(dev);
                }
                FidoDevice::FIDO2(dev) => {
                    let dev = rc::Rc::new(dev);
                    fido2.push(dev)
                }
            });

        // Sort
        fido2.sort_unstable_by(|a, b| {
            // a.description.cmp(&b.description)
            a.aaguid.cmp(&b.aaguid)
        });
        u2f.sort_unstable_by(|a, b| a.description.cmp(&b.description));
        uaf.sort_unstable_by(|a, b| a.description.cmp(&b.description));

        FidoMds { fido2, uaf, u2f }
    }
}

impl FromStr for FidoMds {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RawFidoMds::from_str(s).map(|rawmds| rawmds.into())
    }
}

impl FidoMds {
    pub fn fido2_query(&self, query: &Query) -> Option<Vec<rc::Rc<FIDO2>>> {
        debug!(?query);

        // Iterate over the set of metadata.
        let fds = self
            .fido2
            .iter()
            .filter(|fd| fd.query_match(query))
            // This is cheap due to Rc,
            .cloned()
            .collect::<Vec<rc::Rc<FIDO2>>>();

        // If != empty.
        if fds.is_empty() {
            None
        } else {
            Some(fds)
        }
    }

    pub fn fido2_to_attestation_ca_list(fds: &[rc::Rc<FIDO2>]) -> Option<AttestationCaList> {
        let mut att_ca_builder = AttestationCaListBuilder::new();

        for fd in fds {
            for ca in fd.attestation_root_certificates.iter() {
                trace!(?fd);

                att_ca_builder
                    .insert_device_der(
                        ca.as_slice(),
                        fd.aaguid,
                        fd.description.clone(),
                        fd.alternative_descriptions.clone(),
                    )
                    .map_err(|err| {
                        error!(?err, "Failed to add FIDO2 device to attestation ca list");
                    })
                    .ok()?;
            }
        }

        Some(att_ca_builder.build())
    }
}
