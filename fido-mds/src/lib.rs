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
#![warn(missing_docs)]
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

use crate::mds::AuthenticatorStatus;
use crate::mds::FidoDevice as RawFidoDevice;
use crate::mds::FidoMds as RawFidoMds;
use crate::mds::MetadataStatement as RawMetadataStatement;
use crate::mds::StatusReport as RawStatusReport;
use crate::mds::UserVerificationMethod as RawUserVerificationMethod;
use crate::mds::VerificationMethodAndCombinations;

use crate::mds::{
    AttestationType, AuthenticationAlgorithm, AuthenticatorGetInfo, BiometricAccuracyDescriptor,
    CodeAccuracyDescriptor, EcdaaAnchor, ExtensionDescriptor, KeyProtection,
    PatternAccuracyDescriptor, ProtocolFamily, PublicKeyAlg,
};

use compact_jwt::JwtError;
use std::cmp::Ordering;
use std::fmt;
use std::rc;
use std::str::FromStr;
use tracing::{debug, warn};

use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

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

impl StatusReport {
    /// Retrieve the effective date of this report
    fn effective_date(&self) -> Option<&str> {
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
#[derive(Debug, Clone)]
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

impl PartialEq for UserVerificationMethod {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl fmt::Display for UserVerificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserVerificationMethod::None => write!(f, "None"),
            UserVerificationMethod::PresenceInternal => write!(f, "PresenceInternal"),
            UserVerificationMethod::PasscodeInternal(_) => write!(f, "PasscodeInternal"),
            UserVerificationMethod::PasscodeExternal(_) => write!(f, "PasscodeExternal"),
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
}

impl fmt::Display for FIDO2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.aaguid, self.description)
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
            user_verification_details,
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
            authenticator_get_info,
        } = metadata_statement;

        let status_reports: BTreeSet<_> = status_reports
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

        let attestation_root_certificates = attestation_root_certificates.into_iter()
            .filter_map(|cert| {
                let trim_cert = cert.trim();
                if trim_cert != cert {
                    warn!(
                        "Invalid attestation root certificate - leading/trailing whitespace: {:?}, {:?}, {:?}",
                        aaid, aaguid, attestation_certificate_key_identifiers
                    );
                    invalid_metadata = true;
                    None
                } else {
                    match base64::decode_config(trim_cert, base64::STANDARD) {
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

        let user_verification_details: Vec<Vec<_>> = user_verification_details.into_iter()
            .map(|inner| {
                inner.into_iter()
                    .filter_map(|uvm| {
                        uvm.try_into()
                            .map_err(|_| {
                                warn!(
                                    "Invalid user verification details located in: {:?}, {:?}, {:?}",
                                    aaid, aaguid, attestation_certificate_key_identifiers
                                );
                                invalid_metadata = true;
                            })
                            .ok()
                    })
                    .collect()
            })
            .collect();

        user_verification_details.iter().for_each(|uvm_or| {
            if uvm_or.contains(&UserVerificationMethod::None) && uvm_or.len() != 1 {
                debug!(?uvm_or);
                warn!(
                    "Illogical user verification method located in - None may not exist with other UVM: {:?}, {:?}, {:?}",
                    aaid, aaguid, attestation_certificate_key_identifiers
                );
            }
        });

        if !supported_extensions.is_empty() && authenticator_get_info.is_some() {
            warn!(
                "Inconsistent supported extension descriptors in - {:?}, {:?}, {:?}",
                aaid, aaguid, attestation_certificate_key_identifiers
            );
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
    /// The set of FIDO2 device metadata that exists within the Metadata Statement.
    pub fido2: BTreeMap<Uuid, FIDO2>,
    /// The set of (legacy) UAF device metadata that exists within the Metadata Statement.
    pub uaf: BTreeMap<String, UAF>,
    /// The set of (legacy) U2f device metadata that exists within the Metadata Statement.
    pub u2f: BTreeMap<String, rc::Rc<U2F>>,
}

impl From<RawFidoMds> for FidoMds {
    fn from(rawmds: RawFidoMds) -> Self {
        let mut fido2 = BTreeMap::new();
        let mut uaf = BTreeMap::new();
        let mut u2f = BTreeMap::new();

        rawmds
            .entries
            .into_iter()
            .filter_map(|device| device.try_into().ok())
            .for_each(|fd| match fd {
                FidoDevice::Uaf(dev) => {
                    uaf.insert(dev.aaid.clone(), dev);
                }
                FidoDevice::U2F(dev) => {
                    let akis = dev.attestation_certificate_key_identifiers.clone();
                    let dev = rc::Rc::new(dev);

                    akis.into_iter().for_each(|aki| {
                        u2f.insert(aki, dev.clone());
                    })
                }
                FidoDevice::FIDO2(dev) => {
                    fido2.insert(dev.aaguid, dev);
                }
            });

        FidoMds { fido2, uaf, u2f }
    }
}

impl FromStr for FidoMds {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RawFidoMds::from_str(s).map(|rawmds| rawmds.into())
    }
}
