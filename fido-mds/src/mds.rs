//! An implementation of the types for the fido metadata service as defined by
//! <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html>
//!
//! This allows parsing the fido metadata blob and consuming it's content. See `FidoMds`
//! for more.

use compact_jwt::{crypto::JwsX509VerifierBuilder, JwsCompact, JwsVerifier, JwtError};
use openssl::x509;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use uuid::Uuid;

static GLOBAL_SIGN_ROOT_CA_R3: &str = r#"
-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----
"#;

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-format

fn assume_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Unclear
pub struct Upv {
    /// Major
    pub major: u16,
    /// Minor
    pub minor: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification methods.
pub struct CodeAccuracyDescriptor {
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// The numeric system base (radix) of the code, e.g. 10 in the case of decimal digits.
    pub base: u16,
    /// The minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
    pub min_length: u16,
    /// Maximum number of false attempts before the authenticator will block this method (at least
    /// for some time). 0 means it will never block.
    pub max_retries: Option<u16>,
    /// Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or
    /// similar). 0 means this user verification method will be blocked, either permanently or until
    /// an alternative user verification method method succeeded. All alternative user verification
    /// methods must be specified appropriately in the Metadata in userVerificationDetails.
    pub block_slowdown: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// The BiometricAccuracyDescriptor describes relevant accuracy/complexity aspects in the case of a biometric user verification method.
pub struct BiometricAccuracyDescriptor {
    /// The false rejection rate [ISOIEC-19795-1] for a single template, i.e. the percentage of
    /// verification transactions with truthful claims of identity that are incorrectly denied. For
    /// example a FRR of 10% would be encoded as 0.1.
    ///
    /// This value is self attested and, if the authenticator passed biometric certification, the
    /// data is an independently verified FRR as measured when meeting the FRR target specified in
    /// the biometric certification requirements FIDOBiometricsRequirements for the indicated
    /// biometric certification level (see certLevel in related biometricStatusReport as specified
    /// in FIDOMetadataService).
    #[serde(rename = "selfAttestedFRR")]
    pub self_attested_frr: Option<f32>,
    /// The false acceptance rate ISOIEC-19795-1 for a single template, i.e. the percentage of
    /// verification transactions with wrongful claims of identity that are incorrectly confirmed.
    /// For example a FAR of 0.002% would be encoded as 0.00002.
    ///
    /// This value is self attested and, if the authenticator passed biometric certification, the
    /// data is an independently verified FAR specified in the biometric certification requirements
    /// FIDOBiometricsRequirements for the indicated biomeric certification level (see certLevel
    /// in related biometricStatusReport as specified in FIDOMetadataService).
    #[serde(rename = "selfAttestedFAR")]
    pub self_attested_far: Option<f32>,

    /// Maximum number of alternative templates from different fingers allowed (for other modalities,
    /// multiple parts of the body that can be used interchangeably), e.g. 3 if the user is allowed
    /// to enroll up to 3 different fingers to a fingerprint based authenticator.
    pub max_templates: Option<u16>,
    /// Maximum number of false attempts before the authenticator will block this method (at least
    /// for some time). 0 means it will never block.
    pub max_retries: Option<u16>,
    /// Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or
    /// similar). 0 means that this user verification method will be blocked either permanently or
    /// until an alternative user verification method succeeded. All alternative user verification
    /// methods must be specified appropriately in the metadata in userVerificationDetails.
    pub block_slowdown: Option<u16>,

    /// ⚠️  WARNING - CONTENT AND USE OF THIS VALUE IS NOT DOCUMENTED BY FIDO
    #[serde(rename = "iAPARThreshold")]
    pub iapar_threshold: Option<serde_json::Value>,
}

impl Hash for BiometricAccuracyDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.self_attested_frr
            .map(|f| f.to_le_bytes())
            .unwrap_or([0; 4])
            .hash(state);
        self.self_attested_far
            .map(|f| f.to_le_bytes())
            .unwrap_or([0; 4])
            .hash(state);
        self.max_templates.hash(state);
        self.max_retries.hash(state);
        self.block_slowdown.hash(state);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// The PatternAccuracyDescriptor describes relevant accuracy/complexity aspects in the case that a
/// pattern is used as the user verification method.
pub struct PatternAccuracyDescriptor {
    /// ❌ NOTE - The FIDO metadata values for this value are broken and can not be parsed.
    ///
    /// Number of possible patterns (having the minimum length) out of which exactly one would be
    /// the right one, i.e. 1/probability in the case of equal distribution.
    pub min_complexity: serde_json::Value,
    /// Maximum number of false attempts before the authenticator will block authentication using
    /// this method (at least temporarily). 0 means it will never block.
    pub max_retries: Option<u16>,
    /// Enforced minimum number of seconds wait time after blocking (due to forced reboot or similar
    /// mechanism). 0 means this user verification method will be blocked, either permanently or
    /// until an alternative user verification method method succeeded. All alternative user
    /// verification methods must be specified appropriately in the metadata under
    /// userVerificationDetails.
    pub block_slowdown: Option<u16>,
}

impl Hash for PatternAccuracyDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.max_retries
            .map(|f| f.to_le_bytes())
            .unwrap_or([0; 2])
            .hash(state);
        self.block_slowdown
            .map(|f| f.to_le_bytes())
            .unwrap_or([0; 2])
            .hash(state);
    }
}

/// User Verification Methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserVerificationMethod {
    /// None
    #[serde(rename = "none")]
    None,
    /// All. MUST NOT APPEAR IN ANY UVM.
    #[serde(rename = "all")]
    All,
    /// presence_internal
    #[serde(rename = "presence_internal")]
    PresenceInternal,
    /// passcode_internal
    #[serde(rename = "passcode_internal")]
    PasscodeInternal,
    /// passcode_external
    #[serde(rename = "passcode_external")]
    PasscodeExternal,
    /// fingerprint_internal
    #[serde(rename = "fingerprint_internal")]
    FingerprintInternal,
    /// handprint_internal
    #[serde(rename = "handprint_internal")]
    HandprintInternal,
    /// eyeprint_internal
    #[serde(rename = "eyeprint_internal")]
    EyeprintInternal,
    /// pattern_internal
    #[serde(rename = "pattern_internal")]
    PatternInternal,
    /// voiceprint_internal
    #[serde(rename = "voiceprint_internal")]
    VoiceprintInternal,
    /// location_internal
    #[serde(rename = "location_internal")]
    LocationInternal,
    /// faceprint_internal
    #[serde(rename = "faceprint_internal")]
    FaceprintInternal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// A descriptor for a specific base user verification method as implemented by the authenticator.
pub struct VerificationMethodAndCombinations {
    /// a single USER_VERIFY constant case-sensitive string name. See section "User Verification
    /// Methods" in FIDORegistry (e.g. "presence_internal"). This value MUST NOT be empty.
    pub user_verification_method: UserVerificationMethod,
    /// May optionally be used in the case of method USER_VERIFY_PASSCODE_INTERNAL or USER_VERIFY_PASSCODE_EXTERNAL.
    pub ca_desc: Option<CodeAccuracyDescriptor>,
    /// May optionally be used in the case of method USER_VERIFY_FINGERPRINT_INTERNAL,
    /// USER_VERIFY_VOICEPRINT_INTERNAL, USER_VERIFY_FACEPRINT_INTERNAL,
    /// USER_VERIFY_EYEPRINT_INTERNAL, or USER_VERIFY_HANDPRINT_INTERNAL.
    pub ba_desc: Option<BiometricAccuracyDescriptor>,
    /// May optionally be used in case of method USER_VERIFY_PATTERN_INTERNAL or USER_VERIFY_PATTERN_EXTERNAL
    pub pa_desc: Option<PatternAccuracyDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor must be specified in this field.
pub struct EcdaaAnchor {
    /// base64url encoding of the result of ECPoint2ToB of the ECPoint2 X = P_2^xX=P
    /// See FIDOEcdaaAlgorithm for the definition of ECPoint2ToB.
    #[serde(rename = "X")]
    pub x: String,
    /// base64url encoding of the result of ECPoint2ToB of the ECPoint2 Y = P_2^yY=P
    /// See FIDOEcdaaAlgorithm for the definition of ECPoint2ToB.
    #[serde(rename = "Y")]
    pub y: String,
    /// base64url encoding of the result of BigNumberToB(cc). See section "Issuer Specific ECDAA Parameters" in FIDOEcdaaAlgorithm for an explanation of cc. See FIDOEcdaaAlgorithm for the definition of BigNumberToB.
    pub c: String,
    /// base64url encoding of the result of BigNumberToB(sxsx). See section "Issuer Specific ECDAA Parameters" in FIDOEcdaaAlgorithm for an explanation of sxsx. See FIDOEcdaaAlgorithm for the definition of BigNumberToB.
    pub sx: String,
    /// base64url encoding of the result of BigNumberToB(sysy). See section "Issuer Specific ECDAA Parameters" in FIDOEcdaaAlgorithm for an explanation of sysy. See FIDOEcdaaAlgorithm for the definition of BigNumberToB.
    pub sy: String,
    /// Name of the Barreto-Naehrig elliptic curve for G1. "BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported. See section "Supported Curves for ECDAA" in FIDOEcdaaAlgorithm for details.
    #[serde(rename = "G1Curve")]
    pub g1curve: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// This descriptor contains an extension supported by the authenticator.
pub struct ExtensionDescriptor {
    /// Identifies the extension.
    pub id: String,
    /// The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.
    pub tag: Option<u16>,
    /// Contains arbitrary data further describing the extension and/or data needed to correctly process the extension.
    pub data: Option<String>,
    /// Indicates whether unknown extensions must be ignored (false) or must lead to an error (true)
    /// when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
    ///
    /// A value of false indicates that unknown extensions must be ignored
    ///
    /// A value of true indicates that unknown extensions must result in an error.
    pub fail_if_unknown: bool,
}

/// The assertion scheme in use by this device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AssertionScheme {
    /// No assertion scheme was provided
    #[default]
    Unknown,
    /// Fido 2
    #[serde(rename = "FIDOV2")]
    FidoV2,
}

/// The family of protocols this device belongs to.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum ProtocolFamily {
    /// No protocol family was provided
    #[default]
    Unknown,
    /// Uaf
    #[serde(rename = "uaf")]
    Uaf,
    /// Universal Second Factor
    #[serde(rename = "u2f")]
    U2f,
    /// Fido 2. This is the preferred type
    #[serde(rename = "fido2")]
    Fido2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The list of authentication algorithms supported by the authenticator.
pub enum AuthenticationAlgorithm {
    /// secp256r1_ecdsa_sha256_raw
    #[serde(rename = "secp256r1_ecdsa_sha256_raw")]
    Secp256r1EcdsaSha256Raw,
    /// secp256r1_ecdsa_sha256_der
    #[serde(rename = "secp256r1_ecdsa_sha256_der")]
    Secp256r1EcdsaSha256Der,
    /// secp256k1_ecdsa_sha256_raw
    #[serde(rename = "secp256k1_ecdsa_sha256_raw")]
    Secp256K1EcdsaSha256Raw,
    /// rsa_emsa_pkcs1_sha256_raw
    #[serde(rename = "rsa_emsa_pkcs1_sha256_raw")]
    RsaEmsaPkcs1Sha256Raw,
    /// ed25519_eddsa_sha512_raw
    #[serde(rename = "ed25519_eddsa_sha512_raw")]
    Ed25519EddsaSha512Raw,
    /// secp384r1_ecdsa_sha384_raw
    #[serde(rename = "secp384r1_ecdsa_sha384_raw")]
    Secp384r1EcdsaSha384Raw,
    /// secp521r1_ecdsa_sha512_raw
    #[serde(rename = "secp521r1_ecdsa_sha512_raw")]
    Secp521r1EcdsaSha512Raw,
    /// rsassa_pkcsv15_sha256_raw
    #[serde(rename = "rsassa_pkcsv15_sha256_raw")]
    RsassaPkcsv15Sha256Raw,
    /// rsassa_pkcsv15_sha1_raw
    #[serde(rename = "rsassa_pkcsv15_sha1_raw")]
    RsassaPkcsv15Sha1Raw,
    /// rsassa_pss_sha256_raw
    #[serde(rename = "rsassa_pss_sha256_raw")]
    RsassaPssSha256Raw,
}

impl fmt::Display for AuthenticationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticationAlgorithm::Secp256r1EcdsaSha256Raw => {
                write!(f, "secp256r1_ecdsa_sha256_raw")
            }
            AuthenticationAlgorithm::Secp256r1EcdsaSha256Der => {
                write!(f, "secp256r1_ecdsa_sha256_der")
            }
            AuthenticationAlgorithm::Secp256K1EcdsaSha256Raw => {
                write!(f, "secp256k1_ecdsa_sha256_raw")
            }
            AuthenticationAlgorithm::RsaEmsaPkcs1Sha256Raw => {
                write!(f, "rsa_emsa_pkcs1_sha256_raw")
            }
            AuthenticationAlgorithm::Ed25519EddsaSha512Raw => write!(f, "ed25519_eddsa_sha512_raw"),
            AuthenticationAlgorithm::Secp384r1EcdsaSha384Raw => {
                write!(f, "secp384r1_ecdsa_sha384_raw")
            }
            AuthenticationAlgorithm::Secp521r1EcdsaSha512Raw => {
                write!(f, "secp521r1_ecdsa_sha512_raw")
            }
            AuthenticationAlgorithm::RsassaPkcsv15Sha256Raw => {
                write!(f, "rsassa_pkcsv15_sha256_raw")
            }
            AuthenticationAlgorithm::RsassaPkcsv15Sha1Raw => {
                write!(f, "rsassa_pkcsv15_sha1_raw")
            }
            AuthenticationAlgorithm::RsassaPssSha256Raw => {
                write!(f, "rsassa_pss_sha256_raw")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The public key format used by the authenticator during registration operations.
pub enum PublicKeyAlg {
    /// ecc_x962_raw
    #[serde(rename = "ecc_x962_raw")]
    EccX962Raw,
    /// ecc_x962_der
    #[serde(rename = "ecc_x962_der")]
    EccX962Der,
    /// rsa_2048_raw
    #[serde(rename = "rsa_2048_raw")]
    Rsa2048Raw,
    /// cose
    #[serde(rename = "cose")]
    Cose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A type of attestation
pub enum AttestationType {
    /// basic_full
    #[serde(rename = "basic_full")]
    BasicFull,
    /// basic_surrogate
    #[serde(rename = "basic_surrogate")]
    BasicSurrogate,
    /// attca
    #[serde(rename = "attca")]
    AttCa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The class of key protection.
pub enum KeyProtection {
    /// The key is stored in hardware. This is exclusive to `software`
    #[serde(rename = "hardware")]
    Hardware,
    /// Secure Element
    #[serde(rename = "secure_element")]
    SecureElement,
    /// The private key is stored in a key-wrapped-key. This can still be "hardware" backed
    /// where the KWK can only be decrypted by a specific device's hardware.
    #[serde(rename = "remote_handle")]
    RemoteHandle,
    /// Trusted Execution Environment.
    #[serde(rename = "tee")]
    Tee,
    /// The key is stored in software. This is exclusive to `hardware`
    #[serde(rename = "software")]
    Software,
}

/// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MatcherProtection {
    /// on_chip
    #[serde(rename = "on_chip")]
    OnChip,
    /// tee
    #[serde(rename = "tee")]
    Tee,
    /// software
    #[serde(rename = "software")]
    Software,
}

/// Attachment hint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AttachmentHint {
    /// external
    #[serde(rename = "external")]
    External,
    /// wired
    #[serde(rename = "wired")]
    Wired,
    /// wireless
    #[serde(rename = "wireless")]
    Wireless,
    /// nfc
    #[serde(rename = "nfc")]
    Nfc,
    /// internal
    #[serde(rename = "internal")]
    Internal,
    /// bluetooth
    #[serde(rename = "bluetooth")]
    Bluetooth,
    /// network
    #[serde(rename = "network")]
    Network,
    /// wifi-direct
    #[serde(rename = "wifi_direct")]
    WifiDirect,
}

/// The authenticator versions this device supports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticatorVersion {
    /// U2F
    #[serde(rename = "U2F_V2")]
    U2fV2,
    /// FIDO 2.0
    #[serde(rename = "FIDO_2_0")]
    Fido2_0,
    /// FIDO 2.1 PRE
    #[serde(rename = "FIDO_2_1_PRE")]
    Fido2_1Pre,
    /// FIDO 2.1
    #[serde(rename = "FIDO_2_1")]
    Fido2_1,
}

impl fmt::Display for AuthenticatorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticatorVersion::U2fV2 => write!(f, "U2F V2"),
            AuthenticatorVersion::Fido2_0 => write!(f, "FIDO 2.0"),
            AuthenticatorVersion::Fido2_1Pre => write!(f, "FIDO 2.1 PRE"),
            AuthenticatorVersion::Fido2_1 => write!(f, "FIDO 2.1"),
        }
    }
}

/// The authenticator transports that this device supports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticatorTransport {
    /// usb
    #[serde(rename = "usb")]
    Usb,
    /// nfc
    #[serde(rename = "nfc")]
    Nfc,
    /// lightning
    #[serde(rename = "lightning")]
    Lightning,
    /// ble
    #[serde(rename = "ble")]
    Ble,
    /// internal
    #[serde(rename = "internal")]
    Internal,
    /// wireless
    #[serde(rename = "wireless")]
    Wireless,
    /// hybrid (formerly caBLE)
    #[serde(rename = "hybrid")]
    Hybrid,
}

impl fmt::Display for AuthenticatorTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticatorTransport::Usb => write!(f, "usb"),
            AuthenticatorTransport::Nfc => write!(f, "nfc"),
            AuthenticatorTransport::Lightning => write!(f, "lightning"),
            AuthenticatorTransport::Ble => write!(f, "ble"),
            AuthenticatorTransport::Internal => write!(f, "internal"),
            AuthenticatorTransport::Wireless => write!(f, "wireless"),
            AuthenticatorTransport::Hybrid => write!(f, "hybrid (caBLE)"),
        }
    }
}

impl FromStr for AuthenticatorTransport {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "usb" => Ok(AuthenticatorTransport::Usb),
            "nfc" => Ok(AuthenticatorTransport::Nfc),
            "lightning" => Ok(AuthenticatorTransport::Lightning),
            "ble" => Ok(AuthenticatorTransport::Ble),
            "internal" => Ok(AuthenticatorTransport::Internal),
            "wireless" => Ok(AuthenticatorTransport::Wireless),
            _ => Err(()),
        }
    }
}

/// Describes this device's capability to allow credentials to be
/// accessible to a single device, or multiple devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MultiDeviceCredentialSupport {
    /// Multiple devices are not supported, this credential is bound to one
    /// device.
    #[default]
    Unsupported,
    /// The authenticator will provide its multiple device support during
    /// registration through setting the flag "backup eligible".
    Explicit,
    /// This authenticator always is multi device
    Implicit,
}

impl fmt::Display for MultiDeviceCredentialSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "unsupported (no)"),
            Self::Explicit => write!(f, "explicit (see backup_eligible flag)"),
            Self::Implicit => write!(f, "implicit (yes)"),
        }
    }
}


/// The output of authenticatorGetInfo. Some fields are hidden as they are duplicated
/// in the metadata statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticatorGetInfo {
    /// The list of supported CTAP versions
    pub versions: Vec<AuthenticatorVersion>,
    /// The list of supported extension identifiers.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// The AAGUID (UUID) of this device
    pub aaguid: Uuid,
    /// List of supported Options
    #[serde(default)]
    pub options: BTreeMap<String, bool>,
    /// The largest ctap message size this device supports
    pub max_msg_size: Option<u32>,
    /// The list of PIN UV auth protocols
    #[serde(default)]
    pub pin_uv_auth_protocols: Vec<u32>,
    /// The maximum number of credentials ID's that can be listed and provided to this device.
    pub max_credential_count_in_list: Option<u32>,
    /// The maximum length of a credential ID that can be provided to this device.
    pub max_credential_id_length: Option<u32>,
    /// The list of transports this device supports
    #[serde(default)]
    pub transports: Vec<AuthenticatorTransport>,
    #[serde(default)]
    pub(crate) algorithms: Vec<serde_json::Value>,
    /// The maximum size of large blob array this device can store, if the extension is supported.
    pub max_serialized_large_blob_array: Option<u32>,
    #[serde(rename = "forcePINChange")]
    force_pin_change: Option<bool>,
    /// The minimum pin length that this device requires.
    #[serde(rename = "minPINLength")]
    pub min_pin_length: Option<u32>,
    firmware_version: Option<u32>,
    /// The maximum size of the credBlob if supported
    pub max_cred_blob_length: Option<u32>,
    /// The maximum number of discoverable (resident) keys this device supports.
    #[serde(rename = "maxRPIDsForSetMinPINLength")]
    pub max_rpids_for_set_min_pin_length: Option<u32>,
    /// _
    pub preferred_platform_uv_attempts: Option<u32>,
    uv_modality: Option<u32>,
    #[serde(default)]
    pub certifications: BTreeMap<String, u32>,
    /// The number of remaining resident keys on this device.
    pub remaining_discoverable_credentials: Option<u32>,
    /// Vendor specific details
    #[serde(default)]
    pub vendor_prototype_config_commands: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// A statement describing a device and it's associated properties.
pub struct MetadataStatement {
    /// Legal Header
    pub legal_header: Option<String>,
    /// The Authenticator Attestation ID. See UAFProtocol for the definition of the AAID structure.
    /// This field must be set if the authenticator implements FIDO UAF.
    pub aaid: Option<String>,
    /// The Authenticator Attestation GUID. See FIDOKeyAttestation for the definition of the
    /// AAGUID structure. This field must be set if the authenticator implements FIDO 2.
    pub aaguid: Option<Uuid>,
    /// A list of the attestation certificate public key identifiers encoded as hex string. This
    /// value must be calculated according to method 1 for computing the keyIdentifier as defined
    /// in RFC5280 section 4.2.1.2. The hex string must not contain any non-hex characters
    /// (e.g. spaces). All hex letters must be lower case. This field must be set if neither aaid
    /// nor aaguid are set. Setting this field implies that the attestation certificate(s) are
    /// dedicated to a single authenticator model.
    ///
    /// All attestationCertificateKeyIdentifier values should be unique within the scope of the Metadata Service.
    pub attestation_certificate_key_identifiers: Option<Vec<String>>,
    /// A human-readable, short description of the authenticator, in English.
    pub description: String,
    /// A list of human-readable short descriptions of the authenticator in different languages.
    #[serde(default)]
    pub alternative_descriptions: BTreeMap<String, String>,
    /// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified
    /// in this metadata statement.
    ///
    /// Adding new StatusReport entries with status UPDATE_AVAILABLE to the metadata TOC object
    /// FIDOMetadataService must also change this authenticatorVersion if the update fixes severe
    /// security issues, e.g. the ones reported by preceding StatusReport entries with status code
    /// USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE, USER_KEY_PHYSICAL_COMPROMISE, REVOKED.
    ///
    /// It is recommended to assume increased risk if this version is higher (newer) than the
    /// firmware version present in an authenticator. For example, if a StatusReport entry with
    /// status USER_VERIFICATION_BYPASS or USER_KEY_REMOTE_COMPROMISE precedes the UPDATE_AVAILABLE
    /// entry, than any firmware version lower (older) than the one specified in the metadata statement
    /// is assumed to be vulnerable.
    pub authenticator_version: u32,
    /// The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported. If this field
    /// is missing, the assumed protocol family is "uaf". Metadata Statements for U2F authenticators
    /// must set the value of protocolFamily to "u2f" and FIDO 2.0/WebAuthentication Authenticator
    /// implementations must set the value of protocolFamily to "fido2".
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub protocol_family: ProtocolFamily,
    /// Version of this structure
    pub schema: u16,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// The FIDO unified protocol version(s) (related to the specific protocol family) supported by
    /// this authenticator. See UAFProtocol for the definition of the Version structure.
    pub upv: Vec<Upv>,
    /// The list of authentication algorithms supported by the authenticator. Must be set to the
    /// complete list of the supported ALG_ constants defined in the FIDO Registry of Predefined
    /// Values FIDORegistry if the authenticator supports multiple algorithms. Each value must be non-zero.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub authentication_algorithms: Vec<AuthenticationAlgorithm>,
    /// The list of public key formats supported by the authenticator during registration operations.
    /// Must be set to the complete list of the supported ALG_KEY constants defined in the FIDO Registry
    /// of Predefined Values FIDORegistry if the authenticator model supports multiple encodings.
    /// Because this information is not present in APIs related to authenticator discovery or policy,
    /// a FIDO server must be prepared to accept and process any and all key representations defined
    /// for any public key algorithm it supports. Each value must be non-zero.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub public_key_alg_and_encodings: Vec<PublicKeyAlg>,
    /// The supported attestation type(s). (e.g. TAG_ATTESTATION_BASIC_FULL(0x3E07), TAG_ATTESTATION_BASIC_SURROGATE(0x3E08)).
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub attestation_types: Vec<AttestationType>,
    /// A list of alternative VerificationMethodANDCombinations.
    ///
    /// userVerificationDetails is a two dimensional array, that informs RP what
    /// VerificationMethodANDCombinations user may be required to perform in order to pass user
    /// verification, e.g User need to pass fingerprint, or faceprint, or password and palm print, etc.
    ///
    /// The outer array is an OR over the values, and the inner arrays are ANDs. For example:
    ///
    ///
    /// [
    ///   [
    ///      { user_verification_method: ... }
    ///   ],
    ///   // OR
    ///   [
    ///      { user_verification_method: ... },
    ///      // AND
    ///      { user_verification_method: ... }
    ///   ],
    /// ]
    ///
    pub user_verification_details: Vec<Vec<VerificationMethodAndCombinations>>,
    /// The list of key protection types supported by the authenticator. Must be set to the complete
    /// list of the supported KEY_PROTECTION_ constant case-sensitive string names.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub key_protection: Vec<KeyProtection>,
    /// This entry is set to true, if the Uauth private key is restricted by the authenticator to
    /// only sign valid FIDO signature assertions.
    ///
    /// This entry is set to false, if the authenticator doesn't restrict the Uauth key to only
    /// sign valid FIDO signature assertions. In this case, the calling application could potentially
    /// get any hash value signed by the authenticator.
    ///
    /// If this field is missing, the assumed value is isKeyRestricted=true
    #[serde(default = "assume_true")]
    pub is_key_restricted: bool,
    /// This entry is set to true, if Uauth key usage always requires a fresh user verification.
    ///
    /// If this field is missing, the assumed value is isFreshUserVerificationRequired=true.
    ///
    /// This entry is set to false, if the Uauth key can be used without requiring a fresh user
    /// verification, e.g. without any additional user interaction, if the user was verified a
    /// (potentially configurable) caching time ago.
    ///
    /// In the case of isFreshUserVerificationRequired=false, the FIDO server must verify the
    /// registration response and/or authentication response and verify that the (maximum) caching
    /// time (sometimes also called "authTimeout") is acceptable.
    ///
    /// This entry solely refers to the user verification. In the case of transaction confirmation,
    /// the authenticator must always ask the user to authorize the specific transaction.
    #[serde(default = "assume_true")]
    pub is_fresh_user_verification_required: bool,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub matcher_protection: Vec<MatcherProtection>,
    /// The authenticator's overall claimed cryptographic strength in bits (sometimes also called
    /// security strength or security level). This is the minimum of the cryptographic strength of
    /// all involved cryptographic methods (e.g. RNG, underlying hash, key wrapping algorithm,
    /// signing algorithm, attestation algorithm), e.g. see FIPS180-4, FIPS186-4, FIPS198-1,
    /// SP800-38B, SP800-38C, SP800-38D, SP800-38F, SP800-90C, SP800-90ar1, FIPS140-2 etc.
    ///
    /// If this value is absent, the cryptographic strength is unknown. If the cryptographic strength
    /// of one of the involved cryptographic methods is unknown the overall claimed cryptographic
    /// strength is also unknown.
    pub crypto_strength: Option<u16>,
    /// 🤔 Authors Note: Generally attachment hint is a very problematic thing to provide to browsers
    /// as they are not always used or expected in work flows. It's likely this field is "useless"
    /// as a result.
    ///
    /// A list of attachment hints that MAY be used with this device.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub attachment_hint: Vec<AttachmentHint>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// A 16-bit number representing a combination of the bit flags defined by the
    /// TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values FIDORegistry.
    /// This value must be 0, if transaction confirmation is not supported by the authenticator.
    pub tc_display: Vec<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    pub tc_display_content_type: Option<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    #[serde(rename = "tcDisplayPNGCharacteristics")]
    pub tc_display_png_characteristics: Option<serde_json::Value>,
    /// ❌ NOTE - The FIDO metadata specification defines this as a an array of base64 values, however
    /// many values are INVALID and contain leading/trailing whitespace that MAY confuse your base64 parser
    ///
    /// ⚠️  WARNING - Content of this value MAY have extra leading or trailing whitespace which MAY
    /// cause issues when parsing.
    ///
    /// Each element of this array represents a PKIX RFC5280 X.509 certificate that is a valid
    /// trust anchor for this authenticator model. Multiple certificates might be used for different
    /// batches of the same model. The array does not represent a certificate chain, but only the
    /// trust anchor of that chain. A trust anchor can be a root certificate, an intermediate CA
    /// certificate or even the attestation certificate itself.
    ///
    /// Each array element is a base64-encoded (section 4 of RFC4648), DER-encoded ITU-X690-2008
    /// PKIX certificate value. Each element must be dedicated for authenticator attestation.
    ///
    // /// ❗️ This is decoded from Base64 for you so that you can directly access the DER of the certificate.
    // attestation_root_certificates: Vec<Base64UrlSafeData>,
    pub attestation_root_certificates: Vec<String>,
    /// A list of trust anchors used for ECDAA attestation. This entry must be present if and only
    /// if attestationType includes TAG_ATTESTATION_ECDAA. The entries in attestationRootCertificates
    /// have no relevance for ECDAA attestation. Each ecdaaTrustAnchor must be dedicated to a single
    /// authenticator model (e.g as identified by its AAID/AAGUID).
    #[serde(default)]
    pub ecdaa_trust_anchors: Vec<EcdaaAnchor>,
    /// An icon representing this device.
    pub icon: Option<serde_json::Value>,
    /// The list of supported extensions of this authenticator
    #[serde(default)]
    pub supported_extensions: Vec<ExtensionDescriptor>,
    /// Describes supported versions, extensions, AAGUID of the device and its capabilities.
    ///
    /// The information is the same reported by an authenticator when invoking the 'authenticatorGetInfo'
    /// method, see FIDOCTAP.
    pub authenticator_get_info: Option<AuthenticatorGetInfo>,

    #[serde(default)]
    /// Defines if credentials in this authenticator can be accessed on multiple
    /// devices. If set to `unsupported` this means that it is a single device
    /// credential.
    pub multi_device_credential_support: MultiDeviceCredentialSupport,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// See `BiometricsStatusReport`
pub enum BiometricModality {
    /// No valid biometric modality was provided.
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// A status report for the device if it provides biometrics
pub struct BiometricsStatusReport {
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// Achieved level of the biometric certification of this biometric component of the authenticator
    pub cert_level: u16,
    /// A single a single USER_VERIFY short form case-sensitive string name constant, representing
    /// biometric modality. See section "User Verification Methods" in FIDORegistry
    /// (e.g. "fingerprint_internal").
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub modality: BiometricModality,
    /// ISO-8601 formatted date since when the certLevel achieved, if applicable. If no date is
    /// given, the status is assumed to be effective while present.
    pub effective_date: Option<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// Describes the externally visible aspects of the Biometric Certification evaluation.
    ///
    /// For example, if it states "on chip" this means the biometrics are kept inside the device only
    pub certification_descriptor: Option<String>,
    /// The unique identifier for the issued Biometric Certification.
    pub certificate_number: Option<String>,
    /// The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".
    pub certification_policy_version: Option<String>,
    /// The version of the Biometric Requirements FIDOBiometricsRequirements the implementation is certified to, e.g. "1.0.0".
    pub certification_requirements_version: Option<String>,
}

/// The fido certification status of the device associated to this aaid/aaguid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthenticatorStatus {
    /// The device is NOT fido certified
    #[serde(rename = "NOT_FIDO_CERTIFIED")]
    NotFidoCertified,
    /// The divec is fido certified. This will be phased out in favour of the FIDO_CERTIFIED_L1
    /// field.
    #[serde(rename = "FIDO_CERTIFIED")]
    FidoCertified,
    /// Indicates that malware is able to bypass the user verification. This means that the
    /// authenticator could be used without the user’s consent and potentially even without the
    /// user’s knowledge.
    #[serde(rename = "USER_VERIFICATION_BYPASS")]
    UserVerificationBypass,
    /// Indicates that an attestation key for this authenticator is known to be compromised.
    /// The relying party SHOULD check the certificate field and use it to identify the compromised
    /// authenticator batch. If the certificate field is not set, the relying party should reject
    /// all new registrations of the compromised authenticator. The Authenticator manufacturer
    /// should set the date to the date when compromise has occurred.
    #[serde(rename = "ATTESTATION_KEY_COMPROMISE")]
    AttestationKeyCompromise,
    /// This authenticator has identified weaknesses that allow registered keys to be compromised
    /// and should not be trusted. This would include both, e.g. weak entropy that causes
    /// predictable keys to be generated or side channels that allow keys or signatures to be
    /// forged, guessed or extracted.
    #[serde(rename = "USER_KEY_REMOTE_COMPROMISE")]
    UserKeyRemoteCompromise,
    /// This authenticator has known weaknesses in its key protection mechanism(s) that allow user
    /// keys to be extracted by an adversary in physical possession of the device.
    #[serde(rename = "USER_KEY_PHYSICAL_COMPROMISE")]
    UserKeyPhysicalCompromise,
    /// A software or firmware update is available for the device. The Authenticator manufacturer
    /// should set the url to the URL where users can obtain an update and the date the update was
    /// published. When this status code is used, then the field authenticatorVersion in the
    /// authenticator Metadata Statement FIDOMetadataStatement MUST be updated, if the update fixes
    /// severe security issues, e.g. the ones reported by preceding StatusReport entries with status
    /// code USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE,
    /// USER_KEY_PHYSICAL_COMPROMISE, REVOKED. The Relying party MUST reject the Metadata Statement
    /// if the authenticatorVersion has not increased
    #[serde(rename = "UPDATE_AVAILABLE")]
    UpdateAvailable,
    /// The FIDO Alliance has determined that this authenticator should not be trusted for any
    /// reason. For example if it is known to be a fraudulent product or contain a deliberate
    /// backdoor. Relying parties SHOULD reject any future registration of this authenticator model.
    #[serde(rename = "REVOKED")]
    Revoked,
    /// The authenticator vendor has completed and submitted the self-certification checklist to
    /// the FIDO Alliance. If this completed checklist is publicly available, the URL will be
    /// specified in url.
    #[serde(rename = "SELF_ASSERTION_SUBMITTED")]
    SelfAssertionSubmitted,
    /// This device is certified at level 1
    #[serde(rename = "FIDO_CERTIFIED_L1")]
    FidoCertifiedL1,
    /// This device is certified at level 1 plus
    #[serde(rename = "FIDO_CERTIFIED_L1plus")]
    FidoCertifiedL1Plus,
    /// This device is certified at level 2
    #[serde(rename = "FIDO_CERTIFIED_L2")]
    FidoCertifiedL2,
    /// This device is certified at level 2 plus
    #[serde(rename = "FIDO_CERTIFIED_L2plus")]
    FidoCertifiedL2Plus,
    /// This device is certified at level 3
    #[serde(rename = "FIDO_CERTIFIED_L3")]
    FidoCertifiedL3,
    /// This device is certified at level 3 plus
    #[serde(rename = "FIDO_CERTIFIED_L3plus")]
    FidoCertifiedL3Plus,
}

impl FromStr for AuthenticatorStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "not-certified" => Ok(AuthenticatorStatus::NotFidoCertified),
            "uv-bypass" => Ok(AuthenticatorStatus::UserVerificationBypass),
            "key-compromise" => Ok(AuthenticatorStatus::AttestationKeyCompromise),
            "remote-exploit" => Ok(AuthenticatorStatus::UserKeyRemoteCompromise),
            "physical-compromise" => Ok(AuthenticatorStatus::UserKeyPhysicalCompromise),
            "update-available" => Ok(AuthenticatorStatus::UpdateAvailable),
            "revoked" => Ok(AuthenticatorStatus::Revoked),
            "self-asserted" => Ok(AuthenticatorStatus::SelfAssertionSubmitted),
            "valid" | "l1" => Ok(AuthenticatorStatus::FidoCertifiedL1),
            "l1+" => Ok(AuthenticatorStatus::FidoCertifiedL1Plus),
            "l2" => Ok(AuthenticatorStatus::FidoCertifiedL2),
            "l2+" => Ok(AuthenticatorStatus::FidoCertifiedL2Plus),
            "l3" => Ok(AuthenticatorStatus::FidoCertifiedL3),
            "l3+" => Ok(AuthenticatorStatus::FidoCertifiedL3Plus),
            _ => Err(()),
        }
    }
}

impl AuthenticatorStatus {
    pub(crate) fn numeric(&self) -> u8 {
        match self {
            AuthenticatorStatus::NotFidoCertified
            | AuthenticatorStatus::UserVerificationBypass
            | AuthenticatorStatus::AttestationKeyCompromise
            | AuthenticatorStatus::UserKeyRemoteCompromise
            | AuthenticatorStatus::UserKeyPhysicalCompromise
            | AuthenticatorStatus::UpdateAvailable
            | AuthenticatorStatus::Revoked
            | AuthenticatorStatus::SelfAssertionSubmitted => 0,
            AuthenticatorStatus::FidoCertified | AuthenticatorStatus::FidoCertifiedL1 => 10,
            AuthenticatorStatus::FidoCertifiedL1Plus => 11,
            AuthenticatorStatus::FidoCertifiedL2 => 20,
            AuthenticatorStatus::FidoCertifiedL2Plus => 21,
            AuthenticatorStatus::FidoCertifiedL3 => 30,
            AuthenticatorStatus::FidoCertifiedL3Plus => 31,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Contains an AuthenticatorStatus and additional data associated with it, if any.
///
/// The latest StatusReport entry MUST reflect the "current" status. For example, if the latest
/// entry has status USER_VERIFICATION_BYPASS, then it is recommended assuming an increased risk
/// associated with all authenticators of this AAID; if the latest entry has status UPDATE_AVAILABLE,
/// then the update is intended to address at least all previous issues reported in this StatusReport
/// dictionary.
pub struct StatusReport {
    /// The status of the authenticator.
    pub status: AuthenticatorStatus,
    /// ISO-8601 formatted date since when the status code was set, if applicable. If no date is
    /// given, the status is assumed to be effective while present.
    pub effective_date: Option<String>,
    /// The authenticatorVersion that this status report relates to. In the case of FIDO_CERTIFIED*
    /// status values, the status applies to higher authenticatorVersions until there is a new statusReport.
    pub authenticator_version: Option<u32>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// Base64-encoded RFC4648 (not base64url!) DER ITU-X690-2008 PKIX certificate value related
    /// to the current status, if applicable.
    pub certificate: Option<String>,
    /// HTTPS URL where additional information may be found related to the current status, if applicable.
    pub url: Option<String>,
    /// Describes the externally visible aspects of the Authenticator Certification evaluation.
    ///
    /// For example it could state that the authenticator is a "SecurityKey based on a CC EAL 5
    /// certified chip hardware".
    pub certification_descriptor: Option<String>,
    /// The unique identifier for the issued Certification.
    pub certificate_number: Option<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".
    pub certification_policy_version: Option<String>,
    /// The Document Version of the Authenticator Security Requirements (DV)
    /// FIDOAuthenticatorSecurityRequirements the implementation is certified to, e.g. "1.2.0".
    pub certification_requirements_version: Option<String>,

    /// ⚠️  WARNING - CONTENT AND USE OF THIS VALUE IS NOT DOCUMENTED BY FIDO
    certification_profiles: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// A statement describing a device and it's associated properties.
pub struct FidoDevice {
    /// If this device is identified by an aaid, it will be listed here.
    pub aaid: Option<String>,
    /// Alternately, if the device is identified by an AAGUID it will be set here. Generally all
    /// FIDO2 devices will use aaguid.
    pub aaguid: Option<Uuid>,
    /// A list of the attestation certificate public key identifiers encoded as hex string. This
    /// value MUST be calculated according to method 1 for computing the keyIdentifier as defined
    /// in RFC5280 section 4.2.1.2.
    pub attestation_certificate_key_identifiers: Option<Vec<String>>,
    /// The FIDOMetadataStatement pertaining to this device.
    pub metadata_statement: MetadataStatement,
    /// ⚠️  WARNING - 2022-08-11 - no biometric status reports have been published, so we are unable
    /// to validate the correctness of this type and it's parser.
    ///
    /// Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator
    #[serde(default)]
    pub biometric_status_reports: Vec<BiometricsStatusReport>,
    /// An array of status reports applicable to this authenticator.
    pub status_reports: Vec<StatusReport>,
    /// ISO-8601 formatted date since when the status report array was set to the current value.
    pub time_of_last_status_change: String, // iso 8601 time.
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// URL of a list of rogue (i.e. untrusted) individual authenticators.
    #[serde(rename = "rogueListURL")]
    pub rogue_list_url: Option<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// The hash value computed over the Base64url encoding of the UTF-8 representation of the JSON
    /// encoded rogueList available at rogueListURL (with type rogueListEntry). The hash algorithm
    /// related to the signature algorithm specified in the JWTHeader (see Metadata BLOB) MUST be used.
    ///
    /// This hash value MUST be present and non-empty whenever rogueListURL is present.
    pub rogue_list_hash: Option<String>,
}

impl fmt::Display for FidoDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_string_pretty(self).map_err(|_| fmt::Error)?;
        write!(f, "FidoDevice {s}")
    }
}

/// The parsed content of the Fido Metadata Server. This content can be retrieved from it's online
/// url at <https://mds.fidoalliance.org/> . It's recommended you re-download this content every few weeks. This can be parsed
/// from it's str representation - for from_str to suceed, the metadata jwt content MUST be correctly
/// signed be pinned root certificate authority, the full chain is verified, and the content of the
/// JWT is signed correctly.
///
/// The fido metadata specification listed at <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html>
/// has a number of errors (~20 deviations). When they are found, the "true implementation" of the content of the JWT
/// is used, rather than the specification.
///
/// Generally the use of meanings, and definitions of many fields is fuzzy at best. This makes it
/// harder for you to fully rely on all the content of this document and what it implies for your
/// use case. When a field is un-clear, a `⚠️  WARNING` will be listed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FidoMds {
    /// The set of device metadata
    pub entries: Vec<FidoDevice>,
    /// legal header
    pub legal_header: String,
    /// ISO-8601 formatted date when the next update will be provided at latest.
    pub next_update: String,
    /// The serial number of this UAF Metadata BLOB Payload. Serial numbers MUST be consecutive and
    /// strictly monotonic, i.e. the successor BLOB will have a no value exactly incremented by one.
    pub no: u32,
}

impl FromStr for FidoMds {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Setup the trusted CA store so that we can validate the authenticity of the MDS blob.
        let root_ca = x509::X509::from_pem(GLOBAL_SIGN_ROOT_CA_R3.as_bytes())
            .map_err(|_| JwtError::OpenSSLError)?;

        let jws = JwsCompact::from_str(s)?;

        let fullchain = jws
            .get_x5c_chain()
            .and_then(|chain| chain.ok_or(JwtError::InvalidHeaderFormat))?;

        let verifier = JwsX509VerifierBuilder::new()
            .add_fullchain(fullchain)
            .add_trust_root(root_ca)
            .build()
            .map_err(|_| JwtError::OpenSSLError)?;

        // Now we can release the embedded cert, since we have asserted the trust in the chain
        // that has signed this metadata.
        let released = verifier.verify(&jws)?;

        let metadata: FidoMds = released.from_json().map_err(|serde_err| {
            tracing::error!(?serde_err);
            JwtError::Serde
        })?;

        // trace!(?metadata);

        Ok(metadata)
    }
}
