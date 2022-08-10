//! An implementation of the types for the fido metadata service as defined by
//! https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
//!
//! This allows parsing the fido metadata blob and consuming it's content. See `FidoMds`
//! for more.


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

// use base64urlsafedata::Base64UrlSafeData;
use compact_jwt::{JwtError, JwsUnverified, Jws};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use openssl::stack;
use openssl::x509;
use openssl::x509::store;
use tracing::{debug, error};

use std::collections::BTreeMap;
use uuid::Uuid;

static GLOBAL_SIGN_ROOT_CA_R3: &'static str = r#"
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Unclear
pub struct Upv {
    /// Major
    pub major: u16,
    /// Minor
    pub minor: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification methods.
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-CodeAccuracyDescriptor
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-BiometricAccuracyDescriptor
/// The BiometricAccuracyDescriptor describes relevant accuracy/complexity aspects in the case of a biometric user verification method.
pub struct BiometricAccuracyDescriptor {
    /// The false acceptance rate [ISO19795-1] for a single reference data set, i.e. the percentage
    /// of non-matching data sets that are accepted as valid ones. For example a FAR of 0.002% would
    /// be encoded as 0.00002.
    #[serde(rename = "FAR")]
    pub far: Option<f32>,
    /// The false rejection rate for a single reference data set, i.e. the percentage of presented
    /// valid data sets that lead to a (false) non-acceptance. For example a FRR of 10% would be encoded as 0.1.
    #[serde(rename = "FRR")]
    pub frr: Option<f32>,
    /// The equal error rate for a single reference data set.
    #[serde(rename = "ERR")]
    pub err: Option<f32>,
    /// The false artefact acceptance rate [ISO30107-1], i.e. the percentage of artefacts that are incorrectly accepted by the system. For example a FAAR of 0.1% would be encoded as 0.001.
    #[serde(rename = "FAAR")]
    pub faar: Option<f32>,
    /// ❌ NOTE - The FIDO metadata specification does NOT define this value!
    ///
    #[serde(rename = "selfAttestedFRR")]
    pub self_attested_frr: Option<f32>,
    /// ❌ NOTE - The FIDO metadata specification does NOT define this value!
    ///
    #[serde(rename = "selfAttestedFAR")]
    pub self_attested_far: Option<f32>,
    /// ❌ NOTE - The FIDO metadata specification does NOT define this value!
    ///
    /// ❌ NOTE - The FIDO metadata values for this value are broken and can not be parsed.
    pub max_templates: serde_json::Value,
    /// Maximum number of alternative reference data sets, e.g. 3 if the user is allowed to enroll
    /// 3 different fingers to a fingerprint based authenticator.
    pub max_reference_data_sets: Option<u16>,
    /// Maximum number of false attempts before the authenticator will block this method (at least
    /// for some time). 0 means it will never block.
    pub max_retries: Option<u16>,
    /// Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or
    /// similar). 0 means that this user verification method will be blocked either permanently or
    /// until an alternative user verification method succeeded. All alternative user verification
    /// methods must be specified appropriately in the metadata in userVerificationDetails.
    pub block_slowdown: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-PatternAccuracyDescriptor
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// ❌ NOTE - The FIDO metadata specification defines this with a value for user_verification
/// which is NOT present in reality.
///
/// A descriptor for a specific base user verification method as implemented by the authenticator.
pub struct VerificationMethodAndCombinations {
    // Field missing
    // user_verification: u32,
    /// ❌ NOTE - The FIDO metadata specification does NOT define this value!
    ///
    pub user_verification_method: String,
    /// May optionally be used in the case of method USER_VERIFY_PASSCODE.
    pub ca_desc: Option<CodeAccuracyDescriptor>,
    /// May optionally be used in the case of method USER_VERIFY_FINGERPRINT, USER_VERIFY_VOICEPRINT,
    /// USER_VERIFY_FACEPRINT, USER_VERIFY_EYEPRINT, or USER_VERIFY_HANDPRINT.
    pub ba_desc: Option<BiometricAccuracyDescriptor>,
    /// May optionally be used in case of method USER_VERIFY_PATTERN.
    pub pa_desc: Option<PatternAccuracyDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor must be specified in this field.
pub struct EcdaaAnchor {
    /// base64url encoding of the result of ECPoint2ToB of the ECPoint2 X = P_2^xX=P
    /// See [FIDOEcdaaAlgorithm] for the definition of ECPoint2ToB.
    #[serde(rename = "X")]
    pub x: String,
    /// base64url encoding of the result of ECPoint2ToB of the ECPoint2 Y = P_2^yY=P
    /// See [FIDOEcdaaAlgorithm] for the definition of ECPoint2ToB.
    #[serde(rename = "X")]
    pub y: String,
    /// base64url encoding of the result of BigNumberToB(cc). See section "Issuer Specific ECDAA Parameters" in [FIDOEcdaaAlgorithm] for an explanation of cc. See [FIDOEcdaaAlgorithm] for the definition of BigNumberToB.
    pub c: String,
    /// base64url encoding of the result of BigNumberToB(sxsx). See section "Issuer Specific ECDAA Parameters" in [FIDOEcdaaAlgorithm] for an explanation of sxsx. See [FIDOEcdaaAlgorithm] for the definition of BigNumberToB.
    pub sx: String,
    /// base64url encoding of the result of BigNumberToB(sysy). See section "Issuer Specific ECDAA Parameters" in [FIDOEcdaaAlgorithm] for an explanation of sysy. See [FIDOEcdaaAlgorithm] for the definition of BigNumberToB.
    pub sy: String,
    /// Name of the Barreto-Naehrig elliptic curve for G1. "BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported. See section "Supported Curves for ECDAA" in [FIDOEcdaaAlgorithm] for details.
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
    /// ❌ NOTE - The FIDO metadata specification defines this as fail_if_unknown but it is also used
    /// as failIfUnknown in reality, so we accept both as the same field.
    ///
    /// Indicates whether unknown extensions must be ignored (false) or must lead to an error (true)
    /// when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
    ///
    /// A value of false indicates that unknown extensions must be ignored
    ///
    /// A value of true indicates that unknown extensions must result in an error.
    #[serde(alias = "failIfUnknown")]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
/// A type of key protection
pub enum KeyProtection {
    /// hardware
    #[serde(rename = "hardware")]
    Hardware,
    /// secure_element
    #[serde(rename = "secure_element")]
    SecureElement,
    /// remote_handle
    #[serde(rename = "remote_handle")]
    RemoteHandle,
    /// tee
    #[serde(rename = "tee")]
    Tee,
    /// software
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A statement describing a device and it's associated properties.
pub struct MetadataStatement {
    /// Legal Header
    pub legal_header: Option<String>,
    /// The Authenticator Attestation ID. See [UAFProtocol] for the definition of the AAID structure.
    /// This field must be set if the authenticator implements FIDO UAF.
    pub aaid: Option<String>,
    /// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the definition of the
    /// AAGUID structure. This field must be set if the authenticator implements FIDO 2.
    pub aaguid: Option<Uuid>,
    /// A list of the attestation certificate public key identifiers encoded as hex string. This
    /// value must be calculated according to method 1 for computing the keyIdentifier as defined
    /// in [RFC5280] section 4.2.1.2. The hex string must not contain any non-hex characters
    /// (e.g. spaces). All hex letters must be lower case. This field must be set if neither aaid
    /// nor aaguid are set. Setting this field implies that the attestation certificate(s) are
    /// dedicated to a single authenticator model.
    ///
    /// All attestationCertificateKeyIdentifier values should be unique within the scope of the Metadata Service.
    #[serde(default)]
    pub attestation_certificate_key_identifiers: Vec<String>,
    /// A human-readable, short description of the authenticator, in English.
    pub description: String,
    /// A list of human-readable short descriptions of the authenticator in different languages.
    #[serde(default)]
    pub alternative_descriptions: BTreeMap<String, String>,
    /// ❌ NOTE - The FIDO metadata specification defines this as u16 when in reality it is u32,
    ///
    /// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified
    /// in this metadata statement.
    ///
    /// Adding new StatusReport entries with status UPDATE_AVAILABLE to the metadata TOC object
    /// [FIDOMetadataService] must also change this authenticatorVersion if the update fixes severe
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
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as required, when in reality it is optional
    ///
    /// The FIDO unified protocol version(s) (related to the specific protocol family) supported by
    /// this authenticator. See [UAFProtocol] for the definition of the Version structure.
    #[serde(default)]
    pub version: Vec<Upv>,
    /// The assertion scheme supported by the authenticator. Must be set to one of the enumerated
    /// strings defined in the FIDO UAF Registry of Predefined Values [UAFRegistry], or to "U2FV1BIN"
    /// in the case of the U2F raw message format, or to "FIDOV2" in the case of the
    /// FIDO 2/WebAuthentication assertion scheme.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub assertion_scheme: AssertionScheme,
    /// ❌ NOTE - The FIDO metadata specification defines this as a u16, when in reality it is a string
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as required, when in reality it is optional
    ///
    /// The preferred authentication algorithm supported by the authenticator. Must be set to one of
    /// the ALG_ constants defined in the FIDO Registry of Predefined Values [FIDORegistry].
    /// This value must be non-zero.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub authentication_algorithm: Option<AuthenticationAlgorithm>,
    /// ❌ NOTE - The FIDO metadata specification defines this as an array of u16, when in reality it
    /// is an array of string.
    ///
    /// The list of authentication algorithms supported by the authenticator. Must be set to the
    /// complete list of the supported ALG_ constants defined in the FIDO Registry of Predefined
    /// Values [FIDORegistry] if the authenticator supports multiple algorithms. Each value must be non-zero.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub authentication_algorithms: Vec<AuthenticationAlgorithm>,
    /// ❌ NOTE - The FIDO metadata specification defines this as a u16, when in reality it is a string
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as required, when in reality it is optional
    ///
    /// The preferred public key format used by the authenticator during registration operations.
    /// Must be set to one of the ALG_KEY constants defined in the FIDO Registry of Predefined Values
    /// [FIDORegistry]. Because this information is not present in APIs related to authenticator
    /// discovery or policy, a FIDO server must be prepared to accept and process any and all key
    /// representations defined for any public key algorithm it supports. This value must be non-zero.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub public_key_alg_and_encoding: Option<PublicKeyAlg>,
    /// ❌ NOTE - The FIDO metadata specification defines this as an array of u16, when in reality it
    /// is an array of string.
    ///
    /// The list of public key formats supported by the authenticator during registration operations.
    /// Must be set to the complete list of the supported ALG_KEY constants defined in the FIDO Registry
    /// of Predefined Values [FIDORegistry] if the authenticator model supports multiple encodings.
    /// Because this information is not present in APIs related to authenticator discovery or policy,
    /// a FIDO server must be prepared to accept and process any and all key representations defined
    /// for any public key algorithm it supports. Each value must be non-zero.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub public_key_alg_and_encodings: Vec<PublicKeyAlg>,
    /// ❌ NOTE - The FIDO metadata specification defines this as a u16, when in reality it is a string.
    ///
    /// The supported attestation type(s). (e.g. TAG_ATTESTATION_BASIC_FULL(0x3E07), TAG_ATTESTATION_BASIC_SURROGATE(0x3E08)).
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub attestation_types: Vec<AttestationType>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// ❌ NOTE - The FIDO metadata specification definition of this value is extremely broken - it
    /// is an array of arrays in reality, but the spec claims it is just an array.
    // This type is just straight fucked.
    pub user_verification_details: Vec<Vec<VerificationMethodAndCombinations>>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as required, but it is optional
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as u16, but in reality it is an
    /// array of string.
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    #[serde(default)]
    pub key_protection: Vec<KeyProtection>,
    /// This entry is set to true, if the Uauth private key is restricted by the authenticator to
    /// only sign valid FIDO signature assertions.
    ///
    /// This entry is set to false, if the authenticator doesn't restrict the Uauth key to only
    /// sign valid FIDO signature assertions. In this case, the calling application could potentially
    /// get any hash value signed by the authenticator.
    ///
    /// If this field is missing, the assumed value is isKeyRestricted=true
    pub is_key_restricted: Option<bool>,
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
    pub is_fresh_user_verification_required: Option<bool>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as a u16, when in reality it is a string.
    ///
    /// A 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in
    /// the FIDO Registry of Predefined Values [FIDORegistry].
    ///
    /// ❗️ This is represented as an enum in this project to help you understand the possible values
    /// that *may* exist. This contradicts the MDS spec, but it's better for you the consumer.
    pub matcher_protection: Vec<MatcherProtection>,
    /// The authenticator's overall claimed cryptographic strength in bits (sometimes also called
    /// security strength or security level). This is the minimum of the cryptographic strength of
    /// all involved cryptographic methods (e.g. RNG, underlying hash, key wrapping algorithm,
    /// signing algorithm, attestation algorithm), e.g. see [FIPS180-4], [FIPS186-4], [FIPS198-1],
    /// [SP800-38B], [SP800-38C], [SP800-38D], [SP800-38F], [SP800-90C], [SP800-90ar1], [FIPS140-2] etc.
    ///
    /// If this value is absent, the cryptographic strength is unknown. If the cryptographic strength
    /// of one of the involved cryptographic methods is unknown the overall claimed cryptographic
    /// strength is also unknown.
    pub crypto_strength: Option<u16>,
    /// Description of the particular operating environment that is used for the Authenticator.
    /// These are specified in [FIDORestrictedOperatingEnv].
    pub operating_env: Option<String>,
    /// ❌ NOTE - The FIDO metadata specification defines this as a u32 when in reality it is an
    /// array of string.
    ///
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
    /// ❌ NOTE - The FIDO metadata specification defines this as required, when in reality it is
    /// optional.
    ///
    /// Indicates if the authenticator is designed to be used only as a second factor, i.e.
    /// requiring some other authentication method as a first factor (e.g. username+password).
    pub is_second_factor_only: Option<bool>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    /// ❌ NOTE - The FIDO metadata specification defines this as a u16 when in reality it is an
    /// array of strings.
    ///
    /// A 16-bit number representing a combination of the bit flags defined by the
    /// TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values [FIDORegistry].
    /// This value must be 0, if transaction confirmation is not supported by the authenticator.
    pub tc_display: Vec<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    pub tc_display_content_type: Option<String>,
    /// ⚠️  WARNING - Content of this value is not well documented to it's intent or usage!
    ///
    #[serde(skip_deserializing)]
    pub tc_display_png_characteristics: (),
    /// ❌ NOTE - The FIDO metadata specification defines this as a an array of base64 values, however
    /// many values are INVALID and contain leading/trailing whitespace that MAY confuse your base64 parser
    ///
    /// ⚠️  WARNING - Content of this value MAY have extra leading or trailing whitespace which MAY
    /// cause issues when parsing.
    ///
    /// Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid
    /// trust anchor for this authenticator model. Multiple certificates might be used for different
    /// batches of the same model. The array does not represent a certificate chain, but only the
    /// trust anchor of that chain. A trust anchor can be a root certificate, an intermediate CA
    /// certificate or even the attestation certificate itself.
    ///
    /// Each array element is a base64-encoded (section 4 of [RFC4648]), DER-encoded [ITU-X690-2008]
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
    /// An icon representing this device. This is skipped today.
    #[serde(skip_deserializing)]
    pub icon: (),
    /// The list of supported extensions of this authenticator
    #[serde(default)]
    pub supported_extensions: Vec<ExtensionDescriptor>,
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
    /// biometric modality. See section "User Verification Methods" in [FIDORegistry]
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
    /// The version of the Biometric Requirements [FIDOBiometricsRequirements] the implementation is certified to, e.g. "1.0.0".
    pub certification_requirements_version: Option<String>,
}

/// The fido certification status of the device associated to this aaid/aaguid.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Base64-encoded [RFC4648] (not base64url!) DER [ITU-X690-2008] PKIX certificate value related
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
    /// [FIDOAuthenticatorSecurityRequirements] the implementation is certified to, e.g. "1.2.0".
    pub certification_requirements_version: Option<String>,
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
    /// in [RFC5280] section 4.2.1.2.
    pub attestation_certificate_key_identifiers: Option<Vec<String>>,
    /// The FIDOMetadataStatement pertaining to this device.
    pub metadata_statement: MetadataStatement,
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
    /// encoded rogueList available at rogueListURL (with type rogueListEntry[]). The hash algorithm
    /// related to the signature algorithm specified in the JWTHeader (see Metadata BLOB) MUST be used.
    ///
    /// This hash value MUST be present and non-empty whenever rogueListURL is present.
    pub rogue_list_hash: Option<String>,
}


/// The parsed content of the Fido Metadata Server. This content can be retrieved from it's online
/// url at https://mds.fidoalliance.org/ . It's recommended you re-download this content every few weeks. This can be parsed
/// from it's str representation - for from_str to suceed, the metadata jwt content MUST be correctly
/// signed be pinned root certificate authority, the full chain is verified, and the content of the
/// JWT is signed correctly.
///
/// The fido metadata specification listed at https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
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
        let root_ca = x509::X509::from_pem(GLOBAL_SIGN_ROOT_CA_R3.as_bytes()).map_err(|_| JwtError::OpenSSLError)?;

        let mut ca_store = store::X509StoreBuilder::new().map_err(|_| JwtError::OpenSSLError)?;
        ca_store
            .add_cert(root_ca)
            .map_err(|_| JwtError::OpenSSLError)?;

        let ca_store = ca_store.build();

        let jws = JwsUnverified::from_str(s)?;

        let fullchain = jws.get_x5c_chain()
            .and_then(|chain| chain.ok_or(JwtError::InvalidHeaderFormat))?;

        let (leaf, chain) = fullchain
            .split_first()
            .ok_or(JwtError::InvalidHeaderFormat)?;

        let mut chain_stack = stack::Stack::new().map_err(|_| JwtError::OpenSSLError)?;

        for crt in chain.iter() {
            chain_stack
                .push(crt.clone())
                .map_err(|_| JwtError::OpenSSLError)?;
        }

        let mut ca_ctx = x509::X509StoreContext::new().map_err(|_| JwtError::OpenSSLError)?;

        // Given the ca_store, the leaf cert, and the chain between leaf to ca_store, verify
        // the certificate chain.
        let res: Result<_, _> = ca_ctx
            .init(&ca_store, leaf, &chain_stack, |ca_ctx_ref| {
                ca_ctx_ref.verify_cert().map(|_| {
                    let res = ca_ctx_ref.error();
                    debug!("{:?}", res);
                    if res == x509::X509VerifyResult::OK {
                        Ok(())
                    } else {
                        debug!(
                            "ca_ctx_ref verify cert - error depth={}, sn={:?}",
                            ca_ctx_ref.error_depth(),
                            ca_ctx_ref.current_cert().map(|crt| crt.subject_name())
                        );
                        Err(JwtError::X5cPublicKeyDenied)
                    }
                })
            })
        .map_err(|e| {
            // If an openssl error occured, dump it here.
            error!(?e);
            JwtError::OpenSSLError
        })?;

        debug!(?res);
        let _ = res?;

        // Now we can release the embedded cert, since we have asserted the trust in the chain
        // that has signed this metadata.

        let x: Jws<FidoMds> = jws.validate_embeded()?;

        let metadata = x.into_inner();
        // trace!(?metadata);

        Ok(metadata)
    }
}
