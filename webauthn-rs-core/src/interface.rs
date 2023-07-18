//! Extended Structs and representations for Webauthn Operations. These types are designed
//! to allow persistance and should not change.

use crate::attestation::{verify_attestation_ca_chain, AttestationFormat};
use crate::constants::*;
use crate::error::*;
pub use crate::internals::AttestationObject;
use std::fmt;
use webauthn_rs_proto::cose::*;
use webauthn_rs_proto::extensions::*;
use webauthn_rs_proto::options::*;

use base64urlsafedata::Base64UrlSafeData;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use openssl::hash::MessageDigest;
use openssl::{bn, ec, nid, pkey, x509};
use uuid::Uuid;

/// Representation of an AAGUID
/// <https://www.w3.org/TR/webauthn/#aaguid>
pub type Aaguid = [u8; 16];

/// Representation of a credentials activation counter.
pub type Counter = u32;

/// The in progress state of a credential registration attempt. You must persist this in a server
/// side location associated to the active session requesting the registration. This contains the
/// user unique id which you can use to reference the user requesting the registration.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    pub policy: UserVerificationPolicy,
    pub exclude_credentials: Vec<CredentialID>,
    pub challenge: Base64UrlSafeData,
    pub credential_algorithms: Vec<COSEAlgorithm>,
    pub require_resident_key: bool,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub extensions: RequestRegistrationExtensions,
    pub experimental_allow_passkeys: bool,
}

/// The in progress state of an authentication attempt. You must persist this associated to the UserID
/// requesting the registration.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub credentials: Vec<Credential>,
    pub policy: UserVerificationPolicy,
    pub challenge: Base64UrlSafeData,
    pub appid: Option<String>,
    pub allow_backup_eligible_upgrade: bool,
}

impl AuthenticationState {
    /// set which credentials the user is allowed to authenticate with. This
    /// is used as part of resident key authentication flows where we need
    /// to inject the set of viable credentials after the client has sent us
    /// their public key credential and we identify the user.
    pub fn set_allowed_credentials(&mut self, credentials: Vec<Credential>) {
        self.credentials = credentials;
    }
}

/// An EDDSACurve identifier. You probably will never need to alter
/// or use this value, as it is set inside the Credential for you.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EDDSACurve {
    // +---------+-------+----------+------------------------------------+
    // | Name    | Value | Key Type | Description                        |
    // +---------+-------+----------+------------------------------------+
    // | X25519  | 4     | OKP      | X25519 for use w/ ECDH only        |
    // | X448    | 5     | OKP      | X448 for use w/ ECDH only          |
    // | Ed25519 | 6     | OKP      | Ed25519 for use w/ EdDSA only      |
    // | Ed448   | 7     | OKP      | Ed448 for use w/ EdDSA only        |
    // +---------+-------+----------+------------------------------------+
    // /// Identifies this curve as X25519 ECDH only
    // X25519 = 4,
    // /// Identifies this curve as X448 ECDH only
    // X448 = 5,
    /// Identifies this OKP as ED25519
    ED25519 = 6,
    /// Identifies this OKP as ED448
    ED448 = 7,
}

/// An ECDSACurve identifier. You probably will never need to alter
/// or use this value, as it is set inside the Credential for you.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ECDSACurve {
    // +---------+-------+----------+------------------------------------+
    // | Name    | Value | Key Type | Description                        |
    // +---------+-------+----------+------------------------------------+
    // | P-256   | 1     | EC2      | NIST P-256 also known as secp256r1 |
    // | P-384   | 2     | EC2      | NIST P-384 also known as secp384r1 |
    // | P-521   | 3     | EC2      | NIST P-521 also known as secp521r1 |
    // +---------+-------+----------+------------------------------------+
    /// Identifies this curve as SECP256R1 (X9_62_PRIME256V1 in OpenSSL)
    SECP256R1 = 1,
    /// Identifies this curve as SECP384R1
    SECP384R1 = 2,
    /// Identifies this curve as SECP521R1
    SECP521R1 = 3,
}

impl ECDSACurve {
    /// Returns the size in bytes of the coordinate components (x and y) for the specified curve
    pub(crate) fn coordinate_size(&self) -> usize {
        match self {
            Self::SECP256R1 => 32,
            Self::SECP384R1 => 48,
            Self::SECP521R1 => 66,
        }
    }
}

impl From<&ECDSACurve> for nid::Nid {
    fn from(c: &ECDSACurve) -> Self {
        use ECDSACurve::*;
        match c {
            SECP256R1 => nid::Nid::X9_62_PRIME256V1,
            SECP384R1 => nid::Nid::SECP384R1,
            SECP521R1 => nid::Nid::SECP521R1,
        }
    }
}

/// A COSE Elliptic Curve Public Key. This is generally the provided credential
/// that an authenticator registers, and is used to authenticate the user.
/// You will likely never need to interact with this value, as it is part of the Credential
/// API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSEEC2Key {
    /// The curve that this key references.
    pub curve: ECDSACurve,
    /// The key's public X coordinate.
    pub x: Base64UrlSafeData,
    /// The key's public Y coordinate.
    pub y: Base64UrlSafeData,
}

impl TryFrom<&COSEEC2Key> for ec::EcKey<pkey::Public> {
    type Error = openssl::error::ErrorStack;

    fn try_from(k: &COSEEC2Key) -> Result<Self, Self::Error> {
        let group = ec::EcGroup::from_curve_name((&k.curve).into())?;
        let mut ctx = bn::BigNumContext::new()?;
        let mut point = ec::EcPoint::new(&group)?;
        let x = bn::BigNum::from_slice(k.x.0.as_slice())?;
        let y = bn::BigNum::from_slice(k.y.0.as_slice())?;
        point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;

        ec::EcKey::from_public_key(&group, &point)
    }
}

/// A COSE Elliptic Curve Public Key. This is generally the provided credential
/// that an authenticator registers, and is used to authenticate the user.
/// You will likely never need to interact with this value, as it is part of the Credential
/// API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSEOKPKey {
    /// The curve that this key references.
    pub curve: EDDSACurve,
    /// The key's public X coordinate.
    pub x: [u8; 32],
}

/// A COSE RSA PublicKey. This is a provided credential from a registered
/// authenticator.
/// You will likely never need to interact with this value, as it is part of the Credential
/// API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSERSAKey {
    /// An RSA modulus
    pub n: Base64UrlSafeData,
    /// An RSA exponent
    pub e: [u8; 3],
}

/// The type of Key contained within a COSE value. You should never need
/// to alter or change this type.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum COSEKeyType {
    //    +-----------+-------+-----------------------------------------------+
    //    | Name      | Value | Description                                   |
    //    +-----------+-------+-----------------------------------------------+
    //    | OKP       | 1     | Octet Key Pair                                |
    //    | EC2       | 2     | Elliptic Curve Keys w/ x- and y-coordinate    |
    //    |           |       | pair                                          |
    //    | Symmetric | 4     | Symmetric Keys                                |
    //    | Reserved  | 0     | This value is reserved                        |
    //    +-----------+-------+-----------------------------------------------+
    /// Identifies this as an Eliptic Curve octet key pair
    EC_OKP(COSEOKPKey),
    /// Identifies this as an Eliptic Curve EC2 key
    EC_EC2(COSEEC2Key),
    // EC_Symmetric,
    // EC_Reserved, // should always be invalid.
    /// Identifies this as an RSA key
    RSA(COSERSAKey),
}

/// The numeric if of the COSEKeyType used in the CBOR fields.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum COSEKeyTypeId {
    /// Reserved
    EC_Reserved = 0,
    /// Octet Key Pair
    EC_OKP = 1,
    /// Elliptic Curve Keys w/ x- and y-coordinate
    EC_EC2 = 2,
    /// RSA
    EC_RSA = 3,
    /// Symmetric
    EC_Symmetric = 4,
}

/// A COSE Key as provided by the Authenticator. You should never need
/// to alter or change these values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSEKey {
    /// The type of key that this contains
    pub type_: COSEAlgorithm,
    /// The public key
    pub key: COSEKeyType,
}

/// A user's authenticator credential. It contains an id, the public key
/// and a counter of how many times the authenticator has been used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// The ID of this credential.
    pub cred_id: CredentialID,
    /// The public key of this credential
    pub cred: COSEKey,
    /// The counter for this credential
    pub counter: Counter,
    /// The set of transports this credential indicated it could use. This is NOT
    /// a security property, but a hint for the browser and the user experience to
    /// how to communicate to this specific device.
    pub transports: Option<Vec<AuthenticatorTransport>>,
    /// During registration, if this credential was verified
    /// then this is true. If not it is false. This is based on
    /// the policy at the time of registration of the credential.
    ///
    /// This is a deviation from the Webauthn specification, because
    /// it clarifies the user experience of the credentials to UV
    /// being a per-credential attribute, rather than a per-authentication
    /// ceremony attribute. For example it can be surprising to register
    /// a credential as un-verified but then to use verification with it
    /// in the future.
    pub user_verified: bool,
    /// During registration, this credential indicated that it *may* be possible
    /// for it to exist between multiple hardware authenticators, or be backed up.
    ///
    /// This means the private key is NOT sealed within a hardware cryptograhic
    /// processor, and may have impacts on your risk assessments and modeling.
    pub backup_eligible: bool,
    /// This credential has indicated that it is currently backed up OR that it
    /// is shared between mulitple devices.
    pub backup_state: bool,
    /// During registration, the policy that was requested from this
    /// credential. This is used to understand if the how the verified
    /// component interacts with the device, i.e. an always verified authenticator
    /// vs one that can dynamically request it.
    pub registration_policy: UserVerificationPolicy,
    /// The set of extensions that were verified at registration, that can
    /// be used in future authentication attempts
    pub extensions: RegisteredExtensions,
    /// The attestation certificate of this credential, including parsed metadata from the
    /// credential.
    pub attestation: ParsedAttestation,
    /// the format of the attestation
    pub attestation_format: AttestationFormat,
}

impl Credential {
    /// Re-verify this Credential's attestation chain. This re-applies the same process
    /// for certificate authority verification that occured at registration. This can
    /// be useful if you want to re-assert your credentials match an updated or changed
    /// ca_list from the time that registration occured. This can also be useful to
    /// re-determine certain properties of your device that may exist.
    ///
    /// # Safety
    /// Due to the design of CA infrastructure by certain providers, it is NOT possible
    /// to verify the CA expiry time. Certain vendors use CA intermediates that have
    /// expiries that are only valid for approximately 10 minutes, meaning that if we
    /// enforced time validity, these would false negative for their validity.
    pub fn verify_attestation<'a>(
        &'_ self,
        ca_list: &'a AttestationCaList,
    ) -> Result<Option<&'a AttestationCa>, WebauthnError> {
        // Why do we disable this? Because of Apple. They issue dynamic short lived
        // attestation certs, that last for about 5 minutes. This means that
        // post-registration validation will always fail if we validate time.
        let danger_disable_certificate_time_checks = true;
        verify_attestation_ca_chain(
            &self.attestation.data,
            ca_list,
            danger_disable_certificate_time_checks,
        )
    }
}

impl From<CredentialV3> for Credential {
    fn from(other: CredentialV3) -> Credential {
        let CredentialV3 {
            cred_id,
            cred,
            counter,
            verified,
            registration_policy,
        } = other;

        // prior to 20220520 no multi-device credentials existed to migrate from.
        Credential {
            cred_id: Base64UrlSafeData(cred_id),
            cred,
            counter,
            transports: None,
            user_verified: verified,
            backup_eligible: false,
            backup_state: false,
            registration_policy,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation {
                data: ParsedAttestationData::None,
                metadata: AttestationMetadata::None,
            },
            attestation_format: AttestationFormat::None,
        }
    }
}

/// A legacy serialisation from version 3 of Webauthn RS. Only useful for migrations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialV3 {
    /// The ID of this credential.
    pub cred_id: Vec<u8>,
    /// The public key of this credential
    pub cred: COSEKey,
    /// The counter for this credential
    pub counter: u32,
    /// During registration, if this credential was verified
    /// then this is true. If not it is false. This is based on
    /// the policy at the time of registration of the credential.
    ///
    /// This is a deviation from the Webauthn specification, because
    /// it clarifies the user experience of the credentials to UV
    /// being a per-credential attribute, rather than a per-authentication
    /// ceremony attribute. For example it can be surprising to register
    /// a credential as un-verified but then to use verification with it
    /// in the future.
    pub verified: bool,
    /// During registration, the policy that was requested from this
    /// credential. This is used to understand if the how the verified
    /// component interacts with the device, IE an always verified authenticator
    /// vs one that can dynamically request it.
    pub registration_policy: UserVerificationPolicy,
}

/// Serialised Attestation Data which can be stored in a stable database or similar.
#[derive(Clone, Serialize, Deserialize)]
pub enum SerialisableAttestationData {
    /// See [ParsedAttestationData::Basic]
    Basic(Vec<Base64UrlSafeData>),
    /// See [ParsedAttestationData::Self_]
    Self_,
    /// See [ParsedAttestationData::AttCa]
    AttCa(Vec<Base64UrlSafeData>),
    /// See [ParsedAttestationData::AnonCa]
    AnonCa(Vec<Base64UrlSafeData>),
    /// See [ParsedAttestationData::ECDAA]
    ECDAA,
    /// See [ParsedAttestationData::None]
    None,
    /// See [ParsedAttestationData::Uncertain]
    Uncertain,
}

impl fmt::Debug for SerialisableAttestationData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerialisableAttestationData::Basic(_) => {
                write!(f, "SerialisableAttestationData::Basic")
            }
            SerialisableAttestationData::Self_ => write!(f, "SerialisableAttestationData::Self_"),
            SerialisableAttestationData::AttCa(_) => {
                write!(f, "SerialisableAttestationData::AttCa")
            }
            SerialisableAttestationData::AnonCa(_) => {
                write!(f, "SerialisableAttestationData::AnonCa")
            }
            SerialisableAttestationData::ECDAA => write!(f, "SerialisableAttestationData::ECDAA"),
            SerialisableAttestationData::None => write!(f, "SerialisableAttestationData::None"),
            SerialisableAttestationData::Uncertain => {
                write!(f, "SerialisableAttestationData::Uncertain")
            }
        }
    }
}

/// The processed attestation and its metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedAttestation {
    /// the attestation chain data
    pub data: ParsedAttestationData,
    /// possible metadata (i.e. flags set) about the attestation
    pub metadata: AttestationMetadata,
}

impl Default for ParsedAttestation {
    fn default() -> Self {
        ParsedAttestation {
            data: ParsedAttestationData::None,
            metadata: AttestationMetadata::None,
        }
    }
}

/// The processed Attestation that the Authenticator is providing in it's AttestedCredentialData. This
/// metadata may allow identification of the device and it's specific properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationMetadata {
    /// no metadata available for this device.
    None,
    /// This is commonly found on Fido Authenticators.
    Packed {
        /// This is the unique id of the class/type of device. Often this id can imply the
        /// properties of the device.
        aaguid: Uuid,
    },
    /// This is found on TPM authenticators.
    Tpm {
        /// This is the unique id of the class/type of device. Often this id can imply the
        /// properties of the device.
        aaguid: Uuid,
        /// The firmware version of the device at registration. It can NOT be determined
        /// if this updates later, which may require you to re-register the device if
        /// you need to enforce a version update.
        firmware_version: u64,
    },
    /// various attestation flags set by the device (attested by OS)
    AndroidKey {
        /// is the key master running in a Trusted Execution Environment
        is_km_tee: bool,
        /// did the attestation come from a Trusted Execution Environment
        is_attest_tee: bool,
    },
    /// various attestation flags set by the device (attested via safety-net)
    /// <https://developer.android.com/training/safetynet/attestation#use-response-server>
    AndroidSafetyNet {
        /// the name of apk that originated this key operation
        apk_package_name: String,
        /// cert chain for this apk
        apk_certificate_digest_sha256: Vec<Base64UrlSafeData>,
        /// A stricter verdict of device integrity. If the value of ctsProfileMatch is true, then the profile of the device running your app matches the profile of a device that has passed Android compatibility testing and has been approved as a Google-certified Android device.
        cts_profile_match: bool,
        /// A more lenient verdict of device integrity. If only the value of basicIntegrity is true, then the device running your app likely wasn't tampered with. However, the device hasn't necessarily passed Android compatibility testing.
        basic_integrity: bool,
        /// Types of measurements that contributed to the current API response
        evaluation_type: Option<String>,
    },
}

/// The processed Attestation that the Authenticator is providing in it's AttestedCredentialData
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    try_from = "SerialisableAttestationData",
    into = "SerialisableAttestationData"
)]
pub enum ParsedAttestationData {
    /// The credential is authenticated by a signing X509 Certificate
    /// from a vendor or provider.
    Basic(Vec<x509::X509>),
    /// The credential is authenticated using surrogate basic attestation
    /// it uses the credential private key to create the attestation signature
    Self_,
    /// The credential is authenticated using a CA, and may provide a
    /// ca chain to validate to it's root.
    AttCa(Vec<x509::X509>),
    /// The credential is authenticated using an anonymization CA, and may provide a ca chain to
    /// validate to it's root.
    AnonCa(Vec<x509::X509>),
    /// Unimplemented
    ECDAA,
    /// No Attestation type was provided with this Credential. If in doubt
    /// reject this Credential.
    None,
    /// Uncertain Attestation was provided with this Credential, which may not
    /// be trustworthy in all cases. If in doubt, reject this type.
    Uncertain,
}

#[allow(clippy::from_over_into)]
impl Into<SerialisableAttestationData> for ParsedAttestationData {
    fn into(self) -> SerialisableAttestationData {
        match self {
            ParsedAttestationData::Basic(chain) => SerialisableAttestationData::Basic(
                chain
                    .into_iter()
                    .map(|c| Base64UrlSafeData(c.to_der().expect("Invalid DER")))
                    .collect(),
            ),
            ParsedAttestationData::Self_ => SerialisableAttestationData::Self_,
            ParsedAttestationData::AttCa(chain) => SerialisableAttestationData::AttCa(
                // Base64UrlSafeData(c.to_der().expect("Invalid DER")),
                chain
                    .into_iter()
                    .map(|c| Base64UrlSafeData(c.to_der().expect("Invalid DER")))
                    .collect(),
            ),
            ParsedAttestationData::AnonCa(chain) => SerialisableAttestationData::AnonCa(
                // Base64UrlSafeData(c.to_der().expect("Invalid DER")),
                chain
                    .into_iter()
                    .map(|c| Base64UrlSafeData(c.to_der().expect("Invalid DER")))
                    .collect(),
            ),
            ParsedAttestationData::ECDAA => SerialisableAttestationData::ECDAA,
            ParsedAttestationData::None => SerialisableAttestationData::None,
            ParsedAttestationData::Uncertain => SerialisableAttestationData::Uncertain,
        }
    }
}

impl TryFrom<SerialisableAttestationData> for ParsedAttestationData {
    type Error = WebauthnError;

    fn try_from(data: SerialisableAttestationData) -> Result<Self, Self::Error> {
        Ok(match data {
            SerialisableAttestationData::Basic(chain) => ParsedAttestationData::Basic(
                chain
                    .into_iter()
                    .map(|c| x509::X509::from_der(&c.0).map_err(WebauthnError::OpenSSLError))
                    .collect::<WebauthnResult<_>>()?,
            ),
            SerialisableAttestationData::Self_ => ParsedAttestationData::Self_,
            SerialisableAttestationData::AttCa(chain) => ParsedAttestationData::AttCa(
                // x509::X509::from_der(&c.0).map_err(WebauthnError::OpenSSLError)?,
                chain
                    .into_iter()
                    .map(|c| x509::X509::from_der(&c.0).map_err(WebauthnError::OpenSSLError))
                    .collect::<WebauthnResult<_>>()?,
            ),
            SerialisableAttestationData::AnonCa(chain) => ParsedAttestationData::AnonCa(
                // x509::X509::from_der(&c.0).map_err(WebauthnError::OpenSSLError)?,
                chain
                    .into_iter()
                    .map(|c| x509::X509::from_der(&c.0).map_err(WebauthnError::OpenSSLError))
                    .collect::<WebauthnResult<_>>()?,
            ),
            SerialisableAttestationData::ECDAA => ParsedAttestationData::ECDAA,
            SerialisableAttestationData::None => ParsedAttestationData::None,
            SerialisableAttestationData::Uncertain => ParsedAttestationData::Uncertain,
        })
    }
}

/// Marker type parameter for data related to registration ceremony
#[derive(Debug)]
pub struct Registration;

/// Marker type parameter for data related to authentication ceremony
#[derive(Debug)]
pub struct Authentication;

/// Trait for ceremony marker structs
pub trait Ceremony {
    /// The type of the extension outputs of the ceremony
    type SignedExtensions: DeserializeOwned + std::fmt::Debug + std::default::Default;
}

impl Ceremony for Registration {
    type SignedExtensions = RegistrationSignedExtensions;
}

impl Ceremony for Authentication {
    type SignedExtensions = AuthenticationSignedExtensions;
}

/// The client's response to the request that it use the `credProtect` extension
///
/// Implemented as wrapper struct to (de)serialize
/// [CredentialProtectionPolicy] as a number
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct CredProtectResponse(pub CredentialProtectionPolicy);

/// The output for registration ceremony extensions.
///
/// Implements the registration bits of \[AuthenticatorExtensionsClientOutputs\]
/// from the spec
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistrationSignedExtensions {
    /// The `credProtect` extension
    #[serde(rename = "credProtect")]
    pub cred_protect: Option<CredProtectResponse>,
    /// The `hmac-secret` extension response to a create request
    #[serde(rename = "hmac-secret")]
    pub hmac_secret: Option<bool>,
    /// Extension key-values that we have parsed, but don't strictly recognise.
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_cbor::Value>,
}

/// The output for authentication cermeony extensions.
///
/// Implements the authentication bits of
/// \[AuthenticationExtensionsClientOutputs] from the spec
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationSignedExtensions {
    /// Extension key-values that we have parsed, but don't strictly recognise.
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_cbor::Value>,
}

/// Attested Credential Data
#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    /// The guid of the authenticator. May indicate manufacturer.
    pub aaguid: Aaguid,
    /// The credential ID.
    pub credential_id: CredentialID,
    /// The credentials public Key.
    pub credential_pk: serde_cbor::Value,
}

/// Information about the authentication that occured.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AuthenticationResult {
    /// The credential ID that was used to authenticate.
    pub(crate) cred_id: CredentialID,
    /// If the credential associated needs updating
    pub(crate) needs_update: bool,
    /// If the authentication provided user_verification.
    pub(crate) user_verified: bool,
    /// The current backup state of the authenticator. It may have
    /// changed since registration.
    pub(crate) backup_state: bool,
    /// The current backup eligibility of the authenticator. It may have
    /// changed since registration in rare cases. This transition may ONLY
    /// be false to true, never the reverse. This is common on passkeys
    /// during some upgrades.
    pub(crate) backup_eligible: bool,
    /// The state of the counter
    pub(crate) counter: Counter,
    /// The response from associated extensions.
    pub(crate) extensions: AuthenticationExtensions,
}

impl AuthenticationResult {
    /// The credential ID that was used to authenticate.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred_id
    }

    /// If this authentication result should be applied to the associated
    /// credential to update it's properties.
    pub fn needs_update(&self) -> bool {
        self.needs_update
    }

    /// If the authentication provided user_verification.
    pub fn user_verified(&self) -> bool {
        self.user_verified
    }

    /// The current backup state of the authenticator. It may have
    /// changed since registration.
    pub fn backup_state(&self) -> bool {
        self.backup_state
    }

    /// The current backup eligibility of the authenticator. It may have
    /// changed since registration in rare cases. This transition may ONLY
    /// be false to true, never the reverse. This is common on passkeys
    /// during some upgrades.
    pub fn backup_eligible(&self) -> bool {
        self.backup_eligible
    }

    /// The state of the counter
    pub fn counter(&self) -> Counter {
        self.counter
    }

    /// The response from associated extensions.
    pub fn extensions(&self) -> &AuthenticationExtensions {
        &self.extensions
    }
}

/// A serialised Attestation CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialisableAttestationCa {
    pub(crate) ca: Base64UrlSafeData,
    pub(crate) aaguids: BTreeSet<Uuid>,
}

/// A structure representing an Attestation CA and other options associated to this CA.
///
/// Generally depending on the Attestation CA in use, this can help determine properties
/// of the authenticator that is in use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    try_from = "SerialisableAttestationCa",
    into = "SerialisableAttestationCa"
)]
pub struct AttestationCa {
    /// The x509 root CA of the attestation chain that a security key will be attested to.
    pub ca: x509::X509,
    /// If not empty, the set of acceptable AAGUIDS (Device Ids) that are allowed to be
    /// attested as trusted by this CA. AAGUIDS that are not in this set, but signed by
    /// this CA will NOT be trusted.
    pub aaguids: BTreeSet<Uuid>,
}
#[allow(clippy::from_over_into)]
impl Into<SerialisableAttestationCa> for AttestationCa {
    fn into(self) -> SerialisableAttestationCa {
        SerialisableAttestationCa {
            ca: Base64UrlSafeData(self.ca.to_der().expect("Invalid DER")),
            aaguids: self.aaguids,
        }
    }
}

impl TryFrom<SerialisableAttestationCa> for AttestationCa {
    type Error = WebauthnError;

    fn try_from(data: SerialisableAttestationCa) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(&data.ca.0).map_err(WebauthnError::OpenSSLError)?,
            aaguids: data.aaguids,
        })
    }
}

impl AttestationCa {
    /// Retrieve the Key Identifier for this Attestation Ca
    pub fn get_kid(&self) -> Result<Vec<u8>, WebauthnError> {
        self.ca
            .digest(MessageDigest::sha256())
            .map_err(WebauthnError::OpenSSLError)
            .map(|bytes| bytes.to_vec())
    }

    /// Update the set of aaguids this Attestation CA allows. If an empty btreeset is provided then
    /// this Attestation CA allows all Aaguids.
    pub fn set_aaguids(&mut self, aaguids: BTreeSet<Uuid>) {
        self.aaguids = aaguids;
    }

    /// Update the set of aaguids this Attestation CA allows by adding this AAGUID to the allowed
    /// set.
    pub fn insert_aaguid(&mut self, aaguid: Uuid) {
        self.aaguids.insert(aaguid);
    }

    /// Create a customised attestation CA from a DER public key.
    pub fn new_from_der(data: &[u8]) -> Result<Self, WebauthnError> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(data).map_err(WebauthnError::OpenSSLError)?,
            aaguids: BTreeSet::default(),
        })
    }

    /// The Apple TouchID and FaceID root CA.
    pub fn apple_webauthn_root_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(APPLE_WEBAUTHN_ROOT_CA_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// The yubico u2f root ca. Applies to all devices up to and including series 5.
    pub fn yubico_u2f_root_ca_serial_457200631() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(YUBICO_U2F_ROOT_CA_SERIAL_457200631_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// The microsoft root CA for TPM attestation.
    ///
    /// Not eligible for strict - many TPM's use SHA1 in signatures, which means they are
    /// potentially weak.
    ///
    /// In the future we may reject RS1 signatures, allowing this to be moved into the
    /// strict category.
    pub fn microsoft_tpm_root_certificate_authority_2014() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(MICROSOFT_TPM_ROOT_CERTIFICATE_AUTHORITY_2014_PEM)
                .expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Nitrokey root CA for their FIDO2 device range.
    ///
    /// Not eligible for strict - hardware is difficult to interact with, low quality,
    /// and easy to break or destroy.
    pub fn nitrokey_fido2_root_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(NITROKEY_FIDO2_ROOT_CA_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Nitrokey root CA for their U2F device range.
    ///
    /// Not eligible for strict - hardware is difficult to interact with, low quality,
    /// and easy to break or destroy.
    pub fn nitrokey_u2f_root_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(NITROKEY_U2F_ROOT_CA_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android ROOT CA 1
    pub fn android_root_ca_1() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_ROOT_CA_1).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android ROOT CA 2
    pub fn android_root_ca_2() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_ROOT_CA_2).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android ROOT CA 3
    pub fn android_root_ca_3() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_ROOT_CA_3).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android SOFTWARE ONLY root CA
    pub fn android_software_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_SOFTWARE_ROOT_CA).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Google SafetyNet CA (for android)
    pub fn google_safetynet_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(GOOGLE_SAFETYNET_CA).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Google SafetyNet CA (for android) -- OLD EXPIRED
    #[allow(unused)]
    pub(crate) fn google_safetynet_ca_old() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(GOOGLE_SAFETYNET_CA_OLD).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }
}

/// A list of AttestationCas and associated options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationCaList {
    /// The set of CA's that we trust in this Operation
    pub cas: BTreeMap<Base64UrlSafeData, AttestationCa>,
}

impl TryFrom<AttestationCa> for AttestationCaList {
    type Error = WebauthnError;

    fn try_from(att_ca: AttestationCa) -> Result<Self, Self::Error> {
        let mut new = Self::default();
        new.insert(att_ca)?;
        Ok(new)
    }
}

impl AttestationCaList {
    /// Determine if this attestation list contains any members.
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }

    /// Insert a new att_ca into this Attestation Ca List
    pub fn insert(
        &mut self,
        att_ca: AttestationCa,
    ) -> Result<Option<AttestationCa>, WebauthnError> {
        // Get the key id (kid, digest).
        let att_ca_dgst = att_ca.get_kid()?;
        Ok(self.cas.insert(att_ca_dgst.into(), att_ca))
    }

    /// This is a list of CA's who's manufactured authenticators are of the highest
    /// quality and guarantees for users and RP's. These are devices that not only
    /// are secure, but user friendly, consistent, and correct.
    pub fn strict() -> Self {
        let mut new = Self::default();
        new.insert(AttestationCa::yubico_u2f_root_ca_serial_457200631())
            .expect("Must not fail");
        new
    }

    /// Apple iOS/macOS and Android CAs
    pub fn apple_and_android() -> Self {
        let mut new = Self::default();
        new.insert(AttestationCa::apple_webauthn_root_ca())
            .expect("Must not fail");
        new.insert(AttestationCa::android_root_ca_1())
            .expect("Must not fail");
        new.insert(AttestationCa::android_root_ca_2())
            .expect("Must not fail");
        new.insert(AttestationCa::android_root_ca_3())
            .expect("Must not fail");
        new.insert(AttestationCa::google_safetynet_ca())
            .expect("Must not fail");
        new.insert(AttestationCa::android_software_ca())
            .expect("Must not fail");
        new
    }

    /// Apple iOS/macOS
    pub fn apple() -> Self {
        let mut new = Self::default();
        new.insert(AttestationCa::apple_webauthn_root_ca())
            .expect("Must not fail");
        new
    }

    /// All CA's known to the Webauthn-RS project.
    pub fn all_known_cas() -> Self {
        let mut new = Self::default();
        new.insert(AttestationCa::yubico_u2f_root_ca_serial_457200631())
            .expect("Must not fail");
        new.insert(AttestationCa::microsoft_tpm_root_certificate_authority_2014())
            .expect("Must not fail");
        new.insert(AttestationCa::nitrokey_fido2_root_ca())
            .expect("Must not fail");
        new.insert(AttestationCa::nitrokey_u2f_root_ca())
            .expect("Must not fail");
        new.insert(AttestationCa::apple_webauthn_root_ca())
            .expect("Must not fail");
        new.insert(AttestationCa::android_root_ca_1())
            .expect("Must not fail");
        new.insert(AttestationCa::android_root_ca_2())
            .expect("Must not fail");
        new.insert(AttestationCa::android_root_ca_3())
            .expect("Must not fail");
        new.insert(AttestationCa::google_safetynet_ca())
            .expect("Must not fail");
        new.insert(AttestationCa::android_software_ca())
            .expect("Must not fail");
        new
    }
}
