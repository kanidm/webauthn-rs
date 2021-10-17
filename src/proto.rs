//! JSON Protocol Structs and representations for communication with authenticators
//! and clients.

use crate::base64_data::Base64UrlSafeData;
use crate::error::*;
use std::{collections::BTreeMap, convert::TryFrom};

#[cfg(feature = "wasm")]
use js_sys::{Array, Object, Uint8Array};
use std::borrow::Borrow;
use std::ops::Deref;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Representation of a UserId
pub type UserId = Vec<u8>;

/// Representation of a device counter
pub type Counter = u32;

/// Representation of an AAGUID
/// <https://www.w3.org/TR/webauthn/#aaguid>
pub type Aaguid = Vec<u8>;

/// A challenge issued by the server. This contains a set of random bytes.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Challenge(Vec<u8>);

#[cfg(feature = "core")]
impl Challenge {
    /// Creates a new Challenge from a vector of bytes.
    pub(crate) fn new(challenge: Vec<u8>) -> Self {
        Challenge(challenge)
    }
}

impl Into<Base64UrlSafeData> for Challenge {
    fn into(self) -> Base64UrlSafeData {
        Base64UrlSafeData(self.0)
    }
}

impl From<Base64UrlSafeData> for Challenge {
    fn from(d: Base64UrlSafeData) -> Self {
        Challenge(d.0)
    }
}

impl Borrow<ChallengeRef> for Challenge {
    fn borrow(&self) -> &ChallengeRef {
        ChallengeRef::new(&self.0)
    }
}

impl AsRef<ChallengeRef> for Challenge {
    fn as_ref(&self) -> &ChallengeRef {
        ChallengeRef::new(&self.0)
    }
}

impl Deref for Challenge {
    type Target = ChallengeRef;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

/// A reference to the challenge issued by the server.
/// This contains a set of random bytes.
///
/// ChallengeRef is the ?Sized Type that corresponds to Challenge
/// in the same way that &[u8] corresponds to Vec<u8>.
/// Vec<u8> : &[u8] :: Challenge : &ChallengeRef
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct ChallengeRef([u8]);

impl ChallengeRef {
    /// Creates a new ChallengeRef from a slice
    pub fn new(challenge: &[u8]) -> &ChallengeRef {
        // SAFETY
        // Because of #[repr(transparent)], [u8] is guaranteed to have the same representation as ChallengeRef.
        // This allows safe casting between *const pointers of these types.
        unsafe { &*(challenge as *const [u8] as *const ChallengeRef) }
    }
}

impl<'a> From<&'a Base64UrlSafeData> for &'a ChallengeRef {
    fn from(d: &'a Base64UrlSafeData) -> Self {
        ChallengeRef::new(d.0.as_slice())
    }
}

impl ToOwned for ChallengeRef {
    type Owned = Challenge;

    fn to_owned(&self) -> Self::Owned {
        Challenge(self.0.to_vec())
    }
}

impl AsRef<[u8]> for ChallengeRef {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for ChallengeRef {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
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
    // | X25519  | 4     | OKP      | X25519 for use w/ ECDH only        |
    // | X448    | 5     | OKP      | X448 for use w/ ECDH only          |
    // | Ed25519 | 6     | OKP      | Ed25519 for use w/ EdDSA only      |
    // | Ed448   | 7     | OKP      | Ed448 for use w/ EdDSA only        |
    // +---------+-------+----------+------------------------------------+
    /// Identifies this curve as SECP256R1 (X9_62_PRIME256V1 in OpenSSL)
    SECP256R1 = 1,
    /// Identifies this curve as SECP384R1
    SECP384R1 = 2,
    /// Identifies this curve as SECP521R1
    SECP521R1 = 3,
    // /// Identifies this OKP as ED25519
    // ED25519 = 6,
}

impl TryFrom<i128> for ECDSACurve {
    type Error = WebauthnError;
    fn try_from(u: i128) -> Result<Self, Self::Error> {
        match u {
            1 => Ok(ECDSACurve::SECP256R1),
            2 => Ok(ECDSACurve::SECP384R1),
            3 => Ok(ECDSACurve::SECP521R1),
            _ => Err(WebauthnError::COSEKeyECDSAInvalidCurve),
        }
    }
}

/// A COSE signature algorithm, indicating the type of key and hash type
/// that should be used. You shouldn't need to alter or use this value.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum COSEAlgorithm {
    /// Identifies this key as ECDSA (recommended SECP256R1) with SHA256 hashing
    #[serde(alias = "ECDSA_SHA256")]
    ES256 = -7, // recommends curve SECP256R1
    /// Identifies this key as ECDSA (recommended SECP384R1) with SHA384 hashing
    #[serde(alias = "ECDSA_SHA384")]
    ES384 = -35, // recommends curve SECP384R1
    /// Identifies this key as ECDSA (recommended SECP521R1) with SHA512 hashing
    #[serde(alias = "ECDSA_SHA512")]
    ES512 = -36, // recommends curve SECP521R1
    /// Identifies this key as RS256 aka RSASSA-PKCS1-v1_5 w/ SHA-256
    RS256 = -257,
    /// Identifies this key as RS384 aka RSASSA-PKCS1-v1_5 w/ SHA-384
    RS384 = -258,
    /// Identifies this key as RS512 aka RSASSA-PKCS1-v1_5 w/ SHA-512
    RS512 = -259,
    /// Identifies this key as PS256 aka RSASSA-PSS w/ SHA-256
    PS256 = -37,
    /// Identifies this key as PS384 aka RSASSA-PSS w/ SHA-384
    PS384 = -38,
    /// Identifies this key as PS512 aka RSASSA-PSS w/ SHA-512
    PS512 = -39,
    /// Identifies this key as EdDSA (likely curve ed25519)
    EDDSA = -8,
    /// Identifies this as an INSECURE RS1 aka RSASSA-PKCS1-v1_5 using SHA-1. This is not
    /// used by validators, but can exist in some windows hello tpm's
    INSECURE_RS1 = -65535,
}

impl TryFrom<i128> for COSEAlgorithm {
    type Error = WebauthnError;
    fn try_from(i: i128) -> Result<Self, Self::Error> {
        match i {
            -7 => Ok(COSEAlgorithm::ES256),
            -35 => Ok(COSEAlgorithm::ES384),
            -36 => Ok(COSEAlgorithm::ES512),
            -257 => Ok(COSEAlgorithm::RS256),
            -258 => Ok(COSEAlgorithm::RS384),
            -259 => Ok(COSEAlgorithm::RS512),
            -37 => Ok(COSEAlgorithm::PS256),
            -38 => Ok(COSEAlgorithm::PS384),
            -39 => Ok(COSEAlgorithm::PS512),
            -8 => Ok(COSEAlgorithm::EDDSA),
            -65535 => Ok(COSEAlgorithm::INSECURE_RS1),
            _ => Err(WebauthnError::COSEKeyInvalidAlgorithm),
        }
    }
}

impl From<&COSEAlgorithm> for i64 {
    fn from(c: &COSEAlgorithm) -> Self {
        match c {
            COSEAlgorithm::ES256 => -7,
            COSEAlgorithm::ES384 => -35,
            COSEAlgorithm::ES512 => -6,
            COSEAlgorithm::RS256 => -257,
            COSEAlgorithm::RS384 => -258,
            COSEAlgorithm::RS512 => -259,
            COSEAlgorithm::PS256 => -37,
            COSEAlgorithm::PS384 => -38,
            COSEAlgorithm::PS512 => -39,
            COSEAlgorithm::EDDSA => -8,
            COSEAlgorithm::INSECURE_RS1 => -65535,
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
    pub x: [u8; 32],
    /// The key's public Y coordinate.
    pub y: [u8; 32],
}

/// A COSE RSA PublicKey. This is a provided credential from a registered
/// authenticator.
/// You will likely never need to interact with this value, as it is part of the Credential
/// API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSERSAKey {
    /// An RSA modulus
    pub n: Vec<u8>,
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
    EC_OKP,
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

/// A credential ID type. At the moment this is a vector of bytes, but
/// it could also be a future change for this to be base64 string instead.
///
/// If changed, this would likely be a major library version change.
pub type CredentialID = Vec<u8>;

/// A user's authenticator credential. It contains an id, the public key
/// and a counter of how many times the authenticator has been used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// The ID of this credential.
    pub cred_id: CredentialID,
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

impl Credential {
    #[cfg(feature = "core")]
    pub(crate) fn new(
        acd: &AttestedCredentialData,
        ck: COSEKey,
        counter: u32,
        verified: bool,
        registration_policy: UserVerificationPolicy,
    ) -> Self {
        Credential {
            cred_id: acd.credential_id.clone(),
            cred: ck,
            counter,
            verified,
            registration_policy,
        }
    }
}

impl PartialEq<Credential> for Credential {
    fn eq(&self, c: &Credential) -> bool {
        self.cred_id == c.cred_id
    }
}

/// Defines the User Authenticator Verification policy. This is documented
/// <https://w3c.github.io/webauthn/#enumdef-userverificationrequirement>, and each
/// variant lists it's effects.
///
/// To be clear, Verification means that the Authenticator perform extra or supplementary
/// interaction with the user to verify who they are. An example of this is Apple Touch Id
/// required a fingerprint to be verified, or a yubico device requiring a pin in addition to
/// a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin where touch is
/// the only interaction - we only verify a user is present, but we don't have extra details
/// to the legitimacy of that user.
///
/// As UserVerificationPolicy is *only* used in credential registration, this stores the
/// verification state of the credential in the persisted credential. These persisted
/// credentials define which UserVerificationPolicy is issued during authentications.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationPolicy {
    /// Require User Verification bit to be set, and fail the registration or authentication
    /// if false. If the authenticator is not able to perform verification, it may not be
    /// usable with this policy.
    Required,
    /// Prefer User Verification bit to be set if possible - if not the credential will
    /// be considered "unverified". We STRONGLY DISCOURAGE you from using this value, as
    /// it *can* easily lead to inconistent states and unclear verification policies around
    /// credentials. You *should* use either `Required` or `Discouraged` to clearly
    /// request your requirements.
    #[serde(rename = "preferred")]
    Preferred_DO_NOT_USE,
    /// Request that no verification is performed, and fail if it is. This is intended to
    /// minimise user interaction in workflows, but is potentially a security risk to use.
    Discouraged,
}

impl Default for UserVerificationPolicy {
    fn default() -> Self {
        UserVerificationPolicy::Discouraged
    }
}

/// Relying Party Entity
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    /// The name of the relying party.
    pub name: String,
    /// The id of the relying party.
    pub id: String,
}

/// User Entity
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// The user's id (commonly name) in base64 form.
    pub id: Base64UrlSafeData,
    /// The user's name.
    pub name: String,
    /// The users preferred name for display.
    pub display_name: String,
}

/// Public key cryptographic parameters
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct PubKeyCredParams {
    /// The type of public-key credential.
    #[serde(rename = "type")]
    pub type_: String,
    /// The algorithm in use defined by COSE.
    pub alg: i64,
}

/// A descriptor of a credential that can be used.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    /// The type of credential.
    pub type_: String,
    /// The id of the credential.
    pub id: Base64UrlSafeData,
    /// <https://www.w3.org/TR/webauthn/#transport>
    /// may be usb, nfc, ble, internal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Valid credential protection policies
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub enum CredentialProtectionPolicy {
    /// This reflects "FIDO_2_0" semantics. In this configuration, performing
    /// some form of user verification is optional with or without credentialID
    /// list. This is the default state of the credential if the extension is
    /// not specified.
    UserVerificationOptional = 0x1,
    /// In this configuration, credential is discovered only when its
    /// credentialID is provided by the platform or when some form of user
    /// verification is performed.
    UserVerificationOptionalWithCredentialIDList = 0x2,
    /// This reflects that discovery and usage of the credential MUST be
    /// preceded by some form of user verification.
    UserVerificationRequired = 0x3,
}

impl TryFrom<u8> for CredentialProtectionPolicy {
    type Error = &'static str;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use CredentialProtectionPolicy::*;
        match v {
            0x1 => Ok(UserVerificationOptional),
            0x2 => Ok(UserVerificationOptionalWithCredentialIDList),
            0x3 => Ok(UserVerificationRequired),
            _ => Err("Invalid policy number"),
        }
    }
}

/// The client's response to the request that it use the `credProtect` extension
///
/// Implemented as wrapper struct to (de)serialize
/// [CredentialProtectionPolicy] as a number
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct CredProtectResponse(CredentialProtectionPolicy);

impl From<CredentialProtectionPolicy> for u8 {
    fn from(policy: CredentialProtectionPolicy) -> Self {
        policy as u8
    }
}

impl TryFrom<u8> for CredProtectResponse {
    type Error = <CredentialProtectionPolicy as TryFrom<u8>>::Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        CredentialProtectionPolicy::try_from(v).map(|policy| CredProtectResponse(policy))
    }
}

impl From<CredProtectResponse> for u8 {
    fn from(policy: CredProtectResponse) -> Self {
        u8::from(policy.0)
    }
}

/// The desired options for the client's use of the `credProtect` extension
///
/// <https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-credProtect-extension>
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredProtect {
    /// The credential policy to enact
    pub credential_protection_policy: CredentialProtectionPolicy,
    /// Whether it is better for the authenticator to fail to create a
    /// credential rather than ignore the protection policy
    /// If no value is provided, the client treats it as `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,
}

impl CredProtect {
    /// Create a [CredProtect] object
    pub fn new(
        credential_protection_policy: CredentialProtectionPolicy,
        enforce_credential_protection_policy: Option<bool>,
    ) -> Self {
        CredProtect {
            credential_protection_policy,
            enforce_credential_protection_policy,
        }
    }
}

/// Wrapper for a boolean value to indicate that this extension is requested by
/// the Relying Party.
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct CredBlobGet(pub bool);

/// Wrapper for an ArrayBuffer containing opaque data in an RP-specific format.
/// <https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-credBlob-extension>
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct CredBlobSet(pub Base64UrlSafeData);

impl From<Vec<u8>> for CredBlobSet {
    fn from(bytes: Vec<u8>) -> Self {
        CredBlobSet(Base64UrlSafeData(bytes))
    }
}

/// The response from the client regarding setting the `credBlob` extension
///
/// This is just a wrapper around a [bool] indicating whether the authenticator
/// was able to set the desired `credBlob` data.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct SetCredBlobResponse(bool);

/// The response from the client regarding querying the `credBlob` extension
///
/// This is just a wrapper around a byte array containing the `credBlob`
/// data.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct GetCredBlobResponse(Base64UrlSafeData);

/// Extension option inputs for [PublicKeyCredentialRequestOptions]
///
/// Implements \[AuthenticatorExtensionsClientInputs\] from the spec
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuthenticationExtensions {
    /// The `credBlob` extension options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_cred_blob: Option<CredBlobGet>,

    /// The `appid` extension options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
}

impl RequestAuthenticationExtensions {
    /// Get a builder for the [RequestRegistrationExtensions] struct
    #[must_use]
    pub fn builder() -> RequestAuthenticationExtensionsBuilder {
        RequestAuthenticationExtensionsBuilder::new()
    }
}

/// Builder for [RequestAuthenticationExtensions] objects.
pub struct RequestAuthenticationExtensionsBuilder(RequestAuthenticationExtensions);

impl RequestAuthenticationExtensionsBuilder {
    pub(crate) fn new() -> Self {
        Self(RequestAuthenticationExtensions {
            get_cred_blob: Some(CredBlobGet(false)),
            appid: None,
        })
    }

    /// Returns the inner extensions struct
    pub fn build(self) -> RequestAuthenticationExtensions {
        self.0
    }

    /// Set whether you want to get the credential blob extension
    ///
    /// # Example
    /// ```
    /// # use webauthn_rs::proto::{RequestAuthenticationExtensions, CredBlobGet};
    /// let extensions = RequestAuthenticationExtensions::builder()
    ///     .get_cred_blob(true)
    ///     .build();
    ///
    /// assert_eq!(extensions.get_cred_blob, Some(CredBlobGet(true)));
    /// ```
    pub fn get_cred_blob(mut self, get_cred_blob: bool) -> Self {
        self.0.get_cred_blob = Some(CredBlobGet(get_cred_blob));
        self
    }

    /// Set the AppId extension, for backwards compatibility with FIDO U2F credentials
    ///
    /// # Example
    /// ```
    /// # use webauthn_rs::proto::RequestAuthenticationExtensions;
    /// let extensions = RequestAuthenticationExtensions::builder()
    ///     .appid(String::from("https://domain.tld/app-id.json"))
    ///     .build();
    ///
    /// assert_eq!(extensions.appid, Some(String::from("https://domain.tld/app-id.json")));
    /// ```
    pub fn appid(mut self, appid: String) -> Self {
        self.0.appid = Some(appid);
        self
    }
}

/// Extension option inputs for [PublicKeyCredentialCreationOptions].
///
/// Implements \[AuthenticatorExtensionsClientInputs\] from the spec.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRegistrationExtensions {
    /// The `credProtect` extension options
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredProtect>,

    /// The `credBlob` extension options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<CredBlobSet>,
}

impl RequestRegistrationExtensions {
    /// Get a builder for the [RequestRegistrationExtensions] struct
    #[must_use]
    pub fn builder() -> RequestRegistrationExtensionsBuilder {
        RequestRegistrationExtensionsBuilder::new()
    }
}

/// Builder for [RequestRegistrationExtensions] objects.
pub struct RequestRegistrationExtensionsBuilder(RequestRegistrationExtensions);

impl RequestRegistrationExtensionsBuilder {
    pub(crate) fn new() -> Self {
        Self(RequestRegistrationExtensions {
            cred_protect: None,
            cred_blob: None,
        })
    }

    /// Returns the inner extensions struct
    pub fn build(self) -> RequestRegistrationExtensions {
        self.0
    }

    /// Set the credential protection extension options
    ///
    /// # Example
    /// ```
    /// # use webauthn_rs::proto::{RequestRegistrationExtensions, CredentialProtectionPolicy, CredProtect};
    /// let cred_protect = CredProtect::new(
    ///     CredentialProtectionPolicy::UserVerificationRequired,
    ///     None,
    /// );
    /// let extensions = RequestRegistrationExtensions::builder()
    ///     .cred_protect(cred_protect.clone())
    ///     .build();
    ///
    /// assert_eq!(extensions.cred_protect, Some(cred_protect));
    /// ```
    pub fn cred_protect(mut self, cred_protect: CredProtect) -> Self {
        self.0.cred_protect = Some(cred_protect);
        self
    }

    /// Set the credential blob extension options
    ///
    /// # Example
    /// ```
    /// # use webauthn_rs::proto::{RequestRegistrationExtensions, CredBlobSet};
    /// let cred_blob = vec![0xde, 0xad, 0xbe, 0xef];
    /// let extensions = RequestRegistrationExtensions::builder()
    ///     .cred_blob(cred_blob.clone())
    ///     .build();
    ///
    /// assert_eq!(extensions.cred_blob, Some(CredBlobSet::from(cred_blob)));
    /// ```
    pub fn cred_blob(mut self, cred_blob: Vec<u8>) -> Self {
        self.0.cred_blob = Some(CredBlobSet(Base64UrlSafeData(cred_blob)));
        self
    }
}

/// The output for registration ceremony extensions.
///
/// Implements the registration bits of \[AuthenticatorExtensionsClientOutputs\]
/// from the spec
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSignedExtensions {
    /// The `credProtect` extension
    pub cred_protect: Option<CredProtectResponse>,
    /// The `credBlob` extension
    pub cred_blob: Option<SetCredBlobResponse>,
}

/// The output for authentication cermeony extensions.
///
/// Implements the authentication bits of
/// \[AuthenticationExtensionsClientOutputs] from the spec
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationSignedExtensions {
    /// The credBlob extension
    pub cred_blob: Option<GetCredBlobResponse>,
}

impl Ceremony for Registration {
    type SignedExtensions = RegistrationSignedExtensions;
}

impl Ceremony for Authentication {
    type SignedExtensions = AuthenticationSignedExtensions;
}

/// <https://w3c.github.io/webauthn/#dictionary-makecredentialoptions>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    /// The relying party
    pub rp: RelyingParty,
    /// The user.
    pub user: User,
    /// The one-time challenge for the credential to sign.
    pub challenge: Base64UrlSafeData,
    /// The set of cryptographic types allowed by this server.
    pub pub_key_cred_params: Vec<PubKeyCredParams>,

    /// The timeout for the authenticator to stop accepting the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    /// The requested attestation level from the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,

    /// Credential ID's that are excluded from being able to be registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    /// Criteria defining which authenticators may be used in this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,

    /// Non-standard extensions that may be used by the browser/authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<RequestRegistrationExtensions>,
}

/// <https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    /// How the authenticator should be attached to the client machine.
    /// Note this is only a hint. It is not enforced in anyway shape or form.
    /// <https://www.w3.org/TR/webauthn/#attachment>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// Hint to the credential to create a resident key. Note this can not be enforced
    /// or validated, so the authenticator may choose to ignore this parameter.
    /// <https://www.w3.org/TR/webauthn/#resident-credential>
    pub require_resident_key: bool,

    /// The user verification level to request during registration. Depending on if this
    /// authenticator provides verification may affect future interactions as this is
    /// associated to the credential during registration.
    pub user_verification: UserVerificationPolicy,
}

/// The authenticator attachment hint. This is NOT enforced, and is only used
/// to help a user select a relevant authenticator type.
///
/// <https://www.w3.org/TR/webauthn/#attachment>
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticatorAttachment {
    /// Request a device that is part of the machine aka inseperable.
    /// <https://www.w3.org/TR/webauthn/#attachment>
    #[serde(rename = "platform")]
    Platform,
    /// Request a device that can be seperated from the machine aka an external token.
    /// <https://www.w3.org/TR/webauthn/#attachment>
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// <https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// Do not request attestation.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none>
    None,

    /// Request attestation in a semi-anonymized form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect>
    Indirect,

    /// Request attestation in a direct form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct>
    Direct,
}

/// <https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor>
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// The type of credential
    #[serde(rename = "type")]
    type_: String,
    /// The credential id.
    id: Base64UrlSafeData,
    /// The allowed transports for this credential. Note this is a hint, and is not
    /// enforced.
    #[serde(skip_serializing_if = "Option::is_none")]
    transports: Option<Vec<AuthenticatorTransport>>,
}

impl PublicKeyCredentialDescriptor {
    /// Constructed from a byte array
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            type_: "public-key".to_string(),
            id: Base64UrlSafeData(bytes),
            transports: None,
        }
    }
}

/// <https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(unused)]
pub enum AuthenticatorTransport {
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb>
    Usb,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc>
    Nfc,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble>
    Ble,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal>
    Internal,
}

/// A JSON serializable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationChallengeResponse {
    /// The options.
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[cfg(feature = "wasm")]
impl Into<web_sys::CredentialCreationOptions> for CreationChallengeResponse {
    fn into(self) -> web_sys::CredentialCreationOptions {
        let chal = Uint8Array::from(self.public_key.challenge.0.as_slice());
        let userid = Uint8Array::from(self.public_key.user.id.0.as_slice());

        let jsv = JsValue::from_serde(&self).unwrap();

        let pkcco = js_sys::Reflect::get(&jsv, &"publicKey".into()).unwrap();
        js_sys::Reflect::set(&pkcco, &"challenge".into(), &chal).unwrap();

        let user = js_sys::Reflect::get(&pkcco, &"user".into()).unwrap();
        js_sys::Reflect::set(&user, &"id".into(), &userid).unwrap();

        if let Some(extensions) = self.public_key.extensions {
            if let Some(cred_blob) = extensions.cred_blob {
                let exts = js_sys::Reflect::get(&pkcco, &"extensions".into()).unwrap();
                let cred_blob = Uint8Array::from(cred_blob.0.as_ref());
                js_sys::Reflect::set(&exts, &"credBlob".into(), &cred_blob).unwrap();
            }
        }
        web_sys::CredentialCreationOptions::from(jsv)
    }
}

/// The requested options for the authentication
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    /// The challenge that should be signed by the authenticator.
    pub challenge: Base64UrlSafeData,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The timeout for the authenticator in case of no interaction.
    pub timeout: Option<u32>,
    /// The relying party ID.
    pub rp_id: String,
    /// The set of credentials that are allowed to sign this challenge.
    pub allow_credentials: Vec<AllowCredentials>,
    /// The verification policy the browser will request.
    pub user_verification: UserVerificationPolicy,
    /// extensions.
    pub extensions: Option<RequestAuthenticationExtensions>,
}

/// A JSON serializable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestChallengeResponse {
    /// The options.
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[cfg(feature = "wasm")]
impl Into<web_sys::CredentialRequestOptions> for RequestChallengeResponse {
    fn into(self) -> web_sys::CredentialRequestOptions {
        let chal = Uint8Array::from(self.public_key.challenge.0.as_slice());
        let allow_creds: Array = self
            .public_key
            .allow_credentials
            .iter()
            .map(|ac| {
                let obj = Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &JsValue::from_str(ac.type_.as_str()))
                    .unwrap();

                js_sys::Reflect::set(&obj, &"id".into(), &Uint8Array::from(ac.id.0.as_slice()))
                    .unwrap();

                if let Some(transports) = &ac.transports {
                    let tarray: Array = transports
                        .iter()
                        .map(|s| JsValue::from_str(s.as_str()))
                        .collect();

                    js_sys::Reflect::set(&obj, &"transports".into(), &tarray).unwrap();
                }

                obj
            })
            .collect();

        let jsv = JsValue::from_serde(&self).unwrap();

        let pkcco = js_sys::Reflect::get(&jsv, &"publicKey".into()).unwrap();
        js_sys::Reflect::set(&pkcco, &"challenge".into(), &chal).unwrap();

        js_sys::Reflect::set(&pkcco, &"allowCredentials".into(), &allow_creds).unwrap();

        web_sys::CredentialRequestOptions::from(jsv)
    }
}

impl RequestChallengeResponse {
    #[cfg(feature = "core")]
    pub(crate) fn new(
        challenge: Challenge,
        timeout: u32,
        relaying_party: String,
        allow_credentials: Vec<AllowCredentials>,
        user_verification_policy: UserVerificationPolicy,
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Self {
        RequestChallengeResponse {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: challenge.into(),
                timeout: Some(timeout),
                rp_id: relaying_party,
                allow_credentials,
                user_verification: user_verification_policy,
                extensions,
            },
        }
    }
}

/// The data collected and hashed in the operation.
/// <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata>
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct CollectedClientData {
    /// The credential type
    #[serde(rename = "type")]
    pub type_: String,
    /// The challenge.
    pub challenge: Base64UrlSafeData,
    /// The rp origin as the browser understood it.
    pub origin: url::Url,
    /// The inverse of the sameOriginWithAncestors argument value that was
    /// passed into the internal method.
    #[serde(rename = "crossOrigin", skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,
    /// tokenBinding.
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
    /// This struct be extended, so it's important to be tolerant of unknown
    /// keys.
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_json::value::Value>,
}

/// Token binding
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenBinding {
    /// status
    pub status: String,
    /// id
    pub id: Option<String>,
}

impl TryFrom<&[u8]> for CollectedClientData {
    type Error = WebauthnError;
    fn try_from(data: &[u8]) -> Result<CollectedClientData, WebauthnError> {
        let ccd: CollectedClientData =
            serde_json::from_slice(data).map_err(WebauthnError::ParseJSONFailure)?;
        Ok(ccd)
    }
}

/// Attested Credential Data
#[derive(Debug, Clone)]
pub(crate) struct AttestedCredentialData {
    /// The guid of the authenticator. May indicate manufacturer.
    pub(crate) aaguid: Aaguid,
    /// The credential ID.
    pub(crate) credential_id: CredentialID,
    /// The credentials public Key.
    pub(crate) credential_pk: serde_cbor::Value,
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
    type SignedExtensions: serde::de::DeserializeOwned + std::fmt::Debug;
}

/// <https://w3c.github.io/webauthn/#sctn-attestation>
#[derive(Debug, Clone)]
pub struct AuthenticatorData<T: Ceremony> {
    /// Hash of the relying party id.
    pub(crate) rp_id_hash: Vec<u8>,
    /// The counter of this credentials activations.
    pub counter: u32,
    /// Flag if the user was present.
    pub user_present: bool,
    /// Flag is the user verified to the device. Implies presence.
    pub user_verified: bool,
    /// The optional attestation.
    pub(crate) acd: Option<AttestedCredentialData>,
    /// Extensions supplied by the device.
    pub(crate) extensions: Option<T::SignedExtensions>,
}

/// The processed Attestation that the Authenticator is providing in it's AttestedCredentialData
#[derive(Debug)]
#[cfg(feature = "core")]
pub enum ParsedAttestationData {
    /// The credential is authenticated by a signing X509 Certificate
    /// from a vendor or provider.
    Basic(crate::crypto::X509PublicKey),
    /// The credential is authenticated using surrogate basic attestation
    /// it uses the credential private key to create the attestation signature
    Self_,
    /// The credential is authenticated using a CA, and may provide a
    /// ca chain to validate to it's root.
    AttCa(
        crate::crypto::X509PublicKey,
        Vec<crate::crypto::X509PublicKey>,
    ),
    /// The credential is authenticated using an anonymization CA, and may provide a ca chain to
    /// validate to it's root.
    AnonCa(
        crate::crypto::X509PublicKey,
        Vec<crate::crypto::X509PublicKey>,
    ),
    /// Unimplemented
    ECDAA,
    /// No Attestation type was provided with this Credential. If in doubt
    /// reject this Credential.
    None,
    /// Uncertain Attestation was provided with this Credential, which may not
    /// be trustworthy in all cases. If in doubt, reject this type.
    Uncertain,
}

fn cbor_parser(i: &[u8]) -> nom::IResult<&[u8], serde_cbor::Value> {
    let mut deserializer = serde_cbor::Deserializer::from_slice(i);
    let v = serde::de::Deserialize::deserialize(&mut deserializer)
        .map_err(|_| nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(1))))?;

    let len = deserializer.byte_offset();

    Ok((&i[len..], v))
}

fn extensions_parser<T: Ceremony>(i: &[u8]) -> nom::IResult<&[u8], T::SignedExtensions> {
    map_res!(
        i,
        cbor_parser,
        serde_cbor::value::from_value::<T::SignedExtensions>
    )
}

named!( acd_parser<&[u8], AttestedCredentialData>,
    do_parse!(
        aaguid: take!(16) >>
        cred_id_len: u16!(nom::Endianness::Big) >>
        cred_id: take!(cred_id_len) >>
        cred_pk: cbor_parser >>
        (AttestedCredentialData {
            aaguid: aaguid.to_vec(),
            credential_id: cred_id.to_vec(),
            credential_pk: cred_pk,
        })
    )
);

named!( authenticator_data_flags<&[u8], (bool, bool, bool, bool)>,
    bits!(
        do_parse!(
            exten_pres: map!(take_bits!(u8, 1), |i| i != 0)  >>
            acd_pres: map!(take_bits!(u8, 1), |i| i != 0) >>
            take_bits!(u8, 1) >>
            take_bits!(u8, 1) >>
            take_bits!(u8, 1) >>
            u_ver: map!(take_bits!(u8, 1), |i| i != 0) >>
            take_bits!(u8, 1) >>
            u_pres: map!(take_bits!(u8, 1), |i| i != 0) >>
            ((exten_pres, acd_pres, u_ver, u_pres))
        )
    )
);

fn authenticator_data_parser<T: Ceremony>(i: &[u8]) -> nom::IResult<&[u8], AuthenticatorData<T>> {
    do_parse!(
        i,
        rp_id_hash: take!(32)
            >> data_flags: authenticator_data_flags
            >> counter: u32!(nom::Endianness::Big)
            >> acd: cond!(data_flags.1, acd_parser)
            >> extensions: cond!(data_flags.0, extensions_parser::<T>)
            >> (AuthenticatorData {
                rp_id_hash: rp_id_hash.to_vec(),
                counter,
                user_verified: data_flags.2,
                user_present: data_flags.3,
                acd,
                extensions,
            })
    )
}

impl<T: Ceremony> TryFrom<&[u8]> for AuthenticatorData<T> {
    type Error = WebauthnError;
    fn try_from(auth_data_bytes: &[u8]) -> Result<Self, Self::Error> {
        authenticator_data_parser(auth_data_bytes)
            .map_err(|e| {
                log::debug!("nom -> {:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, ad)| ad)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttestationObjectInner<'a> {
    pub(crate) auth_data: &'a [u8],
    pub(crate) fmt: &'a str,
    pub(crate) att_stmt: serde_cbor::Value,
}

/// Attestation Object
#[derive(Debug)]
pub struct AttestationObject<T: Ceremony> {
    /// auth_data.
    pub(crate) auth_data: AuthenticatorData<T>,
    /// auth_data_bytes.
    pub(crate) auth_data_bytes: Vec<u8>,
    /// format.
    pub(crate) fmt: String,
    /// <https://w3c.github.io/webauthn/#generating-an-attestation-object>
    pub(crate) att_stmt: serde_cbor::Value,
}

impl<T: Ceremony> TryFrom<&[u8]> for AttestationObject<T> {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<AttestationObject<T>, WebauthnError> {
        let aoi: AttestationObjectInner =
            serde_cbor::from_slice(&data).map_err(WebauthnError::ParseCBORFailure)?;
        let auth_data_bytes: &[u8] = aoi.auth_data;
        let auth_data = AuthenticatorData::try_from(auth_data_bytes)?;

        // Yay! Now we can assemble a reasonably sane structure.
        Ok(AttestationObject {
            fmt: aoi.fmt.to_owned(),
            auth_data,
            auth_data_bytes: auth_data_bytes.to_owned(),
            att_stmt: aoi.att_stmt,
        })
    }
}

/// <https://w3c.github.io/webauthn/#authenticatorattestationresponse>
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AuthenticatorAttestationResponseRaw {
    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject>
    #[serde(rename = "attestationObject")]
    pub attestation_object: Base64UrlSafeData,

    /// <https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson>
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
}

/// Parsed AuthenticatorResponse
#[cfg(feature = "core")]
pub(crate) struct AuthenticatorAttestationResponse<T: Ceremony> {
    pub(crate) attestation_object: AttestationObject<T>,
    pub(crate) client_data_json: CollectedClientData,
    pub(crate) client_data_json_bytes: Vec<u8>,
}

#[cfg(feature = "core")]
impl<T: Ceremony> TryFrom<&AuthenticatorAttestationResponseRaw>
    for AuthenticatorAttestationResponse<T>
{
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAttestationResponseRaw) -> Result<Self, Self::Error> {
        let ccdj = CollectedClientData::try_from(aarr.client_data_json.as_ref())?;
        log::debug!("ccdj: {:?}", ccdj);
        let ao = AttestationObject::try_from(aarr.attestation_object.as_ref())?;

        Ok(AuthenticatorAttestationResponse {
            attestation_object: ao,
            client_data_json: ccdj,
            client_data_json_bytes: aarr.client_data_json.clone().into(),
        })
    }
}

/// A client response to a registration challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by registration to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
/// <https://w3c.github.io/webauthn/#iface-pkcredential>
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterPublicKeyCredential {
    /// The id of the PublicKey credential, likely in base64
    pub id: String,

    /// The id of the credential, as binary.
    #[serde(rename = "rawId")]
    pub raw_id: Base64UrlSafeData,

    /// <https://w3c.github.io/webauthn/#dom-publickeycredential-response>
    pub response: AuthenticatorAttestationResponseRaw,

    /// The type of credential.
    #[serde(rename = "type")]
    pub type_: String,
}

#[cfg(feature = "wasm")]
impl From<web_sys::PublicKeyCredential> for RegisterPublicKeyCredential {
    fn from(data: web_sys::PublicKeyCredential) -> RegisterPublicKeyCredential {
        // First, we have to b64 some data here.
        // data.raw_id
        let data_raw_id =
            Uint8Array::new(&js_sys::Reflect::get(&data, &"rawId".into()).unwrap()).to_vec();

        let data_response = js_sys::Reflect::get(&data, &"response".into()).unwrap();
        let data_response_attestation_object = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"attestationObject".into()).unwrap(),
        )
        .to_vec();

        let data_response_client_data_json = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"clientDataJSON".into()).unwrap(),
        )
        .to_vec();

        // Now we can convert to the base64 values for json.
        let data_raw_id_b64 = Base64UrlSafeData(data_raw_id);

        let data_response_attestation_object_b64 =
            Base64UrlSafeData(data_response_attestation_object);

        let data_response_client_data_json_b64 = Base64UrlSafeData(data_response_client_data_json);
        RegisterPublicKeyCredential {
            id: format!("{}", data_raw_id_b64),
            raw_id: data_raw_id_b64,
            type_: "public-key".to_string(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: data_response_attestation_object_b64,
                client_data_json: data_response_client_data_json_b64,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuthenticatorAssertionResponse<T: Ceremony> {
    pub(crate) authenticator_data: AuthenticatorData<T>,
    pub(crate) authenticator_data_bytes: Vec<u8>,
    pub(crate) client_data: CollectedClientData,
    pub(crate) client_data_bytes: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) user_handle: Option<Vec<u8>>,
}

impl<T: Ceremony> TryFrom<&AuthenticatorAssertionResponseRaw>
    for AuthenticatorAssertionResponse<T>
{
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAssertionResponseRaw) -> Result<Self, Self::Error> {
        Ok(AuthenticatorAssertionResponse {
            authenticator_data: AuthenticatorData::try_from(aarr.authenticator_data.as_ref())?,
            authenticator_data_bytes: aarr.authenticator_data.clone().into(),
            client_data: CollectedClientData::try_from(aarr.client_data_json.as_ref())?,
            client_data_bytes: aarr.client_data_json.clone().into(),
            signature: aarr.signature.clone().into(),
            user_handle: aarr.user_handle.clone().map(|uh| uh.into()),
        })
    }
}

/// <https://w3c.github.io/webauthn/#authenticatorassertionresponse>
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticatorAssertionResponseRaw {
    /// Raw authenticator data.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Base64UrlSafeData,

    /// Signed client data.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,

    /// Signature
    pub signature: Base64UrlSafeData,

    /// Optional userhandle.
    #[serde(rename = "userHandle")]
    pub user_handle: Option<Base64UrlSafeData>,
}

/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs>
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationExtensionsClientOutputs {
    /// Indicates whether the client used the provided appid extension
    #[serde(default)]
    pub appid: bool,
}

#[cfg(feature = "wasm")]
impl From<web_sys::AuthenticationExtensionsClientOutputs>
    for AuthenticationExtensionsClientOutputs
{
    fn from(
        ext: web_sys::AuthenticationExtensionsClientOutputs,
    ) -> AuthenticationExtensionsClientOutputs {
        let appid = js_sys::Reflect::get(&ext, &"appid".into())
            .ok()
            .and_then(|jv| jv.as_bool())
            .unwrap_or(false);

        AuthenticationExtensionsClientOutputs { appid }
    }
}

/// A client response to an authentication challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by authentication to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
#[derive(Debug, Deserialize, Serialize)]
pub struct PublicKeyCredential {
    /// The credential Id, likely base64
    pub id: String,
    /// The binary of the credential id.
    #[serde(rename = "rawId")]
    pub raw_id: Base64UrlSafeData,
    /// The authenticator response.
    pub response: AuthenticatorAssertionResponseRaw,
    /// The extensions sent by the client
    pub extensions: Option<AuthenticationExtensionsClientOutputs>,
    /// The authenticator type.
    #[serde(rename = "type")]
    pub type_: String,
}

impl PublicKeyCredential {
    /// Get the supplied userHandle if provided
    pub fn get_user_handle(&self) -> Option<&[u8]> {
        self.response.user_handle.as_ref().map(|uh| uh.as_ref())
    }
}

#[cfg(feature = "wasm")]
impl From<web_sys::PublicKeyCredential> for PublicKeyCredential {
    fn from(data: web_sys::PublicKeyCredential) -> PublicKeyCredential {
        let data_raw_id =
            Uint8Array::new(&js_sys::Reflect::get(&data, &"rawId".into()).unwrap()).to_vec();

        let data_response = js_sys::Reflect::get(&data, &"response".into()).unwrap();

        let data_response_authenticator_data = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"authenticatorData".into()).unwrap(),
        )
        .to_vec();

        let data_response_signature =
            Uint8Array::new(&js_sys::Reflect::get(&data_response, &"signature".into()).unwrap())
                .to_vec();

        let data_response_user_handle =
            &js_sys::Reflect::get(&data_response, &"userHandle".into()).unwrap();
        let data_response_user_handle = if data_response_user_handle.is_undefined() {
            None
        } else {
            Some(Uint8Array::new(data_response_user_handle).to_vec())
        };

        let data_response_client_data_json = Uint8Array::new(
            &js_sys::Reflect::get(&data_response, &"clientDataJSON".into()).unwrap(),
        )
        .to_vec();

        let data_extensions = data.get_client_extension_results();

        // Base64 it

        let data_raw_id_b64 = Base64UrlSafeData(data_raw_id);
        let data_response_client_data_json_b64 = Base64UrlSafeData(data_response_client_data_json);
        let data_response_authenticator_data_b64 =
            Base64UrlSafeData(data_response_authenticator_data);
        let data_response_signature_b64 = Base64UrlSafeData(data_response_signature);

        let data_response_user_handle_b64 = data_response_user_handle.map(|d| Base64UrlSafeData(d));

        PublicKeyCredential {
            id: format!("{}", data_raw_id_b64),
            raw_id: data_raw_id_b64,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: data_response_authenticator_data_b64,
                client_data_json: data_response_client_data_json_b64,
                signature: data_response_signature_b64,
                user_handle: data_response_user_handle_b64,
            },
            extensions: Some(data_extensions.into()),
            type_: "public-key".to_string(),
        }
    }
}

// ===== tpm shit show begins =====

/// A magic constant that defines that a Tpm attestation comes from a TPM
pub const TPM_GENERATED_VALUE: u32 = 0xff544347;

#[derive(Debug, PartialEq)]
#[repr(u16)]
/// Tpm statement types.
pub enum TpmSt {
    /// Unused
    RspCommand = 0x00c4,
    /// Unused
    Null = 0x8000,
    /// Unused
    NoSessions = 0x8001,
    /// Unused
    Sessions = 0x8002,
    /// Unused
    ReservedA = 0x8003,
    /// Unused
    ReservedB = 0x8004,
    /// Unused
    AttestNV = 0x8014,
    /// Unused
    AttestCommandAudit = 0x8015,
    /// Unused
    AttestSessionAudit = 0x8016,
    /// Denote that this attestation contains a certify statement.
    AttestCertify = 0x8017,
    /// Unused
    AttestQuote = 0x8018,
    /// Unused
    AttestTime = 0x8019,
    /// Unused
    AttestCreation = 0x801a,
    /// Unused
    ReservedC = 0x801b,
    /// Unused
    Creation = 0x8021,
    /// Unused
    Verified = 0x8022,
    /// Unused
    AuthSecret = 0x8023,
    /// Unused
    Hashcheck = 0x8024,
    /// Unused
    AuthSigned = 0x8025,
    /// Unused
    FUManifest = 0x8029,
}

impl TpmSt {
    fn new(v: u16) -> Option<Self> {
        match v {
            0x00c4 => Some(TpmSt::RspCommand),
            0x8000 => Some(TpmSt::Null),
            0x8001 => Some(TpmSt::NoSessions),
            0x8002 => Some(TpmSt::Sessions),
            0x8003 => Some(TpmSt::ReservedA),
            0x8004 => Some(TpmSt::ReservedB),
            0x8014 => Some(TpmSt::AttestNV),
            0x8015 => Some(TpmSt::AttestCommandAudit),
            0x8016 => Some(TpmSt::AttestSessionAudit),
            0x8017 => Some(TpmSt::AttestCertify),
            0x8018 => Some(TpmSt::AttestQuote),
            0x8019 => Some(TpmSt::AttestTime),
            0x801a => Some(TpmSt::AttestCreation),
            0x801b => Some(TpmSt::ReservedC),
            0x8021 => Some(TpmSt::Creation),
            0x8022 => Some(TpmSt::Verified),
            0x8023 => Some(TpmSt::AuthSecret),
            0x8024 => Some(TpmSt::Hashcheck),
            0x8025 => Some(TpmSt::AuthSigned),
            0x8029 => Some(TpmSt::FUManifest),
            _ => None,
        }
    }
}

#[derive(Debug)]
/// Information about the TPM's clock. May be obfuscated.
pub struct TpmsClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool, // u8
}

named!( tpmsclockinfo_parser<&[u8], TpmsClockInfo>,
    do_parse!(
        clock: u64!(nom::Endianness::Big) >>
        reset_count: u32!(nom::Endianness::Big) >>
        restart_count: u32!(nom::Endianness::Big) >>
        safe: switch!(take!(1),
            [0] => value!(false) |
            [1] => value!(true)
        ) >>
        (TpmsClockInfo {
            clock, reset_count, restart_count, safe
        })
    )
);

#[derive(Debug)]
/// Tpm name enumeration.
pub enum Tpm2bName {
    /// No name present
    None,
    /// A handle reference
    Handle(u32),
    /// A digest of a name
    Digest(Vec<u8>),
}

#[derive(Debug)]
/// Tpm attestation union, switched by TpmSt.
pub enum TpmuAttest {
    /// The TpmuAttest contains a certify structure.
    AttestCertify(Tpm2bName, Tpm2bName),
    // AttestNV
    // AttestCommandAudit
    // AttestSessionAudit
    // AttestQuote
    // AttestTime
    // AttestCreation
    /// An invalid union
    Invalid,
}

#[derive(Debug)]
/// Tpm attestation structure.
pub struct TpmsAttest {
    /// Magic. Should be set to TPM_GENERATED_VALUE
    pub magic: u32,
    /// The type of attestation for typeattested.
    pub type_: TpmSt,
    /// Ignored in webauthn.
    pub qualified_signer: Tpm2bName,
    /// Ignored in webauthn.
    pub extra_data: Option<Vec<u8>>,
    /// Tpm Clock Information
    pub clock_info: TpmsClockInfo,
    /// The TPM firmware version. May be obfuscated.
    pub firmware_version: u64,
    /// The attestation.
    pub typeattested: TpmuAttest,
}

named!( tpm2b_name<&[u8], Tpm2bName>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(Tpm2bName::None) |
        4 => map!(u32!(nom::Endianness::Big), Tpm2bName::Handle) |
        size => map!(take!(size), |d| Tpm2bName::Digest(d.to_vec()))
    )
);

named!( tpm2b_data<&[u8], Option<Vec<u8>>>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(None) |
        size => map!(take!(size), |d| Some(d.to_vec()))
    )
);

named! ( tpmuattestcertify<&[u8], TpmuAttest>,
    do_parse!(
        name: tpm2b_name >>
        qualified_name: tpm2b_name >>
        (
            TpmuAttest::AttestCertify(name, qualified_name)
        )
    )
);

named!( tpmsattest_parser<&[u8], TpmsAttest>,
    do_parse!(
        magic: verify!(u32!(nom::Endianness::Big), |x| x == TPM_GENERATED_VALUE) >>
        type_: map_opt!(u16!(nom::Endianness::Big), TpmSt::new) >>
        qualified_signer: tpm2b_name >>
        extra_data: tpm2b_data >>
        clock_info: tpmsclockinfo_parser >>
        firmware_version: u64!(nom::Endianness::Big) >>
        // we *could* try to parse this generically, BUT I can't work out how to amke nom
        // reach back to type_ to switch on the type. However, webauthn ONLY needs attestCertify
        // so we can blindly attempt to parse this as it is.
        typeattested: tpmuattestcertify >>
        /*
        typeattested: switch!(type_,
            TpmSt::AttestCertify => tpmuattestcertify |
            _ => value!(TpmuAttest::Invalid)
        ) >>
        */
        (TpmsAttest {
            magic, type_, qualified_signer, extra_data, clock_info, firmware_version, typeattested
        })
    )
);

impl TryFrom<&[u8]> for TpmsAttest {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<TpmsAttest, WebauthnError> {
        tpmsattest_parser(data)
            .map_err(|e| {
                log::debug!("{:?}", e);
                // eprintln!("{:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
/// The tpm cryptographic algorithm that may be in use.
pub enum TpmAlgId {
    /// Error occured
    Error = 0x0000,
    /// RSA
    Rsa = 0x0001,
    /// Insecure Sha1
    Sha1 = 0x0004,
    /// Hmac
    Hmac = 0x0005,
    /// Aes
    Aes = 0x0006,
    // Mgf1 = 0x0007,
    // KeyedHash = 0x0008,
    // Xor = 0x000A,
    /// Sha256
    Sha256 = 0x000B,
    /// Sha384
    Sha384 = 0x000C,
    /// Sha512
    Sha512 = 0x000D,
    /// Null (no algorithm)
    Null = 0x0010,
    // Sm3_256 = 0x0012,
    // Sm4 = 0x0013,
    /// Rsa SSA
    RsaSSA = 0x0014,
    // RsAes = 0x0015,
    /// Rsa PSS
    RsaPSS = 0x0016,
    // Oaep = 0x0017,
    /// Ecdsa
    Ecdsa = 0x0018,
    // Ecdh = 0x0019,
    /// Ecdaa
    Ecdaa = 0x001A,
    // Sm2 = 0x001B,
    // EcSchnorr = 0x001C,
    // EcMqv = 0x001D,
    // Kdf1Sp80056A = 0x0020,
    // Kdf2 = 0x0021,
    // Kdf1Sp800108 = 0x0022,
    /// Ecc
    Ecc = 0x0023,
    // Symcipher = 0x0025,
    // Camellia = 0x0026,
    // Ctr = 0x0040,
    // Ofb = 0x0041,
    // Cbc = 0x0042,
    // Cfb = 0x0043,
    // Ecb = 0x0044,
}

impl TpmAlgId {
    fn new(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(TpmAlgId::Error),
            0x0001 => Some(TpmAlgId::Rsa),
            0x0004 => Some(TpmAlgId::Sha1),
            0x0005 => Some(TpmAlgId::Hmac),
            0x0006 => Some(TpmAlgId::Aes),
            0x000B => Some(TpmAlgId::Sha256),
            0x000C => Some(TpmAlgId::Sha384),
            0x000D => Some(TpmAlgId::Sha512),
            0x0010 => Some(TpmAlgId::Null),
            0x0014 => Some(TpmAlgId::RsaSSA),
            0x0016 => Some(TpmAlgId::RsaPSS),
            0x0018 => Some(TpmAlgId::Ecdsa),
            0x001A => Some(TpmAlgId::Ecdaa),
            0x0023 => Some(TpmAlgId::Ecc),
            _ => None,
        }
    }
}

// Later, this probably would be rewritten interms of the chosen
// symetric algo, but for now it's always Null
#[derive(Debug)]
/// Symmetric crypto definition. Unused in webauthn
pub struct TpmtSymDefObject {
    algorithm: TpmAlgId,
    // keybits: Option<()>,
    // mode: Option<()>,
    // details
}

fn parse_tpmtsymdefobject(input: &[u8]) -> nom::IResult<&[u8], Option<TpmtSymDefObject>> {
    let (data, algorithm) = map_opt!(input, u16!(nom::Endianness::Big), TpmAlgId::new)?;
    match algorithm {
        TpmAlgId::Null => Ok((data, None)),
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// The Rsa Scheme. Unused in webauthn.
pub struct TpmtRsaScheme {
    algorithm: TpmAlgId,
    // details
}

fn parse_tpmtrsascheme(input: &[u8]) -> nom::IResult<&[u8], Option<TpmtRsaScheme>> {
    let (data, algorithm) = map_opt!(input, u16!(nom::Endianness::Big), TpmAlgId::new)?;
    match algorithm {
        TpmAlgId::Null => Ok((data, None)),
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// Rsa Parameters.
pub struct TpmsRsaParms {
    // TPMT_SYM_DEF_OBJECT + ALG_NULL
    symmetric: Option<TpmtSymDefObject>,
    // TPMT_RSA_SCHEME+ (rsapss, rsassa, null)
    scheme: Option<TpmtRsaScheme>,
    // TPMI_RSA_KEY_BITS
    keybits: u16,
    // u32
    /// The Rsa Exponent
    pub exponent: u32,
}

named!( tpmsrsaparms_parser<&[u8], TpmsRsaParms>,
    do_parse!(
        symmetric: parse_tpmtsymdefobject >>
        scheme: parse_tpmtrsascheme >>
        keybits: u16!(nom::Endianness::Big) >>
        exponent: u32!(nom::Endianness::Big) >>
        (TpmsRsaParms {
            symmetric, scheme, keybits, exponent
        })
    )
);

/*
#[derive(Debug)]
pub struct TpmsEccParms {
}
*/

#[derive(Debug)]
/// Asymmetric Public Parameters
pub enum TpmuPublicParms {
    // KeyedHash
    // Symcipher
    /// Rsa
    Rsa(TpmsRsaParms),
    // Ecc(TpmsEccParms),
    // Asym
}

fn parse_tpmupublicparms(input: &[u8], alg: TpmAlgId) -> nom::IResult<&[u8], TpmuPublicParms> {
    // eprintln!("tpmupublicparms input -> {:?}", input);
    match alg {
        TpmAlgId::Rsa => {
            tpmsrsaparms_parser(input).map(|(data, inner)| (data, TpmuPublicParms::Rsa(inner)))
        }
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// Asymmetric Public Key
pub enum TpmuPublicId {
    // KeyedHash
    // Symcipher
    /// Rsa
    Rsa(Vec<u8>),
    // Ecc(TpmsEccParms),
    // Asym
}

named!( tpmsrsapublickey_parser<&[u8], Vec<u8>>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(Vec::new()) |
        size => map!(take!(size), |d| d.to_vec())
    )
);

fn parse_tpmupublicid(input: &[u8], alg: TpmAlgId) -> nom::IResult<&[u8], TpmuPublicId> {
    // eprintln!("tpmupublicparms input -> {:?}", input);
    match alg {
        TpmAlgId::Rsa => {
            tpmsrsapublickey_parser(input).map(|(data, inner)| (data, TpmuPublicId::Rsa(inner)))
        }
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// Tpm Public Key Structure
pub struct TpmtPublic {
    /// The type of public parms and key IE Ecdsa or Rsa
    pub type_: TpmAlgId,
    /// The hash type over pubarea (webauthn specific)
    pub name_alg: TpmAlgId,
    // TPMA_OBJECT
    /// Unused in webauthn.
    pub object_attributes: u32,
    /// Unused in webauthn.
    pub auth_policy: Option<Vec<u8>>,
    //
    // TPMU_PUBLIC_PARMS
    /// Public Parameters
    pub parameters: TpmuPublicParms,
    // TPMU_PUBLIC_ID
    /// Public Key
    pub unique: TpmuPublicId,
}

impl TryFrom<&[u8]> for TpmtPublic {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<TpmtPublic, WebauthnError> {
        tpmtpublic_parser(data)
            .map_err(|e| {
                log::debug!("{:?}", e);
                // eprintln!("{:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, v)| v)
    }
}

named!( tpm2b_digest<&[u8], Option<Vec<u8>>>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(None) |
        size => map!(take!(size), |d| Some(d.to_vec()))
    )
);

named!( tpmtpublic_parser<&[u8], TpmtPublic>,
    do_parse!(
        type_: map_opt!(u16!(nom::Endianness::Big), TpmAlgId::new) >>
        name_alg: map_opt!(u16!(nom::Endianness::Big), TpmAlgId::new) >>
        object_attributes: u32!(nom::Endianness::Big) >>
        auth_policy: tpm2b_digest >>
        parameters: call!(parse_tpmupublicparms, type_) >>
        unique: call!(parse_tpmupublicid, type_) >>
        (TpmtPublic {
            type_, name_alg, object_attributes, auth_policy, parameters, unique
        })
    )
);

#[derive(Debug)]
/// A TPM Signature.
pub enum TpmtSignature {
    // if sigAlg has a type, parse as:
    // signature - TPMU_SIGNATURE
    // Else, due to how this work if no alg, just pass the raw bytes back.
    /// A raw signature, verifyied by a cert + hash combination. May be implementation
    /// specific.
    RawSignature(Vec<u8>),
}

impl TryFrom<&[u8]> for TpmtSignature {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<TpmtSignature, WebauthnError> {
        tpmtsignature_parser(data)
            .map_err(|e| {
                log::debug!("{:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, v)| v)
    }
}

fn tpmtsignature_parser(input: &[u8]) -> nom::IResult<&[u8], TpmtSignature> {
    let (_data, algorithm) = map!(input, u16!(nom::Endianness::Big), TpmAlgId::new)?;
    match algorithm {
        None => Ok((&[], TpmtSignature::RawSignature(Vec::from(input)))),
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttestationObject, CredentialProtectionPolicy, RegisterPublicKeyCredential, Registration,
        RegistrationSignedExtensions, TpmsAttest, TpmtPublic, TpmtSignature, TPM_GENERATED_VALUE,
    };
    use serde_json;
    use std::convert::TryFrom;

    #[test]
    fn deserialise_register_response() {
        let x = r#"
        {   "id":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw",
            "rawId":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw",
            "response":{
                "attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU-CNhi_5_oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ-aF5-lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp_wStyvOkTd4NlWHW8rQ",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwZENXRDJWamRMSVkzN2VSYTVfazdhS3BqdkF2VmNOY04ycVozMjk0blpVIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
            },
            "type":"public-key"
        }
        "#;
        let _y: RegisterPublicKeyCredential = serde_json::from_str(x).unwrap();
    }

    #[test]
    fn deserialise_attestation_object() {
        let raw_ao = base64::decode(
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQCgxaVISCxE+DrcxP5/+aPM88CTI+04J+o61SK6mnepjGZYv062AbtydzWmbAxF00VSAyp0ImP94uoy+0y7w9yilAQIDJiABIVggGT9woA+UoX+jBxuiHQpdkm0kCVh75WTj3TXl4zLJuzoiWCBKiCneKgWJgWiwrZedNwl06GTaXyaGrYS4bPbBraInyg=="
        ).unwrap();

        let _ao = AttestationObject::<Registration>::try_from(raw_ao.as_slice()).unwrap();
    }
    // Add tests for when the objects are too short.
    //
    #[test]
    fn deserialise_tpms_attest() {
        let data: Vec<u8> = vec![
            255, 84, 67, 71, // magic
            128, 23, // type_
            0, 34, // 2b_name size
            0, 11, 174, 74, 152, 70, 1, 87, 191, 156, 96, 74, 177, 221, 37, 132, 6, 8, 101, 35,
            124, 216, 85, 173, 85, 195, 115, 137, 194, 247, 145, 61, 82, 40, // 2b_name data
            0, 20, // exdata size
            234, 98, 144, 49, 146, 39, 99, 47, 44, 82, 115, 48, 64, 40, 152, 224, 227, 42, 63,
            133, // ext data
            0, 0, 0, 2, 219, 215, 137, 38, // clock
            187, 106, 183, 8, // reset
            100, 145, 106, 200, // restart
            1,   // safe
            86, 5, 220, 81, 118, 234, 131, 141, // fw vers
            0, 34, // type attested.
            0, 11, 239, 53, 112, 255, 253, 12, 189, 168, 16, 253, 10, 149, 108, 7, 31, 212, 143,
            21, 153, 7, 7, 153, 99, 73, 205, 97, 90, 110, 182, 120, 4, 250, 0, 34, 0, 11, 249, 72,
            224, 84, 16, 96, 147, 197, 167, 195, 110, 181, 77, 207, 147, 16, 34, 64, 139, 185, 120,
            190, 196, 209, 213, 29, 1, 136, 76, 235, 223, 247,
        ];

        let tpms_attest = TpmsAttest::try_from(data.as_slice()).unwrap();
        println!("{:?}", tpms_attest);
        assert!(tpms_attest.magic == TPM_GENERATED_VALUE);
    }

    #[test]
    fn deserialise_tpmt_public() {
        // The TPMT_PUBLIC structure (see [TPMv2-Part2] section 12.2.4) used by the TPM to represent the credential public key.
        let data: Vec<u8> = vec![
            0, 1, 0, 11, 0, 6, 4, 114, 0, 32, 157, 255, 203, 243, 108, 56, 58, 230, 153, 251, 152,
            104, 220, 109, 203, 137, 215, 21, 56, 132, 190, 40, 3, 146, 44, 18, 65, 88, 191, 173,
            34, 174, 0, 16, 0, 16, 8, 0, 0, 0, 0, 0, 1, 0, 220, 20, 243, 114, 251, 142, 90, 236,
            17, 204, 181, 223, 8, 72, 230, 209, 122, 44, 90, 55, 96, 134, 69, 16, 125, 139, 112,
            81, 154, 230, 133, 211, 129, 37, 75, 208, 222, 70, 210, 239, 209, 188, 152, 93, 222,
            222, 154, 169, 217, 160, 90, 243, 135, 151, 25, 87, 240, 178, 106, 119, 150, 89, 23,
            223, 158, 88, 107, 72, 101, 61, 184, 132, 19, 110, 144, 107, 22, 178, 252, 206, 50,
            207, 11, 177, 137, 35, 139, 68, 212, 148, 121, 249, 50, 35, 89, 52, 47, 26, 23, 6, 15,
            115, 155, 127, 59, 168, 208, 196, 78, 125, 205, 0, 98, 43, 223, 233, 65, 137, 103, 2,
            227, 35, 81, 107, 247, 230, 186, 111, 27, 4, 57, 42, 220, 32, 29, 181, 159, 6, 176,
            182, 94, 191, 222, 212, 235, 60, 101, 83, 86, 217, 203, 151, 251, 254, 219, 204, 195,
            10, 74, 147, 5, 27, 167, 127, 117, 149, 245, 157, 92, 124, 2, 196, 214, 107, 246, 228,
            171, 229, 100, 212, 67, 88, 215, 75, 33, 183, 199, 51, 171, 210, 213, 65, 45, 96, 96,
            226, 29, 130, 254, 58, 92, 252, 133, 207, 105, 63, 156, 208, 149, 142, 9, 83, 1, 193,
            217, 244, 35, 137, 43, 138, 137, 140, 82, 231, 195, 145, 213, 230, 185, 245, 104, 105,
            62, 142, 124, 34, 9, 157, 167, 188, 243, 112, 104, 248, 63, 50, 19, 53, 173, 69, 12,
            39, 252, 9, 69, 223,
        ];
        let tpmt_public = TpmtPublic::try_from(data.as_slice()).unwrap();
        println!("{:?}", tpmt_public);
    }

    #[test]
    fn deserialise_tpmt_signature() {
        // The attestation signature, in the form of a TPMT_SIGNATURE structure as specified in [TPMv2-Part2] section 11.3.4.
        let data: Vec<u8> = vec![
            5, 3, 162, 216, 151, 57, 210, 103, 145, 121, 161, 186, 63, 232, 221, 255, 89, 37, 17,
            59, 155, 241, 77, 30, 35, 201, 30, 140, 84, 214, 250, 185, 47, 248, 58, 89, 177, 187,
            231, 202, 220, 45, 167, 126, 243, 194, 94, 33, 39, 205, 163, 51, 40, 171, 35, 118, 196,
            244, 247, 143, 166, 193, 223, 94, 244, 157, 121, 220, 22, 94, 163, 15, 151, 223, 214,
            131, 105, 202, 40, 16, 176, 11, 154, 102, 100, 212, 174, 103, 166, 92, 90, 154, 224,
            20, 165, 106, 127, 53, 91, 230, 217, 199, 172, 195, 203, 242, 41, 158, 64, 252, 65, 9,
            155, 160, 63, 40, 94, 94, 64, 145, 173, 71, 85, 173, 2, 199, 18, 148, 88, 223, 93, 154,
            203, 197, 170, 142, 35, 249, 146, 107, 146, 2, 14, 54, 39, 151, 181, 10, 176, 216, 117,
            25, 196, 2, 205, 159, 140, 155, 56, 89, 87, 31, 135, 93, 97, 78, 95, 176, 228, 72, 237,
            130, 171, 23, 66, 232, 35, 115, 218, 105, 168, 6, 253, 121, 161, 129, 44, 78, 252, 44,
            11, 23, 172, 66, 37, 214, 113, 128, 28, 33, 209, 66, 34, 32, 196, 153, 80, 87, 243,
            162, 7, 25, 62, 252, 243, 174, 31, 168, 98, 123, 100, 2, 143, 134, 36, 154, 236, 18,
            128, 175, 185, 189, 177, 51, 53, 216, 190, 43, 63, 35, 84, 14, 64, 249, 23, 9, 125,
            147, 160, 176, 137, 30, 174, 245, 148, 189,
        ];
        let tpmt_sig = TpmtSignature::try_from(data.as_slice()).unwrap();
        println!("{:?}", tpmt_sig);
    }

    #[test]
    fn deserialize_extensions() {
        let data: Vec<u8> = vec![
            161, 107, 99, 114, 101, 100, 80, 114, 111, 116, 101, 99, 116, 3,
        ];

        let extensions: RegistrationSignedExtensions = serde_cbor::from_slice(&data).unwrap();

        let cred_protect = extensions
            .cred_protect
            .expect("should have cred protect extension");
        println!("{:?}", cred_protect);
        assert_eq!(
            cred_protect.0,
            CredentialProtectionPolicy::UserVerificationRequired
        );
    }

    #[test]
    fn credential_protection_policy_conversions() {
        use CredentialProtectionPolicy::*;
        assert_eq!(
            UserVerificationOptional,
            CredentialProtectionPolicy::try_from(UserVerificationOptional as u8).unwrap()
        );
        assert_eq!(
            UserVerificationOptionalWithCredentialIDList,
            CredentialProtectionPolicy::try_from(
                UserVerificationOptionalWithCredentialIDList as u8
            )
            .unwrap()
        );
        assert_eq!(
            UserVerificationRequired,
            CredentialProtectionPolicy::try_from(UserVerificationRequired as u8).unwrap()
        );
    }
}
