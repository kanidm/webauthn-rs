//! Extended Structs and representations for Webauthn Operations. These types are designed
//! to allow persistance and should not change.

use webauthn_rs_proto::cose::*;
use webauthn_rs_proto::extensions::*;
use webauthn_rs_proto::options::*;

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};

use openssl::x509;

/// Representation of an AAGUID
/// <https://www.w3.org/TR/webauthn/#aaguid>
pub type Aaguid = Vec<u8>;

/// The in progress state of a credential registration attempt. You must persist this associated
/// to the UserID requesting the registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    pub(crate) policy: UserVerificationPolicy,
    pub(crate) exclude_credentials: Vec<CredentialID>,
    pub(crate) challenge: Base64UrlSafeData,
    pub(crate) credential_algorithms: Vec<COSEAlgorithm>,
}

/// The in progress state of an authentication attempt. You must persist this associated to the UserID
/// requesting the registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub(crate) credentials: Vec<Credential>,
    pub(crate) policy: UserVerificationPolicy,
    pub(crate) challenge: Base64UrlSafeData,
    pub(crate) appid: Option<String>,
}

impl AuthenticationState {
    /// set which credentials the user is allowed to authenticate with
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

/// An X509PublicKey. This is what is otherwise known as a public certificate
/// which comprises a public key and other signed metadata related to the issuer
/// of the key.
pub struct X509PublicKey {
    pub(crate) pubk: x509::X509,
    pub(crate) t: COSEAlgorithm,
}

impl std::fmt::Debug for X509PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "X509PublicKey")
    }
}

/// The processed Attestation that the Authenticator is providing in it's AttestedCredentialData
#[derive(Debug)]
pub enum ParsedAttestationData {
    /// The credential is authenticated by a signing X509 Certificate
    /// from a vendor or provider.
    Basic(X509PublicKey),
    /// The credential is authenticated using surrogate basic attestation
    /// it uses the credential private key to create the attestation signature
    Self_,
    /// The credential is authenticated using a CA, and may provide a
    /// ca chain to validate to it's root.
    AttCa(X509PublicKey, Vec<X509PublicKey>),
    /// The credential is authenticated using an anonymization CA, and may provide a ca chain to
    /// validate to it's root.
    AnonCa(X509PublicKey, Vec<X509PublicKey>),
    /// Unimplemented
    ECDAA,
    /// No Attestation type was provided with this Credential. If in doubt
    /// reject this Credential.
    None,
    /// Uncertain Attestation was provided with this Credential, which may not
    /// be trustworthy in all cases. If in doubt, reject this type.
    Uncertain,
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

/// The response from the client regarding setting the `credBlob` extension
///
/// This is just a wrapper around a [bool] indicating whether the authenticator
/// was able to set the desired `credBlob` data.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct SetCredBlobResponse(bool);

/// The output for registration ceremony extensions.
///
/// Implements the registration bits of \[AuthenticatorExtensionsClientOutputs\]
/// from the spec
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSignedExtensions {
    /// The `credProtect` extension
    pub cred_protect: Option<CredProtectResponse>,
    /// The `credBlob` extension
    pub cred_blob: Option<SetCredBlobResponse>,
}

/// The response from the client regarding querying the `credBlob` extension
///
/// This is just a wrapper around a byte array containing the `credBlob`
/// data.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct GetCredBlobResponse(Base64UrlSafeData);

/// The output for authentication cermeony extensions.
///
/// Implements the authentication bits of
/// \[AuthenticationExtensionsClientOutputs] from the spec
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationSignedExtensions {
    /// The credBlob extension
    pub cred_blob: Option<GetCredBlobResponse>,
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

/// Data returned by this authenticator during registration.
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
    pub extensions: Option<T::SignedExtensions>,
}
