//! Extended Structs and representations for Webauthn Operations. These types are designed
//! to allow persistance and should not change.

use crate::error::*;
use std::fmt;
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
    pub(crate) require_resident_key: bool,
    pub(crate) authenticator_attachment: Option<AuthenticatorAttachment>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredExtensions {}

impl RegisteredExtensions {
    pub(crate) fn none() -> Self {
        RegisteredExtensions {}
    }
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
    pub user_verified: bool,
    /// During registration, the policy that was requested from this
    /// credential. This is used to understand if the how the verified
    /// component interacts with the device, IE an always verified authenticator
    /// vs one that can dynamically request it.
    pub registration_policy: UserVerificationPolicy,
    /// The set of registrations that were verified at registration, that can
    /// be used in future authentication attempts
    pub extensions: RegisteredExtensions,
    /// The attestation certificate of this credential.
    pub attestation: ParsedAttestationData,
    // pub attestation: SerialisableAttestationData,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum SerialisableAttestationData {
    Basic(Vec<Base64UrlSafeData>),
    Self_,
    AttCa(Vec<Base64UrlSafeData>),
    AnonCa(Vec<Base64UrlSafeData>),
    ECDAA,
    None,
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

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AuthenticationResult {
    /// The credential ID that was used to authenticate.
    pub cred_id: CredentialID,
    /// If the authentication provided user_verification.
    pub user_verified: bool,
    /// The state of the counter
    pub counter: u32,
    // /// The response from associated extensions.
    // pub extensions:
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialisableAttestationCa {
    pub(crate) ca: Base64UrlSafeData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    try_from = "SerialisableAttestationCa",
    into = "SerialisableAttestationCa"
)]
pub struct AttestationCa {
    pub(crate) ca: x509::X509,
}

impl Into<SerialisableAttestationCa> for AttestationCa {
    fn into(self) -> SerialisableAttestationCa {
        SerialisableAttestationCa {
            ca: Base64UrlSafeData(self.ca.to_der().expect("Invalid DER")),
        }
    }
}

impl TryFrom<SerialisableAttestationCa> for AttestationCa {
    type Error = WebauthnError;

    fn try_from(data: SerialisableAttestationCa) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(&data.ca.0).map_err(WebauthnError::OpenSSLError)?,
        })
    }
}

// Apple makes a webauthn root certificate public at
// https://www.apple.com/certificateauthority/private/.
// The certificate data itself (as linked in the cert listing linked above) can be found at
// https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem.
pub const APPLE_WEBAUTHN_ROOT_CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----";

// Yubico root cert.
// https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
pub const YUBICO_U2F_ROOT_CA_SERIAL_457200631_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
-----END CERTIFICATE-----";

// https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates
pub const MICROSOFT_TPM_ROOT_CERTIFICATE_AUTHORITY_2014_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIF9TCCA92gAwIBAgIQXbYwTgy/J79JuMhpUB5dyzANBgkqhkiG9w0BAQsFADCB
jDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMt
TWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4X
DTE0MTIxMDIxMzExOVoXDTM5MTIxMDIxMzkyOFowgYwxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
aWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9v
dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAJ+n+bnKt/JHIRC/oI/xgkgsYdPzP0gpvduDA2GbRtth+L4W
UyoZKGBw7uz5bjjP8Aql4YExyjR3EZQ4LqnZChMpoCofbeDR4MjCE1TGwWghGpS0
mM3GtWD9XiME4rE2K0VW3pdN0CLzkYbvZbs2wQTFfE62yNQiDjyHFWAZ4BQH4eWa
8wrDMUxIAneUCpU6zCwM+l6Qh4ohX063BHzXlTSTc1fDsiPaKuMMjWjK9vp5UHFP
a+dMAWr6OljQZPFIg3aZ4cUfzS9y+n77Hs1NXPBn6E4Db679z4DThIXyoKeZTv1a
aWOWl/exsDLGt2mTMTyykVV8uD1eRjYriFpmoRDwJKAEMOfaURarzp7hka9TOElG
yD2gOV4Fscr2MxAYCywLmOLzA4VDSYLuKAhPSp7yawET30AvY1HRfMwBxetSqWP2
+yZRNYJlHpor5QTuRDgzR+Zej+aWx6rWNYx43kLthozeVJ3QCsD5iEI/OZlmWn5W
Yf7O8LB/1A7scrYv44FD8ck3Z+hxXpkklAsjJMsHZa9mBqh+VR1AicX4uZG8m16x
65ZU2uUpBa3rn8CTNmw17ZHOiuSWJtS9+PrZVA8ljgf4QgA1g6NPOEiLG2fn8Gm+
r5Ak+9tqv72KDd2FPBJ7Xx4stYj/WjNPtEUhW4rcLK3ktLfcy6ea7Rocw5y5AgMB
AAGjUTBPMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR6
jArOL0hiF+KU0a5VwVLscXSkVjAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0B
AQsFAAOCAgEAW4ioo1+J9VWC0UntSBXcXRm1ePTVamtsxVy/GpP4EmJd3Ub53JzN
BfYdgfUL51CppS3ZY6BoagB+DqoA2GbSL+7sFGHBl5ka6FNelrwsH6VVw4xV/8kl
IjmqOyfatPYsz0sUdZev+reeiGpKVoXrK6BDnUU27/mgPtem5YKWvHB/soofUrLK
zZV3WfGdx9zBr8V0xW6vO3CKaqkqU9y6EsQw34n7eJCbEVVQ8VdFd9iV1pmXwaBA
fBwkviPTKEP9Cm+zbFIOLr3V3CL9hJj+gkTUuXWlJJ6wVXEG5i4rIbLAV59UrW4L
onP+seqvWMJYUFxu/niF0R3fSGM+NU11DtBVkhRZt1u0kFhZqjDz1dWyfT/N7Hke
3WsDqUFsBi+8SEw90rWx2aUkLvKo83oU4Mx4na+2I3l9F2a2VNGk4K7l3a00g51m
iPiq0Da0jqw30PaLluTMTGY5+RnZVh50JD6nk+Ea3wRkU8aiYFnpIxfKBZ72whmY
Ya/egj9IKeqpR0vuLebbU0fJBf880K1jWD3Z5SFyJXo057Mv0OPw5mttytE585ZI
y5JsaRXlsOoWGRXE3kUT/MKR1UoAgR54c8Bsh+9Dq2wqIK9mRn15zvBDeyHG6+cz
urLopziOUeWokxZN1syrEdKlhFoPYavm6t+PzIcpdxZwHA+V3jLJPfI=
-----END CERTIFICATE-----";

impl AttestationCa {
    pub fn apple_webauthn_root_ca() -> Self {
        // COSEAlgorithm::ES384,
        AttestationCa {
            ca: x509::X509::from_pem(APPLE_WEBAUTHN_ROOT_CA_PEM).unwrap(),
        }
    }

    pub fn yubico_u2f_root_ca_serial_457200631() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(YUBICO_U2F_ROOT_CA_SERIAL_457200631_PEM).unwrap(),
        }
    }

    pub fn microsoft_tpm_root_certificate_authority_2014() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(MICROSOFT_TPM_ROOT_CERTIFICATE_AUTHORITY_2014_PEM).unwrap(),
        }
    }


}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationCaList {
    pub(crate) cas: Vec<AttestationCa>,
}

impl AttestationCaList {
    /// This is a list of CA's who's manufactured authenticators are of the highest
    /// quality and guarantees for users and RP's. These are devices that not only
    /// are secure, but user friendly, consistent, and correct.
    pub fn strict() -> Self {
        AttestationCaList {
            cas: vec![
                AttestationCa::apple_webauthn_root_ca(),
                AttestationCa::yubico_u2f_root_ca_serial_457200631(),
            ],
        }
    }

    /// All CA's known to the Webauthn-RS project.
    pub fn all_known_cas() -> Self {
        AttestationCaList {
            cas: vec![
                AttestationCa::apple_webauthn_root_ca(),
                AttestationCa::yubico_u2f_root_ca_serial_457200631(),
                AttestationCa::microsoft_tpm_root_certificate_authority_2014(),
            ],
        }
    }
}
