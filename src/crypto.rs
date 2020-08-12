//! Cryptographic operation wrapper for Webauthn. This module exists to
//! allow ease of auditing, safe operation wrappers for the webauthn library,
//! and cryptographic provider abstraction. This module currently uses OpenSSL
//! as the cryptographic primitive provider.

#![allow(non_camel_case_types)]

use openssl::{bn, ec, hash, nid, pkey, sha, sign, x509};
use std::convert::TryFrom;

// use super::constants::*;
use super::error::*;
use crate::proto::Aaguid;
// use super::proto::*;

// Why OpenSSL over another rust crate?
// - Well, the openssl crate allows us to reconstruct a public key from the
//   x/y group coords, where most others want a pkcs formatted structure. As
//   a result, it's easiest to use openssl as it gives us exactly what we need
//   for these operations, and despite it's many challenges as a library, it
//   has resources and investment into it's maintenance, so we can a least
//   assert a higher level of confidence in it that <backyard crypto here>.

// Object({Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]), Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]), Integer(-1): U64(1), Integer(1): U64(2), Integer(3): I64(-7)})
//

/// An X509PublicKey. This is what is otherwise known as a public certificate
/// which comprises a public key and other signed metadata related to the issuer
/// of the key.
pub struct X509PublicKey {
    pubk: x509::X509,
}

impl std::fmt::Debug for X509PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "X509PublicKey")
    }
}

impl TryFrom<&[u8]> for X509PublicKey {
    type Error = WebauthnError;

    // Must be DER bytes. If you have PEM, base64decode first!
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        let pubk = x509::X509::from_der(d).map_err(|e| WebauthnError::OpenSSLError(e))?;
        Ok(X509PublicKey { pubk: pubk })
    }
}

impl X509PublicKey {
    pub(crate) fn is_secp256r1(&self) -> Result<bool, WebauthnError> {
        // Can we get the public key?
        let pk = self
            .pubk
            .public_key()
            .map_err(|e| WebauthnError::OpenSSLError(e))?;

        let ec_key = pk.ec_key().map_err(|e| WebauthnError::OpenSSLError(e))?;

        ec_key
            .check_key()
            .map_err(|e| WebauthnError::OpenSSLError(e))?;

        let ec_grpref = ec_key.group();

        let ec_curve = ec_grpref
            .curve_name()
            .ok_or(WebauthnError::OpenSSLErrorNoCurveName)?;

        Ok(ec_curve == nid::Nid::X9_62_PRIME256V1)
    }

    pub(crate) fn verify_signature(
        &self,
        signature: &Vec<u8>,
        verification_data: &Vec<u8>,
    ) -> Result<bool, WebauthnError> {
        let pkey = self
            .pubk
            .public_key()
            .map_err(|e| WebauthnError::OpenSSLError(e))?;

        // TODO: Should this determine the hash type from the x509 cert? Or other?
        let mut verifier = sign::Verifier::new(hash::MessageDigest::sha256(), &pkey)
            .map_err(|e| WebauthnError::OpenSSLError(e))?;
        verifier
            .update(verification_data.as_slice())
            .map_err(|e| WebauthnError::OpenSSLError(e))?;
        verifier
            .verify(signature.as_slice())
            .map_err(|e| WebauthnError::OpenSSLError(e))
    }

    pub(crate) fn assert_packed_attest_req(&self) -> Result<(), WebauthnError> {
        // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation
        // Statement Certificate Requirements.
        // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements

        // The attestation certificate MUST have the following fields/extensions:
        // Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).

        // Subject field MUST be set to:
        //
        // Subject-C
        //  ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        // Subject-O
        //  Legal name of the Authenticator vendor (UTF8String)
        // Subject-OU
        //  Literal string “Authenticator Attestation” (UTF8String)
        // Subject-CN
        //  A UTF8String of the vendor’s choosing
        let subject_name_ref = self.pubk.subject_name();

        let subject_c = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(14))
            .into_iter()
            .take(1)
            .next();
        let subject_o = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(17))
            .into_iter()
            .take(1)
            .next();
        let subject_ou = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(18))
            .into_iter()
            .take(1)
            .next();
        let subject_cn = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(13))
            .into_iter()
            .take(1)
            .next();

        if subject_c.is_none() || subject_o.is_none() || subject_cn.is_none() {
            return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
        }

        match subject_ou {
            Some(ou) => match ou.data().as_utf8() {
                Ok(ou_d) => {
                    if ou_d.to_string() != "Authenticator Attestation" {
                        return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
                    }
                }
                Err(_) => return Err(WebauthnError::AttestationCertificateRequirementsNotMet),
            },
            None => return Err(WebauthnError::AttestationCertificateRequirementsNotMet),
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.

        // The Basic Constraints extension MUST have the CA component set to false.

        // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL
        // Distribution Point extension [RFC5280] are both OPTIONAL as the status of many
        // attestation certificates is available through authenticator metadata services. See, for
        // example, the FIDO Metadata Service [FIDOMetadataService].
        Ok(())
    }

    pub(crate) fn get_fido_gen_ce_aaguid(&self) -> Option<Aaguid> {
        None
    }
}

/// An ECDSACurve identifier. You probabably will never need to alter
/// or use this value, as it is set inside the Credential for you.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

impl TryFrom<u64> for ECDSACurve {
    type Error = WebauthnError;
    fn try_from(u: u64) -> Result<Self, Self::Error> {
        match u {
            1 => Ok(ECDSACurve::SECP256R1),
            2 => Ok(ECDSACurve::SECP384R1),
            3 => Ok(ECDSACurve::SECP521R1),
            _ => Err(WebauthnError::COSEKeyECDSAInvalidCurve),
        }
    }
}

impl ECDSACurve {
    fn to_openssl_nid(&self) -> nid::Nid {
        match self {
            ECDSACurve::SECP256R1 => nid::Nid::X9_62_PRIME256V1,
            ECDSACurve::SECP384R1 => nid::Nid::SECP384R1,
            ECDSACurve::SECP521R1 => nid::Nid::SECP521R1,
        }
    }
}

/// A COSE Key Content type, indicating the type of key and hash type
/// that should be used with this key. You shouldn't need to alter or
/// use this value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum COSEContentType {
    //    +-----------+-------+-----------------------------------------------+
    //    | Name      | Value | Description                                   |
    //    +-----------+-------+-----------------------------------------------+
    //    | OKP       | 1     | Octet Key Pair                                |
    //    | EC2       | 2     | Elliptic Curve Keys w/ x- and y-coordinate    |
    //    |           |       | pair                                          |
    //    | Symmetric | 4     | Symmetric Keys                                |
    //    | Reserved  | 0     | This value is reserved                        |
    //    +-----------+-------+-----------------------------------------------+
    /// Identifies this key as ECDSA (recommended SECP256R1) with SHA256 hashing
    ECDSA_SHA256 = -7, // recommends curve SECP256R1
    /// Identifies this key as ECDSA (recommended SECP384R1) with SHA384 hashing
    ECDSA_SHA384 = -35, // recommends curve SECP384R1
    /// Identifies this key as ECDSA (recommended SECP521R1) with SHA512 hashing
    ECDSA_SHA512 = -36, // recommends curve SECP521R1
}

impl TryFrom<i64> for COSEContentType {
    type Error = WebauthnError;
    fn try_from(i: i64) -> Result<Self, Self::Error> {
        match i {
            -7 => Ok(COSEContentType::ECDSA_SHA256),
            -35 => Ok(COSEContentType::ECDSA_SHA384),
            -36 => Ok(COSEContentType::ECDSA_SHA512),
            _ => Err(WebauthnError::COSEKeyECDSAContentType),
        }
    }
}

impl From<&COSEContentType> for i64 {
    fn from(c: &COSEContentType) -> Self {
        match c {
            COSEContentType::ECDSA_SHA256 => -7,
            COSEContentType::ECDSA_SHA384 => -35,
            COSEContentType::ECDSA_SHA512 => -6,
        }
    }
}

/// A COSE Eliptic Curve Public Key. This is generally the provided credential
/// that an authenticator registers, and is used to authenticate the user.
/// You will likely never need to interact with this value, as it is part of the Credential
/// API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct COSEEC2Key {
    /// The curve that this key references.
    pub curve: ECDSACurve,
    /// The key's public X coordinate.
    pub x: [u8; 32],
    /// The key's public Y coordinate.
    pub y: [u8; 32],
}

/// The type of Key contained within a COSE value. You should never need
/// to alter or change this type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum COSEKeyType {
    /// Identifies this as an Eliptic Curve EC2 key
    EC_EC2(COSEEC2Key),
    // EC_OKP,
    // EC_Symmetric,
    // EC_Reserved, // should always be invalid.
}

/// A COSE Key as provided by the Authenticator. You should never need
/// to alter or change these values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct COSEKey {
    /// The type of key that this contains
    pub type_: COSEContentType,
    /// The public key
    pub key: COSEKeyType,
}

impl TryFrom<&serde_cbor::Value> for COSEKey {
    type Error = WebauthnError;
    fn try_from(d: &serde_cbor::Value) -> Result<COSEKey, Self::Error> {
        let m = d
            .as_object()
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;

        // See also https://tools.ietf.org/html/rfc8152#section-3.1
        // These values look like:
        // Object({
        //     // negative (-) values are per-algo specific
        //     Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]),
        //     Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]),
        //     Integer(-1): U64(1),
        //     Integer(1): U64(2), // algorithm identifier
        //     Integer(3): I64(-7) // content type see https://tools.ietf.org/html/rfc8152#section-8.1 -7 being ES256 + SHA256
        // })
        // Now each of these integers has a specific meaning, and you need to parse them in order.
        // First, value 1 for the key type.

        let key_type_value = m
            .get(&serde_cbor::ObjectKey::Integer(1))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let key_type = key_type_value
            .as_u64()
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;

        let content_type_value = m
            .get(&serde_cbor::ObjectKey::Integer(3))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let content_type = content_type_value
            .as_i64()
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;

        match key_type {
            2 => {
                // This indicates this is an EC2 key consisting of crv, x, y, which are stored in
                // crv (-1), x (-2) and y (-3)
                // Get these values now ....

                let curve_type_value = m
                    .get(&serde_cbor::ObjectKey::Integer(-1))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let curve_type = curve_type_value
                    .as_u64()
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;

                // Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.

                // Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.

                let x_value = m
                    .get(&serde_cbor::ObjectKey::Integer(-2))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let x = x_value
                    .as_bytes()
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;

                let y_value = m
                    .get(&serde_cbor::ObjectKey::Integer(-3))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let y = y_value
                    .as_bytes()
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;

                if x.len() != 32 || y.len() != 32 {
                    return Err(WebauthnError::COSEKeyECDSAXYInvalid);
                }

                // Set the x and y, we know they are proper sizes.
                let mut x_temp = [0; 32];
                x_temp.copy_from_slice(x.as_slice());
                let mut y_temp = [0; 32];
                y_temp.copy_from_slice(y.as_slice());

                // Right, now build the struct.
                let cose_key = COSEKey {
                    type_: COSEContentType::try_from(content_type)?,
                    key: COSEKeyType::EC_EC2(COSEEC2Key {
                        curve: ECDSACurve::try_from(curve_type)?,
                        x: x_temp,
                        y: y_temp,
                    }),
                };

                // The rfc additionally states:
                //   "   Applications MUST check that the curve and the key type are
                //     consistent and reject a key if they are not."
                // this means feeding the values to openssl to validate them for us!

                cose_key.validate()?;
                // return it
                Ok(cose_key)
            }
            _ => Err(WebauthnError::COSEKeyInvalidType),
        }
    }
}

impl COSEKey {
    pub(crate) fn get_alg_key_ecc_x962_raw(&self) -> Result<Vec<u8>, WebauthnError> {
        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        // Note: This signifies uncompressed ECC key format.
        match &self.key {
            COSEKeyType::EC_EC2(ecpk) => {
                let r: [u8; 1] = [0x04];
                Ok(r.iter()
                    .chain(ecpk.x.iter())
                    .chain(ecpk.y.iter())
                    .map(|b| *b)
                    .collect())
            } // _ => Err(WebauthnError::COSEKeyInvalidType),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => {
                // Get the curve type
                let curve = ec2k.curve.to_openssl_nid();
                let ec_group = ec::EcGroup::from_curve_name(curve)
                    .map_err(|e| WebauthnError::OpenSSLError(e))?;

                let xbn =
                    bn::BigNum::from_slice(&ec2k.x).map_err(|e| WebauthnError::OpenSSLError(e))?;
                let ybn =
                    bn::BigNum::from_slice(&ec2k.y).map_err(|e| WebauthnError::OpenSSLError(e))?;

                let ec_key = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(|e| WebauthnError::OpenSSLError(e))?;

                ec_key
                    .check_key()
                    .map_err(|e| WebauthnError::OpenSSLError(e))
            } // _ => Err(WebauthnError::COSEKeyInvalid),
        }
    }

    fn get_openssl_pkey(&self) -> Result<pkey::PKey<pkey::Public>, WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => {
                // Get the curve type
                let curve = ec2k.curve.to_openssl_nid();
                let ec_group = ec::EcGroup::from_curve_name(curve)
                    .map_err(|e| WebauthnError::OpenSSLError(e))?;

                let xbn =
                    bn::BigNum::from_slice(&ec2k.x).map_err(|e| WebauthnError::OpenSSLError(e))?;
                let ybn =
                    bn::BigNum::from_slice(&ec2k.y).map_err(|e| WebauthnError::OpenSSLError(e))?;

                let ec_key = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(|e| WebauthnError::OpenSSLError(e))?;

                // Validate the key is sound. IIRC this actually checks the values
                // are correctly on the curve as specified
                ec_key
                    .check_key()
                    .map_err(|e| WebauthnError::OpenSSLError(e))?;

                let p =
                    pkey::PKey::from_ec_key(ec_key).map_err(|e| WebauthnError::OpenSSLError(e))?;
                Ok(p)
            } // _ => Err(WebauthnError::COSEKeyInvalid),
        }
    }

    pub(crate) fn verify_signature(
        &self,
        signature: &Vec<u8>,
        verification_data: &Vec<u8>,
    ) -> Result<bool, WebauthnError> {
        let pkey = self.get_openssl_pkey()?;

        // TODO: Should this determine the hash type from the x509 cert? Or other?
        let mut verifier = sign::Verifier::new(hash::MessageDigest::sha256(), &pkey)
            .map_err(|e| WebauthnError::OpenSSLError(e))?;
        verifier
            .update(verification_data.as_slice())
            .map_err(|e| WebauthnError::OpenSSLError(e))?;
        verifier
            .verify(signature.as_slice())
            .map_err(|e| WebauthnError::OpenSSLError(e))
    }
}

pub(crate) fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish().iter().map(|b| *b).collect()
}
