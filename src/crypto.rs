use openssl::{sha, bn, ec, nid, pkey, x509};
use std::convert::TryFrom;

use super::constants::*;
use super::error::*;
use super::proto::*;

// Why OpenSSL over another rust crate?
// - Well, the openssl crate allows us to reconstruct a public key from the
//   x/y group coords, where most others want a pkcs formatted structure. As
//   a result, it's easiest to use openssl as it gives us exactly what we need
//   for these operations, and despite it's many challenges as a library, it
//   has resources and investment into it's maintenance, so we can a least
//   assert a higher level of confidence in it that <backyard crypto here>.

// Object({Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]), Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]), Integer(-1): U64(1), Integer(1): U64(2), Integer(3): I64(-7)})
//

pub(crate) struct X509PublicKey {
    pubk: x509::X509,
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

        println!("{:?}", ec_curve);
        Ok(ec_curve == nid::Nid::X9_62_PRIME256V1)
    }
}

#[derive(Debug)]
pub enum ECDSACurve {
    SECP256R1 = 1,
    SECP384R1 = 2,
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

//    +-----------+-------+-----------------------------------------------+
//    | Name      | Value | Description                                   |
//    +-----------+-------+-----------------------------------------------+
//    | OKP       | 1     | Octet Key Pair                                |
//    | EC2       | 2     | Elliptic Curve Keys w/ x- and y-coordinate    |
//    |           |       | pair                                          |
//    | Symmetric | 4     | Symmetric Keys                                |
//    | Reserved  | 0     | This value is reserved                        |
//    +-----------+-------+-----------------------------------------------+

#[derive(Debug)]
pub enum COSEContentType {
    ECDSA_SHA256 = -7,  // recommends curve SECP256R1
    ECDSA_SHA384 = -35, // recommends curve SECP384R1
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

#[derive(Debug)]
pub struct COSEEC2Key {
    curve: ECDSACurve,
    x: [u8; 32],
    y: [u8; 32],
}

#[derive(Debug)]
// Is this the right name?
pub enum COSEKeyType {
    EC_EC2(COSEEC2Key),
    // EC_OKP,
    // EC_Symmetric,
    // EC_Reserved, // should always be invalid.
}

#[derive(Debug)]
pub struct COSEKey {
    type_: COSEContentType,
    key: COSEKeyType,
}

impl TryFrom<&serde_cbor::Value> for COSEKey {
    type Error = WebauthnError;
    fn try_from(d: &serde_cbor::Value) -> Result<COSEKey, Self::Error> {
        println!("{:?}", d);

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

                println!("{:?}", cose_key);

                // The rfc additionally states:
                //   "   Applications MUST check that the curve and the key type are
                //     consistent and reject a key if they are not."
                // this means feeding the values to openssl to validate them for us!

                cose_key.validate()?;
                println!("Credential Key is valid");
                // return it
                Ok(cose_key)
            }
            _ => Err(WebauthnError::COSEKeyInvalidType),
        }
    }
}

impl COSEKey {
    pub fn get_ALG_KEY_ECC_X962_RAW(&self) -> Result<Vec<u8>, WebauthnError> {
        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        // Note: This signifies uncompressed ECC key format.
        unimplemented!();
    }

    pub fn validate(&self) -> Result<(), WebauthnError> {
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
            }
            _ => Err(WebauthnError::COSEKeyInvalid),
        }
    }
}

pub(crate) fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish().iter().map(|b| *b).collect()
}

/*
fn verify_ecdsa_sha256(
    kty: u64,      // This is the key type
    x: &[u8],      // The X point
    y: &[u8],      // The Y point
    groupref: u64, // The curve to use
    data: &Vec<u8>,
) -> Result<(), ()> {
    // you need the key type. Check value 1 (kty) frmo cred_pk, and compare to:
    //
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
    // In the case I have here, my key is 2, so secp384r1

    let xbn = bn::BigNum::from_slice(x).unwrap();
    let ybn = bn::BigNum::from_slice(y).unwrap();

    let group = ec::EcGroup::from_curve_name(nid::Nid::SECP384R1).unwrap();

    let ec_key = ec::EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();
    assert!(ec_key.check_key().is_ok());
    // Check the x/y points are actually on the curve. Does check_key do this?

    Err(())
}
*/

pub(crate) fn bytes_to_x509_public_key(c_pk: &Vec<u8>) -> Result<X509PublicKey, WebauthnError> {
    let pubk = x509::X509::from_der(c_pk).map_err(|e| WebauthnError::OpenSSLError(e))?;

    Ok(X509PublicKey { pubk: pubk })
}
