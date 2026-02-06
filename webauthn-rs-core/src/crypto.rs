//! Cryptographic operation wrapper for Webauthn. This module exists to
//! allow ease of auditing, safe operation wrappers for the webauthn library,
//! and cryptographic provider abstraction. This module currently uses OpenSSL
//! as the cryptographic primitive provider.

#![allow(non_camel_case_types)]

use super::error::*;
use crate::proto::*;
use crypto_glue::{
    ecdsa_p256::{
        self, EcdsaP256PublicEncodedPoint, EcdsaP256PublicKey, EcdsaP256Signature,
        EcdsaP256VerifyingKey,
    },
    ecdsa_p384::{
        self, EcdsaP384PublicEncodedPoint, EcdsaP384PublicKey, EcdsaP384Signature,
        EcdsaP384VerifyingKey,
    },
    ecdsa_p521::{
        self,
        EcdsaP521PublicEncodedPoint,
        EcdsaP521PublicKey,
        // EcdsaP521Signature, EcdsaP521VerifyingKey,
    },
    rsa::{BigUint, RS256PublicKey, RS256Signature, RS256VerifyingKey},
    s256,
    traits::{Digest, OwnedToRef, Verifier},
    x509::{self, Certificate, GeneralName, ObjectIdentifier, OtherName, SubjectAltName},
};

/// Validate an x509 signature is valid for the supplied data
pub fn verify_signature(
    certificate: &Certificate,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    let valid = x509::x509_verify_signature(verification_data, signature, certificate)
        .inspect_err(|err| {
            error!(?err, "x509 Verification Error");
        })
        .is_ok();

    Ok(valid)
}

pub(crate) struct TpmSanData<'a> {
    pub manufacturer: &'a str,
    pub _model: &'a str,
    pub _version: &'a str,
}

#[derive(Default)]
struct TpmSanDataBuilder<'a> {
    manufacturer: Option<&'a str>,
    model: Option<&'a str>,
    version: Option<&'a str>,
}

impl<'a> TpmSanDataBuilder<'a> {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn manufacturer(mut self, value: &'a str) -> Self {
        self.manufacturer = Some(value);
        self
    }

    pub(crate) fn model(mut self, value: &'a str) -> Self {
        self.model = Some(value);
        self
    }

    pub(crate) fn version(mut self, value: &'a str) -> Self {
        self.version = Some(value);
        self
    }

    pub(crate) fn build(self) -> WebauthnResult<TpmSanData<'a>> {
        self.manufacturer
            .zip(self.model)
            .zip(self.version)
            .map(|((manufacturer, model), version)| TpmSanData {
                manufacturer,
                _model: model,
                _version: version,
            })
            .ok_or(WebauthnError::AttestationCertificateRequirementsNotMet)
    }
}

// pub(crate) const TCG_AT_TPM_MANUFACTURER: Oid = der_parser::oid!(2.23.133 .2 .1);
// pub(crate) const TCG_AT_TPM_MODEL: Oid = der_parser::oid!(2.23.133 .2 .2);
// pub(crate) const TCG_AT_TPM_VERSION: Oid = der_parser::oid!(2.23.133 .2 .3);

pub(crate) const TCG_AT_TPM_MANUFACTURER_RAW: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.2.1");
pub(crate) const TCG_AT_TPM_MODEL_RAW: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.2.2");
pub(crate) const TCG_AT_TPM_VERSION_RAW: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.2.3");

impl<'a> TryFrom<&'a SubjectAltName> for TpmSanData<'a> {
    type Error = WebauthnError;

    fn try_from(x509_name: &'a SubjectAltName) -> Result<Self, Self::Error> {
        x509_name
            .0
            .iter()
            .try_fold(TpmSanDataBuilder::new(), |builder, general_name| {
                let next = match general_name {
                    GeneralName::OtherName(OtherName { type_id, value }) => {
                        if *type_id == TCG_AT_TPM_MANUFACTURER_RAW {
                            let attr_value = str::from_utf8(value.value())?;
                            builder.manufacturer(attr_value)
                        } else if *type_id == TCG_AT_TPM_MODEL_RAW {
                            let attr_value = str::from_utf8(value.value())?;
                            builder.model(attr_value)
                        } else if *type_id == TCG_AT_TPM_VERSION_RAW {
                            let attr_value = str::from_utf8(value.value())?;
                            builder.version(attr_value)
                        } else {
                            builder
                        }
                    }
                    _ => builder,
                };
                Ok(next)
            })
            .map_err(|_: std::str::Utf8Error| WebauthnError::ParseNOMFailure)
            .and_then(TpmSanDataBuilder::build)
    }
}

pub(crate) fn only_hash_from_type(
    alg: COSEAlgorithm,
    _input: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    match alg {
        COSEAlgorithm::INSECURE_RS1 => {
            // sha1
            warn!("INSECURE SHA1 USAGE DETECTED");
            Err(WebauthnError::CredentialInsecureCryptography)
        }
        c_alg => {
            debug!(?c_alg, "WebauthnError::COSEKeyInvalidType");
            Err(WebauthnError::COSEKeyInvalidType)
        }
    }
}

impl TryFrom<&serde_cbor_2::Value> for COSEKey {
    type Error = WebauthnError;
    fn try_from(d: &serde_cbor_2::Value) -> Result<COSEKey, Self::Error> {
        let m = cbor_try_map!(d)?;

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
            .get(&serde_cbor_2::Value::Integer(1))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let key_type = cbor_try_i128!(key_type_value)?;
        /*
            // Some keys may return this as a string rather than int.
            // The only key so far is the solokey and it's ed25519 support
            // is broken, so there isn't much point enabling this today.
            .or_else(|_| {
                // tstr is also supported as a type on this field.
                cbor_try_string!(key_type_value)
                    .and_then(|kt_str| {
                        match kt_str.as_str() {
                            "OKP" => Ok(1),
                            "EC2" => Ok(2),
                            "RSA" => Ok(3),
                            _ => Err(WebauthnError::COSEKeyInvalidCBORValue)
                        }
                    })
            })?;
        */

        let content_type_value = m
            .get(&serde_cbor_2::Value::Integer(3))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let content_type = cbor_try_i128!(content_type_value)?;

        let type_ = COSEAlgorithm::try_from(content_type)
            .map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)?;

        // https://www.iana.org/assignments/cose/cose.xhtml
        // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
        // match key_type {
        // 1 => {} OctetKey
        if key_type == (COSEKeyTypeId::EC_EC2 as i128)
            && (type_ == COSEAlgorithm::ES256
                || type_ == COSEAlgorithm::ES384
                || type_ == COSEAlgorithm::ES521)
        {
            // This indicates this is an EC2 key consisting of crv, x, y, which are stored in
            // crv (-1), x (-2) and y (-3)
            // Get these values now ....

            let curve_type_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let curve_type = cbor_try_i128!(curve_type_value)?;

            let curve = ECDSACurve::try_from(curve_type)?;

            let x_value = m
                .get(&serde_cbor_2::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let x = cbor_try_bytes!(x_value)?;

            let y_value = m
                .get(&serde_cbor_2::Value::Integer(-3))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let y = cbor_try_bytes!(y_value)?;

            let coord_len = curve.coordinate_size();
            if x.len() != coord_len || y.len() != coord_len {
                return Err(WebauthnError::COSEKeyECDSAXYInvalid);
            }

            // Right, now build the struct.
            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve,
                    x: x.to_vec().into(),
                    y: y.to_vec().into(),
                }),
            };

            // The rfc additionally states:
            //   "   Applications MUST check that the curve and the key type are
            //     consistent and reject a key if they are not."
            // this means feeding the values to openssl to validate them for us!

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::EC_RSA as i128) && (type_ == COSEAlgorithm::RS256) {
            // RSAKey

            // -37 -> PS256
            // -257 -> RS256 aka RSASSA-PKCS1-v1_5 with SHA-256

            // -1 -> n 256 bytes
            // -2 -> e 3 bytes

            let n_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let n = cbor_try_bytes!(n_value)?;

            let e_value = m
                .get(&serde_cbor_2::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let e = cbor_try_bytes!(e_value)?;

            if n.len() != 256 || e.len() != 3 {
                return Err(WebauthnError::COSEKeyRSANEInvalid);
            }

            // Set the n and e, we know they are proper sizes.
            let mut e_temp = [0; 3];
            e_temp.copy_from_slice(e.as_slice());

            // Right, now build the struct.
            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::RSA(COSERSAKey {
                    n: n.to_vec().into(),
                    e: e_temp,
                }),
            };

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::EC_OKP as i128) && (type_ == COSEAlgorithm::EDDSA) {
            // https://datatracker.ietf.org/doc/html/rfc8152#section-13.2

            let curve_type_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let curve = cbor_try_i128!(curve_type_value).and_then(EDDSACurve::try_from)?;

            /*
                // Some keys may return this as a string rather than int.
                // The only key so far is the solokey and it's ed25519 support
                // is broken, so there isn't much point enabling this today.
                .or_else(|_| {
                    // tstr is also supported as a type on this field.
                    cbor_try_string!(curve_type_value)
                        .and_then(|ct_str| {
                            trace!(?ct_str);
                            match ct_str.as_str() {
                                "EdDSA" => Ok(-8),
                                _ => Err(WebauthnError::COSEKeyInvalidCBORValue)
                            }
                        })
                })?;
            */

            let x_value = m
                .get(&serde_cbor_2::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let x = cbor_try_bytes!(x_value)?;

            if x.len() != curve.coordinate_size() {
                return Err(WebauthnError::COSEKeyEDDSAXInvalid);
            }

            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::EC_OKP(COSEOKPKey {
                    curve,
                    x: x.to_vec().into(),
                }),
            };

            // The rfc additionally states:
            //   "   Applications MUST check that the curve and the key type are
            //     consistent and reject a key if they are not."
            // this means feeding the values to openssl to validate them for us!
            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else {
            debug!(?key_type, ?type_, "WebauthnError::COSEKeyInvalidType");
            Err(WebauthnError::COSEKeyInvalidType)
        }
    }
}

impl TryFrom<(COSEAlgorithm, &Certificate)> for COSEKey {
    type Error = WebauthnError;

    fn try_from((alg, certificate): (COSEAlgorithm, &Certificate)) -> Result<COSEKey, Self::Error> {
        let subject_public_key_info = certificate
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();

        let key = match alg {
            COSEAlgorithm::ES256 => {
                let pub_key = EcdsaP256PublicKey::try_from(subject_public_key_info)
                    .map_err(|_err| WebauthnError::CertificatePublicKeyAlgorthimMismatch)?;

                let point = EcdsaP256PublicEncodedPoint::from(pub_key);

                let Some(xbn) = point.x().map(|x| x.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                let Some(ybn) = point.y().map(|y| y.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: xbn.into(),
                    y: ybn.into(),
                }))
            }

            COSEAlgorithm::ES384 => {
                let pub_key = EcdsaP384PublicKey::try_from(subject_public_key_info)
                    .map_err(|_err| WebauthnError::CertificatePublicKeyAlgorthimMismatch)?;

                let point = EcdsaP384PublicEncodedPoint::from(pub_key);

                let Some(xbn) = point.x().map(|x| x.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                let Some(ybn) = point.y().map(|y| y.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP384R1,
                    x: xbn.into(),
                    y: ybn.into(),
                }))
            }
            COSEAlgorithm::ES521 => {
                let pub_key = EcdsaP521PublicKey::try_from(subject_public_key_info)
                    .map_err(|_err| WebauthnError::CertificatePublicKeyAlgorthimMismatch)?;

                let point = EcdsaP521PublicEncodedPoint::from(pub_key);

                let Some(xbn) = point.x().map(|x| x.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                let Some(ybn) = point.y().map(|y| y.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP521R1,
                    x: xbn.into(),
                    y: ybn.into(),
                }))
            }

            COSEAlgorithm::RS256
            | COSEAlgorithm::RS384
            | COSEAlgorithm::RS512
            | COSEAlgorithm::PS256
            | COSEAlgorithm::PS384
            | COSEAlgorithm::PS512
            | COSEAlgorithm::EDDSA
            | COSEAlgorithm::PinUvProtocol
            | COSEAlgorithm::INSECURE_RS1 => {
                error!(
                    "unsupported X509 to COSE conversion for COSE algorithm type {:?}",
                    alg
                );
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }?;

        Ok(COSEKey { type_: alg, key })
    }
}

enum COSEKeyPublic {
    EcdsaP256(EcdsaP256PublicKey),
    EcdsaP384(EcdsaP384PublicKey),
    EcdsaP521(EcdsaP521PublicKey),
    RsaS256(RS256PublicKey),
    // Ed25519(),
    // Ed448(),
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
                    .copied()
                    .collect())
            }
            _ => {
                debug!("get_alg_key_ecc_x962_raw");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), WebauthnError> {
        self.get_public_key().map(|_| ())
    }

    /// Retrieve the public key of this COSEKey as an OpenSSL structure
    fn get_public_key(&self) -> Result<COSEKeyPublic, WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => match ec2k.curve {
                ECDSACurve::SECP256R1 => {
                    ecdsa_p256::from_coords_raw(ec2k.x.as_ref(), ec2k.y.as_ref())
                        .map(COSEKeyPublic::EcdsaP256)
                        .ok_or_else(|| WebauthnError::EcdsaPointInvalid)
                }
                ECDSACurve::SECP384R1 => {
                    ecdsa_p384::from_coords_raw(ec2k.x.as_ref(), ec2k.y.as_ref())
                        .map(COSEKeyPublic::EcdsaP384)
                        .ok_or_else(|| WebauthnError::EcdsaPointInvalid)
                }
                ECDSACurve::SECP521R1 => {
                    ecdsa_p521::from_coords_raw(ec2k.x.as_ref(), ec2k.y.as_ref())
                        .map(COSEKeyPublic::EcdsaP521)
                        .ok_or_else(|| WebauthnError::EcdsaPointInvalid)
                }
            },
            COSEKeyType::RSA(rsak) => {
                let n = BigUint::from_bytes_be(&rsak.n);
                let e = BigUint::from_bytes_be(&rsak.e);

                RS256PublicKey::new(n, e)
                    .map(COSEKeyPublic::RsaS256)
                    .map_err(|_err| WebauthnError::RsaParametersInvalid)
            }
            COSEKeyType::EC_OKP(_edk) => {
                // !!!
                // Today, RustCrypto doesn't directly support ed25519 or ed448. As a result
                // I'm opting to skip these.
                //
                // We don't actually *advertise* support for either of these directly in our
                // default algorithm offerings, so the impact of this should be minimal.
                /*
                match &edk.curve {
                    EDDSACurve::ED25519 => {

                    }
                    EDDSACurve::ED448 => {
                    }
                }

                let xref = edk.x.as_ref();
                */
                Err(WebauthnError::SshPublicKeyEDUnsupported)
            }
        }
    }

    /// Verifies data was signed with this [COSEKey].
    pub fn verify_signature(
        &self,
        signature: &[u8],
        verification_data: &[u8],
    ) -> Result<bool, WebauthnError> {
        let public_key = self.get_public_key()?;

        match public_key {
            COSEKeyPublic::EcdsaP256(pub_key) => {
                let signature = EcdsaP256Signature::from_der(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = EcdsaP256VerifyingKey::from(&pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
            COSEKeyPublic::EcdsaP384(pub_key) => {
                let signature = EcdsaP384Signature::from_der(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = EcdsaP384VerifyingKey::from(&pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
            COSEKeyPublic::EcdsaP521(_pub_key) => {
                // Currently this is unsupported by p521 but will be available
                // in future. There really isn't *huge* reason to use p521 anyway,
                // so for now we disable this and move on.
                /*
                let signature = EcdsaP521Signature::from_der(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = EcdsaP521VerifyingKey::from(&pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
                */
                Ok(false)
            }
            COSEKeyPublic::RsaS256(pub_key) => {
                let signature = RS256Signature::try_from(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = RS256VerifyingKey::new(pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
        }
    }
}

/// Compute the sha256 of a slice of data.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = s256::Sha256::new();
    hasher.update(data);
    *hasher.finalize().as_ref()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use hex_literal::hex;
    use serde_cbor_2::Value;

    #[test]
    fn cbor_es256() {
        let hex_data = hex!(
                "A5"         // Map - 5 elements
                "01 02"      //   1:   2,  ; kty: EC2 key type
                "03 26"      //   3:  -7,  ; alg: ES256 signature algorithm
                "20 01"      //  -1:   1,  ; crv: P-256 curve
                "21 58 20   65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d" // -2:   x,  ; x-coordinate
                "22 58 20   1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c" // -3:   y,  ; y-coordinate
        );

        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES256);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP256R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    #[test]
    fn cbor_es384() {
        let hex_data = hex!(
                "A5"         // Map - 5 elements
                "01 02"      //   1:   2,  ; kty: EC2 key type
                "03 38 22"   //   3:  -35,  ; alg: ES384 signature algorithm
                "20 02"      //  -1:   2,  ; crv: P-384 curve
                "21 58 30   ceeaf818731db7af2d02e029854823d71bdbf65fb0c6ff69" // -2: x, ; x-coordinate
                           "42c9cf891efe18ea81430517d777f5c43550da801be5bf2f"
                "22 58 30   dda1d0ead72e042efb7c36a38cc021abb2ca1a2e38159edd" // -3: y ; y-coordinate
                           "a8c25f391e9a38d79dd56b9427d1c7c70cfa778ab849b087"
        );

        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES384);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!(
                        "ceeaf818731db7af2d02e029854823d71bdbf65fb0c6ff69
                         42c9cf891efe18ea81430517d777f5c43550da801be5bf2f"
                    )
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!(
                        "dda1d0ead72e042efb7c36a38cc021abb2ca1a2e38159edd
                         a8c25f391e9a38d79dd56b9427d1c7c70cfa778ab849b087"
                    )
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP384R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    #[test]
    fn cbor_es512() {
        let hex_data = hex!(
                "A5"         // Map - 5 elements
                "01 02"      //   1:   2,  ; kty: EC2 key type
                "03 38 23"   //   3:  -36,  ; alg: ES512 signature algorithm
                "20 03"      //  -1:   3,  ; crv: P-521 curve
                "21 58 42   0106cfaacf34b13f24bbb2f806fd9cfacff9a2a5ef9ecfcd85664609a0b2f6d4fd" // -2:   x,  ; x-coordinate
                           "b8e1d58630905f13f38d8eed8714eceb716920a3a235581623261fed961f7b7d72"
                "22 58 42   0089597a052a8d3c8b2b5692d467dea19f8e1b9ca17fa563a1a826855dade04811" // -3:   y,  ; y-coordinate
                           "b2881819e72f1706daeaf7d3773b2e284983a0eec33c2fe3ff5697722e95b29536");

        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES521);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!(
                        "0106cfaacf34b13f24bbb2f806fd9cfacff9a2a5ef9ecfcd85664609a0b2f6d4fd
                         b8e1d58630905f13f38d8eed8714eceb716920a3a235581623261fed961f7b7d72"
                    )
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!(
                        "0089597a052a8d3c8b2b5692d467dea19f8e1b9ca17fa563a1a826855dade04811
                         b2881819e72f1706daeaf7d3773b2e284983a0eec33c2fe3ff5697722e95b29536"
                    )
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP521R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    /*
    #[test]
    fn cbor_ed25519() {
        let hex_data = hex!(
        "A4"         // Map - 4 elements
        "01 01"      //   1:   1,  ; kty: OKP key type
        "03 27"      //   3:  -8,  ; alg: EDDSA signature algorithm
        "20 06"      //  -1:   6,  ; crv: Ed25519 curve
        "21 58 20   43565027f918beb00257d112b903d15b93f5cbc7562dfc8458fbefd714546e3c" // -2:   x,  ; Y-coordinate
        );
        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();
        assert_eq!(key.type_, COSEAlgorithm::EDDSA);
        match key.key {
            COSEKeyType::EC_OKP(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("43565027f918beb00257d112b903d15b93f5cbc7562dfc8458fbefd714546e3c")
                );
                assert_eq!(pkey.curve, EDDSACurve::ED25519);
            }
            _ => panic!("Key should be parsed OKP key"),
        }
    }

    #[test]
    fn cbor_ed448() {
        let hex_data = hex!(
            "A4"         // Map - 4 elements
            "01 01"      //   1:   1,  ; kty: OKP key type
            "03 27"      //   3:  -8,  ; alg: EDDSA signature algorithm
            "20 07"      //  -1:   7,  ; crv: Ed448 curve
            "21 58 39   0c04658f79c3fd86c4b3d676057b76353126e9b905a7e204c07846c1a2ab3791b02fc5e9c6930345ea7bf8524b944220d4bd711c010c9b2a80" // -2:   x,  ; Y-coordinate
        );
        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();
        assert_eq!(key.type_, COSEAlgorithm::EDDSA);
        match key.key {
            COSEKeyType::EC_OKP(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("0c04658f79c3fd86c4b3d676057b76353126e9b905a7e204c07846c1a2ab3791b02fc5e9c6930345ea7bf8524b944220d4bd711c010c9b2a80")
                );
                assert_eq!(pkey.curve, EDDSACurve::ED448);
            }
            _ => panic!("Key should be parsed OKP key"),
        }
    }
    */
}
