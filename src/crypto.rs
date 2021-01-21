//! Cryptographic operation wrapper for Webauthn. This module exists to
//! allow ease of auditing, safe operation wrappers for the webauthn library,
//! and cryptographic provider abstraction. This module currently uses OpenSSL
//! as the cryptographic primitive provider.

#![allow(non_camel_case_types)]

use core::convert::TryFrom;
use openssl::{bn, ec, hash, nid, pkey, rsa, sha, sign, x509};

// use super::constants::*;
use super::error::*;
use crate::proto::{
    Aaguid, COSEContentType, COSEEC2Key, COSEKey, COSEKeyType, COSERSAKey, ECDSACurve,
};
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

// Apple makes a webauthn root certificate public at
// https://www.apple.com/certificateauthority/private/.
// The certificate data itself (as linked in the cert listing linked above) can be found at
// https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem.
pub(crate) const APPLE_X509_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
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

fn verify_signature(
    pkey: &pkey::PKeyRef<pkey::Public>,
    stype: COSEContentType,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    let mut verifier = match stype {
        COSEContentType::ECDSA_SHA256 => sign::Verifier::new(hash::MessageDigest::sha256(), &pkey)
            .map_err(WebauthnError::OpenSSLError),
        COSEContentType::RS256 => {
            let mut verifier = sign::Verifier::new(hash::MessageDigest::sha256(), &pkey)
                .map_err(WebauthnError::OpenSSLError)?;
            verifier
                .set_rsa_padding(rsa::Padding::PKCS1)
                .map_err(WebauthnError::OpenSSLError)?;
            Ok(verifier)
        }
        COSEContentType::INSECURE_RS1 => {
            let mut verifier = sign::Verifier::new(hash::MessageDigest::sha1(), &pkey)
                .map_err(WebauthnError::OpenSSLError)?;
            verifier
                .set_rsa_padding(rsa::Padding::PKCS1)
                .map_err(WebauthnError::OpenSSLError)?;
            Ok(verifier)
        }
        _ => Err(WebauthnError::COSEKeyInvalidType),
    }?;

    verifier
        .update(verification_data)
        .map_err(WebauthnError::OpenSSLError)?;
    verifier
        .verify(signature)
        .map_err(WebauthnError::OpenSSLError)
}

/// An X509PublicKey. This is what is otherwise known as a public certificate
/// which comprises a public key and other signed metadata related to the issuer
/// of the key.
pub struct X509PublicKey {
    pubk: x509::X509,
    t: COSEContentType,
}

impl std::fmt::Debug for X509PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "X509PublicKey")
    }
}

impl TryFrom<(&[u8], COSEContentType)> for X509PublicKey {
    type Error = WebauthnError;

    // Must be DER bytes. If you have PEM, base64decode first!
    fn try_from((d, t): (&[u8], COSEContentType)) -> Result<Self, Self::Error> {
        let pubk = x509::X509::from_der(d).map_err(WebauthnError::OpenSSLError)?;

        #[allow(clippy::single_match)]
        match &t {
            COSEContentType::ECDSA_SHA256 => {
                let pk = pubk.public_key().map_err(WebauthnError::OpenSSLError)?;

                let ec_key = pk.ec_key().map_err(WebauthnError::OpenSSLError)?;

                ec_key.check_key().map_err(WebauthnError::OpenSSLError)?;

                let ec_grpref = ec_key.group();

                let ec_curve = ec_grpref
                    .curve_name()
                    .ok_or(WebauthnError::OpenSSLErrorNoCurveName)?;

                if ec_curve != nid::Nid::X9_62_PRIME256V1 {
                    return Err(WebauthnError::CertificatePublicKeyInvalid);
                }
            }
            _ => {}
        }

        Ok(X509PublicKey { pubk, t })
    }
}

impl X509PublicKey {
    pub(crate) fn verify_signature(
        &self,
        signature: &[u8],
        verification_data: &[u8],
    ) -> Result<bool, WebauthnError> {
        let pkey = self
            .pubk
            .public_key()
            .map_err(WebauthnError::OpenSSLError)?;

        verify_signature(&pkey, self.t, signature, verification_data)
    }

    pub(crate) fn assert_tpm_attest_req(&self) -> Result<(), WebauthnError> {
        // TPM attestation certificate MUST have the following fields/extensions:

        // Version MUST be set to 3.
        // version is not an attribute in openssl rust so I can't verify this

        // Subject field MUST be set to empty.
        let subject_name_ref = self.pubk.subject_name();
        if subject_name_ref.entries().count() != 0 {
            return Err(WebauthnError::AttestationCertificateRequirementsNotMet);
        }

        // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        // https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
        //
        // I actually have no idea how to parse or process this ...
        // self.pubk.subject_alt_names

        // Today there is no way to view eku/bc from openssl rust

        // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.

        // The Basic Constraints extension MUST have the CA component set to false.

        // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution
        // Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is
        // available through metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].

        Ok(())
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
            .take(1)
            .next();
        let subject_o = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(17))
            .take(1)
            .next();
        let subject_ou = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(18))
            .take(1)
            .next();
        let subject_cn = subject_name_ref
            .entries_by_nid(nid::Nid::from_raw(13))
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

    pub(crate) fn apple_x509() -> X509PublicKey {
        Self {
            pubk: x509::X509::from_pem(APPLE_X509_PEM).unwrap(),
            // This content type was obtained statically (this certificate is static data)
            t: COSEContentType::ECDSA_SHA384,
        }
    }
}

impl TryFrom<nid::Nid> for ECDSACurve {
    type Error = WebauthnError;
    fn try_from(nid: nid::Nid) -> Result<Self, Self::Error> {
        match nid {
            nid::Nid::X9_62_PRIME256V1 => Ok(ECDSACurve::SECP256R1),
            nid::Nid::SECP384R1 => Ok(ECDSACurve::SECP384R1),
            nid::Nid::SECP521R1 => Ok(ECDSACurve::SECP521R1),
            _ => Err(WebauthnError::ECDSACurveInvalidNid),
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

impl COSEContentType {
    pub(crate) fn only_hash_from_type(&self, input: &[u8]) -> Result<Vec<u8>, WebauthnError> {
        match self {
            COSEContentType::INSECURE_RS1 => {
                // sha1
                hash::hash(hash::MessageDigest::sha1(), input)
                    .map(|dbytes| Vec::from(dbytes.as_ref()))
                    .map_err(WebauthnError::OpenSSLError)
            }
            _ => Err(WebauthnError::COSEKeyInvalidType),
        }
    }
}

impl TryFrom<&serde_cbor::Value> for COSEKey {
    type Error = WebauthnError;
    fn try_from(d: &serde_cbor::Value) -> Result<COSEKey, Self::Error> {
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
            .get(&serde_cbor::Value::Integer(1))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let key_type = cbor_try_i128!(key_type_value)?;

        let content_type_value = m
            .get(&serde_cbor::Value::Integer(3))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let content_type = cbor_try_i128!(content_type_value)?;

        // https://www.iana.org/assignments/cose/cose.xhtml
        // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
        match key_type {
            // 1 => {} OctetKey
            2 => {
                // This indicates this is an EC2 key consisting of crv, x, y, which are stored in
                // crv (-1), x (-2) and y (-3)
                // Get these values now ....

                let curve_type_value = m
                    .get(&serde_cbor::Value::Integer(-1))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let curve_type = cbor_try_i128!(curve_type_value)?;

                // Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.

                // Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.

                let x_value = m
                    .get(&serde_cbor::Value::Integer(-2))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let x = cbor_try_bytes!(x_value)?;

                let y_value = m
                    .get(&serde_cbor::Value::Integer(-3))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let y = cbor_try_bytes!(y_value)?;

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
            3 => {
                // RSAKey

                // -37 -> PS256
                // -257 -> RS256 aka RSASSA-PKCS1-v1_5 with SHA-256

                // -1 -> n 256 bytes
                // -2 -> e 3 bytes

                let n_value = m
                    .get(&serde_cbor::Value::Integer(-1))
                    .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
                let n = cbor_try_bytes!(n_value)?;

                let e_value = m
                    .get(&serde_cbor::Value::Integer(-2))
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
                    type_: COSEContentType::try_from(content_type)?,
                    key: COSEKeyType::RSA(COSERSAKey {
                        n: n.to_vec(),
                        e: e_temp,
                    }),
                };

                cose_key.validate()?;
                // return it
                Ok(cose_key)
            }
            _ => {
                log::debug!("try from");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }
}

impl TryFrom<&X509PublicKey> for COSEKey {
    type Error = WebauthnError;
    fn try_from(cert: &X509PublicKey) -> Result<COSEKey, Self::Error> {
        let key = match cert.t {
            COSEContentType::ECDSA_SHA256
            | COSEContentType::ECDSA_SHA384
            | COSEContentType::ECDSA_SHA512 => {
                let ec_key = cert
                    .pubk
                    .public_key()
                    .and_then(|pk| pk.ec_key())
                    .map_err(WebauthnError::OpenSSLError)?;

                ec_key.check_key().map_err(WebauthnError::OpenSSLError)?;

                let ec_grpref = ec_key.group();

                let mut ctx =
                    openssl::bn::BigNumContext::new().map_err(WebauthnError::OpenSSLError)?;
                let mut xbn = openssl::bn::BigNum::new().map_err(WebauthnError::OpenSSLError)?;
                let mut ybn = openssl::bn::BigNum::new().map_err(WebauthnError::OpenSSLError)?;

                ec_key
                    .public_key()
                    .affine_coordinates_gfp(ec_grpref, &mut xbn, &mut ybn, &mut ctx)
                    .map_err(WebauthnError::OpenSSLError)?;

                let curve = ec_grpref
                    .curve_name()
                    .ok_or(WebauthnError::OpenSSLErrorNoCurveName)
                    .and_then(ECDSACurve::try_from)?;

                let mut x = [0; 32];
                x.copy_from_slice(xbn.to_vec().as_slice());

                let mut y = [0; 32];
                y.copy_from_slice(ybn.to_vec().as_slice());

                Ok(COSEKeyType::EC_EC2(COSEEC2Key { curve, x, y }))
            }
            COSEContentType::RS256
            | COSEContentType::RS384
            | COSEContentType::RS512
            | COSEContentType::PS256
            | COSEContentType::PS384
            | COSEContentType::PS512
            | COSEContentType::EDDSA
            | COSEContentType::INSECURE_RS1 => {
                log::error!(
                    "unsupported X509 to COSE conversion for COSE content type {:?}",
                    cert.t
                );
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }?;

        Ok(COSEKey { type_: cert.t, key })
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
                    .copied()
                    .collect())
            }
            _ => {
                log::debug!("get_alg_key_ecc_x962_raw");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => {
                // Get the curve type
                let curve = ec2k.curve.to_openssl_nid();
                let ec_group =
                    ec::EcGroup::from_curve_name(curve).map_err(WebauthnError::OpenSSLError)?;

                let xbn = bn::BigNum::from_slice(&ec2k.x).map_err(WebauthnError::OpenSSLError)?;
                let ybn = bn::BigNum::from_slice(&ec2k.y).map_err(WebauthnError::OpenSSLError)?;

                let ec_key = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(WebauthnError::OpenSSLError)?;

                ec_key.check_key().map_err(WebauthnError::OpenSSLError)
            }
            COSEKeyType::RSA(rsak) => {
                let nbn = bn::BigNum::from_slice(&rsak.n).map_err(WebauthnError::OpenSSLError)?;
                let ebn = bn::BigNum::from_slice(&rsak.e).map_err(WebauthnError::OpenSSLError)?;

                let _rsa_key = rsa::Rsa::from_public_components(nbn, ebn)
                    .map_err(WebauthnError::OpenSSLError)?;
                /*
                // Only applies to keys with private components!
                rsa_key
                    .check_key()
                    .map_err(WebauthnError::OpenSSLError)
                */
                Ok(())
            }
            _ => Err(WebauthnError::COSEKeyInvalidType),
        }
    }

    fn get_openssl_pkey(&self) -> Result<pkey::PKey<pkey::Public>, WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => {
                // Get the curve type
                let curve = ec2k.curve.to_openssl_nid();
                let ec_group =
                    ec::EcGroup::from_curve_name(curve).map_err(WebauthnError::OpenSSLError)?;

                let xbn = bn::BigNum::from_slice(&ec2k.x).map_err(WebauthnError::OpenSSLError)?;
                let ybn = bn::BigNum::from_slice(&ec2k.y).map_err(WebauthnError::OpenSSLError)?;

                let ec_key = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(WebauthnError::OpenSSLError)?;

                // Validate the key is sound. IIRC this actually checks the values
                // are correctly on the curve as specified
                ec_key.check_key().map_err(WebauthnError::OpenSSLError)?;

                let p = pkey::PKey::from_ec_key(ec_key).map_err(WebauthnError::OpenSSLError)?;
                Ok(p)
            }
            COSEKeyType::RSA(rsak) => {
                let nbn = bn::BigNum::from_slice(&rsak.n).map_err(WebauthnError::OpenSSLError)?;
                let ebn = bn::BigNum::from_slice(&rsak.e).map_err(WebauthnError::OpenSSLError)?;

                let rsa_key = rsa::Rsa::from_public_components(nbn, ebn)
                    .map_err(WebauthnError::OpenSSLError)?;

                let p = pkey::PKey::from_rsa(rsa_key).map_err(WebauthnError::OpenSSLError)?;
                Ok(p)
            }
            _ => {
                log::debug!("get_openssl_pkey");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }

    pub(crate) fn verify_signature(
        &self,
        signature: &[u8],
        verification_data: &[u8],
    ) -> Result<bool, WebauthnError> {
        let pkey = self.get_openssl_pkey()?;
        verify_signature(&pkey, self.type_, signature, verification_data)
    }
}

/// Compute the sha256 of a slice of data.
pub fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish().iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nid_to_curve() {
        assert_eq!(
            ECDSACurve::try_from(nid::Nid::X9_62_PRIME256V1).unwrap(),
            ECDSACurve::SECP256R1
        );
    }
}
