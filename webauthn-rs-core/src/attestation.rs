//! Attestation information and verifications procedures.
//! This contains a transparent type allowing callbacks to
//! make attestation decisions. See the WebauthnConfig trait
//! for more details.

use std::convert::TryFrom;

use crate::crypto::{
    assert_packed_attest_req, assert_tpm_attest_req, compute_sha256, only_hash_from_type,
    verify_signature,
};
use crate::error::WebauthnError;
use crate::internals::*;
use crate::proto::*;
use base64urlsafedata::Base64UrlSafeData;
use openssl::hash::MessageDigest;
use openssl::sha::sha256;
use openssl::stack;
use openssl::x509;
use openssl::x509::store;
use openssl::x509::verify;
use uuid::Uuid;
use x509_parser::oid_registry::Oid;

/// x509 certificate extensions are validated in the webauthn spec by checking
/// that the value of the extension is equal to some other value
pub trait AttestationX509Extension {
    /// the type of the value in the certificate extension
    type Output: Eq;

    /// the oid of the extension
    const OID: Oid<'static>;

    /// how to parse the value out of the certificate extension
    fn parse(i: &[u8]) -> der_parser::error::BerResult<(Self::Output, AttestationMetadata)>;

    /// if `true`, then validating this certificate fails if this extension is
    /// missing
    const IS_REQUIRED: bool;

    /// what error to return if validation fails---i.e. if the "other value" is
    /// not equal to that in the extension
    const VALIDATION_ERROR: WebauthnError;
}

/// The Fido AAGUID x509 extension
pub struct FidoGenCeAaguid;
pub(crate) struct AppleAnonymousNonce;

pub(crate) struct AndroidKeyAttestationExtensionData;

impl AttestationX509Extension for FidoGenCeAaguid {
    // If cert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid)
    const OID: Oid<'static> = der_parser::oid!(1.3.6 .1 .4 .1 .45724 .1 .1 .4);

    // verify that the value of this extension matches the aaguid in authenticatorData.
    type Output = Aaguid;

    fn parse(i: &[u8]) -> der_parser::error::BerResult<(Self::Output, AttestationMetadata)> {
        let (rem, aaguid) = der_parser::der::parse_der_octetstring(i)?;
        let aaguid: Aaguid = aaguid
            .as_slice()
            .expect("octet string can be used as a slice")
            .try_into()
            .map_err(|_| der_parser::error::BerError::InvalidLength)?;

        Ok((rem, (aaguid, AttestationMetadata::None)))
    }

    const IS_REQUIRED: bool = false;

    const VALIDATION_ERROR: WebauthnError = WebauthnError::AttestationCertificateAAGUIDMismatch;
}

pub(crate) mod android_key_attestation {
    use der_parser::ber::BerObjectContent;

    use crate::proto::AttestationMetadata;

    #[derive(Clone, PartialEq, Eq)]
    pub struct Data {
        pub attestation_challenge: Vec<u8>,
        pub attest_enforcement: EnforcementType,
        pub km_enforcement: EnforcementType,
        pub software_enforced: AuthorizationList,
        pub tee_enforced: AuthorizationList,
    }

    #[derive(Clone, PartialEq, Eq, Copy)]
    pub struct AuthorizationList {
        pub all_applications: bool,
        pub origin: Option<u32>,
        pub purpose: Option<u32>,
    }

    pub const KM_ORIGIN_GENERATED: u32 = 0;
    pub const KM_PURPOSE_SIGN: u32 = 2;

    #[derive(Clone, Eq)]
    pub enum EnforcementType {
        Software,
        Tee,
        #[allow(unused)]
        Either,
    }

    impl PartialEq for EnforcementType {
        fn eq(&self, other: &Self) -> bool {
            matches!(
                (self, other),
                (Self::Either, _)
                    | (_, Self::Either)
                    | (Self::Software, Self::Software)
                    | (Self::Tee, Self::Tee)
            )
        }
    }

    impl AuthorizationList {
        pub fn parse(i: &[u8]) -> der_parser::error::BerResult<Self> {
            use der_parser::{der::*, error::BerError};
            parse_der_container(|i: &[u8], hdr: Header| {
                if hdr.tag() != Tag::Sequence {
                    return Err(nom::Err::Error(BerError::BerTypeError));
                }

                let mut all_applications = false;
                let mut origin = None;
                let mut purpose = None;

                let mut i = i;
                while let Ok((k, obj)) = parse_der(i) {
                    i = k;
                    // dbg!(&obj);
                    if obj.content == BerObjectContent::Optional(None) {
                        continue;
                    }

                    match obj.tag() {
                        Tag(600) => {
                            all_applications = true;
                        }
                        Tag(702) => {
                            if let BerObjectContent::Unknown(o) = obj.content {
                                let (_, val) = parse_der_integer(o.data)?;
                                origin = Some(val.as_u32()?);
                            }
                        }
                        Tag(1) => {
                            if let BerObjectContent::Unknown(o) = obj.content {
                                let (_, val) =
                                    parse_der_container(|i, _| parse_der_integer(i))(o.data)?;
                                purpose = Some(val.as_u32()?);
                            }
                        }
                        _ => continue,
                    };
                }

                let al = AuthorizationList {
                    all_applications,
                    origin,
                    purpose,
                };

                Ok((i, al))
            })(i)
        }
    }

    impl Data {
        pub fn parse(i: &[u8]) -> der_parser::error::BerResult<(Vec<u8>, AttestationMetadata)> {
            use der_parser::{der::*, error::BerError};
            parse_der_container(|i: &[u8], hdr: Header| {
                if hdr.tag() != Tag::Sequence {
                    return Err(nom::Err::Error(BerError::BerTypeError));
                }
                let (i, attestation_version) = parse_der_integer(i)?;
                let _attestation_version = attestation_version.as_i64()?;

                let (i, attest_sec_level) = parse_der_enum(i)?; // security level
                let attest_sec_level = attest_sec_level.as_u32()?;
                let (i, _) = parse_der_integer(i)?; // kVers
                let (i, km_sec_level) = parse_der_enum(i)?; // kSeclev
                let km_sec_level = km_sec_level.as_u32()?;

                let (i, attestation_challenge) = parse_der_octetstring(i)?;
                let attestation_challenge = attestation_challenge.as_slice()?.to_vec();

                let (i, _unique_id) = parse_der_octetstring(i)?;

                let (i, software_enforced) = AuthorizationList::parse(i)?;
                let (i, tee_enforced) = AuthorizationList::parse(i)?;

                let attest_enforcement = match attest_sec_level {
                    0 => EnforcementType::Software,
                    1 => EnforcementType::Tee,
                    _ => return Err(der_parser::error::BerError::InvalidTag)?,
                };

                let km_enforcement = match km_sec_level {
                    0 => EnforcementType::Software,
                    1 => EnforcementType::Tee,
                    _ => return Err(der_parser::error::BerError::InvalidTag)?,
                };

                // ensure it is origin bound
                if software_enforced.all_applications || tee_enforced.all_applications {
                    return Err(der_parser::error::BerError::InvalidValue {
                        tag: Tag(600),
                        msg: "all_applications must not be set".to_string(),
                    })?;
                }

                // ensure key master values are set properly
                let software_set = match (software_enforced.origin, software_enforced.purpose) {
                    (Some(origin), Some(purpose))
                        if origin == KM_ORIGIN_GENERATED && purpose == KM_PURPOSE_SIGN =>
                    {
                        true
                    }
                    (None, None) => false,
                    _ => {
                        return Err(der_parser::error::BerError::InvalidValue {
                            tag: Tag(701),
                            msg: "invalid key master values (software)".to_string(),
                        })?;
                    }
                };

                let tee_set = match (tee_enforced.origin, tee_enforced.purpose) {
                    (Some(origin), Some(purpose))
                        if origin == KM_ORIGIN_GENERATED && purpose == KM_PURPOSE_SIGN =>
                    {
                        true
                    }
                    (None, None) => false,
                    _ => {
                        return Err(der_parser::error::BerError::InvalidValue {
                            tag: Tag(701),
                            msg: "invalid key master values (tee)".to_string(),
                        })?;
                    }
                };

                if !tee_set && !software_set {
                    return Err(der_parser::error::BerError::InvalidValue {
                        tag: Tag(701),
                        msg: "both software and tee not set (keymaster values)".to_string(),
                    })?;
                }

                let metadata = AttestationMetadata::AndroidKey {
                    is_km_tee: km_enforcement == EnforcementType::Tee,
                    is_attest_tee: attest_enforcement == EnforcementType::Tee,
                };

                Ok((i, (attestation_challenge, metadata)))
            })(i)
        }
    }
}

impl AttestationX509Extension for AndroidKeyAttestationExtensionData {
    // If cert contains an extension with OID 1.3.6.1.4.1.11129.2.1.17 (android key attestation)
    const OID: Oid<'static> = der_parser::oid!(1.3.6 .1 .4 .1 .11129 .2 .1 .17);

    // verify that the value of this extension matches the aaguid in authenticatorData.
    type Output = Vec<u8>;

    fn parse(i: &[u8]) -> der_parser::error::BerResult<(Self::Output, AttestationMetadata)> {
        android_key_attestation::Data::parse(i)
    }

    const IS_REQUIRED: bool = true;

    const VALIDATION_ERROR: WebauthnError = WebauthnError::AttestationCertificateNonceMismatch;
}

impl AttestationX509Extension for AppleAnonymousNonce {
    type Output = [u8; 32];

    // 4. Verify that nonce equals the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert. The nonce here is used to prove that the attestation is live and to protect the integrity of the authenticatorData and the client data.
    const OID: Oid<'static> = der_parser::oid!(1.2.840 .113635 .100 .8 .2);

    fn parse(i: &[u8]) -> der_parser::error::BerResult<(Self::Output, AttestationMetadata)> {
        use der_parser::{der::*, error::BerError};
        parse_der_container(|i: &[u8], hdr: Header| {
            if hdr.tag() != Tag::Sequence {
                return Err(nom::Err::Error(BerError::BerTypeError));
            }
            let (i, tagged_nonce) = parse_der_tagged_explicit(1, parse_der_octetstring)(i)?;
            let (class, _tag, nonce) = tagged_nonce.as_tagged()?;
            if class != Class::ContextSpecific {
                return Err(nom::Err::Error(BerError::BerTypeError));
            }
            let nonce = nonce
                .as_slice()?
                .try_into()
                .map_err(|_| der_parser::error::BerError::InvalidLength)?;
            Ok((i, (nonce, AttestationMetadata::None)))
        })(i)
    }

    const IS_REQUIRED: bool = true;

    const VALIDATION_ERROR: WebauthnError = WebauthnError::AttestationCertificateNonceMismatch;
}

/// Validate an x509 extension is present in an x509 certificate
pub fn validate_extension<T>(
    x509: &x509::X509,
    data: &<T as AttestationX509Extension>::Output,
) -> Result<AttestationMetadata, WebauthnError>
where
    T: AttestationX509Extension,
{
    let der_bytes = x509.to_der()?;
    x509_parser::parse_x509_certificate(&der_bytes)
        .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?
        .1
        .extensions()
        .iter()
        .find_map(|extension| {
            (extension.oid == T::OID).then(|| {
                T::parse(extension.value)
                    .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)
                    .and_then(|(_, (output, metadata))| {
                        if &output == data {
                            Ok(metadata)
                        } else {
                            Err(T::VALIDATION_ERROR)
                        }
                    })
            })
        })
        .unwrap_or({
            if T::IS_REQUIRED {
                Err(WebauthnError::AttestationStatementMissingExtension)
            } else {
                Ok(AttestationMetadata::None)
            }
        })
}

/// The type of attestation on the credential
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash)]
pub enum AttestationFormat {
    /// Packed attestation
    Packed,
    /// TPM attestation (like Micrsoft)
    Tpm,
    /// Android hardware attestation
    AndroidKey,
    /// Older Android Safety Net
    AndroidSafetyNet,
    /// Old U2F attestation type
    FIDOU2F,
    /// Apple touchID/faceID
    AppleAnonymous,
    /// No attestation
    None,
}

impl TryFrom<&str> for AttestationFormat {
    type Error = WebauthnError;

    fn try_from(a: &str) -> Result<AttestationFormat, Self::Error> {
        match a {
            "packed" => Ok(AttestationFormat::Packed),
            "tpm" => Ok(AttestationFormat::Tpm),
            "android-key" => Ok(AttestationFormat::AndroidKey),
            "android-safetynet" => Ok(AttestationFormat::AndroidSafetyNet),
            "fido-u2f" => Ok(AttestationFormat::FIDOU2F),
            "apple" => Ok(AttestationFormat::AppleAnonymous),
            "none" => Ok(AttestationFormat::None),
            _ => Err(WebauthnError::AttestationNotSupported),
        }
    }
}

// Perform the Verification procedure for 8.2. Packed Attestation Statement Format
// https://w3c.github.io/webauthn/#sctn-packed-attestation
pub(crate) fn verify_packed_attestation(
    acd: &AttestedCredentialData,
    att_obj: &AttestationObject<Registration>,
    client_data_hash: &[u8],
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    let att_stmt = &att_obj.att_stmt;
    let auth_data_bytes = &att_obj.auth_data_bytes;

    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
    let att_stmt_map =
        cbor_try_map!(att_stmt).map_err(|_| WebauthnError::AttestationStatementMapInvalid)?;

    let x5c_key = &serde_cbor_2::Value::Text("x5c".to_string());
    let ecdaa_key_id_key = &serde_cbor_2::Value::Text("ecdaaKeyId".to_string());

    let alg_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("alg".to_string()))
        .ok_or(WebauthnError::AttestationStatementAlgMissing)?;

    let alg = cbor_try_i128!(alg_value)
        .map_err(|_| WebauthnError::AttestationStatementAlgInvalid)
        .and_then(|v| {
            COSEAlgorithm::try_from(v).map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)
        })?;

    trace!(x5c = ?att_stmt_map.get(x5c_key));
    trace!(ecdaa = ?att_stmt_map.get(ecdaa_key_id_key));

    match (
        att_stmt_map.get(x5c_key),
        att_stmt_map.get(ecdaa_key_id_key),
    ) {
        (Some(x5c), _) => {
            // 2. If x5c is present, this indicates that the attestation type is not ECDAA.

            // The elements of this array contain attestnCert and its certificate chain, each
            // encoded in X.509 format. The attestation certificate attestnCert MUST be the first
            // element in the array.
            // x5c: [ attestnCert: bytes, * (caCert: bytes) ]
            let x5c_array_ref =
                cbor_try_array!(x5c).map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?;

            let arr_x509: Result<Vec<_>, _> = x5c_array_ref
                .iter()
                .map(|values| {
                    cbor_try_bytes!(values)
                        .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)
                        .and_then(|b| x509::X509::from_der(b).map_err(WebauthnError::OpenSSLError))
                })
                .collect();

            let arr_x509 = arr_x509?;

            // Must have at least one x509 cert, this is the leaf certificate.
            let attestn_cert = arr_x509
                .get(0)
                .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

            trace!(?attestn_cert);

            // Verify that sig is a valid signature over the concatenation of authenticatorData
            // and clientDataHash using the attestation public key in attestnCert with the
            // algorithm specified in alg.

            let verification_data: Vec<u8> = auth_data_bytes
                .iter()
                .chain(client_data_hash.iter())
                .copied()
                .collect();

            let is_valid_signature = att_stmt_map
                .get(&serde_cbor_2::Value::Text("sig".to_string()))
                .ok_or(WebauthnError::AttestationStatementSigMissing)
                .and_then(|s| cbor_try_bytes!(s))
                .and_then(|sig| verify_signature(alg, attestn_cert, sig, &verification_data))?;

            if !is_valid_signature {
                trace!("packed x509 signature invalid");
                return Err(WebauthnError::AttestationStatementSigInvalid);
            }

            // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation
            // Statement Certificate Requirements.
            // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements

            assert_packed_attest_req(attestn_cert)?;

            // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
            // (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid
            // in authenticatorData.

            validate_extension::<FidoGenCeAaguid>(attestn_cert, &acd.aaguid)?;

            // Optionally, inspect x5c and consult externally provided knowledge to determine
            // whether attStmt conveys a Basic or AttCA attestation.

            // If successful, return implementation-specific values representing attestation type
            // Basic, AttCA or uncertainty, and attestation trust path x5c.

            Ok((
                ParsedAttestationData::Basic(arr_x509),
                AttestationMetadata::Packed {
                    aaguid: Uuid::from_bytes(acd.aaguid),
                },
            ))
        }
        (None, Some(_ecdaa_key_id)) => {
            // 3. If ecdaaKeyId is present, then the attestation type is ECDAA.
            // TODO: Perform the the verification procedure for ECDAA
            debug!("_ecdaa_key_id");
            Err(WebauthnError::AttestationNotSupported)
        }
        (None, None) => {
            // 4. If neither x5c nor ecdaaKeyId is present, self attestation is in use.
            let credential_public_key = COSEKey::try_from(&acd.credential_pk)?;

            // 4.a. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            if alg != credential_public_key.type_ {
                return Err(WebauthnError::AttestationStatementAlgMismatch);
            }

            // 4.b. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
            let verification_data: Vec<u8> = auth_data_bytes
                .iter()
                .chain(client_data_hash.iter())
                .copied()
                .collect();

            let is_valid_signature = att_stmt_map
                .get(&serde_cbor_2::Value::Text("sig".to_string()))
                .ok_or(WebauthnError::AttestationStatementSigMissing)
                .and_then(|s| cbor_try_bytes!(s))
                .and_then(|sig| credential_public_key.verify_signature(sig, &verification_data))?;

            if !is_valid_signature {
                trace!("Invalid Self Attestation Signature");
                return Err(WebauthnError::AttestationStatementSigInvalid);
            }

            // 4.c. If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.
            Ok((ParsedAttestationData::Self_, AttestationMetadata::None))
        }
    }
}

// https://w3c.github.io/webauthn/#fido-u2f-attestation
// https://medium.com/@herrjemand/verifying-fido-u2f-attestations-in-fido2-f83fab80c355
pub(crate) fn verify_fidou2f_attestation(
    acd: &AttestedCredentialData,
    att_obj: &AttestationObject<Registration>,
    client_data_hash: &[u8],
) -> Result<ParsedAttestationData, WebauthnError> {
    let att_stmt = &att_obj.att_stmt;

    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    //
    // ^-- This is already DONE as a factor of serde_cbor_2 not erroring up to this point,
    // and those errors will be handled better than just "unwrap" :)
    // we'll also find out quickly when we attempt to access the data as a map ...

    // TODO: https://github.com/duo-labs/webauthn/blob/master/protocol/attestation_u2f.go#L22
    // Apparently, aaguid must be 0x00

    // Check that x5c has exactly one element and let att_cert be that element.
    let att_stmt_map =
        cbor_try_map!(att_stmt).map_err(|_| WebauthnError::AttestationStatementMapInvalid)?;
    let x5c = att_stmt_map
        .get(&serde_cbor_2::Value::Text("x5c".to_string()))
        .ok_or(WebauthnError::AttestationStatementX5CMissing)?;

    let sig_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("sig".to_string()))
        .ok_or(WebauthnError::AttestationStatementSigMissing)?;

    let sig =
        cbor_try_bytes!(sig_value).map_err(|_| WebauthnError::AttestationStatementSigMissing)?;

    // https://github.com/duo-labs/webauthn/blob/master/protocol/attestation_u2f.go#L61
    let att_cert_array =
        cbor_try_array!(x5c).map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?;

    // Now it's a vec<Value>, get the first.
    if att_cert_array.len() != 1 {
        return Err(WebauthnError::AttestationStatementX5CInvalid);
    }

    let arr_x509 = att_cert_array
        .iter()
        .map(|att_cert_bytes| {
            cbor_try_bytes!(att_cert_bytes).and_then(|att_cert| {
                x509::X509::from_der(att_cert.as_slice()).map_err(WebauthnError::OpenSSLError)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Let certificate public key be the public key conveyed by att_cert.
    let cerificate_public_key = arr_x509
        .get(0)
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
    //
    // // try from asserts this condition given the alg.
    let alg = COSEAlgorithm::ES256;

    // Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
    //
    // Already extracted, and provided as args to this function.

    // Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).

    let credential_public_key = COSEKey::try_from(&acd.credential_pk)?;

    let public_key_u2f = credential_public_key.get_alg_key_ecc_x962_raw()?;

    // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
    let r: [u8; 1] = [0x00];
    let verification_data: Vec<u8> = r
        .iter()
        .chain(att_obj.auth_data.rp_id_hash.iter())
        .chain(client_data_hash.iter())
        .chain(acd.credential_id.0.iter())
        .chain(public_key_u2f.iter())
        .copied()
        .collect();

    // Verify the sig using verificationData and certificate public key per [SEC1].
    let verified = verify_signature(alg, cerificate_public_key, sig, &verification_data)?;

    if !verified {
        error!("signature verification failed!");
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }

    let attestation = ParsedAttestationData::Basic(arr_x509);
    // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.

    // If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.

    Ok(attestation)
}

// https://w3c.github.io/webauthn/#sctn-tpm-attestation
pub(crate) fn verify_tpm_attestation(
    acd: &AttestedCredentialData,
    att_obj: &AttestationObject<Registration>,
    client_data_hash: &[u8],
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    debug!("begin verify_tpm_attest");

    let att_stmt = &att_obj.att_stmt;
    let auth_data_bytes = &att_obj.auth_data_bytes;

    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR
    // decoding on it to extract the contained fields.
    let att_stmt_map =
        cbor_try_map!(att_stmt).map_err(|_| WebauthnError::AttestationStatementMapInvalid)?;

    // The version of the TPM specification to which the signature conforms.
    let ver_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("ver".to_string()))
        .ok_or(WebauthnError::AttestationStatementVerMissing)?;

    let ver =
        cbor_try_string!(ver_value).map_err(|_| WebauthnError::AttestationStatementVerInvalid)?;

    if ver != "2.0" {
        return Err(WebauthnError::AttestationStatementVerUnsupported);
    }

    // A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature.
    // String("alg"): I64(-65535),
    let alg_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("alg".to_string()))
        .ok_or(WebauthnError::AttestationStatementAlgMissing)?;

    let alg = cbor_try_i128!(alg_value)
        .map_err(|_| WebauthnError::AttestationStatementAlgInvalid)
        .and_then(|v| {
            COSEAlgorithm::try_from(v).map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)
        })?;

    // eprintln!("alg = {:?}", alg);

    // The TPMS_ATTEST structure over which the above signature was computed, as specified in [TPMv2-Part2] section 10.12.8.
    // String("certInfo"): Bytes([]),
    let certinfo_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("certInfo".to_string()))
        .ok_or(WebauthnError::AttestationStatementCertInfoMissing)?;

    let certinfo_bytes = cbor_try_bytes!(certinfo_value)
        .map_err(|_| WebauthnError::AttestationStatementCertInfoMissing)?;

    let certinfo = TpmsAttest::try_from(certinfo_bytes.as_slice())?;

    // eprintln!("certinfo -> {:?}", certinfo);

    // The TPMT_PUBLIC structure (see [TPMv2-Part2] section 12.2.4) used by the TPM to represent the credential public key.
    // String("pubArea"): Bytes([]),
    let pubarea_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("pubArea".to_string()))
        .ok_or(WebauthnError::AttestationStatementPubAreaMissing)?;

    let pubarea_bytes = cbor_try_bytes!(pubarea_value)
        .map_err(|_| WebauthnError::AttestationStatementPubAreaMissing)?;

    let pubarea = TpmtPublic::try_from(pubarea_bytes.as_slice())?;

    // eprintln!("pubarea -> {:?}", pubarea);

    // The attestation signature, in the form of a TPMT_SIGNATURE structure as specified in [TPMv2-Part2] section 11.3.4.
    // String("sig"): Bytes([]),
    let sig_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("sig".to_string()))
        .ok_or(WebauthnError::AttestationStatementSigMissing)?;

    let sig_bytes =
        cbor_try_bytes!(sig_value).map_err(|_| WebauthnError::AttestationStatementSigMissing)?;

    let sig = TpmtSignature::try_from(sig_bytes.as_slice())?;

    // eprintln!("sig -> {:?}", sig);

    // x5c -> aik_cert followed by its certificate chain, in X.509 encoding.
    // String("x5c"): Array( // root Bytes([]), // chain Bytes([])])
    let x5c_value = att_stmt_map
        .get(&serde_cbor_2::Value::Text("x5c".to_string()))
        .ok_or(WebauthnError::AttestationStatementX5CMissing)?;

    let x5c_array_ref =
        cbor_try_array!(x5c_value).map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?;

    let arr_x509: Result<Vec<_>, _> = x5c_array_ref
        .iter()
        .map(|values| {
            cbor_try_bytes!(values)
                .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)
                .and_then(|b| x509::X509::from_der(b).map_err(WebauthnError::OpenSSLError))
        })
        .collect();

    let arr_x509 = arr_x509?;

    // Must have at least one x509 cert
    let aik_cert = arr_x509
        .get(0)
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // Verify that the public key specified by the parameters and unique fields of pubArea is
    // identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
    let credential_public_key = COSEKey::try_from(&acd.credential_pk)?;

    // Check the algo is the same
    match (
        &credential_public_key.key,
        &pubarea.parameters,
        &pubarea.unique,
    ) {
        (
            COSEKeyType::RSA(cose_rsa),
            TpmuPublicParms::Rsa(_tpm_parms),
            TpmuPublicId::Rsa(tpm_modulus),
        ) => {
            // Is it possible to check the exponent? I think it's not ... as the tpm_parms and the
            // cose rse disagree in my test vectors.
            // cose_rsa.e != tpm_parms.exponent ||

            // check the pkey is the same.
            if cose_rsa.n.as_ref() != tpm_modulus {
                return Err(WebauthnError::AttestationTpmPubAreaMismatch);
            }
        }
        (
            COSEKeyType::EC_EC2(COSEEC2Key { curve, x, y }),
            TpmuPublicParms::Ecc(ecc_parms),
            TpmuPublicId::Ecc(ecc_points),
        ) => {
            match (curve, ecc_parms.curve_id) {
                (ECDSACurve::SECP256R1, TpmiEccCurve::NistP256)
                | (ECDSACurve::SECP384R1, TpmiEccCurve::NistP384)
                | (ECDSACurve::SECP521R1, TpmiEccCurve::NistP521) => {
                    // Ok!
                }
                c_mismatch => {
                    debug!(?c_mismatch, "TpmiEccCurve ID mismatch");
                    return Err(WebauthnError::AttestationTpmPubAreaMismatch);
                }
            }

            if x.0 != ecc_points.x || y.0 != ecc_points.y {
                debug!("Invalid X or Y coords in TpmuPublicId");
                return Err(WebauthnError::AttestationTpmPubAreaMismatch);
            }
        }
        ex => {
            debug!(?ex, "Unrecognised combination");
            return Err(WebauthnError::AttestationTpmPubAreaMismatch);
        }
    }

    // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
    let verification_data: Vec<u8> = auth_data_bytes
        .iter()
        .chain(client_data_hash.iter())
        .copied()
        .collect();

    // Validate that certInfo is valid:
    // Done in parsing.

    // Verify that magic is set to TPM_GENERATED_VALUE.
    // Done in parsing.

    // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
    if certinfo.type_ != TpmSt::AttestCertify {
        return Err(WebauthnError::AttestationTpmStInvalid);
    }

    let extra_data_hash = match certinfo.extra_data {
        Some(h) => h,
        None => return Err(WebauthnError::AttestationTpmExtraDataInvalid),
    };

    // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm
    // employed in "alg".
    let hash_verification_data = only_hash_from_type(alg, verification_data.as_slice())?;

    if hash_verification_data != extra_data_hash {
        return Err(WebauthnError::AttestationTpmExtraDataMismatch);
    }

    // verification_data

    // Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2]
    // section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the
    // algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
    // https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
    // https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    match certinfo.typeattested {
        TpmuAttest::AttestCertify(name, _qname) => {
            let name = match name {
                Tpm2bName::Digest(name) => name,
                _ => return Err(WebauthnError::AttestationTpmPubAreaHashInvalid),
            };
            // Name contains two bytes at the start for what algo is used. The spec
            // says nothing about validating them, so instead we prepend the bytes into the hash
            // so we do enforce these are checked
            let hname = match pubarea.name_alg {
                TpmAlgId::Sha256 => {
                    let mut v = vec![0, 11];
                    let r = compute_sha256(pubarea_bytes);
                    v.append(&mut r.to_vec());
                    v
                }
                _ => return Err(WebauthnError::AttestationTpmPubAreaHashUnknown),
            };
            if hname != name {
                return Err(WebauthnError::AttestationTpmPubAreaHashInvalid);
            }
        }
        _ => return Err(WebauthnError::AttestationTpmAttestCertifyInvalid),
    }

    // Verify that x5c is present.
    // done in parsing.

    // Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1]
    // section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields
    // MAY be used as an input to risk engines.
    // https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
    // for now, we ignore, but we could pass these into the attestation result.

    // Verify the sig is a valid signature over certInfo using the attestation public key in
    // aik_cert with the algorithm specified in alg.

    let sig_valid = match sig {
        TpmtSignature::RawSignature(dsig) => {
            // Alg was pre-loaded into the x509 struct during parsing
            // so we should just be able to verify
            verify_signature(alg, aik_cert, &dsig, certinfo_bytes)?
        }
    };

    // eprintln!("sig_valid -> {:?}", sig_valid);

    if !sig_valid {
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }

    // Verify that aik_cert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate
    // Requirements.
    assert_tpm_attest_req(aik_cert)?;

    // If aik_cert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid)
    // verify that the value of this extension matches the aaguid in authenticatorData.

    validate_extension::<FidoGenCeAaguid>(aik_cert, &acd.aaguid)?;

    // If successful, return implementation-specific values representing attestation type AttCA
    // and attestation trust path x5c.
    Ok((
        ParsedAttestationData::AttCa(arr_x509),
        AttestationMetadata::Tpm {
            aaguid: Uuid::from_bytes(acd.aaguid),
            firmware_version: certinfo.firmware_version,
        },
    ))
}

pub(crate) fn verify_apple_anonymous_attestation(
    acd: &AttestedCredentialData,
    att_obj: &AttestationObject<Registration>,
    client_data_hash: &[u8],
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    let att_stmt = &att_obj.att_stmt;
    let auth_data_bytes = &att_obj.auth_data_bytes;

    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    let att_stmt_map =
        cbor_try_map!(att_stmt).map_err(|_| WebauthnError::AttestationStatementMapInvalid)?;

    let x5c_key = &serde_cbor_2::Value::Text("x5c".to_string());

    let x5c_value = att_stmt_map
        .get(x5c_key)
        .ok_or(WebauthnError::AttestationStatementX5CMissing)?;

    let x5c_array_ref =
        cbor_try_array!(x5c_value).map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?;

    let credential_public_key = COSEKey::try_from(&acd.credential_pk)?;
    let alg = credential_public_key.type_;

    let arr_x509: Result<Vec<_>, _> = x5c_array_ref
        .iter()
        .map(|values| {
            cbor_try_bytes!(values)
                .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)
                .and_then(|b| x509::X509::from_der(b).map_err(WebauthnError::OpenSSLError))
        })
        .collect();

    let arr_x509 = arr_x509?;

    // Must have at least one cert
    let attestn_cert = arr_x509
        .first()
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // 2. Concatenate authenticatorData and clientDataHash to form nonceToHash.
    let nonce_to_hash: Vec<u8> = auth_data_bytes
        .iter()
        .chain(client_data_hash.iter())
        .copied()
        .collect();

    // 3. Perform SHA-256 hash of nonceToHash to produce nonce.
    let nonce = compute_sha256(&nonce_to_hash);

    // 4. Verify that nonce equals the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert. The nonce here is used to prove that the attestation is live and to protect the integrity of the authenticatorData and the client data.

    validate_extension::<AppleAnonymousNonce>(attestn_cert, &nonce)?;

    // 5. Verify credential public key matches the Subject Public Key of credCert.
    let subject_public_key = COSEKey::try_from((alg, attestn_cert))?;

    if credential_public_key != subject_public_key {
        return Err(WebauthnError::AttestationCredentialSubjectKeyMismatch);
    }

    // 6. If successful, return implementation-specific values representing attestation type Anonymous CA and attestation trust path x5c.
    Ok((
        ParsedAttestationData::AnonCa(arr_x509),
        AttestationMetadata::None,
    ))
}

/// <https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation>
pub(crate) fn verify_android_key_attestation(
    acd: &AttestedCredentialData,
    att_obj: &AttestationObject<Registration>,
    client_data_hash: &[u8],
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    let att_stmt = &att_obj.att_stmt;
    let auth_data_bytes = &att_obj.auth_data_bytes;

    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    let att_stmt_map =
        cbor_try_map!(att_stmt).map_err(|_| WebauthnError::AttestationStatementMapInvalid)?;

    let alg = {
        let alg_value = att_stmt_map
            .get(&serde_cbor_2::Value::Text("alg".to_string()))
            .ok_or(WebauthnError::AttestationStatementAlgMissing)?;

        cbor_try_i128!(alg_value)
            .map_err(|_| WebauthnError::AttestationStatementAlgInvalid)
            .and_then(|v| {
                COSEAlgorithm::try_from(v).map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)
            })?
    };

    let sig = {
        let sig_value = att_stmt_map
            .get(&serde_cbor_2::Value::Text("sig".to_string()))
            .ok_or(WebauthnError::AttestationStatementSigMissing)?;

        cbor_try_bytes!(sig_value).map_err(|_| WebauthnError::AttestationStatementSigMissing)?
    };

    let arr_x509 = {
        let x5c_key = &serde_cbor_2::Value::Text("x5c".to_string());

        let x5c_value = att_stmt_map
            .get(x5c_key)
            .ok_or(WebauthnError::AttestationStatementX5CMissing)?;

        let x5c_array_ref = cbor_try_array!(x5c_value)
            .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?;

        let arr_x509: Result<Vec<_>, _> = x5c_array_ref
            .iter()
            .map(|values| {
                cbor_try_bytes!(values)
                    .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)
                    .and_then(|b| x509::X509::from_der(b).map_err(WebauthnError::OpenSSLError))
            })
            .collect();

        arr_x509?
    };

    // Must have at least one cert
    let attestn_cert = arr_x509
        .first()
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // Concatenate authenticatorData and clientDataHash to form the data to verify.
    let data_to_verify: Vec<u8> = auth_data_bytes
        .iter()
        .chain(client_data_hash.iter())
        .copied()
        .collect();

    // 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg.

    let verified = verify_signature(alg, attestn_cert, sig, &data_to_verify)?;

    if !verified {
        error!("signature verification failed!");
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }

    // 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
    let credential_public_key = COSEKey::try_from(&acd.credential_pk)?;
    let subject_public_key = COSEKey::try_from((credential_public_key.type_, attestn_cert))?;

    if credential_public_key != subject_public_key {
        return Err(WebauthnError::AttestationCredentialSubjectKeyMismatch);
    }

    // 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
    // The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
    // For the following, use only the teeEnforced authorization list if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.

    // let pem = attestn_cert.to_pem()?;
    // dbg!(std::str::from_utf8(&pem).unwrap());

    let meta = validate_extension::<AndroidKeyAttestationExtensionData>(
        attestn_cert,
        &client_data_hash.to_vec(),
    )?;

    // arr_x509.iter().for_each(|c| {
    //     let pem = c.to_pem().unwrap();
    //     dbg!(std::str::from_utf8(&pem).unwrap());
    // });

    // 5. If successful, return implementation-specific values representing attestation type Anonymous CA and attestation trust path x5c.
    Ok((ParsedAttestationData::Basic(arr_x509), meta))
}

/// <https://www.w3.org/TR/webauthn/#sctn-android-safetynet-attestation>
pub(crate) fn verify_android_safetynet_attestation(
    _acd: &AttestedCredentialData,
    att_obj: &AttestationObject<Registration>,
    client_data_hash: &[u8],
    danger_ignore_timestamp: bool,
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    let att_stmt = &att_obj.att_stmt;
    let auth_data_bytes = &att_obj.auth_data_bytes;

    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    let att_stmt_map =
        cbor_try_map!(att_stmt).map_err(|_| WebauthnError::AttestationStatementMapInvalid)?;

    // there's only 1 version now
    let _ver = {
        let ver = att_stmt_map
            .get(&serde_cbor_2::Value::Text("ver".to_string()))
            .ok_or(WebauthnError::AttestationStatementVerMissing)?;

        cbor_try_string!(ver).map_err(|_| WebauthnError::AttestationStatementVerInvalid)?
    };

    let response = {
        let response = att_stmt_map
            .get(&serde_cbor_2::Value::Text("response".to_string()))
            .ok_or(WebauthnError::AttestationStatementResponseMissing)?;

        cbor_try_bytes!(response).map_err(|_| WebauthnError::AttestationStatementResponseMissing)?
    };

    // Concatenate authenticatorData and clientDataHash to form the data to verify.
    let data_to_verify: Vec<u8> = auth_data_bytes
        .iter()
        .chain(client_data_hash.iter())
        .copied()
        .collect();
    let data_to_verify = sha256(&data_to_verify);

    // 2. Verify that response is a valid SafetyNet response of version ver by following the steps
    // indicated by the SafetyNet online documentation. As of this writing, there is only one format
    // of the SafetyNet response and ver is reserved for future use.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SafteyNetAttestResponse {
        timestamp_ms: u64,
        nonce: Base64UrlSafeData,
        apk_package_name: String,
        apk_certificate_digest_sha256: Vec<Base64UrlSafeData>,
        cts_profile_match: bool,
        basic_integrity: bool,
        evaluation_type: Option<String>,
    }

    let response_str = std::str::from_utf8(response.as_slice())
        .map_err(|_| WebauthnError::AttestationStatementResponseInvalid)?;

    #[derive(Debug, thiserror::Error)]
    #[allow(missing_docs)]
    enum SafetyNetError {
        #[error("JWT error")]
        Jwt(#[from] compact_jwt::JwtError),

        #[error("No cert in chain")]
        MissingCertChain,

        #[error("Invalid Cert")]
        BadCert,

        #[error("Base64 error: {0}")]
        Base64(#[from] base64::DecodeError),

        #[error("openssl")]
        OpenSSL(#[from] openssl::error::ErrorStack),

        #[error("nonce mismatch")]
        NonceMismatch,

        #[error("hostname invalid")]
        InvalidHostname,

        #[error("False CTS Profile Match")]
        CtsProfileMatchFailed,

        #[error("Timestamp too old")]
        Expired,

        #[error("Time error: {0}")]
        Time(#[from] std::time::SystemTimeError),
    }

    let (x5c, safetynet_response) =
        |token: &str| -> Result<(Vec<x509::X509>, SafteyNetAttestResponse), SafetyNetError> {
            trace!(?token);
            use std::str::FromStr;
            let jwsu = compact_jwt::JwsUnverified::from_str(token)?;

            let certs = jwsu
                .get_x5c_chain()?
                .ok_or(SafetyNetError::MissingCertChain)?;

            let leaf_cert = certs.get(0).ok_or(SafetyNetError::BadCert)?;

            // Verify with the internal certificate.
            let jws: compact_jwt::Jws<SafteyNetAttestResponse> = jwsu.validate_embeded()?;

            let verified_claims = jws.into_inner();

            // 3. Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
            if verified_claims.nonce.0 != data_to_verify.to_vec() {
                return Err(SafetyNetError::NonceMismatch);
            }

            // 4. Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the SafetyNet online documentation.
            let common_name = {
                let name = leaf_cert
                    .subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .next()
                    .ok_or(SafetyNetError::InvalidHostname)?;
                name.data().as_utf8()?.to_string()
            };

            // §8.5.5 Verify that attestationCert is issued to the hostname "attest.android.com"
            if common_name.as_str() != "attest.android.com" {
                return Err(SafetyNetError::InvalidHostname);
            }

            // §8.5.6 Verify that the ctsProfileMatch attribute in the payload of response is true.
            if !verified_claims.cts_profile_match {
                return Err(SafetyNetError::CtsProfileMatchFailed);
            }

            // Verify sanity of timestamp in the payload
            if !danger_ignore_timestamp {
                let expires: std::time::Duration = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    + std::time::Duration::from_secs(60);
                if verified_claims.timestamp_ms as u128 > expires.as_millis() {
                    return Err(SafetyNetError::Expired);
                }
            }

            Ok((certs, verified_claims))
        }(response_str)
        .map_err(|e| {
            error!("jwt saftey-net error: {:?}", e);
            WebauthnError::AttestationStatementResponseInvalid
        })?;

    let SafteyNetAttestResponse {
        timestamp_ms: _,
        nonce: _,
        apk_package_name,
        apk_certificate_digest_sha256,
        cts_profile_match,
        basic_integrity,
        evaluation_type,
    } = safetynet_response;

    let metadata = AttestationMetadata::AndroidSafetyNet {
        apk_package_name,
        apk_certificate_digest_sha256,
        cts_profile_match,
        basic_integrity,
        evaluation_type,
    };

    // 5. If successful, return implementation-specific values representing attestation type Anonymous CA and attestation trust path x5c.
    Ok((ParsedAttestationData::Basic(x5c), metadata))
}

/// Verify the attestation chain
pub fn verify_attestation_ca_chain<'a>(
    att_data: &'_ ParsedAttestationData,
    ca_list: &'a AttestationCaList,
    danger_disable_certificate_time_checks: bool,
) -> Result<Option<&'a AttestationCa>, WebauthnError> {
    // If the ca_list is empty, Immediately fail since no valid attestation can be created.
    if ca_list.cas.is_empty() {
        return Err(WebauthnError::AttestationCertificateTrustStoreEmpty);
    }

    // Do we have a format we can actually check?
    let fullchain = match att_data {
        ParsedAttestationData::Basic(chain) => chain,
        ParsedAttestationData::AttCa(chain) => chain,
        ParsedAttestationData::AnonCa(chain) => chain,
        ParsedAttestationData::Self_ | ParsedAttestationData::None => {
            // nothing to check
            return Ok(None);
        }
        ParsedAttestationData::ECDAA | ParsedAttestationData::Uncertain => {
            return Err(WebauthnError::AttestationNotVerifiable);
        }
    };

    for crt in fullchain {
        debug!(?crt);
    }
    debug!(?ca_list);

    let (leaf, chain) = fullchain
        .split_first()
        .ok_or(WebauthnError::AttestationLeafCertMissing)?;

    // Convert the chain to a stackref so that openssl can use it.
    let mut chain_stack = stack::Stack::new().map_err(WebauthnError::OpenSSLError)?;

    for crt in chain.iter() {
        chain_stack
            .push(crt.clone())
            .map_err(WebauthnError::OpenSSLError)?;
    }

    // Create the x509 store that we will validate against.
    let mut ca_store = store::X509StoreBuilder::new().map_err(WebauthnError::OpenSSLError)?;

    // In tests we may need to allow disabling time window validity.
    if danger_disable_certificate_time_checks {
        ca_store
            .set_flags(verify::X509VerifyFlags::NO_CHECK_TIME)
            .map_err(WebauthnError::OpenSSLError)?;
    }

    for ca_crt in ca_list.cas.values() {
        ca_store
            .add_cert(ca_crt.ca.clone())
            .map_err(WebauthnError::OpenSSLError)?;
    }

    let ca_store = ca_store.build();

    let mut ca_ctx = x509::X509StoreContext::new().map_err(WebauthnError::OpenSSLError)?;

    // Providing the cert and chain, validate we have a ref to our store.
    // Note this is a result<result ... because the inner .init must return an errorstack
    // for openssl.
    let res: Result<_, _> = ca_ctx
        .init(&ca_store, leaf, &chain_stack, |ca_ctx_ref| {
            ca_ctx_ref.verify_cert().map(|_| {
                // The value as passed in is a boolean that we ignore in favour of the richer error type.
                let res = ca_ctx_ref.error();
                debug!("{:?}", res);
                if res == x509::X509VerifyResult::OK {
                    ca_ctx_ref
                        .chain()
                        .and_then(|chain| {
                            // If there is a chain here, we get the root.
                            let idx = chain.len() - 1;
                            chain.get(idx)
                        })
                        .and_then(|ca_cert| {
                            // If we got it from the stack, we can now digest it.
                            ca_cert.digest(MessageDigest::sha256()).ok()
                            // We let the digest bubble out now, we've done too much here
                            // already!
                        })
                        .ok_or(WebauthnError::AttestationTrustFailure)
                } else {
                    debug!(
                        "ca_ctx_ref verify cert - error depth={}, sn={:?}",
                        ca_ctx_ref.error_depth(),
                        ca_ctx_ref.current_cert().map(|crt| crt.subject_name())
                    );
                    Err(WebauthnError::AttestationChainNotTrusted(res.to_string()))
                }
            })
        })
        .map_err(|e| {
            // If an openssl error occured, dump it here.
            error!(?e);
            e
        })?;

    // Now we have a result<DigestOfCaUsed, Error> and we want to attach our related
    // attestation CA.
    res.and_then(|dgst| {
        ca_list
            .cas
            .get(dgst.as_ref())
            .ok_or_else(|| {
                WebauthnError::AttestationChainNotTrusted("Invalid CA digest maps".to_string())
            })
            // We need to wrap in an extra Some here to indicate to the caller that we
            // did use a CA compare to the Ok(None) case.
            .map(Some)
    })
}
