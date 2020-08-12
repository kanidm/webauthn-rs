//! Attestation information and verifications procedures.
//! This contains a transparent type allowing callbacks to
//! make attestation decisions. See the WebauthnConfig trait
//! for more details.

use std::convert::TryFrom;

use crate::crypto;
use crate::crypto::COSEContentType;
use crate::error::WebauthnError;
use crate::proto::{AttestedCredentialData, Credential};
use log::debug;
use serde_cbor::{ObjectKey, Value};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(crate) enum AttestationFormat {
    Packed,
    TPM,
    AndroidKey,
    AndroidSafetyNet,
    FIDOU2F,
    None,
}

impl TryFrom<&str> for AttestationFormat {
    type Error = WebauthnError;

    fn try_from(a: &str) -> Result<AttestationFormat, Self::Error> {
        match a {
            "packed" => Ok(AttestationFormat::Packed),
            "tpm" => Ok(AttestationFormat::TPM),
            "android-key" => Ok(AttestationFormat::AndroidKey),
            "android-safetynet" => Ok(AttestationFormat::AndroidSafetyNet),
            "fido-u2f" => Ok(AttestationFormat::FIDOU2F),
            "none" => Ok(AttestationFormat::None),
            _ => Err(WebauthnError::AttestationNotSupported),
        }
    }
}

/// The type of Attestation that the Authenticator is providing.
#[derive(Debug)]
pub enum AttestationType {
    /// The credential is authenticated by a signing X509 Certificate
    /// from a vendor or provider.
    Basic(Credential, crypto::X509PublicKey),
    /// The credential is authenticated using surrogate basic attestation
    /// it uses the credential private key to create the attestation signature
    Self_(Credential),
    /// The credential is authenticated using a CA, and may provide a
    /// ca chain to validate to it's root.
    AttCa(
        Credential,
        crypto::X509PublicKey,
        Vec<crypto::X509PublicKey>,
    ),
    /// Unimplemented
    ECDAA,
    /// No Attestation type was provided with this Credential. If in doubt
    /// reject this Credential.
    None(Credential),
    /// Uncertain Attestation was provided with this Credential, which may not
    /// be trustworthy in all cases. If in doubt, reject this type.
    Uncertain(Credential),
}

// Check that alg from att_stmt_map matches alg_from_auhenticator_data
fn is_matching_agorithm(
    att_stmt_map: &BTreeMap<ObjectKey, Value>,
    alg_from_auhenticator_data: &COSEContentType,
) -> bool {
    att_stmt_map
        .get(&serde_cbor::ObjectKey::String("alg".to_string()))
        .and_then(|alg| alg.as_i64())
        .map(|alg| alg == i64::from(alg_from_auhenticator_data))
        .unwrap_or(false)
}

// Perform the Verification procedure for 8.2. Packed Attestation Statement Format
// https://w3c.github.io/webauthn/#sctn-packed-attestation
pub(crate) fn verify_packed_attestation(
    att_stmt: &serde_cbor::Value,
    acd: &AttestedCredentialData,
    auth_data_bytes: Vec<u8>,
    client_data_hash: &Vec<u8>,
    counter: u32,
) -> Result<AttestationType, WebauthnError> {
    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields
    let att_stmt_map = att_stmt
        .as_object()
        .ok_or(WebauthnError::AttestationStatementMapInvalid)?;

    let x5c_key = &serde_cbor::ObjectKey::String("x5c".to_string());
    let ecdaa_key_id_key = &serde_cbor::ObjectKey::String("ecdaaKeyId".to_string());
    match (
        att_stmt_map.get(x5c_key),
        att_stmt_map.get(ecdaa_key_id_key),
    ) {
        (Some(x5c), _) => {
            debug!("x5c");
            let credential_public_key = crypto::COSEKey::try_from(&acd.credential_pk)?;
            // 2. If x5c is present, this indicates that the attestation type is not ECDAA.

            // The elements of this array contain attestnCert and its certificate chain, each
            // encoded in X.509 format. The attestation certificate attestnCert MUST be the first
            // element in the array.
            // x5c: [ attestnCert: bytes, * (caCert: bytes) ]
            let x5c_array_ref = x5c
                .as_array()
                .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

            let arr_x509: Result<Vec<_>, _> = x5c_array_ref
                .iter()
                .map(|values| {
                    values
                        .as_bytes()
                        .ok_or(WebauthnError::AttestationStatementX5CInvalid)
                        .and_then(|b| crypto::X509PublicKey::try_from(b.as_slice()))
                })
                .collect();

            let mut arr_x509 = arr_x509?;

            // Must have at least one x509 cert
            if arr_x509.len() == 0 {
                return Err(WebauthnError::AttestationStatementX5CInvalid);
            }

            let attestn_cert = arr_x509.remove(0);

            // Verify that sig is a valid signature over the concatenation of authenticatorData
            // and clientDataHash using the attestation public key in attestnCert with the
            // algorithm specified in alg.

            let verification_data: Vec<u8> = auth_data_bytes
                .iter()
                .chain(client_data_hash.iter())
                .map(|b| *b)
                .collect();
            let is_valid_signature = att_stmt_map
                .get(&serde_cbor::ObjectKey::String("sig".to_string()))
                .and_then(|s| s.as_bytes())
                .ok_or(WebauthnError::AttestationStatementSigMissing)
                .and_then(|sig| attestn_cert.verify_signature(&sig, &verification_data))?;
            if !is_valid_signature {
                return Err(WebauthnError::AttestationStatementSigInvalid);
            }

            // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation
            // Statement Certificate Requirements.
            // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements

            attestn_cert.assert_packed_attest_req()?;

            // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
            // (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid
            // in authenticatorData.

            if let Some(aaguid) = attestn_cert.get_fido_gen_ce_aaguid() {
                if acd.aaguid != aaguid {
                    return Err(WebauthnError::AttestationCertificateAAGUIDMismatch);
                }
            }

            // Optionally, inspect x5c and consult externally provided knowledge to determine
            // whether attStmt conveys a Basic or AttCA attestation.
            // TODO: I'm not clear on this ....

            // If successful, return implementation-specific values representing attestation type
            // Basic, AttCA or uncertainty, and attestation trust path x5c.

            Ok(AttestationType::Basic(
                Credential::new(acd, credential_public_key, counter),
                attestn_cert,
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
            let credential_public_key = crypto::COSEKey::try_from(&acd.credential_pk)?;

            // 4.a. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            if !is_matching_agorithm(att_stmt_map, &credential_public_key.type_) {
                return Err(WebauthnError::AttestationStatementAlgMismatch);
            }

            // 4.b. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
            let verification_data: Vec<u8> = auth_data_bytes
                .iter()
                .chain(client_data_hash.iter())
                .map(|b| *b)
                .collect();
            let is_valid_signature = att_stmt_map
                .get(&serde_cbor::ObjectKey::String("sig".to_string()))
                .and_then(|s| s.as_bytes())
                .ok_or(WebauthnError::AttestationStatementSigMissing)
                .and_then(|sig| credential_public_key.verify_signature(&sig, &verification_data))?;
            if !is_valid_signature {
                return Err(WebauthnError::AttestationStatementSigInvalid);
            }

            // 4.c. If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.
            Ok(AttestationType::Self_(Credential::new(
                acd,
                credential_public_key,
                counter,
            )))
        }
    }
}

// https://w3c.github.io/webauthn/#fido-u2f-attestation
// https://medium.com/@herrjemand/verifying-fido-u2f-attestations-in-fido2-f83fab80c355
pub(crate) fn verify_fidou2f_attestation(
    att_stmt: &serde_cbor::Value,
    acd: &AttestedCredentialData,
    // authDataBytes: &Vec<u8>,
    client_data_hash: &Vec<u8>,
    rp_id_hash: &Vec<u8>,
    counter: u32,
) -> Result<AttestationType, WebauthnError> {
    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    //
    // ^-- This is already DONE as a factor of serde_cbor not erroring up to this point,
    // and those errors will be handled better than just "unwrap" :)
    // we'll also find out quickly when we attempt to access the data as a map ...

    // TODO: https://github.com/duo-labs/webauthn/blob/master/protocol/attestation_u2f.go#L22
    // Apparently, aaguid must be 0x00

    // Check that x5c has exactly one element and let att_cert be that element.
    let att_stmt_map = att_stmt
        .as_object()
        .ok_or(WebauthnError::AttestationStatementMapInvalid)?;
    let x5c = att_stmt_map
        .get(&serde_cbor::ObjectKey::String("x5c".to_string()))
        .ok_or(WebauthnError::AttestationStatementX5CMissing)?;

    let sig_value = att_stmt_map
        .get(&serde_cbor::ObjectKey::String("sig".to_string()))
        .ok_or(WebauthnError::AttestationStatementSigMissing)?;

    let sig = sig_value
        .as_bytes()
        .ok_or(WebauthnError::AttestationStatementSigMissing)?;

    // https://github.com/duo-labs/webauthn/blob/master/protocol/attestation_u2f.go#L61
    let att_cert_array = x5c
        .as_array()
        // Option<Vec<Value>>
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;
    // Now it's a vec<Value>, get the first.
    if att_cert_array.len() != 1 {
        return Err(WebauthnError::AttestationStatementX5CInvalid);
    }

    let att_cert_bytes = att_cert_array
        .first()
        // Now it's an Option<Value>
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // This is the certificate public key.
    // Let certificate public key be the public key conveyed by att_cert.
    let att_cert = att_cert_bytes
        .as_bytes()
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
    //
    // Now, the standard is not super clear here about this, and what format these bytes are in.
    // I am assuming for now it's x509 DER.

    let cerificate_public_key = crypto::X509PublicKey::try_from(att_cert.as_slice())?;

    // Check the types to make sure it's ec p256.

    if !(cerificate_public_key.is_secp256r1()?) {
        return Err(WebauthnError::CertificatePublicKeyInvalid);
    }

    // Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
    //
    // Already extracted, and provided as args to this function.

    // Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).

    let credential_public_key = crypto::COSEKey::try_from(&acd.credential_pk)?;

    let public_key_u2f = credential_public_key.get_alg_key_ecc_x962_raw()?;

    // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
    let r: [u8; 1] = [0x00];
    let verification_data: Vec<u8> = (&r)
        .iter()
        .chain(rp_id_hash.iter())
        .chain(client_data_hash.iter())
        .chain(acd.credential_id.iter())
        .chain(public_key_u2f.iter())
        .map(|b| *b)
        .collect();

    // Verify the sig using verificationData and certificate public key per [SEC1].
    let verified = cerificate_public_key.verify_signature(&sig, &verification_data)?;

    if !verified {
        log::error!("signature verification failed!");
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }

    let credential = Credential::new(acd, credential_public_key, counter);

    // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.

    // If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.

    Ok(AttestationType::Basic(credential, cerificate_public_key))
}

// https://www.w3.org/TR/webauthn/#none-attestation
pub(crate) fn verify_none_attestation(
    // att_stmt: &serde_cbor::Value,
    acd: &AttestedCredentialData,
    counter: u32,
) -> Result<AttestationType, WebauthnError> {
    // No attestation is performed, simply provide a credential.
    let credential_public_key = crypto::COSEKey::try_from(&acd.credential_pk)?;
    let credential = Credential::new(acd, credential_public_key, counter);
    Ok(AttestationType::None(credential))
}
