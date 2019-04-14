use std::convert::TryFrom;

use super::crypto;
use super::error::*;
use super::proto::*;

#[derive(Debug)]
pub enum AttestationFormat {
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
            _ => Err(WebauthnError::InvalidAttestationFormat),
        }
    }
}

#[derive(Debug)]
pub enum AttestationType {
    Basic,
    Self_,
    AttCa,
    ECDAA,
    None,
    Uncertain,
}

// Needs to take a struct
pub enum AttStmtType {
    X5C,
}

// https://w3c.github.io/webauthn/#fido-u2f-attestation
// https://medium.com/@herrjemand/verifying-fido-u2f-attestations-in-fido2-f83fab80c355
pub(crate) fn verify_fidou2f_attestation(
    attStmt: &serde_cbor::Value,
    acd: &AttestedCredentialData,
    authDataBytes: &Vec<u8>,
    client_data_hash: &Vec<u8>,
    rp_id_hash: &Vec<u8>,
) -> Result<AttestationType, WebauthnError> {
    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    //
    // ^-- This is already DONE as a factor of serde_cbor not erroring up to this point,
    // and those errors will be handled better than just "unwrap" :)
    // we'll also find out quickly when we attempt to access the data as a map ...


    // TODO: https://github.com/duo-labs/webauthn/blob/master/protocol/attestation_u2f.go#L22
    // Apparently, aaguid must be 0x00

    // Check that x5c has exactly one element and let attCert be that element.
    let attStmtMap = attStmt
        .as_object()
        .ok_or(WebauthnError::AttestationStatementMapInvalid)?;
    let x5c = attStmtMap
        .get(&serde_cbor::ObjectKey::String("x5c".to_string()))
        .ok_or(WebauthnError::AttestationStatementX5CMissing)?;

    let sig_value = attStmtMap
        .get(&serde_cbor::ObjectKey::String("sig".to_string()))
        .ok_or(WebauthnError::AttestationStatementSigMissing)?;

    let sig = sig_value
        .as_bytes()
        .ok_or(WebauthnError::AttestationStatementSigMissing)?;

    // https://github.com/duo-labs/webauthn/blob/master/protocol/attestation_u2f.go#L61
    let attCertArray = x5c.as_array()
        // Option<Vec<Value>>
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;
        // Now it's a vec<Value>, get the first.
    if attCertArray.len() != 1 {
        return Err(WebauthnError::AttestationStatementX5CInvalid)
    }

    let attCert = attCertArray.first()
        // Now it's an Option<Value>
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // This is the certificate public key.
    // Let certificate public key be the public key conveyed by attCert.
    let certPublicKey = attCert
        .as_bytes()
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;

    // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
    //
    // Now, the standard is not super clear here about this, and what format these bytes are in.
    // I am assuming for now it's x509 DER.

    let ec_cpk = crypto::bytes_to_x509_public_key(&certPublicKey)?;

    // Check the types to make sure it's ec p256.

    if !(ec_cpk.is_secp256r1()?) {
        return Err(WebauthnError::CertificatePublicKeyInvalid);
    }

    // Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
    //
    // Already extracted, and provided as args to this function.

    // Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).

    let credential_pk_cose = crypto::COSEKey::try_from(&acd.credential_pk)?;

    let credential_pk_u2f = credential_pk_cose.get_ALG_KEY_ECC_X962_RAW()?;

    // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
    let r: [u8; 1] = [0x00];
    let verificationData: Vec<u8> = r
        .iter()
        .chain(rp_id_hash.iter())
        .chain(client_data_hash.iter())
        .chain(acd.credential_id.iter())
        .chain(credential_pk_u2f.iter())
        .map(|b| *b)
        .collect();

    println!("{:?}", verificationData);

    // Verify the sig using verificationData and certificate public key per [SEC1].
    let verified = crypto::x509_verify_signature(&ec_cpk, &sig, &verificationData)?;

    if !verified {
        println!("signature verification failed!");
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }

    // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.

    // If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
    Ok(AttestationType::Uncertain)
}
