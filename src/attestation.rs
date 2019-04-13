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

pub(crate) fn verify_fidou2f_attestation(
    attStmt: &serde_cbor::Value,
    acd: &AttestedCredentialData,
    authDataBytes: &Vec<u8>,
    client_data_hash: &Vec<u8>,
) -> Result<AttestationType, WebauthnError> {
    // Given the verification procedure inputs attStmt, authenticatorData and clientDataHash, the verification procedure is as follows:

    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    // ^-- This is already DONE as a factor of serde_cbor not erroring up to this point,
    // and those errors will be handled better than just "unwrap" :)
    // we'll also find out quickly when we attempt to access the data as a map ...

    println!("attStmt: {:?}", attStmt);
    println!("attest_fmt: fido-u2f");

    let attStmtMap = match attStmt.as_object() {
        Some(m) => m,
        None => {
            return Err(WebauthnError::AttestationStatementMapInvalid);
        }
    };

    // If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
    let x5c = attStmtMap.get(&serde_cbor::ObjectKey::String("x5c".to_string()));
    if x5c.is_some() {
        // This is safe since we already did the is_some.
        let x5ci = x5c.unwrap();
        println!("x5ci: {:?}", x5ci);

        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
        // sig is from m
        let sig = match attStmtMap.get(&serde_cbor::ObjectKey::String("sig".to_string())) {
            Some(s) => s,
            None => {
                return Err(WebauthnError::AttestationStatementSigMissing);
            }
        };
        println!("sig: {:?}", sig);
        let concat: Vec<u8> = authDataBytes
            .iter()
            .chain(client_data_hash.iter())
            .map(|b| *b)
            .collect();

        match crypto::verify_attestation_sig(acd, &concat) {
            Ok(_) => {}
            Err(e) => {
                return Err(WebauthnError::AttestationStatementSigInvalid);
            }
        };

        //     Extract leaf cert from “x5c” as attCert
        // TODO: Where is attestnCert in the various structures we have?
        // It's the big bytes blob it seems ...

        // Verify that attestnCert meets the requirements in §8.2.1 Packed Attestation Statement Certificate Requirements.
        // Check that attCert is of version 3(ASN1 INT 2)
        // Check that attCert subject country (C) is set to a valid two character ISO 3166 code
        // Check that attCert subject organisation (O) is not empty
        // Check that attCert subject organisation unit (OU) is set to literal string “Authenticator Attestation”
        // Check that attCert subject common name(CN) is not empty.
        // Check that attCert basic constraints for CA is set to FALSE
        // If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, then check that its value set to the AAGUID returned by the authenticator in authData.
        // Verify signature “sig” over the signatureBase with the public key extracted from leaf attCert in “x5c”, using the algorithm “alg”

        // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.

        // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.

        // If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
        // return Ok(AttStmtType::X5C);
        unimplemented!();
    }

    // If ecdaaKeyId is present, then the attestation type is ECDAA. In this case:

    // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).

    // If successful, return implementation-specific values representing attestation type ECDAA and attestation trust path ecdaaKeyId.

    // If neither x5c nor ecdaaKeyId is present, self attestation is in use.

    // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.

    // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.

    // If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.
    unimplemented!();
}
