use crate::attestation::verify_attestation_ca_chain;
use crate::crypto::compute_sha256;
use crate::internals::AuthenticatorData;
use crate::proto::COSEKey;
use crate::proto::ExtnState;
use crate::proto::RegisteredExtensions;
use crate::proto::Registration;
use crate::proto::{AttestationCa, AttestationCaList};
use uuid::Uuid;

use nom::bytes::complete::{tag, take};
use nom::number::complete::be_u32;

use crate::crypto::verify_signature;
use openssl::{bn, ec, nid, x509};

use crate::error::WebauthnError;

use crate::proto::{
    AttestationMetadata, AttestedPublicKey, COSEAlgorithm, COSEKeyType, ParsedAttestation,
    ParsedAttestationData,
};

use sshkeys::{Curve, EcdsaPublicKey, KeyType, KeyTypeKind, PublicKey, PublicKeyKind};

use crate::attestation::AttestationFormat;
use crate::attestation::{validate_extension, FidoGenCeAaguid};
use crate::crypto::assert_packed_attest_req;

pub fn verify_fido_sk_ssh_attestation(
    attestation: &[u8],
    challenge: &[u8],
    attestation_cas: &AttestationCaList,
    danger_disable_certificate_time_checks: bool,
) -> Result<AttestedPublicKey, WebauthnError> {
    if attestation_cas.is_empty() {
        return Err(WebauthnError::MissingAttestationCaList);
    }

    let alg = COSEAlgorithm::ES256;

    // There doesn't seem to be much in the way of docs about the format of
    // the ssh attestation binary, but reading the source, we see it is setup
    // per: https://github.com/openssh/openssh-portable/blob/master/ssh-sk.c#L436

    let ssh_sk_attest = SshSkAttestation::try_from(attestation)?;

    let acd = ssh_sk_attest
        .auth_data
        .acd
        .as_ref()
        .ok_or(WebauthnError::MissingAttestationCredentialData)?;

    let attestation_format = AttestationFormat::Packed;

    // Ssh simply uses the challenge as the client data hash.
    let client_data_hash = compute_sha256(challenge);

    trace!(?ssh_sk_attest);

    let verification_data: Vec<u8> = ssh_sk_attest
        .auth_data_bytes
        .iter()
        .chain(client_data_hash.iter())
        .copied()
        .collect();

    let is_valid_signature = verify_signature(
        alg,
        &ssh_sk_attest.att_cert,
        &ssh_sk_attest.sig,
        &verification_data,
    )?;

    if !is_valid_signature {
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }

    // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation
    // Statement Certificate Requirements.
    // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements

    assert_packed_attest_req(&ssh_sk_attest.att_cert)?;

    // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
    // (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid
    // in authenticatorData.

    validate_extension::<FidoGenCeAaguid>(&ssh_sk_attest.att_cert, &acd.aaguid)?;

    // In the future if ssh changes their attest format we can provide the full chain here.
    let att_x509 = vec![ssh_sk_attest.att_cert.clone()];

    let attestation = ParsedAttestation {
        data: ParsedAttestationData::Basic(att_x509),
        metadata: AttestationMetadata::Packed {
            aaguid: Uuid::from_bytes(acd.aaguid),
        },
    };

    let ca_crt = verify_attestation_ca_chain(
        &attestation.data,
        attestation_cas,
        danger_disable_certificate_time_checks,
    )?;

    // It may seem odd to unwrap the option and make this not verified at this point,
    // but in this case because we have the ca_list and none was the result (which happens)
    // in some cases, we need to map that through. But we need verify_attesation_ca_chain
    // to still return these option types due to re-attestation in the future.
    let ca_crt = ca_crt.ok_or(WebauthnError::AttestationNotVerifiable)?;

    match &attestation.metadata {
        AttestationMetadata::Packed { aaguid } | AttestationMetadata::Tpm { aaguid, .. } => {
            // If not present, fail.
            if !ca_crt.aaguids.contains(aaguid) {
                trace!(?aaguid, "aaguid not trust by this CA");
                return Err(WebauthnError::AttestationUntrustedAaguid);
            }
        }
        _ => {
            // Fail
            trace!("this attestation format does not contain an aaguid and can not proceed");
            return Err(WebauthnError::AttestationFormatMissingAaguid);
        }
    };

    let cred_protect = match ssh_sk_attest.auth_data.extensions.cred_protect.as_ref() {
        Some(credprotect) => ExtnState::Set(credprotect.0),
        None => ExtnState::NotRequested,
    };

    let extensions = RegisteredExtensions {
        cred_protect,
        ..Default::default()
    };

    // Assert that backup eligible and state are both false.

    if ssh_sk_attest.auth_data.backup_eligible || ssh_sk_attest.auth_data.backup_state {
        error!("Fido ssh sk keys may not be backed up or backup eligible");
        return Err(WebauthnError::SshPublicKeyBackupState);
    }

    // If attestation passes, extract the public key from the attestation.
    //
    // https://github.com/openssh/openssh-portable/blob/c46f6fed419167c1671e4227459e108036c760f8/ssh-sk.c#L291
    let ck = COSEKey::try_from(&acd.credential_pk)?;
    trace!(?ck);

    let pubkey = ck.to_ssh_pubkey()?;
    let user_verified = ssh_sk_attest.auth_data.user_verified;

    Ok(AttestedPublicKey {
        pubkey,
        user_verified,
        extensions,
        attestation,
        attestation_format,
    })
}

#[derive(Debug)]
struct SshSkAttestation {
    att_cert: x509::X509,
    sig: Vec<u8>,
    auth_data_bytes: Vec<u8>,
    auth_data: AuthenticatorData<Registration>,
}

struct SshSkAttestationRaw<'a> {
    // This is the x5c cbor per https://developers.yubico.com/libfido2/Manuals/fido_cred_x5c_ptr.html
    att_cert_raw: &'a [u8],
    // Likely a cbor slice?
    sig_raw: &'a [u8],
    // cbor auth data. Could just be serde slice?
    auth_data_raw: &'a [u8],
}

impl TryFrom<&[u8]> for SshSkAttestation {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<SshSkAttestation, WebauthnError> {
        let sk_raw = ssh_sk_attestation_parser(data)
            .map_err(|e| {
                error!(?e, "try_from ssh_sk_attestation_parser");
                WebauthnError::ParseNOMFailure
            })
            // Discard the remaining bytes.
            .map(|(_, ad)| ad)?;

        // Convert raw fields to parsed ones.

        let sig = sk_raw.sig_raw.to_vec();

        let att_cert =
            x509::X509::from_der(sk_raw.att_cert_raw).map_err(WebauthnError::OpenSSLError)?;

        let auth_data_bytes = serde_cbor::from_slice(sk_raw.auth_data_raw)
            .map_err(|e| {
                error!(?e, "invalid auth data cbor");
                WebauthnError::ParseNOMFailure
            })
            .and_then(|value| cbor_try_bytes!(value))?;

        let auth_data: AuthenticatorData<Registration> =
            AuthenticatorData::try_from(auth_data_bytes.as_slice()).map_err(|e| {
                error!(?e, "invalid auth data structure");
                WebauthnError::ParseNOMFailure
            })?;

        Ok(SshSkAttestation {
            att_cert,
            sig,
            // Probably need auth_data raw.
            auth_data_bytes,
            auth_data,
        })
    }
}

fn ssh_sk_attestation_parser(i: &[u8]) -> nom::IResult<&[u8], SshSkAttestationRaw> {
    // Starts with a 4 byte u32 for the len of the header.

    let (i, _tag_len) = tag([0, 0, 0, 17])(i)?;
    let (i, _tag) = tag("ssh-sk-attest-v01")(i)?;

    let (i, att_cert_len) = be_u32(i)?;
    let (i, att_cert_raw) = take(att_cert_len as usize)(i)?;

    let (i, sig_len) = be_u32(i)?;
    let (i, sig_raw) = take(sig_len as usize)(i)?;

    let (i, auth_data_len) = be_u32(i)?;
    let (i, auth_data_raw) = take(auth_data_len as usize)(i)?;

    let (i, _resvd_flags) = be_u32(i)?;
    let (i, _resvd) = be_u32(i)?;

    Ok((
        i,
        SshSkAttestationRaw {
            att_cert_raw,
            sig_raw,
            auth_data_raw,
        },
    ))
}

impl COSEKey {
    pub(crate) fn to_ssh_pubkey(&self) -> Result<PublicKey, WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(_ec2k) => {
                let pubkey = self.get_openssl_pkey()?;
                let key = pubkey
                    .ec_key()
                    .and_then(|ec| {
                        let mut ctx = bn::BigNumContext::new()?;
                        let c_nid = nid::Nid::X9_62_PRIME256V1; // NIST P-256 curve
                        let group = ec::EcGroup::from_curve_name(c_nid)?;

                        ec.public_key().to_bytes(
                            &group,
                            ec::PointConversionForm::UNCOMPRESSED,
                            &mut ctx,
                        )
                    })
                    .map_err(WebauthnError::OpenSSLError)?;

                let kind = PublicKeyKind::Ecdsa(EcdsaPublicKey {
                    curve: Curve::from_identifier("nistp256").map_err(|_| {
                        error!("Invalid curve identifier");
                        WebauthnError::SshPublicKeyInvalidCurve
                    })?,
                    key,
                    sk_application: Some("ssh:".to_string()),
                });

                Ok(PublicKey {
                    key_type: KeyType {
                        name: "sk-ecdsa-sha2-nistp256@openssh.com",
                        short_name: "ECDSA-SK",
                        is_cert: false,
                        is_sk: true,
                        kind: KeyTypeKind::EcdsaSk,
                        plain: "sk-ecdsa-sha2-nistp256@openssh.com",
                    },
                    kind,
                    comment: None,
                })
            }
            _ => {
                debug!("to_ssh_pubkey");
                Err(WebauthnError::SshPublicKeyInvalidType)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::verify_fido_sk_ssh_attestation;
    use crate::proto::{AttestationCa, AttestationCaList};
    use base64urlsafedata::Base64UrlSafeData;

    #[test]
    fn test_ssh_ecdsa_sk_attest() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create with:
        //  dd if=/dev/urandom of=/Users/william/.ssh/id_ecdsa_sk.chal bs=16 count=1
        //  ssh-keygen -t ecdsa-sk -O challenge=/Users/william/.ssh/id_ecdsa_sk.chal -O write-attestation=/Users/william/.ssh/id_ecdsa_sk.attest -f /Users/william/.ssh/id_ecdsa_sk

        let attest = Base64UrlSafeData::try_from("AAAAEXNzaC1zay1hdHRlc3QtdjAxAAACwTCCAr0wggGloAMCAQICBBisRsAwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDQxMzk0MzQ4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHnqOyx8SXAQYiMM0j/rYOUpMXHUg/EAvoWdaw+DlwMBtUbN1G7PyuPj8w+B6e1ivSaNTB69N7O8vpKowq7rTjqjbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEMtpSB6P90A5k+wKJymhVKgwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAl50Dl9hg+C7hXTEceW66+yL6p+CE2bq0xhu7V/PmtMGKSDe4XDxO2+SDQ/TWpdmxztqK4f7UkSkhcwWOXuHL3WvawHVXxqDo02gluhWef7WtjNr4BIaM+Q6PH4rqF8AWtVwqetSXyJT7cddT15uaSEtsN21yO5mNLh1DBr8QM7Wu+Myly7JWi2kkIm0io1irfYfkrF8uCRqnFXnzpWkJSX1y9U4GusHDtEE7ul6vlMO2TzT566Qay2rig3dtNkZTeEj+6IS93fWxuleYVM/9zrrDRAWVJ+Vt1Zj49WZxWr5DAd0ZETDmufDGQDkSU+IpgD867ydL7b/eP8u9QurWeQAAAEYwRAIgeYp6mYVsuaj0NpHps1qkGkJYroyurnuCKdSYWUCCsVgCIAhFdmhNWGG0cY5l3sZUhjmrwCHpuQ1A0QXbhuEtjM7sAAAAxljE4wYQ6KFiEVlg/h7CI+ZSnJ9LboAgDcteXDIcivHisb9FAAALNMtpSB6P90A5k+wKJymhVKgAQPQVE6m4sayalwAfqHVZBGEP32y5ju2Vo7U3k1zPFKQGLDhpA0dRHWvYbsvTPmqVzSGuxSyRW/ugWzPqsveALlSlAQIDJiABIVggQ25tmKStvyG74d5VF1nSmn9UCTaq/gkNu4mG8PTI11YiWCAMvZ7dwFsRGIN40+RbHnxDitWfGRtXV9rwTbBpG1P3XAAAAAAAAAAA")
            .expect("Failed to decode attestation");

        let challenge = Base64UrlSafeData::try_from("VzCkpMNVYVgXHBuDP74v9A==")
            .expect("Failed to decode attestation");

        let pubkey = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBENubZikrb8hu+HeVRdZ0pp/VAk2qv4JDbuJhvD0yNdWDL2e3cBbERiDeNPkWx58Q4rVnxkbV1fa8E2waRtT91wAAAAEc3NoOg== william@maxixe.dev.blackhats.net.au";
        let mut key = sshkeys::PublicKey::from_string(pubkey).unwrap();
        // Blank the comment
        key.comment = None;

        let mut att_ca = AttestationCa::yubico_u2f_root_ca_serial_457200631();
        // Aaguid for yubikey 5 nano
        att_ca.insert_aaguid(uuid::uuid!("cb69481e-8ff7-4039-93ec-0a2729a154a8"));
        let att_ca_list: AttestationCaList =
            att_ca.try_into().expect("Failed to build att ca list");

        // Parse
        let att = verify_fido_sk_ssh_attestation(
            attest.0.as_slice(),
            challenge.0.as_slice(),
            &att_ca_list,
            false,
        )
        .expect("Failed to parse attestation");

        trace!("key {:?}", key);
        trace!("att {:?}", att.pubkey);
        trace!("att full {:?}", att);

        // Check the supplied pubkey and the attested pubkey are the same.
        assert!(att.pubkey == key);
    }

    /*
    #[test]
    fn test_ssh_ecdsa_sk_credprotect_attest() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create with:
        //  dd if=/dev/urandom of=/Users/william/.ssh/id_ecdsa_sk.chal bs=16 count=1
        //  ssh-keygen -t ecdsa-sk -O verify-required -O challenge=/Users/william/.ssh/id_ecdsa_sk.chal -O write-attestation=/Users/william/.ssh/id_ecdsa_sk.attest -f /Users/william/.ssh/id_ecdsa_sk

        let attest = Base64UrlSafeData::try_from("")
            .expect("Failed to decode attestation");
        let challenge = Base64UrlSafeData::try_from("VzCkpMNVYVgXHBuDP74v9A==")
            .expect("Failed to decode attestation");

        let pubkey = "";
        let mut key = sshkeys::PublicKey::from_string(pubkey).unwrap();
        // Blank the comment
        key.comment = None;

        // Parse
        let att = verify_fido_sk_ssh_attestation(attest.0.as_slice(), challenge.0.as_slice())
            .expect("Failed to parse attestation");

        trace!("key {:?}", key);
        trace!("att {:?}", att.pubkey);
        trace!("att full {:?}", att);

        // Check the supplied pubkey and the attested pubkey are the same.
        assert!(att.pubkey == key);
    }
    */
}