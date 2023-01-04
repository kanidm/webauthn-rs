use crate::internals::AuthenticatorData;
use crate::proto::COSEKey;
use crate::proto::Registration;
use crate::proto::RegisteredExtensions;
use crate::proto::ExtnState;
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
    // pubkey: &[u8],
) -> Result<AttestedPublicKey, WebauthnError> {
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

    // let att_obj =

    let attestation_format = AttestationFormat::Packed;

    // TODO: If/when ssh changes the attest blob, we can parse format here!

    // TODO: We can use verify_packed_attestation once we have the attestation
    // object from the attest blob.

    trace!(?ssh_sk_attest);

    let verification_data: Vec<u8> = ssh_sk_attest
        .auth_data_bytes
        .iter()
        // .chain(client_data_hash)
        .copied()
        .collect();

    let r = verify_signature(
        alg,
        &ssh_sk_attest.att_cert,
        &ssh_sk_attest.sig,
        &verification_data,
    )
    .unwrap();
    error!(?r);

    // Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation
    // Statement Certificate Requirements.
    // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements

    assert_packed_attest_req(&ssh_sk_attest.att_cert)?;

    // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
    // (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid
    // in authenticatorData.

    validate_extension::<FidoGenCeAaguid>(&ssh_sk_attest.att_cert, &acd.aaguid)?;

    // TODO: In future if ssh changes their attest format we can provide the full chain here.
    let att_x509 = vec![ssh_sk_attest.att_cert.clone()];

    let attestation = ParsedAttestation {
        data: ParsedAttestationData::Basic(att_x509),
        metadata: AttestationMetadata::Packed {
            aaguid: Uuid::from_bytes(acd.aaguid),
        },
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
    use base64urlsafedata::Base64UrlSafeData;

    #[test]
    fn test_ssh_ecdsa_sk_attest() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create with:
        //  ssh-keygen -t ecdsa-sk -O write-attestation=~/.ssh/id_ecdsa_sk.attest -f ~/.ssh/id_ecdsa_sk

        let attest = Base64UrlSafeData::try_from(
        "AAAAEXNzaC1zay1hdHRlc3QtdjAxAAAC8DCCAuwwggHUoAMCAQICCQCIobnFT2wgvjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTE2OTc5MzQxNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP3N+hZ2qRVyajtVRGx/tdK/YAcNNGY++kDoDODSHk4cAqXSZ7jZepIkLdQXk7JP2dD0gVMpP5WzOJpEv8J6tRejgZQwgZEwEwYKKwYBBAGCxAoNAQQFBAMFBAMwEAYJKwYBBAGCxAoMBAMCAQcwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQc7sM1OUCSbicb7WURb9yCzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA8JczOIP9yDzuYizYwoJwGCwmYbUWNuokPu/NOMRLKTHvRfZRhf5LRHX7WjD0kJwifo725l/O7b+G4Y+3w9a1tK00wBGCMxw3F/oGcxsn+Tg6zWQZW3HXN8Qxfb5vtnX7lK5omugUPyq7XBqiBqFi2oqHFxjPjZSYFqQLE1DxDfJVtxXysvG1q/tkTkRagkAaqLb59SitNKsSXJ14Y9aG6liaFpSL8q+BeIe6XBHZ8NGxGhZdnhOu6qzYcTpSXlYHjeUoVF2/crpnQocjl59cgarJgS2aJV/jlSWnyZVhKbq14up6YUg0UsO60+UYm5rKuxS5OvAsvgKbl+71jhxCSAAAASDBGAiEAuYjniWggxcWVrsX/0/8N6KWMRNDmpf3dQk/Y4cSuGLQCIQDdQ3Nu5vjOGm5H/NNE0hSbot53h0aWoEYM46GZLODnBAAAAMZYxOMGEOihYhFZYP4ewiPmUpyfS26AIA3LXlwyHIrx4rG/RQAAAARzuwzU5QJJuJxvtZRFv3ILAEBkB7bC8L0QnHND8bFs0wJ4UzHLzPIeJDmwID0cDIwhwI1V3mAQXqs6f2qfRmfDDGuy/rEXU9peERCS0c+nlXVEpQECAyYgASFYIE85NQyOCXu6kaHewAmdcG3P12/TBDFqiHTmQqK6J+ZOIlgg8MWx7zxh66Hv3qTP2CqqjRP0gTrS2g624zScjHeCgkgAAAAAAAAAAA==")
            .expect("Failed to decode attestation");

        let pubkey = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBE85NQyOCXu6kaHewAmdcG3P12/TBDFqiHTmQqK6J+ZO8MWx7zxh66Hv3qTP2CqqjRP0gTrS2g624zScjHeCgkgAAAAEc3NoOg== william@maxixe.dev.blackhats.net.au";
        let mut key = sshkeys::PublicKey::from_string(pubkey).unwrap();
        // Blank the comment
        key.comment = None;

        // Parse
        let att = verify_fido_sk_ssh_attestation(attest.0.as_slice())
            .expect("Failed to parse attestation");

        trace!("key {:?}", key);
        trace!("att {:?}", att.pubkey);
        trace!("att full {:?}", att);

        // Check the supplied pubkey and the attested pubkey are the same.
        assert!(att.pubkey == key);
    }

    #[test]
    fn test_ssh_ecdsa_sk_credprotect_attest() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create with:
        //  ssh-keygen -t ecdsa-sk -O write-attestation=~/.ssh/id_ecdsa_sk.attest -f ~/.ssh/id_ecdsa_sk

        let attest = Base64UrlSafeData::try_from("AAAAEXNzaC1zay1hdHRlc3QtdjAxAAAC8DCCAuwwggHUoAMCAQICCQCIobnFT2wgvjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTE2OTc5MzQxNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP3N+hZ2qRVyajtVRGx/tdK/YAcNNGY++kDoDODSHk4cAqXSZ7jZepIkLdQXk7JP2dD0gVMpP5WzOJpEv8J6tRejgZQwgZEwEwYKKwYBBAGCxAoNAQQFBAMFBAMwEAYJKwYBBAGCxAoMBAMCAQcwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQc7sM1OUCSbicb7WURb9yCzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA8JczOIP9yDzuYizYwoJwGCwmYbUWNuokPu/NOMRLKTHvRfZRhf5LRHX7WjD0kJwifo725l/O7b+G4Y+3w9a1tK00wBGCMxw3F/oGcxsn+Tg6zWQZW3HXN8Qxfb5vtnX7lK5omugUPyq7XBqiBqFi2oqHFxjPjZSYFqQLE1DxDfJVtxXysvG1q/tkTkRagkAaqLb59SitNKsSXJ14Y9aG6liaFpSL8q+BeIe6XBHZ8NGxGhZdnhOu6qzYcTpSXlYHjeUoVF2/crpnQocjl59cgarJgS2aJV/jlSWnyZVhKbq14up6YUg0UsO60+UYm5rKuxS5OvAsvgKbl+71jhxCSAAAARzBFAiB/FTh6vhRgOMm/4ELLdL6opEUEy6b2nU4mcnAzezjYDwIhAIIYxa2zQUEJKLFLZIGlE9Rm8+S5Ln6wlgyVa+dqePJJAAAA1FjS4wYQ6KFiEVlg/h7CI+ZSnJ9LboAgDcteXDIcivHisb/FAAAAA3O7DNTlAkm4nG+1lEW/cgsAQGLYekSea7yiheTcFGTGxK602eGommtVC39E7mYtBf+7+J246YwPehWqWg1e32MLTZbXdGNMH7yErUP9jwQoKJGlAQIDJiABIVggWKx1IQZ8MWXyWF0lykJRGRpSLQrYD2zzDx5Qm0+TAz8iWCAtxQEq+eGx7QNUXwW1noU/46GEF0Z6mBRVCROjHe84MKFrY3JlZFByb3RlY3QDAAAAAAAAAAA=")
            .expect("Failed to decode attestation");

        let pubkey = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBFisdSEGfDFl8lhdJcpCURkaUi0K2A9s8w8eUJtPkwM/LcUBKvnhse0DVF8FtZ6FP+OhhBdGepgUVQkTox3vODAAAAAEc3NoOg== william@maxixe.dev.blackhats.net.au";
        let mut key = sshkeys::PublicKey::from_string(pubkey).unwrap();
        // Blank the comment
        key.comment = None;

        // Parse
        let att = verify_fido_sk_ssh_attestation(attest.0.as_slice())
            .expect("Failed to parse attestation");

        trace!("key {:?}", key);
        trace!("att {:?}", att.pubkey);
        trace!("att full {:?}", att);

        // Check the supplied pubkey and the attested pubkey are the same.
        assert!(att.pubkey == key);
    }
}
