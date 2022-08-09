// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use compact_jwt::{JwtError, JwsUnverified, Jws};
use std::str::FromStr;
use std::fmt;
use serde::{Deserialize, Serialize};
use openssl::stack;
use openssl::x509;
use openssl::x509::store;
use tracing::{debug, error, trace};

use std::collections::BTreeMap;
use uuid::Uuid;

static GLOBAL_SIGN_ROOT_CA_R3: &'static str = r#"
-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----
"#;

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-format

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Upv {
    major: u16,
    minor: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-CodeAccuracyDescriptor
pub struct CodeAccuracyDescriptor {
    base: u16,
    min_length: u16,
    max_retries: Option<u16>,
    block_slowdown: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-BiometricAccuracyDescriptor
pub struct BiometricAccuracyDescriptor {
    #[serde(rename = "FAR")]
    far: Option<f32>,
    #[serde(rename = "FRR")]
    frr: Option<f32>,
    #[serde(rename = "ERR")]
    err: Option<f32>,
    #[serde(rename = "FAAR")]
    faar: Option<f32>,
    // undocumented
    #[serde(rename = "selfAttestedFRR")]
    self_attested_frr: Option<f32>,
    // undocumented
    #[serde(rename = "selfAttestedFAR")]
    self_attested_far: Option<f32>,
    // undocumented
    // Completely broken typing
    max_templates: serde_json::Value,

    max_reference_data_sets: Option<u16>,
    max_retries: Option<u16>,
    block_slowdown: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-PatternAccuracyDescriptor
pub struct PatternAccuracyDescriptor {
    // Spec says u32, is actually ... nfi?
    min_complexity: serde_json::Value,
    max_retries: Option<u16>,
    block_slowdown: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VerificationMethodAndCombinations {
    // Field missing
    // user_verification: u32,
    // Field undocumented
    user_verification_method: String,
    ca_desc: Option<CodeAccuracyDescriptor>,
    ba_desc: Option<BiometricAccuracyDescriptor>,
    pa_desc: Option<PatternAccuracyDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EcdaaAnchor {
    #[serde(rename = "X")]
    x: String,
    #[serde(rename = "X")]
    y: String,
    c: String,
    sx: String,
    sy: String,
    #[serde(rename = "G1Curve")]
    g1curve: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionDescriptor {
    id: String,
    tag: Option<u16>,
    data: Option<String>,
    // Spec defines as failIfUnknown, but MDS uses both variants.
    #[serde(alias = "failIfUnknown")]
    fail_if_unknown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataStatement {
    legal_header: Option<String>,
    aaid: Option<String>,
    aaguid: Option<Uuid>,
    #[serde(default)]
    attestation_certificate_key_identifiers: Vec<String>,
    description: String,
    #[serde(default)]
    alternative_descriptions: BTreeMap<String, String>,
    // Spec defines as u16, is u32 
    authenticator_version: u32,
    protocol_family: Option<String>,
    // Spec defines as required, is actually optional.
    #[serde(default)]
    version: Vec<Upv>,
    // Spec defines as required, is actually optional
    assertion_scheme: Option<String>,
    // Rofl. Lmao. Spec says these are u16, are actually string.
    // Spec defines ase required, it's optional.
    authentication_algorithm: Option<String>,
    #[serde(default)]
    // Spec defines as u16, is string
    authentication_algorithms: Vec<String>,
    // Spec defines as u16, is string
    // Spec defines ase required, it's optional.
    public_key_alg_and_encoding: Option<String>,
    #[serde(default)]
    // Spec defines as u16, is string
    public_key_alg_and_encodings: Vec<String>,
    // Spec defines as u16, is string
    attestation_types: Vec<String>,
    // This type is just straight fucked.
    user_verification_details: Vec<Vec<VerificationMethodAndCombinations>>,
    // Spec defines as required, is optional
    // Spec defines as u16, is vec<string>
    key_protection: Option<Vec<String>>,
    is_key_restricted: Option<bool>,
    is_fresh_user_verification_required: Option<bool>,
    // Spec defines as u16, is String
    matcher_protection: Vec<String>,
    crypto_strength: Option<u16>,
    operating_env: Option<String>,
    // Spec defines as u32, is Vec<string>
    attachment_hint: Vec<String>,
    // Spec defines as required, is optional
    is_second_factor_only: Option<bool>,
    // Spec defines as u16, is vec<String>
    tc_display: Vec<String>,
    tc_display_content_type: Option<String>,
    #[serde(skip_deserializing)]
    tc_display_png_characteristics: (),
    attestation_root_certificates: Vec<String>,
    #[serde(default)]
    ecdaa_trust_anchors: Vec<EcdaaAnchor>,
    #[serde(skip_deserializing)]
    icon: (),
    #[serde(default)]
    supported_extensions: Vec<ExtensionDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BiometricsStatusReport {
    cert_level: u16,
    modality: String,
    effective_date: Option<String>,
    certification_descriptor: Option<String>,
    certificate_number: Option<String>,
    certification_policy_version: Option<String>,
    certification_requirements_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticatorStatus {
    #[serde(rename = "NOT_FIDO_CERTIFIED")]
    NotFidoCertified,
    #[serde(rename = "FIDO_CERTIFIED")]
    FidoCertified,
    #[serde(rename = "USER_VERIFICATION_BYPASS")]
    UserVerificationBypass,
    #[serde(rename = "ATTESTATION_KEY_COMPROMISE")]
    AttestationKeyCompromise,
    #[serde(rename = "USER_KEY_REMOTE_COMPROMISE")]
    UserKeyRemoteCompromise,
    #[serde(rename = "USER_KEY_PHYSICAL_COMPROMISE")]
    UserKeyPhysicalCompromise,
    #[serde(rename = "UPDATE_AVAILABLE")]
    UpdateAvailable,
    #[serde(rename = "REVOKED")]
    Revoked,
    #[serde(rename = "SELF_ASSERTION_SUBMITTED")]
    SelfAssertionSubmitted,
    #[serde(rename = "FIDO_CERTIFIED_L1")]
    FidoCertifiedL1,
    #[serde(rename = "FIDO_CERTIFIED_L1plus")]
    FidoCertifiedL1Plus,
    #[serde(rename = "FIDO_CERTIFIED_L2")]
    FidoCertifiedL2,
    #[serde(rename = "FIDO_CERTIFIED_L2plus")]
    FidoCertifiedL2Plus,
    #[serde(rename = "FIDO_CERTIFIED_L3")]
    FidoCertifiedL3,
    #[serde(rename = "FIDO_CERTIFIED_L3plus")]
    FidoCertifiedL3Plus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusReport {
    status: AuthenticatorStatus,
    effective_date: Option<String>,
    authenticator_version: Option<u32>,
    certificate: Option<String>,
    url: Option<String>,
    certification_descriptor: Option<String>,
    certificate_number: Option<String>,
    certification_policy_version: Option<String>,
    certification_requirements_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FidoDevice {
    aaid: Option<String>,
    // For fido 2 devices.
    aaguid: Option<Uuid>,
    attestation_certificate_key_identifiers: Option<Vec<String>>,
    metadata_statement: MetadataStatement,
    // Could make it default if missing?
    #[serde(default)]
    biometric_status_reports: Vec<BiometricsStatusReport>,
    status_reports: Vec<StatusReport>,
    time_of_last_status_change: String, // iso 8601 time.
    #[serde(rename = "rogueListURL")]
    rogue_list_url: Option<String>,
    rogue_list_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FidoMds {
    entries: Vec<FidoDevice>,
    legal_header: String,
    next_update: String,
    no: u32,
}

impl FromStr for FidoMds {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Setup the trusted CA store so that we can validate the authenticity of the MDS blob.
        let root_ca = x509::X509::from_pem(GLOBAL_SIGN_ROOT_CA_R3.as_bytes()).map_err(|_| JwtError::OpenSSLError)?;

        let mut ca_store = store::X509StoreBuilder::new().map_err(|_| JwtError::OpenSSLError)?;
        ca_store
            .add_cert(root_ca)
            .map_err(|_| JwtError::OpenSSLError)?;

        let ca_store = ca_store.build();

        let jws = JwsUnverified::from_str(s)?;

        let fullchain = jws.get_x5c_chain()
            .and_then(|chain| chain.ok_or(JwtError::InvalidHeaderFormat))?;

        let (leaf, chain) = fullchain
            .split_first()
            .ok_or(JwtError::InvalidHeaderFormat)?;

        let mut chain_stack = stack::Stack::new().map_err(|_| JwtError::OpenSSLError)?;

        for crt in chain.iter() {
            chain_stack
                .push(crt.clone())
                .map_err(|_| JwtError::OpenSSLError)?;
        }

        let mut ca_ctx = x509::X509StoreContext::new().map_err(|_| JwtError::OpenSSLError)?;

        // Given the ca_store, the leaf cert, and the chain between leaf to ca_store, verify
        // the certificate chain.
        let res: Result<_, _> = ca_ctx
            .init(&ca_store, leaf, &chain_stack, |ca_ctx_ref| {
                ca_ctx_ref.verify_cert().map(|_| {
                    let res = ca_ctx_ref.error();
                    debug!("{:?}", res);
                    if res == x509::X509VerifyResult::OK {
                        Ok(())
                    } else {
                        debug!(
                            "ca_ctx_ref verify cert - error depth={}, sn={:?}",
                            ca_ctx_ref.error_depth(),
                            ca_ctx_ref.current_cert().map(|crt| crt.subject_name())
                        );
                        Err(JwtError::X5cPublicKeyDenied)
                    }
                })
            })
        .map_err(|e| {
            // If an openssl error occured, dump it here.
            error!(?e);
            JwtError::OpenSSLError
        })?;

        // Now we can release the embedded cert, since we have asserted the trust in the chain
        // that has signed this metadata.

        let x: Jws<FidoMds> = jws.validate_embeded()?;

        let metadata = x.into_inner();
        // tracing::trace!(?metadata);
        let s_pretty = serde_json::to_string_pretty(&metadata.entries[0]).unwrap();
        trace!(%s_pretty);

        Ok(metadata);
    }
}

impl fmt::Display for FidoMds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
