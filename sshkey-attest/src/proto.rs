//! Serialisable formats of attested ssh keys

use serde::{Deserialize, Serialize};
use sshkeys::PublicKey;
use webauthn_rs_core::attestation::AttestationFormat;
use webauthn_rs_core::proto::{ParsedAttestation, RegisteredExtensions};

#[derive(Clone, Debug, Serialize, Deserialize)]
/*
#[serde(
    try_from = "SerialisableAttestedPublicKey",
    into = "SerialisableAttestedPublicKey"
)]
*/
/// An attested public key. This contains the ssh public key as well as the
/// attestation metadata.
pub struct AttestedPublicKey {
    /// The ssh public key
    pub pubkey: PublicKey,
    /// The set of registrations that were verified at registration, that can
    /// be used in future authentication attempts
    pub extensions: RegisteredExtensions,
    /// The parser attestation data
    pub attestation: ParsedAttestation,
    /// The format of the attestation presented by the device.
    pub attestation_format: AttestationFormat,
}
