//! Serialisable formats of attested ssh keys

use serde::{Deserialize, Serialize};
use webauthn_rs_core::attestation::AttestationFormat;
use webauthn_rs_core::proto::{ParsedAttestation, RegisteredExtensions};

pub use sshkeys::PublicKey;

/// An attested public key. This contains the ssh public key as well as the
/// attestation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedPublicKey {
    /// The ssh public key
    pub pubkey: PublicKey,
    /// The set of extensions that were verified at registration, that can
    /// be used in future authentication attempts
    pub extensions: RegisteredExtensions,
    /// The parser attestation data
    pub attestation: ParsedAttestation,
    /// The format of the attestation presented by the device.
    pub attestation_format: AttestationFormat,
}
