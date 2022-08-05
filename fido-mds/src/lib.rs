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

use std::collections::BTreeMap;
use uuid::Uuid;

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-format

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataStatement {
    #[serde(flatten)]
    keys: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricsStatusReport {
    #[serde(flatten)]
    keys: BTreeMap<String, serde_json::Value>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    #[serde(flatten)]
    keys: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidoDevice {
    aaid: Option<String>,
    // For fido 2 devices.
    aaguid: Option<Uuid>,
    attestationCertificateKeyIdentifiers: Option<Vec<String>>,
    metadataStatement: MetadataStatement,
    // Could make it default if missing?
    #[serde(default)]
    biometricStatusReports: Vec<BiometricsStatusReport>,
    statusReports: Vec<StatusReport>,
    timeOfLastStatusChange: String, // iso 8601 time.
    rogueListURL: Option<String>,
    rogueListHash: Option<String>,

    // #[serde(flatten)]
    // keys: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidoMds {
    entries: Vec<FidoDevice>,
    legalHeader: String,
    nextUpdate: String,
    no: u32,
}

impl FromStr for FidoMds {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let jws = JwsUnverified::from_str(s)?;
        tracing::trace!(?jws);

        // How do validate chain?
        let chain = jws.get_x5c_chain()?;

        if let Some(chain) = chain {
            for cert in chain.iter() {
                tracing::trace!(?cert);
            }
        };

        let x: Jws<FidoMds> = jws.validate_embeded()?;

        let metadata = x.into_inner();
        // tracing::trace!(?metadata);
        let s_pretty = serde_json::to_string_pretty(&metadata.entries[0]).unwrap();
        tracing::trace!(%s_pretty);

        todo!();
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
