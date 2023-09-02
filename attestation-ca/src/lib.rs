use base64urlsafedata::Base64UrlSafeData;
use openssl::error::ErrorStack as OpenSSLErrorStack;
use openssl::{hash, x509};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

/// A serialised Attestation CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialisableAttestationCa {
    pub(crate) ca: Base64UrlSafeData,
    pub(crate) aaguids: BTreeSet<Uuid>,
}

/// A structure representing an Attestation CA and other options associated to this CA.
///
/// Generally depending on the Attestation CA in use, this can help determine properties
/// of the authenticator that is in use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    try_from = "SerialisableAttestationCa",
    into = "SerialisableAttestationCa"
)]
pub struct AttestationCa {
    /// The x509 root CA of the attestation chain that a security key will be attested to.
    pub ca: x509::X509,
    /// If not empty, the set of acceptable AAGUIDS (Device Ids) that are allowed to be
    /// attested as trusted by this CA. AAGUIDS that are not in this set, but signed by
    /// this CA will NOT be trusted.
    pub aaguids: BTreeSet<Uuid>,
}

#[allow(clippy::from_over_into)]
impl Into<SerialisableAttestationCa> for AttestationCa {
    fn into(self) -> SerialisableAttestationCa {
        SerialisableAttestationCa {
            ca: Base64UrlSafeData(self.ca.to_der().expect("Invalid DER")),
            aaguids: self.aaguids,
        }
    }
}

impl TryFrom<SerialisableAttestationCa> for AttestationCa {
    type Error = OpenSSLErrorStack;

    fn try_from(data: SerialisableAttestationCa) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(&data.ca.0)?,
            aaguids: data.aaguids,
        })
    }
}

impl TryFrom<&[u8]> for AttestationCa {
    type Error = OpenSSLErrorStack;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::X509::from_pem(data)?,
            aaguids: Default::default(),
        })
    }
}

impl AttestationCa {
    /// Retrieve the Key Identifier for this Attestation Ca
    pub fn get_kid(&self) -> Result<Vec<u8>, OpenSSLErrorStack> {
        self.ca
            .digest(hash::MessageDigest::sha256())
            .map(|bytes| bytes.to_vec())
    }

    /// Update the set of aaguids this Attestation CA allows. If an empty btreeset is provided then
    /// this Attestation CA allows all Aaguids.
    pub fn set_aaguids(&mut self, aaguids: BTreeSet<Uuid>) {
        self.aaguids = aaguids;
    }

    /// Update the set of aaguids this Attestation CA allows by adding this AAGUID to the allowed
    /// set.
    pub fn insert_aaguid(&mut self, aaguid: Uuid) {
        self.aaguids.insert(aaguid);
    }

    /// Create a customised attestation CA from a DER public key.
    pub fn new_from_der(data: &[u8]) -> Result<Self, OpenSSLErrorStack> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(data)?,
            aaguids: BTreeSet::default(),
        })
    }
}

/// A list of AttestationCas and associated options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationCaList {
    /// The set of CA's that we trust in this Operation
    pub cas: BTreeMap<Base64UrlSafeData, AttestationCa>,
}

impl TryFrom<AttestationCa> for AttestationCaList {
    type Error = OpenSSLErrorStack;

    fn try_from(att_ca: AttestationCa) -> Result<Self, Self::Error> {
        let mut new = Self::default();
        new.insert(att_ca)?;
        Ok(new)
    }
}

impl TryFrom<&[u8]> for AttestationCaList {
    type Error = OpenSSLErrorStack;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut new = Self::default();
        let att_ca = AttestationCa::try_from(data)?;
        new.insert(att_ca)?;
        Ok(new)
    }
}

impl TryFrom<&[(&[u8], Uuid)]> for AttestationCaList {
    type Error = OpenSSLErrorStack;

    fn try_from(iter: &[(&[u8], Uuid)]) -> Result<Self, Self::Error> {
        let mut cas = BTreeMap::default();

        for (der, aaguid) in iter {
            let ca = x509::X509::from_der(der)?;

            let kid = ca.digest(hash::MessageDigest::sha256())?;

            if !cas.contains_key(kid.as_ref()) {
                let mut aaguids = BTreeSet::default();
                aaguids.insert(*aaguid);
                let att_ca = AttestationCa { ca, aaguids };
                cas.insert(kid.to_vec().into(), att_ca);
            } else {
                let att_ca = cas.get_mut(kid.as_ref()).expect("Can not fail!");
                // just add the aaguid
                att_ca.aaguids.insert(*aaguid);
            };
        }

        Ok(AttestationCaList { cas })
    }
}

impl AttestationCaList {
    pub fn from_iter<I: IntoIterator<Item = (x509::X509, Uuid)>>(
        iter: I,
    ) -> Result<Self, OpenSSLErrorStack> {
        let mut cas = BTreeMap::default();

        for (ca, aaguid) in iter {
            let kid = ca.digest(hash::MessageDigest::sha256())?;

            if !cas.contains_key(kid.as_ref()) {
                let mut aaguids = BTreeSet::default();
                aaguids.insert(aaguid);
                let att_ca = AttestationCa { ca, aaguids };
                cas.insert(kid.to_vec().into(), att_ca);
            } else {
                let att_ca = cas.get_mut(kid.as_ref()).expect("Can not fail!");
                // just add the aaguid
                att_ca.aaguids.insert(aaguid);
            };
        }

        Ok(AttestationCaList { cas })
    }
}

impl AttestationCaList {
    /// Determine if this attestation list contains any members.
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }

    /// Insert a new att_ca into this Attestation Ca List
    pub fn insert(
        &mut self,
        att_ca: AttestationCa,
    ) -> Result<Option<AttestationCa>, OpenSSLErrorStack> {
        // Get the key id (kid, digest).
        let att_ca_dgst = att_ca.get_kid()?;
        Ok(self.cas.insert(att_ca_dgst.into(), att_ca))
    }
}
