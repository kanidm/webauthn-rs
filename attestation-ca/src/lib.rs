use crypto_glue::{
    der::Error as DerError,
    s256::Sha256Output,
    traits::{DecodeDer, DecodePem, EncodeDer},
    x509,
};
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, IfIsHumanReadable,
};
use std::collections::BTreeMap;
use std::fmt;
use tracing::error;
use uuid::Uuid;

#[derive(Debug)]
pub enum Error {
    DerDecode(DerError),
    DerEncode(DerError),
    PemDecode(DerError),
    PemEncode(DerError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceDescription {
    pub(crate) en: String,
    pub(crate) localised: BTreeMap<String, String>,
}

impl DeviceDescription {
    /// A default description of device.
    pub fn description_en(&self) -> &str {
        self.en.as_str()
    }

    /// A map of locale identifiers to a localised description of the device.
    /// If the request locale is not found, you should try other user preferenced locales
    /// falling back to the default value.
    pub fn description_localised(&self) -> &BTreeMap<String, String> {
        &self.localised
    }
}

/// A serialised Attestation CA.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialisableAttestationCa {
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
    pub(crate) ca: Vec<u8>,
    pub(crate) aaguids: BTreeMap<Uuid, DeviceDescription>,
    pub(crate) blanket_allow: bool,
}

/// A structure representing an Attestation CA and other options associated to this CA.
///
/// Generally depending on the Attestation CA in use, this can help determine properties
/// of the authenticator that is in use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    try_from = "SerialisableAttestationCa",
    into = "SerialisableAttestationCa"
)]
pub struct AttestationCa {
    /// The x509 root CA of the attestation chain that a security key will be attested to.
    ca: x509::Certificate,
    /// If not empty, the set of acceptable AAGUIDS (Device Ids) that are allowed to be
    /// attested as trusted by this CA. AAGUIDS that are not in this set, but signed by
    /// this CA will NOT be trusted.
    aaguids: BTreeMap<Uuid, DeviceDescription>,
    blanket_allow: bool,
}

#[allow(clippy::from_over_into)]
impl Into<SerialisableAttestationCa> for AttestationCa {
    fn into(self) -> SerialisableAttestationCa {
        SerialisableAttestationCa {
            ca: self.ca.to_der().expect("Invalid DER"),
            aaguids: self.aaguids,
            blanket_allow: self.blanket_allow,
        }
    }
}

impl TryFrom<SerialisableAttestationCa> for AttestationCa {
    type Error = crate::Error;

    fn try_from(data: SerialisableAttestationCa) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::Certificate::from_der(&data.ca).map_err(|err| {
                error!(?err, "Unable to decode certificate DER");
                Error::DerDecode(err)
            })?,
            aaguids: data.aaguids,
            blanket_allow: data.blanket_allow,
        })
    }
}

impl AttestationCa {
    pub fn ca(&self) -> &x509::Certificate {
        &self.ca
    }

    pub fn aaguids(&self) -> &BTreeMap<Uuid, DeviceDescription> {
        &self.aaguids
    }

    pub fn blanket_allow(&self) -> bool {
        self.blanket_allow
    }

    /// Retrieve the Key Identifier for this Attestation Ca
    pub fn get_kid(&self) -> Result<Sha256Output, Error> {
        x509::x509_digest_sha256(&self.ca).map_err(|err| {
            error!(?err, "Unable to encode certificate for digest");
            Error::DerEncode(err)
        })
    }

    fn insert_device(
        &mut self,
        aaguid: Uuid,
        desc_english: String,
        desc_localised: BTreeMap<String, String>,
    ) {
        self.blanket_allow = false;
        self.aaguids.insert(
            aaguid,
            DeviceDescription {
                en: desc_english,
                localised: desc_localised,
            },
        );
    }

    fn new_from_pem(data: &[u8]) -> Result<Self, Error> {
        Ok(AttestationCa {
            ca: x509::Certificate::from_pem(data).map_err(|err| {
                error!(?err, "Unable to decode certificate PEM");
                Error::PemDecode(err)
            })?,
            aaguids: BTreeMap::default(),
            blanket_allow: true,
        })
    }

    fn union(&mut self, other: &Self) {
        // if either is a blanket allow, we just do that.
        if self.blanket_allow || other.blanket_allow {
            self.blanket_allow = true;
            self.aaguids.clear();
        } else {
            self.blanket_allow = false;
            for (o_aaguid, o_device) in other.aaguids.iter() {
                // We can use the entry api here since o_aaguid is copy.
                self.aaguids
                    .entry(*o_aaguid)
                    .or_insert_with(|| o_device.clone());
            }
        }
    }

    fn intersection(&mut self, other: &Self) {
        // If they are a blanket allow, do nothing, we are already
        // more restrictive, or we also are a blanket allow
        if other.blanket_allow() {
            // Do nothing
        } else if self.blanket_allow {
            // Just set our aaguids to other, and remove our blanket allow.
            self.blanket_allow = false;
            self.aaguids = other.aaguids.clone();
        } else {
            // Only keep what is also in other.
            self.aaguids
                .retain(|s_aaguid, _| other.aaguids.contains_key(s_aaguid))
        }
    }

    fn can_retain(&self) -> bool {
        // Only retain a CA if it's a blanket allow, or has aaguids remaining.
        self.blanket_allow || !self.aaguids.is_empty()
    }
}

#[serde_as]
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialisableAttestationCaList {
    /// The set of CA's that we trust in this Operation
    #[serde_as(as = "IfIsHumanReadable< BTreeMap<Base64<UrlSafe, Unpadded>, _> >")]
    cas: BTreeMap<[u8; 32], AttestationCa>,
}

impl From<AttestationCaList> for SerialisableAttestationCaList {
    fn from(acl: AttestationCaList) -> Self {
        Self {
            cas: acl
                .cas
                .into_iter()
                .map(|(key, value)| {
                    let key: [u8; 32] = *key.as_ref();
                    (key, value)
                })
                .collect(),
        }
    }
}

impl From<SerialisableAttestationCaList> for AttestationCaList {
    fn from(acl: SerialisableAttestationCaList) -> Self {
        Self {
            cas: acl
                .cas
                .into_iter()
                .map(|(key, value)| {
                    let key = Sha256Output::from(key);
                    (key, value)
                })
                .collect(),
        }
    }
}

/// A list of AttestationCas and associated options.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    from = "SerialisableAttestationCaList",
    into = "SerialisableAttestationCaList"
)]
pub struct AttestationCaList {
    /// The set of CA's that we trust in this Operation
    cas: BTreeMap<Sha256Output, AttestationCa>,
}

impl TryFrom<&[u8]> for AttestationCaList {
    type Error = crate::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut new = Self::default();
        let att_ca = AttestationCa::new_from_pem(data)?;
        new.insert(att_ca)?;
        Ok(new)
    }
}

impl AttestationCaList {
    pub fn cas(&self) -> &BTreeMap<Sha256Output, AttestationCa> {
        &self.cas
    }

    pub fn clear(&mut self) {
        self.cas.clear()
    }

    pub fn len(&self) -> usize {
        self.cas.len()
    }

    /// Determine if this attestation list contains any members.
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }

    /// Insert a new att_ca into this Attestation Ca List
    pub fn insert(&mut self, att_ca: AttestationCa) -> Result<Option<AttestationCa>, Error> {
        // Get the key id (kid, digest).
        let att_ca_dgst = att_ca.get_kid()?;
        Ok(self.cas.insert(att_ca_dgst.into(), att_ca))
    }

    /// Join two CA lists into one, taking all elements from both.
    pub fn union(&mut self, other: &Self) {
        for (o_kid, o_att_ca) in other.cas.iter() {
            if let Some(s_att_ca) = self.cas.get_mut(o_kid) {
                s_att_ca.union(o_att_ca)
            } else {
                self.cas.insert(o_kid.clone(), o_att_ca.clone());
            }
        }
    }

    /// Retain only the CA's and devices that exist in self and other.
    pub fn intersection(&mut self, other: &Self) {
        self.cas.retain(|s_kid, s_att_ca| {
            // First, does this exist in our partner?
            if let Some(o_att_ca) = other.cas.get(s_kid) {
                // Now, intersect.
                s_att_ca.intersection(o_att_ca);
                if s_att_ca.can_retain() {
                    // Still as elements, retain.
                    true
                } else {
                    // Nothing remains, remove.
                    false
                }
            } else {
                // Not in other, remove.
                false
            }
        })
    }
}

#[derive(Default)]
pub struct AttestationCaListBuilder {
    cas: BTreeMap<Sha256Output, AttestationCa>,
}

impl AttestationCaListBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_device_x509(
        &mut self,
        ca: x509::Certificate,
        aaguid: Uuid,
        desc_english: String,
        desc_localised: BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let kid = x509::x509_digest_sha256(&ca).map_err(|err| {
            error!(?err, "Unable to encode certificate for digest");
            Error::DerEncode(err)
        })?;

        let mut att_ca = if let Some(att_ca) = self.cas.remove(&kid) {
            att_ca
        } else {
            AttestationCa {
                ca,
                aaguids: BTreeMap::default(),
                blanket_allow: false,
            }
        };

        att_ca.insert_device(aaguid, desc_english, desc_localised);

        self.cas.insert(kid, att_ca);

        Ok(())
    }

    pub fn insert_device_der(
        &mut self,
        ca_der: &[u8],
        aaguid: Uuid,
        desc_english: String,
        desc_localised: BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let ca = x509::Certificate::from_der(ca_der).map_err(|err| {
            error!(?err, "Unable to encode certificate for digest");
            Error::DerDecode(err)
        })?;
        self.insert_device_x509(ca, aaguid, desc_english, desc_localised)
    }

    pub fn insert_device_pem(
        &mut self,
        ca_pem: &[u8],
        aaguid: Uuid,
        desc_english: String,
        desc_localised: BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let ca = x509::Certificate::from_pem(ca_pem).map_err(|err| {
            error!(?err, "Unable to encode certificate for digest");
            Error::PemDecode(err)
        })?;
        self.insert_device_x509(ca, aaguid, desc_english, desc_localised)
    }

    pub fn build(self) -> AttestationCaList {
        let cas = self
            .cas
            .into_iter()
            .map(|(kid, att_ca)| (kid.into(), att_ca))
            .collect();

        AttestationCaList { cas }
    }
}
