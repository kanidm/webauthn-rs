pub mod aaguid;
pub mod certificate_authority;
pub mod device;
pub mod image;
pub mod manufacturer;
pub mod quirks;

pub mod query;

pub mod data;

use std::fmt;

use crate::device::*;
use crate::query::Query;
use std::rc::Rc;

use webauthn_attestation_ca::{AttestationCaList, AttestationCaListBuilder};

pub mod prelude {
    pub use crate::aaguid::Aaguid;
    pub use crate::certificate_authority::Authority;
    pub use crate::device::{Device, Sku};
    pub use crate::manufacturer::Manufacturer;
    pub use crate::query::Query;
    pub use crate::{Data, DataBuilder};

    pub(crate) use openssl::error::ErrorStack as OpenSSLErrorStack;
    pub(crate) use openssl::x509;
    pub(crate) use std::collections::BTreeSet;
    pub(crate) use std::rc::Rc;
}

#[derive(Default)]
pub struct DataBuilder {
    devices: Vec<Rc<Device>>,
}

impl DataBuilder {
    pub fn build(self) -> Data {
        Data {
            devices: self.devices,
        }
    }
}

pub struct Data {
    devices: Vec<Rc<Device>>,
}

impl Default for Data {
    fn default() -> Self {
        Self::strict()
    }
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Data")
    }
}

impl Data {
    /// This is a list of webauthn authenticators that are of the highest
    /// quality and guarantees for users and RP's. These are devices that not only
    /// are secure, but user friendly, consistent, and correct.
    pub fn strict() -> Self {
        DataBuilder::default().add_yubico().build()
    }

    pub fn all_known_devices() -> Self {
        DataBuilder::default().add_yubico().build()
    }

    pub fn query(&self, query: &Query) -> Option<Data> {
        tracing::debug!(?query);

        let devices: Vec<_> = self
            .devices
            .iter()
            .filter(|dev| dev.query_match(query))
            // This is cheap due to Rc,
            .cloned()
            .collect();

        if devices.is_empty() {
            None
        } else {
            Some(Data { devices })
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().map(|d| d.as_ref())
    }
}

// Allowed as AttestationCaList is foreign.
#[allow(clippy::from_over_into)]
impl TryInto<AttestationCaList> for &Data {
    type Error = crate::prelude::OpenSSLErrorStack;

    fn try_into(self) -> Result<AttestationCaList, Self::Error> {
        let mut att_ca_builder = AttestationCaListBuilder::new();

        for dev in self.devices.iter() {
            for sku in dev.skus.iter() {
                for authority in dev.aaguid.ca.iter() {
                    att_ca_builder.insert_device_x509(
                        authority.ca.clone(),
                        dev.aaguid.id,
                        sku.display_name.clone(),
                        Default::default(),
                    )?;
                }
            }
        }

        Ok(att_ca_builder.build())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_init_data() {
        let data = Data::default();

        println!("{data}");
        for i in data.iter() {
            println!("{i:?}");
        }
    }
}
