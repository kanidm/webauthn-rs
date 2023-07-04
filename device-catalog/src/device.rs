use crate::aaguid::Aaguid;
use crate::image::Image;
use crate::manufacturer::Manufacturer;
use crate::quirks::Quirk;
use std::collections::BTreeSet;

use crate::query::Query;
use std::rc::Rc;

#[derive(Debug)]
pub struct Device {
    pub aaguid: Rc<Aaguid>,
    pub images: Vec<Rc<Image>>,
    pub quirks: BTreeSet<Quirk>,
    // This is used to derive some minimum properties.
    pub skus: Vec<Rc<Sku>>,
    pub mfr: Rc<Manufacturer>,
    // include the fido version of the mds here.
}

#[derive(Debug)]
pub struct Sku {
    pub display_name: String,
    pub version: String,
}

impl Device {
    pub(crate) fn query_match(&self, _q: &Query) -> bool {
        todo!();
    }
}
