use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Deserialize, Serialize, Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Quirk {
    QuirkMcQuirkleton,
}

pub type Quirks = BTreeMap<Uuid, BTreeSet<Quirk>>;
