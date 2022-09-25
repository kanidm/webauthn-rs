use serde::Serialize;
use serde_cbor::{from_slice, Value};
use std::collections::{BTreeMap, BTreeSet};

mod get_info;
mod make_credential;

pub use self::get_info::*;
pub use self::make_credential::*;
use crate::error::WebauthnCError;
use crate::transport::iso7816::ISO7816RequestAPDU;

const FRAG_MAX: usize = 0xF0;

pub trait CBORResponse: Sized + std::fmt::Debug {
    fn try_from(i: &[u8]) -> Result<Self, WebauthnCError>;
}

pub trait CBORCommand: Serialize + Sized {
    /// CTAP comand byte
    const CMD: u8;

    /// If true (default), then the command has a payload, which will be
    /// serialized into CBOR format.
    ///
    /// If false, then the command has no payload.
    const HAS_PAYLOAD: bool = true;

    type Response: CBORResponse;

    /// Converts a CTAP v2 command into a binary form.
    fn cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        // CTAP v2.1, s8.2.9.1.2 (USB CTAPHID_CBOR), s8.3.5 (NFC framing).
        // TODO: BLE is different, it includes a u16 length after the command?
        if !Self::HAS_PAYLOAD {
            return Ok(vec![Self::CMD]);
        }

        let b = serde_cbor::to_vec(self)?;
        let mut x = Vec::with_capacity(b.len() + 1);
        x.push(Self::CMD);
        x.extend_from_slice(&b);
        Ok(x)
    }

    /// Converts a CTAP v2 command into a form suitable for transmission with
    /// short ISO/IEC 7816-4 APDUs (over NFC).
    fn to_short_apdus(&self) -> Result<Vec<ISO7816RequestAPDU>, serde_cbor::Error> {
        let cbor = self.cbor()?;
        let chunks = cbor.chunks(FRAG_MAX).rev();
        let mut o = Vec::with_capacity(chunks.len());
        let mut last = true;

        for chunk in chunks {
            o.insert(
                0,
                ISO7816RequestAPDU {
                    cla: if last { 0x80 } else { 0x90 },
                    ins: 0x10,
                    p1: 0x00,
                    p2: 0x00,
                    data: chunk.to_vec(),
                    ne: if last { 256 } else { 0 },
                },
            );
            last = false;
        }

        Ok(o)
    }

    /// Converts a CTAP v2 command into a form suitable for transmission with
    /// extended ISO/IEC 7816-4 APDUs (over NFC).
    fn to_extended_apdu(&self) -> Result<ISO7816RequestAPDU, serde_cbor::Error> {
        Ok(ISO7816RequestAPDU {
            cla: 0x80,
            ins: 0x10,
            p1: 0x00,
            p2: 0x00,
            data: self.cbor()?,
            ne: 0xFFFF,
        })
    }
}

fn value_to_vec_string(v: Value, loc: &str) -> Option<Vec<String>> {
    if let Value::Array(v) = v {
        let mut x = Vec::with_capacity(v.len());
        for s in v.into_iter() {
            if let Value::Text(s) = s {
                x.push(s);
            } else {
                error!("Invalid value inside {}: {:?}", loc, s);
            }
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_set_string(v: Value, loc: &str) -> Option<BTreeSet<String>> {
    if let Value::Array(v) = v {
        let mut x = BTreeSet::new();
        for s in v.into_iter() {
            if let Value::Text(s) = s {
                x.insert(s);
            } else {
                error!("Invalid value inside {}: {:?}", loc, s);
            }
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_vec_u32(v: Value, loc: &str) -> Option<Vec<u32>> {
    if let Value::Array(v) = v {
        let x = v
            .into_iter()
            .filter_map(|i| {
                if let Value::Integer(i) = i {
                    u32::try_from(i)
                        .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
                        .ok()
                } else {
                    error!("Invalid type for {}: {:?}", loc, i);
                    None
                }
            })
            .collect();
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_u32(v: &Value, loc: &str) -> Option<u32> {
    if let Value::Integer(i) = v {
        u32::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

#[derive(Debug)]
pub struct NoResponse {}
impl CBORResponse for NoResponse {
    fn try_from(_raw: &[u8]) -> Result<Self, WebauthnCError> {
        Ok(Self {})
    }
}

// TODO: switch to #derive
#[macro_export]
macro_rules! deserialize_cbor {
    ($name:ident) => {
        impl CBORResponse for $name {
            fn try_from(i: &[u8]) -> Result<Self, WebauthnCError> {
                from_slice(&i).map_err(|e| {
                    error!("deserialise: {:?}", e);
                    WebauthnCError::Cbor
                })
            }
        }
    };
}
