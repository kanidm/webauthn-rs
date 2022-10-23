use serde::Serialize;
use serde_cbor::{ser::to_vec_packed, Value};
use std::collections::{BTreeMap, BTreeSet};

mod client_pin;
mod config;
mod get_assertion;
mod get_info;
mod make_credential;
mod reset;

pub use self::client_pin::*;
pub use self::config::*;
pub use self::get_assertion::*;
pub use self::get_info::*;
pub use self::make_credential::*;
pub use self::reset::*;
use crate::error::WebauthnCError;
use crate::transport::iso7816::ISO7816RequestAPDU;

const FRAG_MAX: usize = 0xF0;

pub trait CBORResponse: Sized + std::fmt::Debug {
    fn try_from(i: &[u8]) -> Result<Self, WebauthnCError>;
}

pub trait CBORCommand: Serialize + Sized + std::fmt::Debug {
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

        // Canonical example returns 0x33 (PIN error)
        trace!("Sending: {:?}", self);
        let b = /* if Self::CMD == 1 {
            vec![168, 1, 88, 32, 104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65, 2, 162, 98, 105, 100, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, 100, 110, 97, 109, 101, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, 3, 163, 98, 105, 100, 88, 32, 43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112, 100, 110, 97, 109, 101, 113, 116, 101, 115, 116, 99, 116, 97, 112, 64, 99, 116, 97, 112, 46, 99, 111, 109, 107, 100, 105, 115, 112, 108, 97, 121, 78, 97, 109, 101, 105, 84, 101, 115, 116, 32, 67, 116, 97, 112, 4, 131, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 57, 1, 0, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 56, 36, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 6, 161, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 245, 7, 161, 98, 114, 107, 245, 8, 80, 252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8, 9, 1]
        } else */ { to_vec_packed(self)? };
        trace!(
            "CBOR payload: {:?}",
            serde_cbor::from_slice::<'_, serde_cbor::Value>(&b[..])
        );
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
            p1: 0, // 0x80,  // client supports NFCCTAP_GETRESPONSE
            p2: 0x00,
            data: self.cbor()?,
            ne: 65536,
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

/// Converts a [Value::Bool] into [Option<bool>]. Returns `None` for other [Value] types.
fn value_to_bool(v: Value, loc: &str) -> Option<bool> {
    if let Value::Bool(b) = v {
        Some(b)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Converts a [Value::Bytes] into [Option<Vec<u8>>]. Returns `None` for other [Value] types.
fn value_to_vec_u8(v: Value, loc: &str) -> Option<Vec<u8>> {
    if let Value::Bytes(b) = v {
        Some(b)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_string(v: Value, loc: &str) -> Option<String> {
    if let Value::Text(s) = v {
        Some(s)
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
        impl crate::cbor::CBORResponse for $name {
            fn try_from(i: &[u8]) -> Result<Self, crate::error::WebauthnCError> {
                if i.is_empty() {
                    TryFrom::try_from(BTreeMap::new()).map_err(|e| {
                        error!("Tried to deserialise empty input, got error: {:?}", e);
                        crate::error::WebauthnCError::Cbor
                    })
                } else {
                    serde_cbor::from_slice(&i).map_err(|e| {
                        error!("deserialise: {:?}", e);
                        crate::error::WebauthnCError::Cbor
                    })
                }
            }
        }
    };
}
