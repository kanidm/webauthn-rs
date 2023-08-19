//! CTAP 2 commands.
use serde::Serialize;
use serde_cbor_2::{ser::to_vec_packed, Value};
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
mod bio_enrollment;
mod client_pin;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
mod config;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
mod credential_management;
mod get_assertion;
mod get_info;
mod make_credential;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
mod reset;
mod selection;

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
pub use self::bio_enrollment::*;
pub use self::client_pin::*;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
pub use self::config::*;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
pub use self::credential_management::*;
pub use self::get_assertion::*;
pub use self::get_info::*;
pub use self::make_credential::*;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
pub use self::reset::*;
pub use self::selection::*;
use crate::error::WebauthnCError;
use crate::transport::iso7816::ISO7816RequestAPDU;

const FRAG_MAX: usize = 0xF0;

/// Common trait for all CBOR responses.
///
/// Ths handles some of the response deserialization process.
pub trait CBORResponse: Sized + std::fmt::Debug + Send {
    fn try_from(i: &[u8]) -> Result<Self, WebauthnCError>;
}

/// Common trait for all CBOR commands.
///
/// This handles some of the command serialization process.
pub trait CBORCommand: Serialize + Sized + std::fmt::Debug + Send {
    /// CTAP comand byte
    const CMD: u8;

    /// If true (default), then the command has a payload, which will be
    /// serialized into CBOR format.
    ///
    /// If false, then the command has no payload.
    const HAS_PAYLOAD: bool = true;

    /// The response type associated with this command.
    type Response: CBORResponse;

    /// Converts a CTAP v2 command into a binary form.
    fn cbor(&self) -> Result<Vec<u8>, serde_cbor_2::Error> {
        // CTAP v2.1, s8.2.9.1.2 (USB CTAPHID_CBOR), s8.3.5 (NFC framing).
        // Similar form used for caBLE.
        // TODO: BLE is different, it includes a u16 length after the command?
        if !Self::HAS_PAYLOAD {
            return Ok(vec![Self::CMD]);
        }

        trace!("Sending: {:?}", self);
        let mut b = to_vec_packed(self)?;
        trace!(
            "CBOR: cmd={}, cbor={:?}",
            Self::CMD,
            serde_cbor_2::from_slice::<'_, serde_cbor_2::Value>(&b[..])
        );

        b.reserve(1);
        b.insert(0, Self::CMD);
        Ok(b)
    }
}

/// Converts a CTAP v2 command into a form suitable for transmission with
/// short ISO/IEC 7816-4 APDUs (over NFC).
pub fn to_short_apdus(cbor: &[u8]) -> Vec<ISO7816RequestAPDU> {
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

    o
}

/// Converts a CTAP v2 command into a form suitable for transmission with
/// extended ISO/IEC 7816-4 APDUs (over NFC).
pub fn to_extended_apdu(cbor: Vec<u8>) -> ISO7816RequestAPDU {
    ISO7816RequestAPDU {
        cla: 0x80,
        ins: 0x10,
        p1: 0, // 0x80,  // client supports NFCCTAP_GETRESPONSE
        p2: 0x00,
        data: cbor,
        ne: 65536,
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

fn value_to_set_u64(v: Value, loc: &str) -> Option<BTreeSet<u64>> {
    if let Value::Array(v) = v {
        let mut x = BTreeSet::new();
        for i in v.into_iter() {
            if let Value::Integer(i) = i {
                if let Ok(i) = u64::try_from(i) {
                    x.insert(i);
                    continue;
                }
            }
            error!("Invalid value inside {}: {:?}", loc, i);
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_vec(v: Value, loc: &str) -> Option<Vec<Value>> {
    if let Value::Array(v) = v {
        Some(v)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_map(v: Value, loc: &str) -> Option<BTreeMap<Value, Value>> {
    if let Value::Map(v) = v {
        Some(v)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_vec_u32(v: Value, loc: &str) -> Option<Vec<u32>> {
    value_to_vec(v, loc).map(|v| {
        v.into_iter()
            .filter_map(|i| value_to_u32(&i, loc))
            .collect()
    })
}

#[cfg(feature = "ctap2-management")]
pub(crate) fn value_to_u8(v: &Value, loc: &str) -> Option<u8> {
    if let Value::Integer(i) = v {
        u8::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

pub(crate) fn value_to_u32(v: &Value, loc: &str) -> Option<u32> {
    if let Value::Integer(i) = v {
        u32::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

#[cfg(any(doc, feature = "cable"))]
pub(crate) fn value_to_u64(v: &Value, loc: &str) -> Option<u64> {
    if let Value::Integer(i) = v {
        u64::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_i128(v: impl Borrow<Value>, loc: &str) -> Option<i128> {
    let v = v.borrow();
    if let Value::Integer(i) = v {
        Some(*i)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_usize(v: impl Borrow<Value>, loc: &str) -> Option<usize> {
    let v = v.borrow();
    if let Value::Integer(i) = v {
        usize::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Converts a [`Value::Bool`] into [`Option<bool>`]. Returns [`Option::None`] for other [`Value`] types.
pub(crate) fn value_to_bool(v: &Value, loc: &str) -> Option<bool> {
    if let Value::Bool(b) = v {
        Some(*b)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Converts a [`Value::Bytes`] into [`Option<Vec<u8>>`]. Returns [`Option::None`] for other [`Value`] types.
pub(crate) fn value_to_vec_u8(v: Value, loc: &str) -> Option<Vec<u8>> {
    if let Value::Bytes(b) = v {
        Some(b)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

pub(crate) fn value_to_string(v: Value, loc: &str) -> Option<String> {
    if let Value::Text(s) = v {
        Some(s)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Type for commands which have no response data.
#[derive(Debug)]
pub struct NoResponse {}

impl CBORResponse for NoResponse {
    fn try_from(_raw: &[u8]) -> Result<Self, WebauthnCError> {
        Ok(Self {})
    }
}

fn map_int_keys(m: BTreeMap<Value, Value>) -> Result<BTreeMap<u32, Value>, WebauthnCError> {
    m.into_iter()
        .map(|(k, v)| {
            let k = value_to_u32(&k, "map_int_keys").ok_or(WebauthnCError::Internal)?;

            Ok((k, v))
        })
        .collect()
}

// TODO: switch to #derive
#[macro_export]
macro_rules! deserialize_cbor {
    ($name:ident) => {
        impl $crate::ctap2::commands::CBORResponse for $name {
            fn try_from(i: &[u8]) -> Result<Self, $crate::error::WebauthnCError> {
                if i.is_empty() {
                    TryFrom::try_from(std::collections::BTreeMap::new()).map_err(|e| {
                        error!("Tried to deserialise empty input, got error: {:?}", e);
                        $crate::error::WebauthnCError::Cbor
                    })
                } else {
                    // Convert to Value (Value::Map)
                    let v =
                        serde_cbor_2::from_slice::<'_, serde_cbor_2::Value>(&i).map_err(|e| {
                            error!("deserialise: {:?}", e);
                            $crate::error::WebauthnCError::Cbor
                        })?;

                    // Extract the BTreeMap
                    let v = if let serde_cbor_2::Value::Map(v) = v {
                        Ok(v)
                    } else {
                        error!("deserialise: unexpected CBOR type {:?}", v);
                        Err($crate::error::WebauthnCError::Cbor)
                    }?;

                    // Convert BTreeMap<Value, Value> into BTreeMap<u32, Value>
                    let v = $crate::ctap2::commands::map_int_keys(v)?;

                    TryFrom::try_from(v).map_err(|_| {
                        error!("deserialising structure");
                        $crate::error::WebauthnCError::Cbor
                    })
                }
            }
        }
    };
}
