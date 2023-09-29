use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use crate::{ALLOWED_DECODING_FORMATS, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::de::{Error, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde wrapper for `Vec<u8>` which emits URL-safe, non-padded Base64 for
/// *only* human-readable formats, and accepts Base64 and binary formats.
///
/// * Deserialisation is described in the [module documentation][crate].
///
/// * Serialisation to [a human-readable format][0] (such as JSON) emits
///   URL-safe, non-padded Base64 (per [RFC 4648 §5][sec5]).
///
/// * Serialisation to [a non-human-readable format][0] (such as CBOR) emits
///   a native "bytes" type, and not encode the value.
///
/// [0]: https://docs.rs/serde/latest/serde/trait.Serializer.html#method.is_human_readable
/// [sec5]: https://datatracker.ietf.org/doc/html/rfc4648#section-5
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct HumanBinaryData(Vec<u8>);

impl Deref for HumanBinaryData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HumanBinaryData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<u8>> for HumanBinaryData {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<[u8; N]> for HumanBinaryData {
    fn from(value: [u8; N]) -> Self {
        Self(value.to_vec())
    }
}

impl From<&[u8]> for HumanBinaryData {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<HumanBinaryData> for Vec<u8> {
    fn from(value: HumanBinaryData) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for HumanBinaryData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

macro_rules! partial_eq_impl {
    ($type:ty) => {
        impl PartialEq<$type> for HumanBinaryData {
            fn eq(&self, other: &$type) -> bool {
                self.0.eq(other)
            }
        }

        impl PartialEq<HumanBinaryData> for $type {
            fn eq(&self, other: &HumanBinaryData) -> bool {
                self.eq(&other.0)
            }
        }
    };
}

partial_eq_impl!(Vec<u8>);
partial_eq_impl!([u8]);

impl<const N: usize> PartialEq<[u8; N]> for HumanBinaryData {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0.eq(other)
    }
}

impl<const N: usize> PartialEq<HumanBinaryData> for [u8; N] {
    fn eq(&self, other: &HumanBinaryData) -> bool {
        self.as_slice().eq(&other.0)
    }
}

struct HumanBinaryDataVisitor;

impl<'de> Visitor<'de> for HumanBinaryDataVisitor {
    type Value = HumanBinaryData;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a url-safe base64-encoded string, bytes, or sequence of integers"
        )
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        // Forgive alt base64 decoding formats
        for config in ALLOWED_DECODING_FORMATS {
            if let Ok(data) = config.decode(v) {
                return Ok(HumanBinaryData(data));
            }
        }

        Err(serde::de::Error::invalid_value(Unexpected::Str(v), &self))
    }

    fn visit_seq<A>(self, mut v: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut data = if let Some(sz) = v.size_hint() {
            Vec::with_capacity(sz)
        } else {
            Vec::new()
        };

        while let Some(i) = v.next_element()? {
            data.push(i)
        }
        Ok(HumanBinaryData(data))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(HumanBinaryData(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(HumanBinaryData(v.into()))
    }
}

impl<'de> Deserialize<'de> for HumanBinaryData {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        // Was previously _str
        deserializer.deserialize_any(HumanBinaryDataVisitor)
    }
}

impl Serialize for HumanBinaryData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let encoded = URL_SAFE_NO_PAD.encode(self);
            serializer.serialize_str(&encoded)
        } else {
            serializer.serialize_bytes(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_json() {
        let expected = [0x00, 0x01, 0x02, 0xff];

        // JSON as Array<Number>
        assert_eq!(
            serde_json::from_str::<HumanBinaryData>("[0,1,2,255]").unwrap(),
            expected
        );

        // JSON as Array<Number> with whitespace
        assert_eq!(
            serde_json::from_str::<HumanBinaryData>("[0, 1, 2, 255]").unwrap(),
            expected
        );

        // RFC 4648 §5 non-padded (URL-safe)
        assert_eq!(
            serde_json::from_str::<HumanBinaryData>("\"AAEC_w\"").unwrap(),
            expected
        );

        // RFC 4648 §5 padded (URL-safe)
        assert_eq!(
            serde_json::from_str::<HumanBinaryData>("\"AAEC_w==\"").unwrap(),
            expected
        );

        // RFC 4648 §4 non-padded (standard)
        assert_eq!(
            serde_json::from_str::<HumanBinaryData>("\"AAEC/w\"").unwrap(),
            expected
        );

        // RFC 4648 §4 padded (standard)
        assert_eq!(
            serde_json::from_str::<HumanBinaryData>("\"AAEC/w==\"").unwrap(),
            expected
        );
    }

    #[test]
    fn to_json() {
        let input = HumanBinaryData(vec![0x00, 0x01, 0x02, 0xff]);

        // JSON output should be a String, RFC 4648 §5 non-padded (URL-safe)
        assert_eq!(serde_json::to_string(&input).unwrap(), "\"AAEC_w\"");
    }

    #[test]
    fn from_cbor() {
        let expected = [0x00, 0x01, 0x02, 0xff];

        // Data as bytes
        assert_eq!(
            serde_cbor_2::from_slice::<HumanBinaryData>(&[
                0x44, // bytes(4)
                0x00, 0x01, 0x02, 0xff
            ])
            .unwrap(),
            expected
        );

        // Data as array
        assert_eq!(
            serde_cbor_2::from_slice::<HumanBinaryData>(&[
                0x84, // array(4)
                0x00, // 0
                0x01, // 1
                0x02, // 2
                0x18, 0xff // 0xff
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §5 non-padded (URL-safe)
        assert_eq!(
            serde_cbor_2::from_slice::<HumanBinaryData>(&[
                0x66, // text(6)
                0x41, 0x41, 0x45, 0x43, 0x5F, 0x77, // "AAEC_w"
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §5 padded (URL-safe)
        assert_eq!(
            serde_cbor_2::from_slice::<HumanBinaryData>(&[
                0x68, // text(8)
                0x41, 0x41, 0x45, 0x43, 0x5F, 0x77, 0x3D, 0x3D // "AAEC_w=="
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §4 non-padded (standard)
        assert_eq!(
            serde_cbor_2::from_slice::<HumanBinaryData>(&[
                0x66, // text(6)
                0x41, 0x41, 0x45, 0x43, 0x2F, 0x77, // "AAEC/w"
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §4 padded (standard)
        assert_eq!(
            serde_cbor_2::from_slice::<HumanBinaryData>(&[
                0x68, // text(8)
                0x41, 0x41, 0x45, 0x43, 0x2F, 0x77, 0x3D, 0x3D // "AAEC/w=="
            ])
            .unwrap(),
            expected
        );
    }

    #[test]
    fn to_cbor() {
        let input = HumanBinaryData(vec![0x00, 0x01, 0x02, 0xff]);

        // CBOR output should be bytes, not Base64 encoded
        assert_eq!(
            serde_cbor_2::to_vec(&input).unwrap(),
            vec![
                0x44, // bytes(4)
                0x00, 0x01, 0x02, 0xff
            ]
        );
    }
}
