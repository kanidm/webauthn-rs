//! Base64 data that encodes to Base64 UrlSafe, but can decode from multiple
//! base64 implementations to account for various clients and libraries. Compatible
//! with serde.

#![deny(warnings)]
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

mod human;

pub use crate::human::HumanBinaryData;

use base64::{
    engine::general_purpose::{
        GeneralPurpose, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
    },
    Engine,
};
use serde::de::{Error, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::fmt;
use std::hash::Hash;

static ALLOWED_DECODING_FORMATS: &[GeneralPurpose] =
    &[URL_SAFE_NO_PAD, URL_SAFE, STANDARD, STANDARD_NO_PAD];

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
/// A container for binary that should be base64 encoded in serialisation. In reverse
/// when deserializing, will decode from many different types of base64 possible.
pub struct Base64UrlSafeData(pub Vec<u8>);

impl fmt::Display for Base64UrlSafeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", URL_SAFE_NO_PAD.encode(self))
    }
}

impl Borrow<[u8]> for Base64UrlSafeData {
    fn borrow(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for Base64UrlSafeData {
    fn from(v: Vec<u8>) -> Base64UrlSafeData {
        Base64UrlSafeData(v)
    }
}

// We have to allow this because we can't implement a trait on an external type
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Base64UrlSafeData {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for Base64UrlSafeData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&str> for Base64UrlSafeData {
    type Error = ();

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        for config in ALLOWED_DECODING_FORMATS {
            if let Ok(data) = config.decode(v) {
                return Ok(Base64UrlSafeData(data));
            }
        }
        Err(())
    }
}

struct Base64UrlSafeDataVisitor;

impl<'de> Visitor<'de> for Base64UrlSafeDataVisitor {
    type Value = Base64UrlSafeData;

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
                return Ok(Base64UrlSafeData(data));
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
        Ok(Base64UrlSafeData(data))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Base64UrlSafeData(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Base64UrlSafeData(v.into()))
    }
}

impl<'de> Deserialize<'de> for Base64UrlSafeData {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        // Was previously _str
        deserializer.deserialize_any(Base64UrlSafeDataVisitor)
    }
}

impl Serialize for Base64UrlSafeData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(self);
        serializer.serialize_str(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_try_from() {
        assert!(Base64UrlSafeData::try_from("aGVsbG8=").is_ok());
        assert!(Base64UrlSafeData::try_from("abcdefghij").is_err());
    }

    #[test]
    fn from_json() {
        let expected = Base64UrlSafeData(vec![0x00, 0x01, 0x02, 0xff]);

        // JSON as Array<Number>
        assert_eq!(
            serde_json::from_str::<Base64UrlSafeData>("[0,1,2,255]").unwrap(),
            expected
        );

        // JSON as Array<Number> with whitespace
        assert_eq!(
            serde_json::from_str::<Base64UrlSafeData>("[0, 1, 2, 255]").unwrap(),
            expected
        );

        // RFC 4648 §5 non-padded (URL-safe)
        assert_eq!(
            serde_json::from_str::<Base64UrlSafeData>("\"AAEC_w\"").unwrap(),
            expected
        );

        // RFC 4648 §5 padded (URL-safe)
        assert_eq!(
            serde_json::from_str::<Base64UrlSafeData>("\"AAEC_w==\"").unwrap(),
            expected
        );

        // RFC 4648 §4 non-padded (standard)
        assert_eq!(
            serde_json::from_str::<Base64UrlSafeData>("\"AAEC/w\"").unwrap(),
            expected
        );

        // RFC 4648 §4 padded (standard)
        assert_eq!(
            serde_json::from_str::<Base64UrlSafeData>("\"AAEC/w==\"").unwrap(),
            expected
        );
    }

    #[test]
    fn to_json() {
        let input = Base64UrlSafeData(vec![0x00, 0x01, 0x02, 0xff]);

        // JSON output should be a String, RFC 4648 §5 non-padded (URL-safe)
        assert_eq!(serde_json::to_string(&input).unwrap(), "\"AAEC_w\"");
    }

    #[test]
    fn from_cbor() {
        let expected = Base64UrlSafeData(vec![0x00, 0x01, 0x02, 0xff]);

        // Data as bytes
        assert_eq!(
            serde_cbor_2::from_slice::<Base64UrlSafeData>(&[
                0x44, // bytes(4)
                0x00, 0x01, 0x02, 0xff
            ])
            .unwrap(),
            expected
        );

        // Data as array
        assert_eq!(
            serde_cbor_2::from_slice::<Base64UrlSafeData>(&[
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
            serde_cbor_2::from_slice::<Base64UrlSafeData>(&[
                0x66, // text(6)
                0x41, 0x41, 0x45, 0x43, 0x5F, 0x77, // "AAEC_w"
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §5 padded (URL-safe)
        assert_eq!(
            serde_cbor_2::from_slice::<Base64UrlSafeData>(&[
                0x68, // text(8)
                0x41, 0x41, 0x45, 0x43, 0x5F, 0x77, 0x3D, 0x3D // "AAEC_w=="
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §4 non-padded (standard)
        assert_eq!(
            serde_cbor_2::from_slice::<Base64UrlSafeData>(&[
                0x66, // text(6)
                0x41, 0x41, 0x45, 0x43, 0x2F, 0x77, // "AAEC/w"
            ])
            .unwrap(),
            expected
        );

        // RFC 4648 §4 padded (standard)
        assert_eq!(
            serde_cbor_2::from_slice::<Base64UrlSafeData>(&[
                0x68, // text(8)
                0x41, 0x41, 0x45, 0x43, 0x2F, 0x77, 0x3D, 0x3D // "AAEC/w=="
            ])
            .unwrap(),
            expected
        );
    }

    #[test]
    fn to_cbor() {
        let input = Base64UrlSafeData(vec![0x00, 0x01, 0x02, 0xff]);

        // CBOR output should be base64 encoded string
        assert_eq!(
            serde_cbor_2::to_vec(&input).unwrap(),
            vec![
                0x66, // text(6)
                0x41, 0x41, 0x45, 0x43, 0x5F, 0x77 // "AAEC_w"
            ]
        );
    }
}
