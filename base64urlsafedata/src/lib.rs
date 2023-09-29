//! Wrappers for `Vec<u8>` to make Serde serialise and deserialise as URL-safe,
//! non-padded Base64 (per [RFC 4648 §5][sec5]).
//!
//! ## Serialisation behaviour
//!
//! * [`Base64UrlSafeData`] always serialises to URL-safe, non-padded Base64.
//!
//! * [`HumanBinaryData`] only serialises to URL-safe, non-padded Base64 when
//!   using a [human-readable format][0].
//!
//!   Otherwise, it serialises as a "bytes"-like type (like [`serde_bytes`][1]).
//!
//!   This feature is new in `base64urlsafe` v0.1.4.
//!
//! By comparison, Serde's default behaviour is to serialise `Vec<u8>` as a
//! sequence of integers. This is a problem for many formats:
//!
//! * `serde_cbor` encodes as an `array`, rather than a `bytes`. This uses
//!   zig-zag encoded integers for values > `0x1F`, which averages about 1.88
//!   bytes per byte assuming a normal distribution of values.
//!
//! * `serde_json` encodes as an `Array<Number>`, which averages 3.55 bytes per
//!   byte without whitespace.
//!
//! Using Base64 encoding averages 1.33 bytes per byte, and most formats pass
//! strings nearly-verbatim.
//!
//! ## Deserialisation behaviour
//!
//! Both types will deserialise multiple formats, provided the format is
//! self-describing (ie: [implements `deserialize_any`][5]):
//!
//! * Bytes types are passed as-is (new in v0.1.4).
//!
//!   [`HumanBinaryData`] produces this for [non-human-readable formats][0].
//!
//! * Sequences of integers are passed as-is.
//!
//!   Serde's default `Vec<u8>` serialiser produces this for many formats.
//!
//! * Strings are decoded Base64 per [RFC 4648 §5 (URL-safe)][sec5] or
//!   [§4 (standard)][sec4], with optional padding.
//!
//!   [`Base64UrlSafeData`] produces this for all formats, and
//!   [`HumanBinaryData`] produces this for [human-readable formats][0]. This
//!   should also be compatible with many other serialisers.
//!
//! ## Migrating from `Base64UrlSafeData` to `HumanBinaryData`
//!
//! [`Base64UrlSafeData`] always uses Base64 encoding, which isn't optimal for
//! many binary formats. For that reason, it's a good idea to migrate to
//! [`HumanBinaryData`] if you're using a binary format.
//!
//! However, you'll need to make sure *all* readers using [`Base64UrlSafeData`]
//! are on `base64urlsafedata` v0.1.4 or later before switching *anything* to
//! [`HumanBinaryData`]. Otherwise, they'll not be able to read any data in the
//! new format!
//!
//! Once they're all migrated across, you can start issuing writes in the new
//! format. It's a good idea to slowly roll out the change, in case you discover
//! something has been left behind.
//!
//! ## Alternatives
//!
//! * [`serde_bytes`][1], which implements efficient coding of `Vec<u8>`
//!   [for non-human-readable formats only][2].
//!
//! [0]: https://docs.rs/serde/latest/serde/trait.Serializer.html#method.is_human_readable
//! [1]: https://docs.rs/serde_bytes
//! [2]: https://github.com/serde-rs/bytes/issues/37
//! [5]: https://serde.rs/impl-deserialize.html
//! [sec4]: https://datatracker.ietf.org/doc/html/rfc4648#section-4
//! [sec5]: https://datatracker.ietf.org/doc/html/rfc4648#section-5
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
use std::convert::TryFrom;
use std::fmt;
use std::hash::Hash;
use std::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
};

static ALLOWED_DECODING_FORMATS: &[GeneralPurpose] =
    &[URL_SAFE_NO_PAD, URL_SAFE, STANDARD, STANDARD_NO_PAD];

/// Serde wrapper for `Vec<u8>` which always emits URL-safe, non-padded Base64,
/// and accepts Base64 and binary formats.
///
/// * Deserialisation is described in the [module documentation][crate].
///
/// * Serialisation *always* emits URL-safe, non-padded Base64 (per
///   [RFC 4648 §5][sec5]).
///
///   Unlike [`HumanBinaryData`], this happens *regardless* of whether the
///   underlying serialisation format is [human readable][0]. If you're
///   serialising to [non-human-readable formats][0], you should consider
///   [migrating to `HumanBinaryData`][crate].
///
/// Otherwise, this type should work as much like a `Vec<u8>` as possible.
///
/// [0]: https://docs.rs/serde/latest/serde/trait.Serializer.html#method.is_human_readable
/// [sec5]: https://datatracker.ietf.org/doc/html/rfc4648#section-5
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
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

impl Deref for Base64UrlSafeData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Base64UrlSafeData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
