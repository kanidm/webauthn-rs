//! Base64 data that encodes to Base64 UrlSafe, but can decode from multiple
//! base64 implementations to account for various clients and libraries. Compatible
//! with serde.

use serde::de::{Error, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt;

static ALLOWED_DECODING_FORMATS: &[base64::Config] = &[
    base64::URL_SAFE_NO_PAD,
    base64::URL_SAFE,
    base64::STANDARD,
    base64::STANDARD_NO_PAD,
];

#[derive(Debug, Clone, PartialEq, Eq)]
/// A container for binary that should be base64 encoded in serialisation. In reverse
/// when deserializing, will decode from many different types of base64 possible.
pub struct Base64UrlSafeData(pub Vec<u8>);

impl fmt::Display for Base64UrlSafeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            base64::encode_config(&self, base64::URL_SAFE_NO_PAD)
        )
    }
}

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
            if let Ok(data) = base64::decode_config(v, *config) {
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
        write!(formatter, "a base64 url encoded string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        // Forgive alt base64 decoding formats
        for config in ALLOWED_DECODING_FORMATS {
            if let Ok(data) = base64::decode_config(v, *config) {
                return Ok(Base64UrlSafeData(data));
            }
        }

        Err(serde::de::Error::invalid_value(Unexpected::Str(v), &self))
    }
}

impl<'de> Deserialize<'de> for Base64UrlSafeData {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64UrlSafeDataVisitor)
    }
}

impl Serialize for Base64UrlSafeData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::encode_config(&self, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use crate::base64_data::Base64UrlSafeData;
    use std::convert::TryFrom;

    #[test]
    fn test_try_from() {
        assert!(Base64UrlSafeData::try_from("aGVsbG8=").is_ok());
        assert!(Base64UrlSafeData::try_from("abcdefghij").is_err());
    }
}
