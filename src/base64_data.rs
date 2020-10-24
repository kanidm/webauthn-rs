use serde::de::{Error, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl AsRef<Vec<u8>> for Base64UrlSafeData {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl AsRef<[u8]> for Base64UrlSafeData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct Base64UrlSafeDataVisitor;

static ALLOWED_DECODING_FORMATS: &'static [base64::Config] = &[
    base64::URL_SAFE_NO_PAD,
    base64::URL_SAFE,
    base64::STANDARD,
    base64::STANDARD_NO_PAD,
];

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
            match base64::decode_config(v, *config) {
                Ok(data) => return Ok(Base64UrlSafeData(data)),
                Err(_) => {}
            };
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
