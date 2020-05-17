use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{Visitor, Error, Unexpected};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64UrlSafeData(pub Vec<u8>);

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

impl<'de> Visitor<'de> for Base64UrlSafeDataVisitor {
    type Value = Base64UrlSafeData;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a base64 url encoded string")
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where
        E: Error, {

        match base64::decode_config(v, base64::URL_SAFE_NO_PAD) {
            Ok(data) => Ok(Base64UrlSafeData(data)),
            Err(_) => {
                Err(serde::de::Error::invalid_value(Unexpected::Str(v), &self))
            }
        }
    }
}

impl<'de> Deserialize<'de> for Base64UrlSafeData {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
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