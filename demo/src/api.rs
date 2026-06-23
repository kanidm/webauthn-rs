//! Shared API types
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, IfIsHumanReadable, TimestampMilliSeconds,
};
use time::OffsetDateTime;

/// Subset of the passkey model for passing over the API.
#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EnrolledPasskeyInfo {
    /// Enrollment timestamp for the passkey.
    #[serde_as(as = "TimestampMilliSeconds<i64>")]
    pub created: OffsetDateTime,

    /// First 8 bytes of the credential ID.
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
    pub cred_id_short: [u8; 8],

    /// User-supplied label for the passkey.
    pub label: String,

    /// `true` if this is the passkey that was created/used in the current ceremony.
    pub current: bool,
}
