//! Delicious delicacies.
//!
//! Instead of storing registration and authentication state in (server) task memory or saving it
//! to a database, this stores the state in an encrypted, `HttpOnly` `Secure` session cookie.

use crate::server::{ServerError, ServerResult};
use compact_jwt::{
    crypto::{JweA256GCMEncipher, JweA256KWEncipher},
    jwe::{Jwe, JweBuilder},
    JweCompact,
};
use serde::{Deserialize, Serialize};
use std::{mem::take, str::FromStr as _};
use time::{Duration, UtcDateTime};
use webauthn_rs::prelude::*;

/// Maximum age of a session cookie.
pub const MAX_AGE: Duration = Duration::minutes(15);

/// Maximum time a session cookie may be timestamped into the future.
///
/// This shouldn't happen under normal circumstances.
pub const MAX_FUTURE: Duration = Duration::minutes(1);

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SessionCookie {
    pub mtime: UtcDateTime,
    pub op: SessionOperation,
}

/// In progress WebAuthn operation state.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub enum SessionOperation {
    #[default]
    None,

    #[serde(rename = "pa")]
    PasskeyAuthentication(Box<PasskeyAuthentication>),

    #[serde(rename = "pr")]
    PasskeyRegistration(Box<PasskeyRegistration>),
}

impl SessionCookie {
    pub fn new() -> Self {
        Self {
            mtime: UtcDateTime::now(),
            op: SessionOperation::default(),
        }
    }

    /// Take a [PasskeyAuthentication] state from the session cookie, replacing it with None.
    pub fn take_passkey_authentication(&mut self) -> Option<PasskeyAuthentication> {
        let SessionOperation::PasskeyAuthentication(auth) = take(&mut self.op) else {
            return None;
        };

        Some(*auth)
    }

    /// Take a [PasskeyRegistration] state from the session cookie, replacing it with None.
    pub fn take_passkey_registration(&mut self) -> Option<PasskeyRegistration> {
        let SessionOperation::PasskeyRegistration(reg) = take(&mut self.op) else {
            return None;
        };

        Some(*reg)
    }

    /// Store a [PasskeyAuthentication] state into the session cookie, overwriting any existing
    /// operation.
    pub fn store_passkey_authentication(&mut self, auth: PasskeyAuthentication) {
        self.op = SessionOperation::PasskeyAuthentication(Box::new(auth));
    }

    /// Store a [PasskeyRegistration] state into the session cookie, overwriting any existing
    /// operation.
    pub fn store_passkey_registration(&mut self, reg: PasskeyRegistration) {
        self.op = SessionOperation::PasskeyRegistration(Box::new(reg));
    }

    /// Convert this [SessionCookie] into an unencrypted [Jwe], updating the modification time.
    fn into_jwe(mut self) -> ServerResult<Jwe> {
        self.mtime = UtcDateTime::now().truncate_to_second();
        Ok(JweBuilder::into_json(&self)?.build())
    }

    /// Convert this [SessionCookie] into an encrypted JWE.
    pub fn into_encrypted_jwe(self, cipher: &JweA256KWEncipher) -> ServerResult<String> {
        let jwe = self.into_jwe()?;
        Ok(cipher.encipher::<JweA256GCMEncipher>(&jwe)?.to_string())
    }

    /// Parse an encrypted session cookie and check its validity period.
    pub fn from_encrypted_jwe(
        cipher: &JweA256KWEncipher,
        encrypted_jwe: &str,
    ) -> ServerResult<Self> {
        let encrypted_jwe = JweCompact::from_str(encrypted_jwe)?;
        let jwe = cipher.decipher(&encrypted_jwe)?;
        let o: Self = serde_json::from_slice(jwe.payload())?;

        // Check validity period
        let now = UtcDateTime::now();
        if o.mtime > now {
            // Modification time is in the future (shouldn't normally happen).
            if (o.mtime - now) > MAX_FUTURE {
                return Err(ServerError::CookieExpired);
            }
        } else {
            // Modification time is in the past.
            if (now - o.mtime) > MAX_AGE {
                return Err(ServerError::CookieExpired);
            }
        }

        Ok(o)
    }
}
