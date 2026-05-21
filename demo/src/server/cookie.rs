//! Delicious delicacies.
//!
//! Instead of storing registration and authentication state in (server) task memory or saving it
//! to a database, this stores the state in an encrypted, `HttpOnly` `Secure` session cookie.
//!
//! [`SessionCookie`] then stored in a [`Jwe`], which is encrypted with a key-wrapped key before
//! being sent to the client. This avoids the need to persist this data elsewhere in the server.
//!
//! While [`cookie`] has its own way to encrypt data, we discovered a security issue with its
//! implementation.

use crate::server::{ServerError, ServerResult};
use axum::http::{
    header::{COOKIE, SET_COOKIE},
    HeaderMap, HeaderValue,
};
use compact_jwt::{
    crypto::{JweA256GCMEncipher, JweA256KWEncipher},
    jwe::{Jwe, JweBuilder},
    JweCompact,
};
use cookie::{Cookie, CookieJar, SameSite};
use leptos::{context::use_context, server_fn::ServerFnError};
use leptos_axum::{extract, ResponseOptions};
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

const COOKIE_NAME: &str = "webauthn-rs-demo";

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
    PasskeyAuthentication {
        #[serde(rename = "a")]
        auth: Box<PasskeyAuthentication>,

        #[serde(rename = "u")]
        account_id: Uuid,
    },

    #[serde(rename = "pr")]
    PasskeyRegistration {
        #[serde(rename = "r")]
        reg: Box<PasskeyRegistration>,

        #[serde(rename = "u")]
        account_id: Uuid,
    },
}

impl SessionCookie {
    pub fn new() -> Self {
        Self {
            mtime: UtcDateTime::now(),
            op: SessionOperation::default(),
        }
    }

    /// Take a [PasskeyAuthentication] state from the session cookie, replacing it with None.
    pub fn take_passkey_authentication(&mut self) -> Option<(PasskeyAuthentication, Uuid)> {
        let SessionOperation::PasskeyAuthentication {
            auth,
            account_id: uuid,
        } = take(&mut self.op)
        else {
            return None;
        };

        Some((*auth, uuid))
    }

    /// Take a [PasskeyRegistration] state from the session cookie, replacing it with None.
    pub fn take_passkey_registration(&mut self) -> Option<(PasskeyRegistration, Uuid)> {
        let SessionOperation::PasskeyRegistration {
            reg,
            account_id: uuid,
        } = take(&mut self.op)
        else {
            return None;
        };

        Some((*reg, uuid))
    }

    /// Store a [`PasskeyAuthentication`] state into the session cookie, overwriting any existing
    /// operation.
    pub fn store_passkey_authentication(&mut self, auth: PasskeyAuthentication, account_id: Uuid) {
        self.op = SessionOperation::PasskeyAuthentication {
            auth: Box::new(auth),
            account_id,
        };
    }

    /// Store a [`PasskeyRegistration`] state into the session cookie, overwriting any existing
    /// operation.
    pub fn store_passkey_registration(&mut self, reg: PasskeyRegistration, account_id: Uuid) {
        self.op = SessionOperation::PasskeyRegistration {
            reg: Box::new(reg),
            account_id,
        };
    }

    /// Convert this [`SessionCookie`] into an unencrypted [`Jwe`], updating the modification time.
    fn into_jwe(mut self) -> ServerResult<Jwe> {
        self.mtime = UtcDateTime::now().truncate_to_second();
        Ok(JweBuilder::into_json(&self)?.build())
    }

    /// Convert this [`SessionCookie`] into an encrypted JWE.
    fn into_encrypted_jwe(self, cipher: &JweA256KWEncipher) -> ServerResult<String> {
        let jwe = self.into_jwe()?;
        Ok(cipher.encipher::<JweA256GCMEncipher>(&jwe)?.to_string())
    }

    /// Parse an encrypted session cookie and check its validity period.
    fn from_encrypted_jwe(cipher: &JweA256KWEncipher, encrypted_jwe: &str) -> ServerResult<Self> {
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

    /// Load an encrypted [`SessionCookie`] from the [`CookieJar`].
    ///
    /// Returns `None` if the cookie is missing or invalid.
    pub fn from_jar(jar: &CookieJar, cipher: &JweA256KWEncipher) -> Option<Self> {
        let cookie = jar.get(COOKIE_NAME)?;
        Self::from_encrypted_jwe(cipher, cookie.value_trimmed()).ok()
    }

    /// Put an encrypted [`SessionCookie`] into the [`CookieJar`].
    pub fn put_to_jar(
        self,
        cipher: &JweA256KWEncipher,
        jar: &mut CookieJar,
        secure: bool,
    ) -> ServerResult {
        let encrypted_payload = self.into_encrypted_jwe(cipher)?;
        let mut cookie = build_cookie(secure);
        cookie.set_value(encrypted_payload);
        jar.add(cookie);
        Ok(())
    }
}

/// Get a [`CookieJar`] from [`HeaderMap`].
pub async fn get_cookie_jar() -> Result<CookieJar, ServerFnError> {
    let headers: HeaderMap = extract().await?;
    let mut jar = CookieJar::new();
    let mut max_cookies = 32;
    for h in headers.get_all(COOKIE) {
        let Ok(v) = h.to_str() else {
            continue;
        };
        let Ok(cookie) = Cookie::parse_encoded(v) else {
            continue;
        };

        jar.add_original(cookie.into_owned());

        if max_cookies == 0 {
            break;
        }
        max_cookies -= 1;
    }

    Ok(jar)
}

/// Put a [`CookieJar`] into response headers.
pub async fn put_cookie_jar(jar: CookieJar) -> Result<(), ServerFnError> {
    let Some(response) = use_context::<ResponseOptions>() else {
        return Err(ServerFnError::new("putting response headers"));
    };

    for h in jar.delta() {
        response.append_header(SET_COOKIE, HeaderValue::from_str(&h.encoded().to_string())?);
    }

    Ok(())
}

/// Template for `webauthn-rs-demo`'s session cookie.
fn build_cookie(secure: bool) -> Cookie<'static> {
    let cookie = Cookie::build(COOKIE_NAME)
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(secure)
        .path("/")
        .max_age(MAX_AGE);

    cookie.build()
}

/// Remove the session cookie from the [`CookieJar`]
pub fn delete_session_cookie(jar: &mut CookieJar, secure: bool) {
    jar.remove(build_cookie(secure));
}
