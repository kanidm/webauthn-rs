//! webauthn-authenticator-rs is a library for interfacing with FIDO/CTAP 2
//! tokens.
//!
//! This performs the actions that would be taken by a client application (such
//! as a web browser) to facilitate authentication with a remote service.
//!
//! This library aims to provide abstrations over many platform-specific APIs,
//! so that client applications don't need to worry as much about the finer
//! details of the protocol.
//!
//! **This is a "pre-1.0" library:** it is still under active development, and
//! the API is not yet stable or final. *Some of the modules have edge cases
//! which may cause you to get permanently locked out of your authenticator.*
//!
//! This library is not FIDO certified, and currently lacks a thorough security
//! review.
//!
//! ## FIDO / CTAP version support
//!
//! This library currently only supports CTAP 2.0, 2.1 or 2.1-PRE.
//!
//! Authenticators which **only** support CTAP 1.x (U2F) are *unsupported*. This
//! generally only is an issue for older tokens.
//!
//! The authors of this library recommend using [FIDO2 certified][] hardware
//! authenticators with at least [Autenticator Certification Level 2][cert].
//! Be cautious when buying, as there are many products on the market which
//! falsely claim certification, have implementation errors, only support U2F,
//! or use off-the-shelf microcontrollers which do not protect key material
//! ([Level 1][cert]).
//!
//! ## Features and backends
//!
//! **Note:** these links may be broken unless you build the documentation with
//! the appropriate `--features` flag listed inline.
//!
//! * [CTAP 2.0, 2.1 and 2.1-PRE protocol implementation][crate::ctap2]
//! * [caBLE][] (with `--features cable`)
//! * [Mozilla Authenticator][] (with `--features u2fhid`)
//! * [NFC][] via PC/SC API (with `--features nfc`)
//! * [SoftPasskey][] (for testing)
//! * [SoftToken][] (for testing)
//! * [USB HID][] (with `--features usb`)
//! * [Windows 10][] WebAuthn API (with `--features win10`)
//!
//! [FIDO2 certified]: https://fidoalliance.org/fido-certified-showcase/
//! [cert]: https://fidoalliance.org/certification/authenticator-certification-levels/
//! [caBLE]: crate::cable
//! [Mozilla Authenticator]: crate::u2fhid
//! [NFC]: crate::nfc
//! [SoftPasskey]: crate::softpasskey
//! [SoftToken]: crate::softtoken
//! [USB HID]: crate::usb
//! [Windows 10]: crate::win10

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// #![deny(warnings)]
#![warn(unused_extern_crates)]
// #![warn(missing_docs)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
// #![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate tracing;

#[macro_use]
extern crate num_derive;

use crate::error::WebauthnCError;
use url::Url;

use webauthn_rs_proto::{
    CreationChallengeResponse, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential, RequestChallengeResponse,
};

pub mod prelude {
    pub use crate::error::WebauthnCError;
    pub use crate::WebauthnAuthenticator;
    pub use url::Url;
    pub use webauthn_rs_proto::{
        CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
        RequestChallengeResponse,
    };
}

mod authenticator_hashed;
mod crypto;
pub mod ctap2;
pub mod error;
pub mod softpasskey;
pub mod softtoken;
pub mod transport;
pub mod types;
pub mod ui;
mod util;

#[cfg(any(doc, feature = "cable"))]
pub mod cable;

#[cfg(any(doc, feature = "nfc"))]
pub mod nfc;

#[cfg(any(doc, feature = "usb"))]
pub mod usb;

#[cfg(any(doc, feature = "u2fhid"))]
pub mod u2fhid;

#[cfg(any(doc, feature = "win10"))]
pub mod win10;

#[cfg(doc)]
#[doc(hidden)]
mod stubs;

pub use crate::authenticator_hashed::{
    perform_auth_with_request, perform_register_with_request, AuthenticatorBackendHashedClientData,
};

pub struct WebauthnAuthenticator<T>
where
    T: AuthenticatorBackend,
{
    backend: T,
}

pub trait AuthenticatorBackend {
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError>;

    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError>;
}

impl<T> WebauthnAuthenticator<T>
where
    T: AuthenticatorBackend,
{
    pub fn new(backend: T) -> Self {
        WebauthnAuthenticator { backend }
    }
}

impl<T> WebauthnAuthenticator<T>
where
    T: AuthenticatorBackend,
{
    /// 5.1.3. Create a New Credential - PublicKeyCredential’s Create (origin, options, sameOriginWithAncestors) Method
    /// <https://www.w3.org/TR/webauthn/#createCredential>
    ///
    /// 6.3.2. The authenticatorMakeCredential Operation
    /// <https://www.w3.org/TR/webauthn/#op-make-cred>
    pub fn do_registration(
        &mut self,
        origin: Url,
        options: CreationChallengeResponse,
        // _same_origin_with_ancestors: bool,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        // Assert: options.publicKey is present.
        // This is asserted through rust types.

        // If sameOriginWithAncestors is false, return a "NotAllowedError" DOMException.
        // We just don't take this value.

        // Let options be the value of options.publicKey.
        let options = options.public_key;

        // If the timeout member of options is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present, then set lifetimeTimer to a client-specific default.
        let timeout_ms = options
            .timeout
            .map(|t| if t > 60000 { 60000 } else { t })
            .unwrap_or(60000);

        // Let callerOrigin be origin. If callerOrigin is an opaque origin, return a DOMException whose name is "NotAllowedError", and terminate this algorithm.
        // This is a bit unclear - see https://github.com/w3c/wpub/issues/321.
        // It may be a browser specific quirk.
        // https://html.spec.whatwg.org/multipage/origin.html
        // As a result we don't need to check for our needs.

        // Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then return a DOMException whose name is "Security" and terminate this algorithm.
        let effective_domain = origin
            .domain()
            // Checking by IP today muddies things. We'd need a check for rp.id about suffixes
            // to be different for this.
            // .or_else(|| caller_origin.host_str())
            .ok_or(WebauthnCError::Security)
            .map_err(|e| {
                error!("origin has no domain or host_str (ip address only?)");
                e
            })?;

        trace!("effective domain -> {:x?}", effective_domain);
        trace!("relying party id -> {:x?}", options.rp.id);

        // If options.rp.id
        //      Is present
        //          If options.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, return a DOMException whose name is "Security", and terminate this algorithm.
        //      Is not present
        //          Set options.rp.id to effectiveDomain.

        if !effective_domain.ends_with(&options.rp.id) {
            error!("relying party id domain is not a suffix of the effective domain.");
            return Err(WebauthnCError::Security);
        }

        // Check origin is https:// if effectiveDomain != localhost.
        if !(effective_domain == "localhost" || origin.scheme() == "https") {
            error!("An insecure domain or scheme in origin. Must be localhost or https://");
            return Err(WebauthnCError::Security);
        }

        self.backend.perform_register(origin, options, timeout_ms)
    }

    /// <https://www.w3.org/TR/webauthn/#getAssertion>
    pub fn do_authentication(
        &mut self,
        origin: Url,
        options: RequestChallengeResponse,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        // Assert: options.publicKey is present.
        // This is asserted through rust types.

        // If sameOriginWithAncestors is false, return a "NotAllowedError" DOMException.
        // We just don't take this value.

        // Let options be the value of options.publicKey.
        let options = options.public_key;

        // If the timeout member of options is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present, then set lifetimeTimer to a client-specific default.
        let timeout_ms = options
            .timeout
            .map(|t| if t > 60000 { 60000 } else { t })
            .unwrap_or(60000);

        // Let callerOrigin be origin. If callerOrigin is an opaque origin, return a DOMException whose name is "NotAllowedError", and terminate this algorithm.
        // This is a bit unclear - see https://github.com/w3c/wpub/issues/321.
        // It may be a browser specific quirk.
        // https://html.spec.whatwg.org/multipage/origin.html
        // As a result we don't need to check for our needs.

        // Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then return a DOMException whose name is "Security" and terminate this algorithm.
        let effective_domain = origin
            .domain()
            // Checking by IP today muddies things. We'd need a check for rp.id about suffixes
            // to be different for this.
            // .or_else(|| caller_origin.host_str())
            .ok_or(WebauthnCError::Security)
            .map_err(|e| {
                error!("origin has no domain or host_str");
                e
            })?;

        trace!("effective domain -> {:x?}", effective_domain);
        trace!("relying party id -> {:x?}", options.rp_id);

        // If options.rp.id
        //      Is present
        //          If options.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, return a DOMException whose name is "Security", and terminate this algorithm.
        //      Is not present
        //          Set options.rp.id to effectiveDomain.

        if !effective_domain.ends_with(&options.rp_id) {
            error!("relying party id domain is not suffix of effective domain.");
            return Err(WebauthnCError::Security);
        }

        // Check origin is https:// if effectiveDomain != localhost.
        if !(effective_domain == "localhost" || origin.scheme() == "https") {
            error!("An insecure domain or scheme in origin. Must be localhost or https://");
            return Err(WebauthnCError::Security);
        }

        self.backend.perform_auth(origin, options, timeout_ms)
    }
}
