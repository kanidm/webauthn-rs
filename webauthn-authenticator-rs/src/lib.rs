#![deny(warnings)]
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

pub mod error;
pub mod softpasskey;
pub mod softtoken;

#[cfg(feature = "nfc")]
pub mod nfc;

#[cfg(feature = "u2fhid")]
pub mod u2fhid;

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
