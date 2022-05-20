//! Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and authenticators
//! to allow strong, passwordless, cryptographic authentication to be performed. Webauthn
//! is able to operate with many authenticator types, such as U2F, TouchID, Windows Hello
//! and many more.
//!
//! This library aims to provide a secure Webauthn implementation that you can
//! plug into your application, so that you can provide Webauthn to your users.
//!
//! There are a number of focused use cases that this library provides, which are described in
//! the [WebauthnBuilder] and [Webauthn] struct.
//!
//! # Getting started
//!
//! ```
//! use webauthn_rs::prelude::*;
//!
//! let rp_id = "example.com";
//! let rp_origin = Url::parse("https://idm.example.com")
//!     .expect("Invalid URL");
//! let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)
//!     .expect("Invalid configuration");
//! let webauthn = builder.build()
//!     .expect("Invalid configuration");
//!
//! // Initiate a basic registration flow, allowing any cryptograhpic authenticator to proceed.
//! let (ccr, skr) = webauthn
//!     .start_securitykey_registration(
//!         "claire",
//!         None,
//!         None,
//!         None,
//!     )
//!     .expect("Failed to start registration.");
//! ```
//!
//! After this point you then need to use `finish_securitykey_registration`, followed by
//! `start_securitykey_authentication` and `finish_securitykey_authentication`
//!

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(missing_docs)]

#[macro_use]
extern crate tracing;

mod interface;

use url::Url;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::*;
use webauthn_rs_core::WebauthnCore;

use crate::interface::*;

/// A prelude of types that are used by `Webauthn`
pub mod prelude {
    pub use crate::interface::*;
    pub use crate::{Webauthn, WebauthnBuilder};
    pub use url::Url;
    pub use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
    pub use webauthn_rs_core::proto::{AttestationCa, AttestationCaList, AuthenticatorAttachment};
    pub use webauthn_rs_core::proto::{PublicKeyCredential, RegisterPublicKeyCredential};
}

/// A constructor for a new [Webauthn] instance. This accepts and configures a number of site-wide
/// properties that apply to all webauthn operations of this service.
#[derive(Debug)]
pub struct WebauthnBuilder<'a> {
    rp_name: Option<&'a str>,
    rp_id: &'a str,
    rp_origin: &'a Url,
    allow_subdomains: bool,
    algorithms: Vec<COSEAlgorithm>,
}

/// An instance of a Webauthn site. This is the main point of interaction for registering and
/// authenticating credentials for users.
#[derive(Debug)]
pub struct Webauthn {
    core: WebauthnCore,
    algorithms: Vec<COSEAlgorithm>,
}

impl<'a> WebauthnBuilder<'a> {
    /// Initiate a new builder. This takes the relying party id and relying party origin.
    ///
    /// # Safety
    ///
    /// rp_id is what Credentials (Authenticators) bind themself to - rp_id can NOT be changed
    /// without potentially breaking all of your associated credentials in the future!
    ///
    /// # Examples
    ///
    /// ```
    /// use webauthn_rs::prelude::*;
    ///
    /// let rp_id = "example.com";
    /// let rp_origin = Url::parse("https://idm.example.com")
    ///     .expect("Invalid URL");
    /// let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)
    ///     .expect("Invalid configuration");
    /// ```
    ///
    /// # Errors
    ///
    /// rp_id *must* be an effective domain of rp_origin. This means that if you are hosting
    /// `https://idm.example.com`, rp_id must be `idm.example.com`, `example.com` or `com`.
    ///
    /// ```
    /// use webauthn_rs::prelude::*;
    ///
    /// let rp_id = "example.com";
    /// let rp_origin = Url::parse("https://idm.different.com")
    ///     .expect("Invalid URL");
    /// assert!(WebauthnBuilder::new(rp_id, &rp_origin).is_err());
    /// ```
    pub fn new(rp_id: &'a str, rp_origin: &'a Url) -> WebauthnResult<Self> {
        // Check the rp_name and rp_id.
        let valid = rp_origin
            .domain()
            .map(|effective_domain| {
                // We need to prepend the '.' here to ensure that myexample.com != example.com,
                // rather than just ends with.
                effective_domain.ends_with(&format!(".{}", rp_id)) || effective_domain == rp_id
            })
            .unwrap_or(false);

        if valid {
            Ok(WebauthnBuilder {
                rp_name: None,
                rp_id,
                rp_origin,
                allow_subdomains: false,
                algorithms: COSEAlgorithm::secure_algs(),
            })
        } else {
            error!("rp_id is not an effective_domain of rp_origin");
            Err(WebauthnError::Configuration)
        }
    }

    /// Setting this flag to true allows subdomains to be considered valid in Webauthn operations.
    /// An example of this is if you wish for `https://au.idm.example.com` to be a valid domain
    /// for Webauthn when the configuration is `https://idm.example.com`. Generally this occurs
    /// when you have a centralised IDM system, but location specific systems with DNS based
    /// redirection or routing.
    ///
    /// If in doubt, do NOT change this value. Defaults to "false".
    pub fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    /// Set the relying party name. This may be shown to the user. This value can be changed in
    /// the future without affecting credentials that have already registered.
    ///
    /// If not set, defaults to rp_id.
    pub fn rp_name(mut self, rp_name: &'a str) -> Self {
        self.rp_name = Some(rp_name);
        self
    }

    /// Complete the construction of the [Webauthn] instance. If an invalid configuration setting
    /// is found, an Error may be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use webauthn_rs::prelude::*;
    ///
    /// let rp_id = "example.com";
    /// let rp_origin = Url::parse("https://idm.example.com")
    ///     .expect("Invalid URL");
    /// let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)
    ///     .expect("Invalid configuration");
    /// let webauthn = builder.build()
    ///     .expect("Invalid configuration");
    /// ```
    pub fn build(self) -> WebauthnResult<Webauthn> {
        Ok(Webauthn {
            core: unsafe {
                WebauthnCore::new(
                    self.rp_name.unwrap_or(self.rp_id),
                    self.rp_id,
                    self.rp_origin,
                    None,
                    Some(self.allow_subdomains),
                )
            },
            algorithms: self.algorithms,
        })
    }
}

impl Webauthn {
    /// Initiate the registration of a new security key for a user. A security key is any cryptographic
    /// authenticator acting as a single factor of authentication to supplement a password or some
    /// other authentication factor.
    ///
    /// Some examples of security keys include Yubikeys, TouchID, FaceID, Windows Hello and others.
    ///
    /// You *should* pair this authentication with another factor. A security key may opportunistically
    /// allow and enforce user-verification (MFA), but this is NOT guaranteed.
    ///
    /// `user_name` and `user_display_name` *may* be stored in the authenticator, and presented to
    /// the user during authentication workflows in the future. If `user_display_name` is not provided,
    /// `user_name` will be used.
    ///
    /// `exclude_credentials` ensures that a set of credentials may not participate in this registration.
    /// You *should* provide the list of credentials that are already registered to this user's account
    /// to prevent duplicate credential registrations.
    ///
    /// `attestation_ca_list` contains an optional list of Root CA certificates of authenticator
    /// manufacturers that you wish to trust. For example, if you want to only allow Yubikeys on
    /// your site, then you can provide the Yubico Root CA in this list, to validate that all
    /// registered devices are manufactured by Yubico.
    ///
    /// Extensions may ONLY be accessed if an `attestation_ca_list` is provided, else they can
    /// NOT be trusted.
    ///
    /// # Returns
    ///
    /// This function returns a `CreationChallengeResponse` which you must serialise to json and
    /// send to the user agent (e.g. a browser) for it to conduct the registration. You must persist
    /// on the server the `SecurityKeyRegistration` which contains the state of this registration
    /// attempt and is paired to the `CreationChallengeResponse`.
    ///
    /// ```
    /// # use webauthn_rs::prelude::*;
    ///
    /// # let rp_id = "example.com";
    /// # let rp_origin = Url::parse("https://idm.example.com")
    /// #     .expect("Invalid URL");
    /// # let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)
    /// #     .expect("Invalid configuration");
    /// # let webauthn = builder.build()
    /// #     .expect("Invalid configuration");
    ///
    /// // Initiate a basic registration flow, allowing any cryptograhpic authenticator to proceed.
    /// let (ccr, skr) = webauthn
    ///     .start_securitykey_registration(
    ///         "claire",
    ///         None,
    ///         None,
    ///         None,
    ///     )
    ///     .expect("Failed to start registration.");
    ///
    /// // Only allow credentials from manufacturers that are trusted and part of the webauthn-rs
    /// // strict "high quality" list.
    /// let (ccr, skr) = webauthn
    ///     .start_securitykey_registration(
    ///         "claire",
    ///         None,
    ///         None,
    ///         Some(AttestationCaList::strict()),
    ///     )
    ///     .expect("Failed to start registration.");
    /// ```
    pub fn start_securitykey_registration(
        &self,
        user_name: &str,
        user_display_name: Option<&str>,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_ca_list: Option<AttestationCaList>,
        // extensions
    ) -> WebauthnResult<(CreationChallengeResponse, SecurityKeyRegistration)> {
        let attestation = if attestation_ca_list.is_some() {
            AttestationConveyancePreference::Direct
        } else {
            AttestationConveyancePreference::None
        };
        let extensions = None;
        let credential_algorithms = self.algorithms.clone();
        let require_resident_key = false;
        let authenticator_attachment = None;
        let policy = Some(UserVerificationPolicy::Preferred);
        let reject_passkeys = false;

        self.core
            .generate_challenge_register_options(
                user_name.to_string(),
                user_display_name.unwrap_or(user_name).to_string(),
                attestation,
                policy,
                exclude_credentials,
                extensions,
                credential_algorithms,
                require_resident_key,
                authenticator_attachment,
                reject_passkeys,
            )
            .map(|(ccr, rs)| {
                (
                    ccr,
                    SecurityKeyRegistration {
                        rs,
                        ca_list: attestation_ca_list,
                    },
                )
            })
    }

    /// Complete the registration of the credential. The user agent (e.g. a browser) will return the data of `RegisterPublicKeyCredential`,
    /// and the server provides it's paired `SecurityKeyRegistration`. The details of the Authenticator
    /// based on the registration parameters are asserted.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will be returned. See [WebauthnError].
    ///
    /// # Returns
    ///
    /// The returned `SecurityKey` must be associated to the users account, and is used for future
    /// authentications via `start_securitykey_authentication`.
    ///
    /// You MUST assert that the registered credential id has not previously been registered.
    /// to any other account.
    pub fn finish_securitykey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &SecurityKeyRegistration,
    ) -> WebauthnResult<SecurityKey> {
        self.core
            .register_credential(reg, &state.rs, state.ca_list.as_ref())
            .map(|cred| SecurityKey { cred })
    }

    /// Given a set of `SecurityKey`'s, begin an authentication of the user. This returns
    /// a `RequestChallengeResponse`, which should be serialised to json and sent to the user agent (e.g. a browser).
    /// The server must persist the `SecurityKeyAuthentication` state as it is paired to the
    /// `RequestChallengeResponse` and required to complete the authentication.
    pub fn start_securitykey_authentication(
        &self,
        creds: &[SecurityKey],
    ) -> WebauthnResult<(RequestChallengeResponse, SecurityKeyAuthentication)> {
        let extensions = None;
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, SecurityKeyAuthentication { ast }))
    }

    /// Given the `PublicKeyCredential` returned by the user agent (e.g. a browser), and the stored `SecurityKeyAuthentication`
    /// complete the authentication of the user.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will be returned. See [WebauthnError].
    ///
    /// # Returns
    /// On success, `AuthenticationResult` is returned which contains some details of the Authentication
    /// process.
    ///
    /// As per <https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion> 21:
    ///
    /// If the Credential Counter is greater than 0 you MUST assert that the counter is greater than
    /// the stored counter. If the counter is equal or less than this MAY indicate a cloned credential
    /// and you SHOULD invalidate and reject that credential as a result.
    ///
    /// From this `AuthenticationResult` you *should* update the Credential's Counter value if it is
    /// valid per the above check. If you wish
    /// you *may* use the content of the `AuthenticationResult` for extended validations (such as the
    /// user verification flag).
    pub fn finish_securitykey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &SecurityKeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.core.authenticate_credential(reg, &state.ast)
    }

    /// Initiate the registration of a new passwordless key for a user. A passwordless key is a
    /// cryptographic authenticator that is a self-contained multifactor authenticator. This means
    /// that the device (such as a yubikey) verifies the user is who they say they are via a PIN,
    /// biometric or other factor. Only if this verification passes, is the signature released
    /// and provided.
    ///
    /// As a result, the server *only* requires this passwordless key to authenticator the user
    /// and assert their identity.
    ///
    /// You *should* recommend to the user to register multiple passwordkeys to their account on
    /// seperate devices so that they have fall back authentication.
    ///
    /// You *should* have a workflow that allows a user to register new devices without a need to register
    /// other factors. For example, allow a QR code that can be scanned from a phone, or a one-time
    /// link that can be copied to the device.
    ///
    /// You *must* have a recovery workflow in case all devices are lost or destroyed.
    ///
    /// `user_name` and `user_display_name` *may* be stored in the authenticator, and presented to
    /// the user during authentication workflows in the future. If `user_display_name` is not provided,
    /// `user_name` will be used.
    ///
    /// `exclude_credentials` ensures that a set of credentials may not participate in this registration.
    /// You *should* provide the list of credentials that are already registered to this user's account
    /// to prevent duplicate credential registrations.
    ///
    /// `attestation_ca_list` contains an optional list of Root CA certificates of authenticator
    /// manufacturers that you wish to trust. For example, if you want to only allow Yubikeys on
    /// your site, then you can provide the Yubico Root CA in this list, to validate that all
    /// registered devices are manufactured by Yubico.
    ///
    /// extensions may ONLY be accessed if an `attestation_ca_list` is provided, else they can
    /// NOT be trusted.
    ///
    /// You *should* strongly consider using an `attestation_ca_list` with passwordless credentials
    /// to ensure that trusted devices are used only.
    ///
    /// # Returns
    ///
    /// This function returns a `CreationChallengeResponse` which you must serialise to json and
    /// send to the user agent (e.g. a browser) for it to conduct the registration. You must persist
    /// on the server the `PasswordlessKeyRegistration` which contains the state of this registration
    /// attempt and is paired to the `CreationChallengeResponse`.
    ///
    /// ```
    /// # use webauthn_rs::prelude::*;
    ///
    /// # let rp_id = "example.com";
    /// # let rp_origin = Url::parse("https://idm.example.com")
    /// #     .expect("Invalid url");
    /// # let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)
    /// #     .expect("Invalid configuration");
    /// # let webauthn = builder.build()
    /// #     .expect("Invalid configuration");
    ///
    /// // Initiate a basic registration flow, allowing any cryptograhpic authenticator to proceed.
    /// // Hint (but do not enforce) that we prefer this to be a token/key like a yubikey.
    /// let (ccr, skr) = webauthn
    ///     .start_passwordlesskey_registration(
    ///         "claire",
    ///         None,
    ///         None,
    ///         None,
    ///         Some(AuthenticatorAttachment::CrossPlatform),
    ///     )
    ///     .expect("Failed to start registration.");
    ///
    /// // Only allow credentials from manufacturers that are trusted and part of the webauthn-rs
    /// // strict "high quality" list.
    /// // Hint (but do not enforce) that we prefer this to be a device like TouchID.
    /// // To enforce this you can only trust Attestation CA's for embeded types IE TPM or Apple.
    /// let (ccr, skr) = webauthn
    ///     .start_passwordlesskey_registration(
    ///         "claire",
    ///         None,
    ///         None,
    ///         Some(AttestationCaList::strict()),
    ///         Some(AuthenticatorAttachment::Platform),
    ///     )
    ///     .expect("Failed to start registration.");
    /// ```
    pub fn start_passwordlesskey_registration(
        &self,
        user_name: &str,
        user_display_name: Option<&str>,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_ca_list: Option<AttestationCaList>,
        ui_hint_authenticator_attachment: Option<AuthenticatorAttachment>,
        // extensions
    ) -> WebauthnResult<(CreationChallengeResponse, PasswordlessKeyRegistration)> {
        let attestation = AttestationConveyancePreference::Direct;
        let credential_algorithms = self.algorithms.clone();
        let require_resident_key = false;
        let policy = Some(UserVerificationPolicy::Required);
        let reject_passkeys = true;

        // https://www.w3.org/TR/webauthn-2/#sctn-uvm-extension
        // UVM
        // If rk - credProps

        // credProtect
        let extensions = None;
        /*
        let extensions = Some(RequestRegistrationExtensions {
            cred_protect: Some(CredProtect {
                credential_protection_policy: CredentialProtectionPolicy::UserVerificationRequired,
                // If set to true, causes many authenticators to shit the bed.
                enforce_credential_protection_policy: Some(false),
            }),
            cred_blob: None,
            uvm: Some(true),
            cred_props: Some(true),
        });
        */

        // min pin

        self.core
            .generate_challenge_register_options(
                user_name.to_string(),
                user_display_name.unwrap_or(user_name).to_string(),
                attestation,
                policy,
                exclude_credentials,
                extensions,
                credential_algorithms,
                require_resident_key,
                ui_hint_authenticator_attachment,
                reject_passkeys,
            )
            .map(|(ccr, rs)| {
                (
                    ccr,
                    PasswordlessKeyRegistration {
                        rs,
                        ca_list: attestation_ca_list,
                    },
                )
            })
    }

    /// Complete the registration of the credential. The user agent (e.g. a browser) will return the data of `RegisterPublicKeyCredential`,
    /// and the server provides it's paired `PasswordlessKeyRegistration`. The details of the Authenticator
    /// based on the registration parameters are asserted.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will be returned. See [WebauthnError].
    ///
    /// # Returns
    /// The returned `PasswordlessKey` must be associated to the users account, and is used for future
    /// authentications via `start_passwordlesskey_authentication`.
    pub fn finish_passwordlesskey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasswordlessKeyRegistration,
    ) -> WebauthnResult<PasswordlessKey> {
        // TODO: Check the AttestationCa List!!
        self.core
            .register_credential(reg, &state.rs, state.ca_list.as_ref())
            .map(|cred| PasswordlessKey { cred })
    }

    /// Given a set of `PasswordlessKey`'s, begin an authentication of the user. This returns
    /// a `RequestChallengeResponse`, which should be serialised to json and sent to the user agent (e.g. a browser).
    /// The server must persist the `PasswordlessKeyAuthentication` state as it is paired to the
    /// `RequestChallengeResponse` and required to complete the authentication.
    pub fn start_passwordlesskey_authentication(
        &self,
        creds: &[PasswordlessKey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasswordlessKeyAuthentication)> {
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();

        let extensions = Some(RequestAuthenticationExtensions {
            get_cred_blob: Some(CredBlobGet(true)),
            appid: None,
            uvm: Some(true),
        });

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, PasswordlessKeyAuthentication { ast }))
    }

    /// Given the `PublicKeyCredential` returned by the user agent (e.g. a browser), and the stored `PasswordlessKeyAuthentication`
    /// complete the authentication of the user. This asserts that user verification must have been correctly
    /// performed allowing you to trust this as a MFA interfaction.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will be returned. See [WebauthnError].
    ///
    /// # Returns
    /// On success, `AuthenticationResult` is returned which contains some details of the Authentication
    /// process.
    ///
    /// As per <https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion> 21:
    ///
    /// If the Credential Counter is greater than 0 you MUST assert that the counter is greater than
    /// the stored counter. If the counter is equal or less than this MAY indicate a cloned credential
    /// and you SHOULD invalidate and reject that credential as a result.
    ///
    /// From this `AuthenticationResult` you *should* update the Credential's Counter value if it is
    /// valid per the above check. If you wish
    /// you *may* use the content of the `AuthenticationResult` for extended validations (such as the
    /// user verification flag).
    pub fn finish_passwordlesskey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &PasswordlessKeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.core.authenticate_credential(reg, &state.ast)
    }

    /*
    // Register a trusted device credential
    /// * Must be verified
    /// * Must be attested
    /// * Must be a DEVICE (platform) credential
    /// * May request a pin length
    /// * Must return what TYPE of UV (?)
    /// * Must be platform attached
    /// * Need to use credProps
    /// * Optional - RK
     */

    // Authenticate ^
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
