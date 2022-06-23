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
//! In the simplest case where you just want a password replacement, you should use our passkey flow.
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
//! // Initiate a basic registration flow to enroll a cryptographic authenticator
//! let (ccr, skr) = webauthn
//!     .start_passkey_registration(
//!         Uuid::new_v4(),
//!         "claire",
//!         "Claire",
//!         None,
//!     )
//!     .expect("Failed to start registration.");
//! ```
//!
//! After this point you then need to use `finish_passkey_registration`, followed by
//! `start_passkey_authentication` and `finish_passkey_authentication`
//!

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(missing_docs)]

#[macro_use]
extern crate tracing;

mod interface;
// mod trust;

use url::Url;
use uuid::Uuid;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::*;
use webauthn_rs_core::WebauthnCore;

use crate::interface::*;

/// A prelude of types that are used by `Webauthn`
pub mod prelude {
    pub use crate::interface::*;
    pub use crate::{Webauthn, WebauthnBuilder};
    pub use base64urlsafedata::Base64UrlSafeData;
    pub use url::Url;
    pub use uuid::Uuid;
    pub use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
    pub use webauthn_rs_core::proto::{AttestationCa, AttestationCaList, AuthenticatorAttachment};
    pub use webauthn_rs_core::proto::{
        AuthenticationState, Credential, CredentialID, ParsedAttestationData, PublicKeyCredential,
        RegisterPublicKeyCredential,
    };
    pub use webauthn_rs_core::AttestationFormat;
}

/// A constructor for a new [Webauthn] instance. This accepts and configures a number of site-wide
/// properties that apply to all webauthn operations of this service.
#[derive(Debug)]
pub struct WebauthnBuilder<'a> {
    rp_name: Option<&'a str>,
    rp_id: &'a str,
    rp_origin: &'a Url,
    allow_subdomains: bool,
    allow_any_port: bool,
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
                allow_any_port: false,
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

    /// Setting this flag skips port checks on origin matches
    pub fn allow_any_port(mut self, allow: bool) -> Self {
        self.allow_any_port = allow;
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
            core: WebauthnCore::new_unsafe_experts_only(
                self.rp_name.unwrap_or(self.rp_id),
                self.rp_id,
                self.rp_origin,
                None,
                Some(self.allow_subdomains),
                Some(self.allow_any_port),
            ),
            algorithms: self.algorithms,
        })
    }
}

/// An instance of a Webauthn site. This is the main point of interaction for registering and
/// authenticating credentials for users. Depending on your needs, you'll want to allow users
/// to register and authenticate with different kinds of authenticators.
///
/// *I just want something to replace passwords, and I don't have other requirements*
///
/// --> You should use `start_securitykey_registration`
///
/// *I want to replace passwords with strong, multi-factor cryptographic authentication, limited to
/// a known set of trusted authenticator types*
///
/// --> You should use `start_passwordlesskey_registration`
///
/// *I want a security token along with a password to create multi-factor authentication*
///
/// If possible, consider `start_passwordlesskey_registration` instead - it's probably what you
/// want! But if not, and you really want a security key, you should use `start_securitykey_registration`
///
/// In the future we will also add "devicekey"'s which both identify and authenticate the user without
/// need to enter a username or other identity information.
#[derive(Debug)]
pub struct Webauthn {
    core: WebauthnCore,
    algorithms: Vec<COSEAlgorithm>,
}

impl Webauthn {
    /// Initiate the registration of a new pass key for a user. A pass key is any cryptographic
    /// authenticator acting as a single factor of authentication, far stronger than a password
    /// or email-reset link.
    ///
    /// Some examples of pass keys include Yubikeys, TouchID, FaceID, Windows Hello and others.
    ///
    /// You *should* NOT pair this authentication with another factor. A pass key may opportunistically
    /// allow and enforce user-verification (MFA), but this is NOT guaranteed.
    ///
    /// `user_unique_id` *may* be stored in the authenticator. This may allow the credential to
    ///  identify the user during certain client side work flows.
    ///
    /// `user_name` and `user_display_name` *may* be stored in the authenticator. `user_name` is a
    /// friendly account name such as "claire@example.com". `user_display_name` is the persons chosen
    /// way to be identified such as "Claire". Both can change at *any* time on the client side, and
    /// MUST NOT be used as primary keys. They *may not* be present in authentication, these are only
    /// present to allow client work flows to display human friendly identifiers.
    ///
    /// `exclude_credentials` ensures that a set of credentials may not participate in this registration.
    /// You *should* provide the list of credentials that are already registered to this user's account
    /// to prevent duplicate credential registrations. These credentials *can* be from different
    /// authenticator classes since we only require the `CredentialID`
    ///
    /// # Returns
    ///
    /// This function returns a `CreationChallengeResponse` which you must serialise to json and
    /// send to the user agent (e.g. a browser) for it to conduct the registration. You must persist
    /// on the server the `PassKeyRegistration` which contains the state of this registration
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
    ///     .start_passkey_registration(
    ///         Uuid::new_v4(),
    ///         "claire",
    ///         "Claire",
    ///         None, // No other credentials are registered yet.
    ///     )
    ///     .expect("Failed to start registration.");
    ///
    /// // Only allow credentials from manufacturers that are trusted and part of the webauthn-rs
    /// // strict "high quality" list.
    /// let (ccr, skr) = webauthn
    ///     .start_passkey_registration(
    ///         Uuid::new_v4(),
    ///         "claire",
    ///         "Claire",
    ///         None, // No other credentials are registered yet.
    ///     )
    ///     .expect("Failed to start registration.");
    /// ```
    pub fn start_passkey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PassKeyRegistration)> {
        let attestation = AttestationConveyancePreference::None;
        let extensions = None;
        let credential_algorithms = self.algorithms.clone();
        let require_resident_key = false;
        let authenticator_attachment = None;
        let policy = Some(UserVerificationPolicy::Preferred);
        let reject_passkeys = false;

        self.core
            .generate_challenge_register_options(
                user_unique_id.as_bytes(),
                user_name,
                user_display_name,
                attestation,
                policy,
                exclude_credentials,
                extensions,
                credential_algorithms,
                require_resident_key,
                authenticator_attachment,
                reject_passkeys,
            )
            .map(|(ccr, rs)| (ccr, PassKeyRegistration { rs }))
    }

    /// Complete the registration of the credential. The user agent (e.g. a browser) will return the data of `RegisterPublicKeyCredential`,
    /// and the server provides it's paired `PassKeyRegistration`. The details of the Authenticator
    /// based on the registration parameters are asserted.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will be returned. See [WebauthnError].
    ///
    /// # Returns
    ///
    /// The returned `PassKey` must be associated to the users account, and is used for future
    /// authentications via `start_passkey_authentication`.
    ///
    /// You MUST assert that the registered credential id has not previously been registered.
    /// to any other account.
    pub fn finish_passkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PassKeyRegistration,
    ) -> WebauthnResult<PassKey> {
        self.core
            .register_credential(reg, &state.rs, None)
            .map(|cred| PassKey { cred })
    }

    /// Given a set of `PassKey`'s, begin an authentication of the user. This returns
    /// a `RequestChallengeResponse`, which should be serialised to json and sent to the user agent (e.g. a browser).
    /// The server must persist the `PassKeyAuthentication` state as it is paired to the
    /// `RequestChallengeResponse` and required to complete the authentication.
    pub fn start_passkey_authentication(
        &self,
        creds: &[PassKey],
    ) -> WebauthnResult<(RequestChallengeResponse, PassKeyAuthentication)> {
        let extensions = None;
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, PassKeyAuthentication { ast }))
    }

    /// Given the `PublicKeyCredential` returned by the user agent (e.g. a browser), and the stored `PassKeyAuthentication`
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
    /// presence of the user verification flag).
    pub fn finish_passkey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &PassKeyAuthentication,
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
    /// and assert their identity. Because of this reliance on the authenticator, attestation of
    /// the authenticator and it's properties required.
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
    /// `user_unique_id` *may* be stored in the authenticator. This may allow the credential to
    ///  identify the user during certain client side work flows.
    ///
    /// `user_name` and `user_display_name` *may* be stored in the authenticator. `user_name` is a
    /// friendly account name such as "claire@example.com". `user_display_name` is the persons chosen
    /// way to be identified such as "Claire". Both can change at *any* time on the client side, and
    /// MUST NOT be used as primary keys. They *may not* be present in authentication, these are only
    /// present to allow client work flows to display human friendly identifiers.
    ///
    /// `exclude_credentials` ensures that a set of credentials may not participate in this registration.
    /// You *should* provide the list of credentials that are already registered to this user's account
    /// to prevent duplicate credential registrations.
    ///
    /// `attestation_anonymise` determines if we should try to anonymise some details of the device
    /// that is being attested. If set to "true", then attestation is carried out in a privacy
    /// preserving manner. If set to "false" then the device may be directly identifiable. If in
    /// doubt, set to "true".
    ///
    /// `attestation_ca_list` contains an optional list of Root CA certificates of authenticator
    /// manufacturers that you wish to trust. For example, if you want to only allow Yubikeys on
    /// your site, then you can provide the Yubico Root CA in this list, to validate that all
    /// registered devices are manufactured by Yubico.
    ///
    /// `ui_hint_authenticator_attachment` provides a UX/UI hint to the browser about the types
    /// of credentials that could be used in this registration. If set to `None` all authenticator
    /// attachement classes are valid. If set to Platform, only authenticators that are part of the
    /// device are used such as a TPM or TouchId. If set to Cross-Platform, only devices that are
    /// removable from the device can be used such as yubikeys.
    ///
    /// Currently, extensions are *not* possible to request due to webauthn not properly supporting
    /// them in broader contexts.
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
    /// // To enforce this you can validate the properties of the returned device aaguid.
    /// let (ccr, skr) = webauthn
    ///     .start_passwordlesskey_registration(
    ///         Uuid::new_v4(),
    ///         "claire",
    ///         "Claire",
    ///         None,
    ///         true,
    ///         AttestationCaList::strict(),
    ///         Some(AuthenticatorAttachment::CrossPlatform),
    ///     )
    ///     .expect("Failed to start registration.");
    ///
    /// // Only allow credentials from manufacturers that are trusted and part of the webauthn-rs
    /// // strict "high quality" list.
    /// // Hint (but do not enforce) that we prefer this to be a device like TouchID.
    /// // To enforce this you can validate the attestation ca used along with the returned device aaguid
    /// let (ccr, skr) = webauthn
    ///     .start_passwordlesskey_registration(
    ///         Uuid::new_v4(),
    ///         "claire",
    ///         "Claire",
    ///         None,
    ///         true,
    ///         AttestationCaList::strict(),
    ///         Some(AuthenticatorAttachment::Platform),
    ///     )
    ///     .expect("Failed to start registration.");
    /// ```
    pub fn start_passwordlesskey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_anonymise: bool,
        attestation_ca_list: AttestationCaList,
        ui_hint_authenticator_attachment: Option<AuthenticatorAttachment>,
        // extensions
    ) -> WebauthnResult<(CreationChallengeResponse, PasswordlessKeyRegistration)> {
        let attestation = if attestation_anonymise {
            AttestationConveyancePreference::Indirect
        } else {
            AttestationConveyancePreference::Direct
        };
        let credential_algorithms = self.algorithms.clone();
        let require_resident_key = false;
        let policy = Some(UserVerificationPolicy::Required);
        let reject_passkeys = true;

        let extensions = Some(RequestRegistrationExtensions {
            cred_protect: None,
            cred_blob: None,
            uvm: Some(true),
            cred_props: Some(true),
            min_pin_length: Some(true),
            hmac_create_secret: Some(true),
        });

        self.core
            .generate_challenge_register_options(
                user_unique_id.as_bytes(),
                user_name,
                user_display_name,
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
            .register_credential(reg, &state.rs, Some(&state.ca_list))
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
            get_cred_blob: None,
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
    ///
    /// In *some* cases, you *may* be able to identify the user by examinin
    pub fn finish_passwordlesskey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &PasswordlessKeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.core.authenticate_credential(reg, &state.ast)
    }

    /// Initiate the registration of a new security key for a user. A security key is any cryptographic
    /// authenticator acting as a single factor of authentication to supplement a password or some
    /// other authentication factor.
    ///
    /// Some examples of security keys include Yubikeys, TouchID, FaceID, Windows Hello and others.
    ///
    /// You *should* pair this authentication with another factor. A security key may opportunistically
    /// allow and enforce user-verification (MFA), but this is NOT guaranteed.
    ///
    /// `user_unique_id` *may* be stored in the authenticator. This may allow the credential to
    ///  identify the user during certain client side work flows.
    ///
    /// `user_name` and `user_display_name` *may* be stored in the authenticator. `user_name` is a
    /// friendly account name such as "claire@example.com". `user_display_name` is the persons chosen
    /// way to be identified such as "Claire". Both can change at *any* time on the client side, and
    /// MUST NOT be used as primary keys. They *may not* be present in authentication, these are only
    /// present to allow client work flows to display human friendly identifiers.
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
    ///         Uuid::new_v4(),
    ///         "claire",
    ///         "Claire",
    ///         None,
    ///         None,
    ///     )
    ///     .expect("Failed to start registration.");
    ///
    /// // Only allow credentials from manufacturers that are trusted and part of the webauthn-rs
    /// // strict "high quality" list.
    /// let (ccr, skr) = webauthn
    ///     .start_securitykey_registration(
    ///         Uuid::new_v4(),
    ///         "claire",
    ///         "Claire",
    ///         None,
    ///         Some(AttestationCaList::strict()),
    ///     )
    ///     .expect("Failed to start registration.");
    /// ```
    pub fn start_securitykey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_ca_list: Option<AttestationCaList>,
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
        let reject_passkeys = true;

        self.core
            .generate_challenge_register_options(
                user_unique_id.as_bytes(),
                user_name,
                user_display_name,
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
}

#[cfg(feature = "discoverable_passkey")]
impl Webauthn {
    /// WIP DO NOT USE
    pub fn start_discoverable_passkey_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, PassKeyAuthentication)> {
        let extensions = None;
        let creds = Vec::with_capacity(0);

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, PassKeyAuthentication { ast }))
    }

    /// WIP DO NOT USE
    pub fn identify_discoverable_passkey_authentication(
        &self,
        reg: &PublicKeyCredential,
        _state: &PassKeyAuthentication,
    ) -> WebauthnResult<Uuid> {
        reg.get_user_unique_id()
            .and_then(|b| Uuid::from_slice(b).ok())
            .ok_or(WebauthnError::InvalidUserUniqueId)
    }

    /// WIP DO NOT USE
    pub fn finish_discoverable_passkey_authentication(
        &self,
        reg: &PublicKeyCredential,
        mut state: PassKeyAuthentication,
        creds: &[PassKey],
    ) -> WebauthnResult<AuthenticationResult> {
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();
        state.ast.set_allowed_credentials(creds);
        self.core.authenticate_credential(reg, &state.ast)
    }
}

#[cfg(feature = "resident_key_support")]
impl Webauthn {
    /// TODO
    pub fn start_residentkey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_ca_list: AttestationCaList,
        ui_hint_authenticator_attachment: Option<AuthenticatorAttachment>,
    ) -> WebauthnResult<(CreationChallengeResponse, ResidentKeyRegistration)> {
        if attestation_ca_list.is_empty() {
            return Err(WebauthnError::MissingAttestationCaList);
        }

        let attestation = AttestationConveyancePreference::Direct;
        let credential_algorithms = self.algorithms.clone();
        let require_resident_key = true;
        let policy = Some(UserVerificationPolicy::Required);
        let reject_passkeys = true;

        // https://www.w3.org/TR/webauthn-2/#sctn-uvm-extension
        // UVM
        // If rk - credProps

        // credProtect
        let extensions = Some(RequestRegistrationExtensions {
            cred_protect: Some(CredProtect {
                // Since this will contain PII, we need to enforce this.
                credential_protection_policy: CredentialProtectionPolicy::UserVerificationRequired,
                // If set to true, causes many authenticators to shit the bed. As a result,
                // during the registration, we check if the aaguid is credProtect viable and
                // then enforce it there.
                enforce_credential_protection_policy: Some(false),
            }),
            cred_blob: None,
            uvm: Some(true),
            cred_props: Some(true),
            min_pin_length: Some(true),
            hmac_create_secret: None,
        });

        // https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-minpinlength-extension
        // min pin

        self.core
            .generate_challenge_register_options(
                user_unique_id.as_bytes(),
                user_name,
                user_display_name,
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
                    ResidentKeyRegistration {
                        rs,
                        ca_list: attestation_ca_list,
                    },
                )
            })
    }

    /// TODO
    pub fn finish_residentkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &ResidentKeyRegistration,
    ) -> WebauthnResult<ResidentKey> {
        let cred = self
            .core
            .register_credential(reg, &state.rs, Some(&state.ca_list))?;

        trace!("finish residentkey -> {:?}", cred);

        // cred protect ignored :(
        // Is the pin long enough?
        // We'll never know because lol.

        // Is it an approvide cred / aaguid?

        Ok(ResidentKey { cred })
    }

    /// TODO
    pub fn start_residentkey_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, ResidentKeyAuthentication)> {
        let creds = Vec::with_capacity(0);
        let extensions = Some(RequestAuthenticationExtensions {
            get_cred_blob: None,
            appid: None,
            uvm: Some(true),
        });

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, ResidentKeyAuthentication { ast }))
    }

    /// Given the `PublicKeyCredential` returned by the user agent (e.g. a browser), and the stored `PasswordlessKeyAuthentication`
    /// attempt to identify user's unique id. This does NOT authenticate the user, it only retrieve the
    /// unique_user_id if present so that you can then lookup the user's account in a usernameless-flow.
    pub fn identify_residentkey_authentication(
        &self,
        reg: &PublicKeyCredential,
        _state: &ResidentKeyAuthentication,
    ) -> WebauthnResult<Uuid> {
        reg.get_user_unique_id()
            .and_then(|b| Uuid::from_slice(b).ok())
            .ok_or(WebauthnError::InvalidUserUniqueId)
    }

    /// TODO
    pub fn finish_residentkey_authentication(
        &self,
        reg: &PublicKeyCredential,
        mut state: ResidentKeyAuthentication,
        creds: &[ResidentKey],
    ) -> WebauthnResult<AuthenticationResult> {
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();
        state.ast.set_allowed_credentials(creds);
        self.core.authenticate_credential(reg, &state.ast)
    }
}
