//! This package provides a [CTAP 2.0][Ctap20Authenticator],
//! [CTAP 2.1-PRE][Ctap21PreAuthenticator] and [CTAP 2.1][Ctap21Authenticator]
//! protocol implementation on top of [Token], allowing you to interface with
//! FIDO authenticators.
//!
//! The main interface for this package is [CtapAuthenticator].
//!
//! ## Warning
//!
//! This is "alpha" quality code: it still a work in progress, and missing core
//! functionality.
//!
//! **There are edge cases that which cause you to be locked out of your
//! authenticator.**
//!
//! **The API is not final, and subject to change without warning.**
//!
//! ### Known issues
//!
//! There are many limitations with this implementation, which are intended to
//! be addressed in the future:
//!
//! * lock-outs aren't handled; this will just use up all your PIN and UV
//!   retries without warning, **potentially locking you out**.
//!
//!   This also doesn't fall-back to PIN auth if UV (fingerprint) auth is locked
//!   out.
//!
//! * multiple authenticators doesn't work particularly well, and connecting
//!   devices while an action is in progress doesn't work
//!
//! * cancellations and timeouts
//!
//! * session management (re-using `pin_uv_auth_token`)
//!
//! * [U2F compatibility and fall-back][u2f]
//!
//! * [secured state][secure]
//!
//! Many CTAP2 features are unsupported:
//!
//! * [discoverable credentials] (`authenticatorCredentialManagement`)
//!
//! * [large blobs] (`authenticatorLargeBlobs`)
//!
//! * [enterprise attestation]
//!
//! * [request extensions]
//!
//! ## Features
//!
//! * Basic [registration][Ctap20Authenticator::perform_register] and
//!   [authentication][Ctap20Authenticator::perform_auth] with a
//!   [CLI interface][crate::ui::Cli]
//!
//! * [Bluetooth Low Energy][crate::bluetooth], [caBLE / Hybrid][crate::cable],
//!   [NFC][crate::nfc] and [USB HID][crate::usb] authenticators
//!
//! * CTAP 2.1 and NFC [authenticator selection][select_one_token]
//!
//! * Fingerprint (biometric) authentication,
//!   [enrollment and management][BiometricAuthenticator]
//!   (CTAP 2.1 and 2.1-PRE)
//!
//! * Built-in user verification
//!
//! * [Setting][Ctap20Authenticator::set_new_pin] and
//!   [changing][Ctap20Authenticator::change_pin] device PINs
//!
//! * PIN/UV Auth [Protocol One] and [Protocol Two], [getPinToken],
//!   [getPinUvAuthTokenUsingPinWithPermissions], and
//!   [getPinUvAuthTokenUsingUvWithPermissions]
//!
//! * [Factory-resetting authenticators][Ctap20Authenticator::factory_reset]
//!
//! * configuring [user verification][Ctap21Authenticator::toggle_always_uv]
//!   and [minimum PIN length][Ctap21Authenticator::set_min_pin_length]
//!   requirements
//!
//! ## Examples
//!
//! * `webauthn-authenticator-rs/examples/authenticate.rs` works with any
//!   [crate::AuthenticatorBackend], including [CtapAuthenticator].
//! 
//! * `fido-key-manager` will connect to a key, pull hardware information, and
//!   let you reconfigure the key (reset, PIN, fingerprints, etc.)
//!
//! ## Device-specific issues
//!
//! * [Some YubiKey USB tokens][yubi] provide a USB CCID (smartcard) interface,
//!   in addition to a USB HID FIDO interface, which will be detected as an
//!   "NFC reader".
//!
//!   This only provides access to the PIV, OATH or OpenPGP applets, not FIDO.
//!
//!   Use [USBTransport][crate::usb::USBTransport] for these tokens.
//!
//! ## Platform-specific issues
//!
//! See `fido-key-manager/README.md`.
//!
//! [discoverable credentials]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
//! [enterprise attestation]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enable-enterprise-attestation
//! [getPinToken]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
//! [getPinUvAuthTokenUsingPinWithPermissions]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
//! [getPinUvAuthTokenUsingUvWithPermissions]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingUvWithPermissions
//! [large blobs]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorLargeBlobs
//! [PC/SC Lite]: https://pcsclite.apdu.fr/
//! [Protocol One]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1
//! [Protocol Two]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto2
//! [request extensions]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions
//! [secure]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-secure-interaction
//! [u2f]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#u2f-interoperability
//! [yubi]: https://support.yubico.com/hc/en-us/articles/360016614920-YubiKey-USB-ID-Values

// TODO: `commands` may become private in future.
pub mod commands;
#[doc(hidden)]
mod ctap20;
#[doc(hidden)]
mod ctap21;
mod ctap21_bio;
#[doc(hidden)]
mod ctap21pre;
mod pin_uv;

use std::ops::{Deref, DerefMut};

use futures::stream::FuturesUnordered;
use futures::{select, StreamExt};

use crate::authenticator_hashed::AuthenticatorBackendHashedClientData;
use crate::error::WebauthnCError;
use crate::transport::Token;
use crate::ui::UiCallback;

use self::commands::GetInfoRequest;
use self::ctap21_bio::BiometricAuthenticatorInfo;

#[doc(inline)]
pub use self::{
    commands::{CBORCommand, CBORResponse, GetInfoResponse},
    ctap20::Ctap20Authenticator,
    ctap21::Ctap21Authenticator,
    ctap21pre::Ctap21PreAuthenticator,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
#[doc(inline)]
pub use ctap21_bio::BiometricAuthenticator;

/// Abstraction for different versions of the CTAP2 protocol.
///
/// All tokens can [Deref] into [Ctap20Authenticator].
#[derive(Debug)]
pub enum CtapAuthenticator<'a, T: Token, U: UiCallback> {
    /// Interface for CTAP 2.0 tokens.
    Fido20(Ctap20Authenticator<'a, T, U>),
    /// Interface for CTAP 2.1-PRE tokens.
    Fido21Pre(Ctap21PreAuthenticator<'a, T, U>),
    /// Interface for CTAP 2.1 tokens.
    Fido21(Ctap21Authenticator<'a, T, U>),
}

const FIDO_2_0: &str = "FIDO_2_0";
const FIDO_2_1: &str = "FIDO_2_1";
const FIDO_2_1_PRE: &str = "FIDO_2_1_PRE";

impl<'a, T: Token, U: UiCallback> CtapAuthenticator<'a, T, U> {
    /// Initialises the token, and gets a reference to the highest supported FIDO version.
    ///
    /// Returns `None` if we don't support any version of CTAP which the token supports.
    pub async fn new(mut token: T, ui_callback: &'a U) -> Option<CtapAuthenticator<'a, T, U>> {
        token
            .init()
            .await
            .map_err(|e| {
                error!("Error initialising token: {e:?}");
                e
            })
            .ok()?;
        let info = token.transmit(GetInfoRequest {}, ui_callback).await.ok()?;

        Self::new_with_info(info, token, ui_callback)
    }

    /// Creates a connection to an already-initialized token, and gets a reference to the highest supported FIDO version.
    ///
    /// Returns `None` if we don't support any version of CTAP which the token supports.
    pub(crate) fn new_with_info(
        info: GetInfoResponse,
        token: T,
        ui_callback: &'a U,
    ) -> Option<CtapAuthenticator<'a, T, U>> {
        if info.versions.contains(FIDO_2_1) {
            Some(Self::Fido21(Ctap21Authenticator::new(
                info,
                token,
                ui_callback,
            )))
        } else if info.versions.contains(FIDO_2_1_PRE) {
            Some(Self::Fido21Pre(Ctap21PreAuthenticator::new(
                info,
                token,
                ui_callback,
            )))
        } else if info.versions.contains(FIDO_2_0) {
            Some(Self::Fido20(Ctap20Authenticator::new(
                info,
                token,
                ui_callback,
            )))
        } else {
            None
        }
    }

    /// Returns `true` if the token supports biometric commands.
    pub fn supports_biometrics(&self) -> bool {
        match self {
            Self::Fido21(a) => a.supports_biometrics(),
            Self::Fido21Pre(a) => a.supports_biometrics(),
            _ => false,
        }
    }

    /// Returns `true` if the token has configured biometric authentication.
    pub fn configured_biometrics(&self) -> bool {
        match self {
            Self::Fido21(a) => a.configured_biometrics(),
            Self::Fido21Pre(a) => a.configured_biometrics(),
            _ => false,
        }
    }

    #[cfg(any(all(doc, not(doctest), feature = "ctap2-management")))]
    /// Gets a mutable reference to a [BiometricAuthenticator] trait for the
    /// token, if it supports biometric commands.
    ///
    /// Returns `None` if the token does not support biometrics.
    pub fn bio(&mut self) -> Option<&mut dyn BiometricAuthenticator> {
        match self {
            Self::Fido21(a) => a.supports_biometrics().then_some(a),
            Self::Fido21Pre(a) => a.supports_biometrics().then_some(a),
            _ => None,
        }
    }
}

/// Gets a reference to a [CTAP 2.0 compatible interface][Ctap20Authenticator].
///
/// All CTAP2 tokens support these base commands.
impl<'a, T: Token, U: UiCallback> Deref for CtapAuthenticator<'a, T, U> {
    type Target = Ctap20Authenticator<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        use CtapAuthenticator::*;
        match self {
            Fido20(a) => a,
            Fido21Pre(a) => a,
            Fido21(a) => a,
        }
    }
}

/// Gets a mutable reference to a
/// [CTAP 2.0 compatible interface][Ctap20Authenticator].
///
/// All CTAP2 tokens support these base commands.
impl<'a, T: Token, U: UiCallback> DerefMut for CtapAuthenticator<'a, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        use CtapAuthenticator::*;
        match self {
            Fido20(a) => a,
            Fido21Pre(a) => a,
            Fido21(a) => a,
        }
    }
}

/// Wrapper for [Ctap20Authenticator]'s implementation of
/// [AuthenticatorBackendHashedClientData].
impl<'a, T: Token, U: UiCallback> AuthenticatorBackendHashedClientData
    for CtapAuthenticator<'a, T, U>
{
    fn perform_register(
        &mut self,
        client_data_hash: Vec<u8>,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, WebauthnCError> {
        <Ctap20Authenticator<'a, T, U> as AuthenticatorBackendHashedClientData>::perform_register(
            self,
            client_data_hash,
            options,
            timeout_ms,
        )
    }

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, WebauthnCError> {
        <Ctap20Authenticator<'a, T, U> as AuthenticatorBackendHashedClientData>::perform_auth(
            self,
            client_data_hash,
            options,
            timeout_ms,
        )
    }
}

/// Selects one [Token] from an [Iterator] of Tokens.
///
/// This only works on NFC authenticators and CTAP 2.1 (not "2.1 PRE")
/// authenticators.
pub async fn select_one_token<'a, T: Token + 'a, U: UiCallback + 'a>(
    tokens: impl Iterator<Item = &'a mut CtapAuthenticator<'a, T, U>>,
) -> Option<&'a mut CtapAuthenticator<'a, T, U>> {
    let mut tasks: FuturesUnordered<_> = tokens
        .map(|token| async move {
            if !token.token.has_button() {
                // The token doesn't have a button on a transport level (ie: NFC),
                // so immediately mark this as the "selected" token, even if it
                // doesn't support FIDO v2.1.
                trace!("Token has no button, implicitly treading as selected");
                Ok::<_, WebauthnCError>(token)
            } else if let CtapAuthenticator::Fido21(t) = token {
                t.selection().await?;
                Ok::<_, WebauthnCError>(token)
            } else {
                Err(WebauthnCError::NotSupported)
            }
        })
        .collect();

    let token = loop {
        select! {
            res = tasks.select_next_some() => {
                if let Ok(token) = res {
                    break Some(token);
                }
            }
            complete => {
                // No tokens available
                break None;
            }
        }
    };

    tasks.clear();
    token
}
