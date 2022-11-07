pub mod commands;
mod ctap20;
mod ctap21;
mod pin_uv;

use std::ops::{Deref, DerefMut};

use futures::stream::FuturesUnordered;
use futures::{select, StreamExt};

use crate::error::WebauthnCError;
use crate::transport::Token;
use crate::ui::UiCallback;
use crate::AuthenticatorBackend;

pub use self::commands::EnrollSampleStatus;
use self::commands::GetInfoRequest;
pub use self::commands::{CBORCommand, CBORResponse};
pub use self::{ctap20::Ctap20Authenticator, ctap21::Ctap21Authenticator};

#[derive(Debug)]
pub enum CtapAuthenticator<'a, T: Token, U: UiCallback> {
    Fido20(Ctap20Authenticator<'a, T, U>),
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
        token.init().await.ok()?;
        let info = token.transmit(GetInfoRequest {}, ui_callback).await.ok()?;

        if info.versions.contains(FIDO_2_1) {
            Some(Self::Fido21(Ctap21Authenticator::new(
                info,
                token,
                ui_callback,
            )))
        } else if info.versions.contains(FIDO_2_0) || info.versions.contains(FIDO_2_1_PRE) {
            // TODO: Implement FIDO 2.1-PRE properly (prototype authenticatorBioEnrollment, prototype authenticatorCredentialManagement)
            // 2.1-PRE intentionally falls back to v2.0, because 2.1-PRE doesn't support all v2.1 commands.
            Some(Self::Fido20(Ctap20Authenticator::new(
                info,
                token,
                ui_callback,
            )))
        } else {
            None
        }
    }

    /// Gets a reference to a CTAP 2.1 compatible interface, if the token supports it.
    ///
    /// Otherwise, returns `None`.
    pub fn ctap21(&self) -> Option<&Ctap21Authenticator<'a, T, U>> {
        match self {
            Self::Fido21(a) => Some(a),
            _ => None,
        }
    }
}

/// Gets a reference to a CTAP 2.0 compatible interface.
///
/// All CTAP2 tokens support these base commands.
impl<'a, T: Token, U: UiCallback> Deref for CtapAuthenticator<'a, T, U> {
    type Target = Ctap20Authenticator<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        use CtapAuthenticator::*;
        match self {
            Fido20(a) => a,
            Fido21(a) => a,
        }
    }
}

/// Gets a mutable reference to a CTAP 2.0 compatible interface.
///
/// All CTAP2 tokens support these base commands.
impl<'a, T: Token, U: UiCallback> DerefMut for CtapAuthenticator<'a, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        use CtapAuthenticator::*;
        match self {
            Fido20(a) => a,
            Fido21(a) => a,
        }
    }
}

impl<'a, T: Token, U: UiCallback> AuthenticatorBackend for CtapAuthenticator<'a, T, U> {
    fn perform_register(
        &mut self,
        origin: url::Url,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, WebauthnCError> {
        Ctap20Authenticator::perform_register(self, origin, options, timeout_ms)
    }

    fn perform_auth(
        &mut self,
        origin: url::Url,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, WebauthnCError> {
        Ctap20Authenticator::perform_auth(self, origin, options, timeout_ms)
    }
}

/// Selects one [Token] from an [Iterator] of Tokens.
///
/// This only works on NFC authenticators and CTAP 2.1 (not "2.1 PRE")
/// authenticators.
pub async fn select_one_token<'a, T: Token + 'a, U: UiCallback + 'a>(
    tokens: impl Iterator<Item = &'a CtapAuthenticator<'a, T, U>>,
) -> Option<&'a CtapAuthenticator<'a, T, U>> {
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
