//! Low-level transport abstraction layer for communication with FIDO tokens.
//!
//! See [crate::ctap2] for a higher-level abstraction over this API.
mod any;
pub mod iso7816;

pub use crate::transport::any::{AnyToken, AnyTransport};

use async_trait::async_trait;
use futures::executor::block_on;
use std::fmt;
use webauthn_rs_proto::AuthenticatorTransport;

use crate::{ctap2::*, error::WebauthnCError, ui::UiCallback};

/// Represents a transport layer protocol for [Token].
///
/// If you don't care which transport your application uses, use [AnyTransport]
/// to automatically use all available transports on the platform.
#[async_trait]
pub trait Transport<'b>: Sized + fmt::Debug + Send {
    /// The type of [Token] returned by this [Transport].
    type Token: Token + 'b;

    /// Gets a list of all connected tokens for this [Transport].
    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError>;

    fn connect_all<'a, U: UiCallback>(
        &mut self,
        ui: &'a U,
    ) -> Result<Vec<CtapAuthenticator<'a, Self::Token, U>>, WebauthnCError> {
        Ok(self
            .tokens()?
            .drain(..)
            .filter_map(|token| block_on(CtapAuthenticator::new(token, ui)))
            .collect())
    }

    fn connect_one<'a, U: UiCallback>(
        &mut self,
        ui: &'a U,
    ) -> Result<CtapAuthenticator<'a, Self::Token, U>, WebauthnCError> {
        self.tokens()?
            .drain(..)
            .filter_map(|token| block_on(CtapAuthenticator::new(token, ui)))
            .next()
            .ok_or(WebauthnCError::NoSelectedToken)
    }
}

/// Represents a connection to a single FIDO token over a [Transport].
///
/// This is a low level interface to FIDO tokens, passing raw messages.
/// [crate::ctap2] provides a higher level abstraction.
#[async_trait]
pub trait Token: Sized + fmt::Debug + Sync + Send {
    fn has_button(&self) -> bool {
        true
    }

    /// Gets the transport layer used for communication with this token.
    fn get_transport(&self) -> AuthenticatorTransport;

    /// Transmit a CBOR message to a token, and deserialises the response.
    async fn transmit<'a, C, R, U>(&mut self, cmd: C, ui: &U) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
        U: UiCallback,
    {
        let cbor = cmd.cbor().map_err(|_| WebauthnCError::Cbor)?;
        let resp = self.transmit_raw(&cbor, ui).await?;

        R::try_from(resp.as_slice()).map_err(|_| {
            //error!("error: {:?}", e);
            WebauthnCError::Cbor
        })
    }

    /// Transmits a command on the underlying transport.
    ///
    /// `cbor` is a CBOR-encoded command.
    ///
    /// Interfaces need to check for and return any transport-layer-specific
    /// error code [WebauthnCError::Ctap], but don't need to worry about
    /// deserialising CBOR.
    async fn transmit_raw<U>(&mut self, cbor: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback;

    /// Cancels a pending request.
    fn cancel(&self) -> Result<(), WebauthnCError>;

    /// Initializes the [Token]
    async fn init(&mut self) -> Result<(), WebauthnCError>;

    /// Closes the [Token]
    async fn close(&mut self) -> Result<(), WebauthnCError>;
}
