//! Low-level transport abstraction layer for communication with FIDO tokens.
//!
//! See [crate::ctap2] for a higher-level abstraction over this API.
mod any;
pub mod iso7816;
#[cfg(any(all(doc, not(doctest)), feature = "vendor-solokey"))]
pub(crate) mod solokey;
#[cfg(any(doc, feature = "bluetooth", feature = "usb"))]
pub(crate) mod types;

pub use crate::transport::any::{AnyToken, AnyTransport};

use async_trait::async_trait;
use futures::stream::BoxStream;
use std::fmt;
use webauthn_rs_proto::AuthenticatorTransport;

use crate::{ctap2::*, error::WebauthnCError, ui::UiCallback};

#[cfg(any(doc, feature = "bluetooth", feature = "usb"))]
pub(crate) const TYPE_INIT: u8 = 0x80;

#[derive(Debug)]
pub enum TokenEvent<T: Token> {
    Added(T),
    Removed(T::Id),
    EnumerationComplete,
}

/// Represents a transport layer protocol for [Token].
///
/// If you don't care which transport your application uses, use [AnyTransport]
/// to automatically use all available transports on the platform.
#[async_trait]
pub trait Transport<'b>: Sized + fmt::Debug + Send {
    /// The type of [Token] returned by this [Transport].
    type Token: Token + 'b;

    /// Watches for token connection and disconnection on this [Transport].
    ///
    /// Initially, this send synthetic [`TokenEvent::Added`] for all
    /// currently-connected tokens, followed by
    /// [`TokenEvent::EnumerationComplete`].
    async fn watch(&self) -> Result<BoxStream<TokenEvent<Self::Token>>, WebauthnCError>;

    /// Gets all currently-connected devices associated with this [Transport].
    ///
    /// This method does not work for Bluetooth devices. Use
    /// [`watch()`][] instead.
    ///
    /// [`watch()`]: Transport::watch
    async fn tokens(&self) -> Result<Vec<Self::Token>, WebauthnCError>;
}

/// Represents a connection to a single FIDO token over a [Transport].
///
/// This is a low level interface to FIDO tokens, passing raw messages.
/// [crate::ctap2] provides a higher level abstraction.
#[async_trait]
pub trait Token: Sized + fmt::Debug + Sync + Send {
    type Id: Sized + fmt::Debug + Sync + Send;

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
        trace!(">>> {}", hex::encode(&cbor));

        let resp = self.transmit_raw(&cbor, ui).await?;

        trace!("<<< {}", hex::encode(&resp));
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
    async fn cancel(&mut self) -> Result<(), WebauthnCError>;

    /// Initializes the [Token]
    async fn init(&mut self) -> Result<(), WebauthnCError>;

    /// Closes the [Token]
    async fn close(&mut self) -> Result<(), WebauthnCError>;
}
