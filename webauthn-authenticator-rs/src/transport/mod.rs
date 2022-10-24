//! Transport abstraction layer for communication with FIDO tokens.
mod any;
pub mod ctap21pre;
pub mod iso7816;

pub use crate::transport::any::{AnyToken, AnyTransport};
use crate::ui::UiCallback;

use async_trait::async_trait;
use base64urlsafedata::Base64UrlSafeData;
use futures::executor::block_on;
use futures::future::{try_join_all, Fuse};
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, Stream, StreamExt};
use std::fmt;
use std::ops::Deref;
use std::sync::Mutex;
use webauthn_rs_proto::{AuthenticatorTransport, PubKeyCredParams, RelyingParty, User};

use crate::cbor::*;
use crate::error::WebauthnCError;

use self::ctap21pre::Ctap21PreAuthenticator;

#[allow(non_camel_case_types)]
pub enum Selected<T>
where
    T: Token,
{
    // FIDO_2_1(),
    FIDO_2_1_PRE(Ctap2_1_pre<T>),
    // FIDO_2_0(),
    // U2F(),
}

#[allow(non_camel_case_types)]
pub struct Ctap2_1_pre<T>
where
    T: Token,
{
    tokinfo: GetInfoResponse,
    token: T,
}

/// Represents a transport layer protocol for [Token].
///
/// If you don't care which transport your application uses, use [AnyTransport]
/// to automatically use all available transports on the platform.
#[async_trait]
pub trait Transport: Sized + Default + fmt::Debug + Send {
    /// The type of [Token] returned by this [Transport].
    type Token: Token;

    /// Gets a list of all connected tokens for this [Transport].
    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError>;

    /// Selects one token by requesting user interaction
    ///
    /// WIP: This is not yet finished, and doesn't handle threading.
    async fn select_one_token<'a, U: UiCallback>(
        &mut self,
        ui: &'a U,
    ) -> Result<Ctap21PreAuthenticator<'a, Self::Token, U>, WebauthnCError> {
        let mut all_tokens = self.tokens()?;

        let mut tasks: FuturesUnordered<_> = all_tokens
            .drain(..)
            .map(|mut token| async move {
                if token.init().await.is_err() {
                    return None;
                }
                let info = match token.transmit(GetInfoRequest {}, ui).await {
                    Ok(info) => {
                        if !(info.versions.contains("FIDO_2_1_PRE")
                            || info.versions.contains("FIDO_2_0")
                            || info.versions.contains("FIDO_2_1"))
                        {
                            trace!("dropping unsupported token");
                            return None;
                        }
                        info
                    }
                    Err(_) => return None,
                };

                trace!("Trying to selectionRequest");
                // ARRRGGHHH this only works on FIDO_2_1.  Not 2.0, not 2.1PRE.
                // So we need another strategy. I guess this means we need to be able to race EVERYTHING
                if token.transmit(SelectionRequest {}, ui).await.is_ok() {
                    Some((info, Mutex::new(token)))
                } else {
                    None
                }
            }.fuse()).collect();

        loop {
            select! {
                res = tasks.select_next_some() => {
                    if let Some((info, mutex)) = res {
                        trace!(?info);
                        match mutex.into_inner() {
                            Ok(guard) => return Ok(Ctap21PreAuthenticator::new(info, guard, ui)),
                            _ => (),
                        }
                    }
                }
                complete => {
                    // No tokens available
                    return Err(WebauthnCError::NoSelectedToken);
                }
            }
        }
    }
}

/// Represents a connection to a single CTAP token over a [Transport].
#[async_trait]
pub trait Token: Sized + fmt::Debug + Sync + Send {
    /// Gets the transport layer used for communication with this token.
    fn get_transport(&self) -> AuthenticatorTransport;

    /// Transmit a CBOR message to a token, and deserialises the response.
    async fn transmit<'a, C, R, U>(&self, cmd: C, ui: &U) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
        U: UiCallback,
    {
        let resp = self.transmit_raw(cmd, ui).await?;

        R::try_from(resp.as_slice()).map_err(|_| {
            //error!("error: {:?}", e);
            WebauthnCError::Cbor
        })
    }

    /// Transmits a command on the underlying transport.
    ///
    /// Interfaces need to check for and return any transport-layer-specific
    /// error code [WebauthnCError::Ctap], but don't need to worry about
    /// deserialising CBOR.
    async fn transmit_raw<C, U>(&self, cmd: C, ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        C: CBORCommand,
        U: UiCallback;

    /// Cancels a pending request.
    fn cancel(&self) -> Result<(), WebauthnCError>;

    /// Initializes the [Token]
    async fn init(&mut self) -> Result<(), WebauthnCError>;

    /// Selects any available CTAP applet on the [Token]
    fn select_any<U: UiCallback>(self, ui: U) -> Result<Selected<Self>, WebauthnCError> {
        let tokinfo = block_on(self.transmit(GetInfoRequest {}, &ui))?;

        debug!(?tokinfo);

        // TODO: Handle versions better
        if tokinfo.versions.contains("FIDO_2_1_PRE")
            || tokinfo.versions.contains("FIDO_2_0")
            || tokinfo.versions.contains("FIDO_2_1")
        {
            Ok(Selected::FIDO_2_1_PRE(Ctap2_1_pre {
                tokinfo,
                token: self,
            }))
        } else {
            error!(?tokinfo.versions);
            Err(WebauthnCError::NotSupported)
        }
    }

    // TODO: implement better
    fn auth<'a, U: UiCallback>(self, ui: &'a U) -> Result<Ctap21PreAuthenticator<'a, Self, U>, WebauthnCError> {
        let info = block_on(self.transmit(GetInfoRequest {}, ui))?;

        debug!(?info);

        // TODO: Handle versions better
        if info.versions.contains("FIDO_2_1_PRE")
            || info.versions.contains("FIDO_2_0")
            || info.versions.contains("FIDO_2_1")
        {
            Ok(Ctap21PreAuthenticator::new(info, self, ui))
        } else {
            error!(?info.versions);
            Err(WebauthnCError::NotSupported)
        }
    }

    /// Closes the [Token]
    fn close(&self) -> Result<(), WebauthnCError>;
}

impl<T: Token> fmt::Debug for Ctap2_1_pre<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ctap2_1_pre")
            .field("token_info", &self.tokinfo)
            .finish()
    }
}

impl<T: Token> Ctap2_1_pre<T> {
    pub fn hack_make_cred(&mut self) -> Result<NoResponse, WebauthnCError> {
        let mc = MakeCredentialRequest {
            client_data_hash: vec![
                104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226,
                47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65,
            ],
            rp: RelyingParty {
                name: "test".to_string(),
                id: "test".to_string(),
            },
            user: User {
                id: Base64UrlSafeData("test".as_bytes().into()),
                name: "test".to_string(),
                display_name: "test".to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParams {
                type_: "public-key".to_string(),
                alg: -7,
            }],
            exclude_list: vec![],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        todo!();
        // self.token.transmit(mc)
    }

    pub fn deselect_applet(&self) -> Result<(), WebauthnCError> {
        self.token.close()
    }
}
