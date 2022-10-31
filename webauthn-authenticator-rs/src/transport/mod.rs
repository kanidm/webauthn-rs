//! Transport abstraction layer for communication with FIDO tokens.
mod any;
pub mod ctap21pre;
pub mod iso7816;

pub use crate::transport::any::{AnyToken, AnyTransport};
use crate::ui::UiCallback;

use async_trait::async_trait;
use base64urlsafedata::Base64UrlSafeData;
use futures::executor::block_on;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use std::fmt;
use std::sync::Mutex;
use webauthn_rs_proto::{AuthenticatorTransport, PubKeyCredParams, RelyingParty, User};

use crate::ctap2::*;
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
pub trait Transport<'b>: Sized + Default + fmt::Debug + Send {
    /// The type of [Token] returned by this [Transport].
    type Token: Token + 'b;

    /// Gets a list of all connected tokens for this [Transport].
    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError>;

    fn connect_all<'a, U: UiCallback>(
        &mut self,
        ui: &'a U,
    ) -> Result<Vec<Ctap21PreAuthenticator<'a, Self::Token, U>>, WebauthnCError> {
        Ok(self
            .tokens()?
            .drain(..)
            .filter_map(|mut token| {
                if block_on(token.init()).is_err() {
                    return None;
                }
                let info = match block_on(token.transmit(GetInfoRequest {}, ui)) {
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

                Some(Ctap21PreAuthenticator::new(info, token, ui))
            })
            .collect())
    }

    /*
    /// Selects one token by requesting user interaction
    ///
    /// WIP: This is not yet finished, and doesn't handle threading.
    ///
    /// This only works on CTAP 2.1 authenticators
    async fn select_one_token<'a, U: UiCallback>(
        &mut self,
        ui: &'a U,
    ) -> Result<Ctap21PreAuthenticator<'a, Self::Token, U>, WebauthnCError> {
        let mut all_tokens = self.tokens()?;

        let mut tasks: FuturesUnordered<_> = all_tokens
            .drain(..)
            .map(|mut token| {
                async move {
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

                    let auth = Ctap21PreAuthenticator::new(info, token, ui);

                    trace!("Trying to selectionRequest");
                    auth.selection().await.ok()?;
                    Some(auth)

                    // ARRRGGHHH this only works on FIDO_2_1.  Not 2.0, not 2.1PRE.
                    // So we need another strategy. I guess this means we need to be able to race EVERYTHING
                    // if token.transmit(SelectionRequest {}, ui).await.is_ok() {
                    //     Some((info, Mutex::new(token)))
                    // } else {
                    //     None
                    // }
                    // todo!()
                }
                .fuse()
            })
            .collect();

        loop {
            select! {
                res = tasks.select_next_some() => {
                    if let Some(auth) = res {
                        trace!(?auth);
                        return Ok(auth)
                    }
                }
                complete => {
                    // No tokens available
                    return Err(WebauthnCError::NoSelectedToken);
                }
            }
        }
    }
     */
}

/// Represents a connection to a single CTAP token over a [Transport].
#[async_trait]
pub trait Token: Sized + fmt::Debug + Sync + Send {
    fn has_button(&self) -> bool { true }

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
    fn auth<'a, U: UiCallback>(
        self,
        ui: &'a U,
    ) -> Result<Ctap21PreAuthenticator<'a, Self, U>, WebauthnCError> {
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
