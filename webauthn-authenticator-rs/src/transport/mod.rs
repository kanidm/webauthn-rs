//! Transport abstraction layer for communication with FIDO tokens.
mod any;
pub mod ctap21pre;
pub mod iso7816;

pub use crate::transport::any::{AnyToken, AnyTransport};
use crate::ui::UiCallback;

use async_trait::async_trait;
use base64urlsafedata::Base64UrlSafeData;
use std::fmt;
use webauthn_rs_proto::{AuthenticatorTransport, PubKeyCredParams, RelyingParty, User};

use crate::cbor::*;
use crate::error::{CtapError, WebauthnCError};

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
pub trait Transport: Sized + Default + fmt::Debug {
    /// The type of [Token] returned by this [Transport].
    type Token: Token;

    /// Gets a list of all connected tokens for this [Transport].
    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError>;

    /// Selects one token by requesting user interaction
    /// 
    /// WIP: This is not yet finished, and doesn't handle threading.
    async fn select_one_token<U: UiCallback + Sync>(&mut self, ui: &U) -> Result<Self::Token, WebauthnCError> {
        let mut all_tokens = self.tokens()?;

        // TODO: threading / async
        while let Some(mut token) = all_tokens.pop() {
            if let Err(_) = token.init() {
                continue;
            }

            if let Ok(info) = token.transmit(GetInfoRequest{}, ui) {
                if !(info.versions.contains("FIDO_2_1_PRE")
                || info.versions.contains("FIDO_2_0")
                || info.versions.contains("FIDO_2_1")) {
                    continue;
                }
            } else {
                // comms error, skip it.
                continue;
            }
            
            if token.transmit(SelectionRequest {}, ui).is_ok() {
                // Found the token to use
                return Ok(token);
            }
        }

        // Nothing picked
        Err(WebauthnCError::NoSelectedToken)
    }
}

/// Represents a connection to a single CTAP token over a [Transport].
#[async_trait]
pub trait Token: Sized + fmt::Debug {
    /// Gets the transport layer used for communication with this token.
    fn get_transport(&self) -> AuthenticatorTransport;

    /// Transmit a CBOR message to a token, and deserialises the response.
    async fn transmit<'a, C, R, U>(&self, cmd: C, ui: &U) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
        U: UiCallback,
    {
        let resp = self.transmit_raw(cmd, ui)?;

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
    fn init(&mut self) -> Result<(), WebauthnCError>;

    /// Selects any available CTAP applet on the [Token]
    fn select_any<U: UiCallback>(self, ui: U) -> Result<Selected<Self>, WebauthnCError> {
        let tokinfo = self.transmit(GetInfoRequest {}, &ui)?;

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
    fn auth<U: UiCallback>(self, ui: U) -> Result<Ctap21PreAuthenticator<Self, U>, WebauthnCError> {
        let info = self.transmit(GetInfoRequest {}, &ui)?;

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
