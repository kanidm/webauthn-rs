//! Transport abstraction layer for communication with FIDO tokens.
mod any;
pub mod ctap21pre;
pub mod iso7816;

pub use crate::transport::any::{AnyToken, AnyTransport};

use base64urlsafedata::Base64UrlSafeData;
use std::fmt;
use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

use crate::cbor::*;
use crate::error::{WebauthnCError, CtapError};

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
pub trait Transport: Sized + Default + fmt::Debug {
    /// The type of [Token] returned by this [Transport].
    type Token: Token;

    /// Gets a list of all connected tokens for this [Transport].
    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError>;
}

/// Represents a connection to a single CTAP token over a [Transport].
pub trait Token: Sized + fmt::Debug {
    /// Transmit a CBOR message to a token
    fn transmit<'a, C, R>(&self, cmd: C) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
    {
        let resp = self.transmit_raw(cmd)?;

        R::try_from(resp.as_slice()).map_err(|_| {
            //error!("error: {:?}", e);
            WebauthnCError::Cbor
        })
    }

    /// Transmits a CBOR command to a token, returning the deserialized response
    /// and original response.
    fn transmit_plus_raw<'a, C, R>(&self, cmd: C) -> Result<(R, Vec<u8>), WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
    {
        let resp = self.transmit_raw(cmd)?;

        R::try_from(resp.as_slice()).map_err(|_| {
            //error!("error: {:?}", e);
            WebauthnCError::Cbor
        }).map(|v| (v, resp))
    }

    fn transmit_raw<C>(&self, cmd: C) -> Result<Vec<u8>, WebauthnCError>
    where C: CBORCommand;

    /// Initializes the [Token]
    fn init(&mut self) -> Result<(), WebauthnCError>;

    /// Selects any available CTAP applet on the [Token]
    fn select_any(self) -> Result<Selected<Self>, WebauthnCError> {
        let tokinfo = self.transmit(GetInfoRequest {})?;

        debug!(?tokinfo);

        if tokinfo.versions.contains("FIDO_2_1_PRE") {
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
    fn auth(self) -> Result<Ctap21PreAuthenticator<Self>, WebauthnCError> {
        let info = self.transmit(GetInfoRequest {})?;

        debug!(?info);

        if info.versions.contains("FIDO_2_1_PRE") {
            Ok(Ctap21PreAuthenticator::new(info, self))
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
