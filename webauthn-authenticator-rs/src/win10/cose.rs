//! Wrappers for [PubKeyCredParams].
use crate::prelude::WebauthnCError;
use std::pin::Pin;
use webauthn_rs_proto::PubKeyCredParams;
use windows::{
    core::HSTRING,
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    },
};

use super::{constants::CREDENTIAL_TYPE_PUBLIC_KEY, WinWrapper};

pub struct WinCoseCredentialParameters {
    /// Wrapper structure, points to `params`.
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,

    /// Array of all parameters, each points to an entry in `types`.
    ///
    /// [`WEBAUTHN_COSE_CREDENTIAL_PARAMETERS::pCredentialParameters`][] is a pointer to the first
    /// [`WEBAUTHN_COSE_CREDENTIAL_PARAMETER`][], so this needs to be a contiguous block of memory.
    params: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>,

    /// Credential type identifiers used in `params`.
    ///
    /// The string buffer of the [`HSTRING`] is heap allocated and effectively pinned.
    types: Vec<HSTRING>,
}

impl WinWrapper<Vec<PubKeyCredParams>> for WinCoseCredentialParameters {
    type NativeType = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;

    fn new(params: Vec<PubKeyCredParams>) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let res = Self {
            native: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
                cCredentialParameters: params.len() as u32,
                pCredentialParameters: std::ptr::null_mut(),
            },
            params: Vec::with_capacity(params.len()),
            types: Vec::with_capacity(
                params
                    .iter()
                    .filter(|p| p.type_ != WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY)
                    .count(),
            ),
        };

        let mut boxed = Box::new(res);

        for param in params {
            let pwsz_credential_type = if param.type_ == WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY {
                CREDENTIAL_TYPE_PUBLIC_KEY.into()
            } else {
                // Unlikely path, as WebAuthn L3 doesn't specify this.
                let typ = HSTRING::from(param.type_);

                // Even though the `HSTRING` is moved when pushed into the `Vec` (and potentially
                // many times if the `Vec` reallocates), its header and string buffer are heap
                // allocated and don't move.
                let ptr = (&typ).into();
                boxed.types.push(typ);
                ptr
            };

            boxed.params.push(WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: pwsz_credential_type,
                lAlg: param.alg as i32,
            });
        }

        boxed.native.pCredentialParameters = Vec::as_mut_ptr(&mut boxed.params);

        Ok(Box::into_pin(boxed))
    }

    fn native_ptr(&self) -> &WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        &self.native
    }
}
