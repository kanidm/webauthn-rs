//! Wrappers for [PubKeyCredParams].
use crate::prelude::WebauthnCError;
use std::pin::Pin;
use webauthn_rs_proto::PubKeyCredParams;

use super::WinWrapper;

use windows::{
    core::{HSTRING, PCWSTR},
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
    },
};

/// Wrapper for [WEBAUTHN_COSE_CREDENTIAL_PARAMETER] to ensure pointer lifetime.
struct WinCoseCredentialParameter {
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    _typ: Pin<Box<HSTRING>>,
}

impl WinCoseCredentialParameter {
    fn from(p: PubKeyCredParams) -> Self {
        let mut res = Self {
            native: Default::default(),
            _typ: Box::pin(p.type_.into()),
        };

        res.native = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: PCWSTR::from_raw(res._typ.as_ptr()),
            lAlg: p.alg as i32,
        };

        res
    }
}

pub struct WinCoseCredentialParameters {
    native: Pin<Box<WEBAUTHN_COSE_CREDENTIAL_PARAMETERS>>,
    l: Pin<Box<Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>>>,
    params: Pin<Box<Vec<Pin<Box<WinCoseCredentialParameter>>>>>,
}

impl WinWrapper<Vec<PubKeyCredParams>> for WinCoseCredentialParameters {
    type NativeType = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;

    fn new(params: Vec<PubKeyCredParams>) -> Result<Self, WebauthnCError> {
        let params: Vec<Pin<Box<WinCoseCredentialParameter>>> = params
            .into_iter()
            .map(WinCoseCredentialParameter::from)
            .map(Box::pin)
            .collect();
        Ok(WinCoseCredentialParameters::from_wrapped(params))
    }

    fn native_ptr(&self) -> &WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        &self.native
    }
}

impl WinCoseCredentialParameters {
    fn from_wrapped(params: Vec<Pin<Box<WinCoseCredentialParameter>>>) -> Self {
        // pCredentialParams is a pointer to an array of contiguous COSE_CREDENTIAL_PARAMETER structures.
        // But we've got another wrapper type that's a bit longer to store the `type`, so we have to reorganise this.
        // TODO: Consider removing the intermediate step for PubKeyCredParams -> WinCoseCredentialParameter
        // so we can have a proper memory layout the first time.
        let mut res = Self {
            native: Default::default(),
            l: Box::pin(params.iter().map(|p| p.native.clone()).collect()),
            params: Box::pin(params),
        };

        res.native = Box::pin(WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: res.params.len() as u32,
            pCredentialParameters: Vec::as_mut_ptr(&mut res.l) as *mut _,
        });

        res
    }
}
