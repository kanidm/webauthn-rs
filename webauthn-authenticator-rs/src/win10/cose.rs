//! Wrappers for [PubKeyCredParams].
use crate::prelude::WebauthnCError;
use std::pin::Pin;
use webauthn_rs_proto::PubKeyCredParams;

use super::WinWrapper;

use windows::{
    core::HSTRING,
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
    },
};

/// Wrapper for [WEBAUTHN_COSE_CREDENTIAL_PARAMETER] to ensure pointer lifetime.
struct WinCoseCredentialParameter {
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    _typ: HSTRING,
}

impl WinCoseCredentialParameter {
    fn from(p: PubKeyCredParams) -> Pin<Box<Self>> {
        let res = Self {
            native: Default::default(),
            _typ: p.type_.into(),
        };

        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: (&boxed._typ).into(),
            lAlg: p.alg as i32,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }
}

pub struct WinCoseCredentialParameters {
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    _params: Vec<Pin<Box<WinCoseCredentialParameter>>>,
    _l: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>,
}

impl WinWrapper<Vec<PubKeyCredParams>> for WinCoseCredentialParameters {
    type NativeType = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;

    fn new(params: Vec<PubKeyCredParams>) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let params: Vec<Pin<Box<WinCoseCredentialParameter>>> = params
            .into_iter()
            .map(WinCoseCredentialParameter::from)
            .collect();
        Ok(WinCoseCredentialParameters::from_wrapped(params))
    }

    fn native_ptr(&self) -> &WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        &self.native
    }
}

impl WinCoseCredentialParameters {
    fn from_wrapped(params: Vec<Pin<Box<WinCoseCredentialParameter>>>) -> Pin<Box<Self>> {
        let len = params.len();
        let res = Self {
            native: Default::default(),
            _l: Vec::with_capacity(len),
            _params: params,
        };

        // Box and pin the struct so it's on the heap and doesn't move.
        let mut boxed = Box::pin(res);

        // Put in all the "native" values
        let p_ptr = boxed._params.as_ptr();
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let l = &mut Pin::get_unchecked_mut(mut_ref)._l;
            let l_ptr = l.as_mut_ptr();
            for i in 0..len {
                *l_ptr.add(i) = (&(*p_ptr.add(i))).native;
            }

            l.set_len(len);
        }

        // let mut l: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> =
        //     params.iter().map(|p| p.native).collect();

        let native = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: boxed._l.len() as u32,
            pCredentialParameters: boxed._l.as_mut_ptr() as *mut _,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }
}
