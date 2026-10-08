//! Wrappers for [RelyingParty].
use std::{marker::PhantomPinned, pin::Pin};

use webauthn_rs_proto::RelyingParty;
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
    },
};

use super::WinWrapper;
use crate::error::WebauthnCError;

/// Wrapper for [WEBAUTHN_RP_ENTITY_INFORMATION] to ensure pointer lifetime.
pub struct WinRpEntityInformation {
    native: WEBAUTHN_RP_ENTITY_INFORMATION,
    id: HSTRING,
    name: HSTRING,
    _pin: PhantomPinned,
}

impl WinWrapper<RelyingParty> for WinRpEntityInformation {
    type NativeType = WEBAUTHN_RP_ENTITY_INFORMATION;
    fn new(rp: RelyingParty) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let res = Self {
            id: rp.id.into(),
            name: rp.name.into(),
            native: WEBAUTHN_RP_ENTITY_INFORMATION {
                dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
                ..Default::default()
            },
            _pin: PhantomPinned,
        };

        let mut boxed = Box::new(res);

        boxed.native.pwszId = PCWSTR::from(&boxed.id);
        boxed.native.pwszName = PCWSTR::from(&boxed.name);

        Ok(Box::into_pin(boxed))
    }

    fn native_ptr(&self) -> &WEBAUTHN_RP_ENTITY_INFORMATION {
        &self.native
    }
}
