//! Wrappers for [RelyingParty].
use std::pin::Pin;

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
    native: Pin<Box<WEBAUTHN_RP_ENTITY_INFORMATION>>,
    id: Pin<Box<HSTRING>>,
    name: Pin<Box<HSTRING>>,
}

impl WinWrapper<RelyingParty> for WinRpEntityInformation {
    type NativeType = WEBAUTHN_RP_ENTITY_INFORMATION;
    fn new(rp: RelyingParty) -> Result<Self, WebauthnCError> {
        let mut res = Self {
            native: Default::default(),
            id: Box::pin(rp.id.into()),
            name: Box::pin(rp.name.into()),
        };

        res.native = Box::pin(WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR::from_raw(res.id.as_ptr()),
            pwszName: PCWSTR::from_raw(res.name.as_ptr()),
            pwszIcon: PCWSTR::null(),
        });

        Ok(res)
    }

    fn native_ptr(&self) -> &WEBAUTHN_RP_ENTITY_INFORMATION {
        &self.native
    }
}
