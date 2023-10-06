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
    native: WEBAUTHN_RP_ENTITY_INFORMATION,
    id: HSTRING,
    name: HSTRING,
}

impl WinWrapper<RelyingParty> for WinRpEntityInformation {
    type NativeType = WEBAUTHN_RP_ENTITY_INFORMATION;
    fn new(rp: RelyingParty) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let res = Self {
            native: Default::default(),
            id: rp.id.into(),
            name: rp.name.into(),
        };

        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: (&boxed.id).into(),
            pwszName: (&boxed.name).into(),
            pwszIcon: PCWSTR::null(),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        Ok(boxed)
    }

    fn native_ptr(&self) -> &WEBAUTHN_RP_ENTITY_INFORMATION {
        &self.native
    }
}
