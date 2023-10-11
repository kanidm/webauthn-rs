//! Wrappers for [User].
use std::pin::Pin;

use webauthn_rs_proto::User;
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    },
};

use super::WinWrapper;
use crate::error::WebauthnCError;

/// Wrapper for [WEBAUTHN_USER_ENTITY_INFORMATION] to ensure pointer lifetime, analgous to [User].
pub struct WinUserEntityInformation {
    native: WEBAUTHN_USER_ENTITY_INFORMATION,
    _id: Vec<u8>,
    _name: HSTRING,
    _display_name: HSTRING,
}

impl WinWrapper<User> for WinUserEntityInformation {
    type NativeType = WEBAUTHN_USER_ENTITY_INFORMATION;
    fn new(u: &User) -> Result<Pin<Box<Self>>, WebauthnCError> {
        // Construct an incomplete type first, so that all the pointers are fixed.
        let res = Self {
            native: WEBAUTHN_USER_ENTITY_INFORMATION::default(),
            _id: u.id.clone().into(),
            _name: u.name.clone().into(),
            _display_name: u.display_name.clone().into(),
        };

        let mut boxed = Box::pin(res);

        // Create the real native type, which contains bare pointers.
        let native = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: boxed._id.len() as u32,
            pbId: boxed._id.as_ptr() as *mut _,
            pwszName: (&boxed._name).into(),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: (&boxed._display_name).into(),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        Ok(boxed)
    }

    fn native_ptr(&self) -> &WEBAUTHN_USER_ENTITY_INFORMATION {
        &self.native
    }
}
