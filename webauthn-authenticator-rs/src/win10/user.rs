//! Wrappers for [User].
use crate::error::WebauthnCError;
use std::{marker::PhantomPinned, pin::Pin};
use webauthn_rs_proto::User;
use windows::core::PCWSTR;
use windows::{
    core::HSTRING,
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    },
};

use super::WinWrapper;

/// Wrapper for [WEBAUTHN_USER_ENTITY_INFORMATION] to ensure pointer lifetime, analgous to [User].
pub struct WinUserEntityInformation {
    native: WEBAUTHN_USER_ENTITY_INFORMATION,
    id: Vec<u8>,
    name: HSTRING,
    display_name: HSTRING,
    _pin: PhantomPinned,
}

impl WinWrapper<User> for WinUserEntityInformation {
    type NativeType = WEBAUTHN_USER_ENTITY_INFORMATION;
    fn new(u: User) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let res = Self {
            native: WEBAUTHN_USER_ENTITY_INFORMATION {
                dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                cbId: u.id.len() as u32,
                ..Default::default()
            },
            id: u.id,
            name: u.name.into(),
            display_name: u.display_name.into(),
            _pin: PhantomPinned,
        };

        let mut boxed = Box::new(res);

        boxed.native.pbId = boxed.id.as_mut_ptr();
        boxed.native.pwszName = PCWSTR::from_raw(boxed.name.as_ptr());
        boxed.native.pwszDisplayName = PCWSTR::from_raw(boxed.display_name.as_ptr());

        Ok(Box::into_pin(boxed))
    }

    fn native_ptr(&self) -> &WEBAUTHN_USER_ENTITY_INFORMATION {
        &self.native
    }
}
