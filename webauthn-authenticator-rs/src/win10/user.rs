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
    native: Pin<Box<WEBAUTHN_USER_ENTITY_INFORMATION>>,
    id: Pin<Vec<u8>>,
    name: Pin<Box<HSTRING>>,
    display_name: Pin<Box<HSTRING>>,
}

impl WinWrapper<User> for WinUserEntityInformation {
    type NativeType = WEBAUTHN_USER_ENTITY_INFORMATION;
    fn new(u: User) -> Result<Self, WebauthnCError> {
        let mut res = Self {
            native: Default::default(),
            id: Pin::new(u.id.into()),
            name: Box::pin(u.name.into()),
            display_name: Box::pin(u.display_name.into()),
        };

        // Create the real native type, which contains bare pointers.
        res.native = Box::pin(WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: res.id.len() as u32,
            pbId: res.id.as_ptr() as *mut _,
            pwszName: PCWSTR::from_raw(res.name.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR::from_raw(res.display_name.as_ptr()),
        });

        Ok(res)
    }

    fn native_ptr(&self) -> &WEBAUTHN_USER_ENTITY_INFORMATION {
        &self.native
    }
}
