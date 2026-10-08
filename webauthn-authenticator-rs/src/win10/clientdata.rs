//! Wrappers for [CollectedClientData].

use crate::error::WebauthnCError;
use std::{marker::PhantomPinned, pin::Pin};
use webauthn_rs_proto::CollectedClientData;
use windows::{
    core::HSTRING,
    w,
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_CLIENT_DATA, WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
    },
};

use super::WinWrapper;
// Most constants are `&str`, but APIs expect `HSTRING`... there's no good work-around.
// https://github.com/microsoft/windows-rs/issues/2049
/// [windows::Win32::Networking::WindowsWebServices::WEBAUTHN_HASH_ALGORITHM_SHA_256]
const SHA_256: &HSTRING = w!("SHA-256");

/// Wrapper for [WEBAUTHN_CLIENT_DATA] to ensure pointer lifetime.
pub struct WinClientData {
    native: WEBAUTHN_CLIENT_DATA,
    client_data_json: String,
    _pin: PhantomPinned,
}

impl WinClientData {
    pub fn client_data_json(&self) -> &str {
        &self.client_data_json
    }
}

impl WinWrapper<CollectedClientData> for WinClientData {
    type NativeType = WEBAUTHN_CLIENT_DATA;
    fn new(clientdata: CollectedClientData) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let client_data_json =
            serde_json::to_string(&clientdata).map_err(|_| WebauthnCError::Json)?;

        let res = Self {
            native: WEBAUTHN_CLIENT_DATA {
                dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                cbClientDataJSON: client_data_json.len() as u32,
                pbClientDataJSON: std::ptr::null_mut(),
                pwszHashAlgId: SHA_256.into(),
            },
            client_data_json,
            _pin: PhantomPinned,
        };

        let mut boxed = Box::new(res);
        // Add internal pointer now that `client_data_json` is in place.
        boxed.native.pbClientDataJSON = boxed.client_data_json.as_mut_ptr();

        Ok(Box::into_pin(boxed))
    }

    fn native_ptr(&self) -> &WEBAUTHN_CLIENT_DATA {
        &self.native
    }
}
