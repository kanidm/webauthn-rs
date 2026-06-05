//! Wrappers for [CollectedClientData].
use std::pin::Pin;
use webauthn_rs_proto::CollectedClientData;

use super::WinWrapper;
use crate::error::WebauthnCError;

use windows::{
    core::HSTRING,
    w,
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_CLIENT_DATA, WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
    },
};
// Most constants are `&str`, but APIs expect `HSTRING`... there's no good work-around.
// https://github.com/microsoft/windows-rs/issues/2049
/// [windows::Win32::Networking::WindowsWebServices::WEBAUTHN_HASH_ALGORITHM_SHA_256]
const SHA_256: &HSTRING = w!("SHA-256");

/// Wrapper for [WEBAUTHN_CLIENT_DATA] to ensure pointer lifetime.
pub struct WinClientData {
    native: Pin<Box<WEBAUTHN_CLIENT_DATA>>,
    client_data_json: Pin<String>,
}

impl WinClientData {
    pub fn client_data_json(&self) -> &str {
        &self.client_data_json
    }
}

impl WinWrapper<CollectedClientData> for WinClientData {
    type NativeType = WEBAUTHN_CLIENT_DATA;
    fn new(clientdata: CollectedClientData) -> Result<Self, WebauthnCError> {
        // Construct an incomplete type first, so that all the pointers are fixed.
        let mut res = Self {
            native: Default::default(),
            client_data_json: Pin::new(
                serde_json::to_string(&clientdata).map_err(|_| WebauthnCError::Json)?,
            ),
        };

        // Create the real native type, which contains bare pointers.
        res.native = Box::pin(WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: res.client_data_json.len() as u32,
            pbClientDataJSON: res.client_data_json.as_mut_ptr(),
            pwszHashAlgId: SHA_256.into(),
        });

        Ok(res)
    }

    fn native_ptr(&self) -> &WEBAUTHN_CLIENT_DATA {
        &self.native
    }
}
