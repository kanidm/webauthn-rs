use windows::{core::HSTRING, w};

// Most constants are `&str`, but APIs expect `HSTRING`... there's no good work-around.
// https://github.com/microsoft/windows-rs/issues/2049
/// [windows::Win32::Networking::WindowsWebServices::WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY]
pub const CREDENTIAL_TYPE_PUBLIC_KEY: &HSTRING = w!("public-key");
