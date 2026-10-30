use windows::core::PCWSTR;
use windows::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB,
    WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
    WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH,
};

/// # Safety
/// parameter p should:
///   - be a valid null terminated wide string
///   - have a static lifetime (program constant such as w! strings )
const unsafe fn static_pcwstr_as_wide(p: PCWSTR) -> &'static [u16] {
    let start = p.as_ptr();
    let mut end = start;
    while *end != 0 {
        end = end.add(1)
    }
    let len = end.offset_from_unsigned(start);
    core::slice::from_raw_parts(p.0, len)
}

// Safety: these constants are statically defined constants using the w!() macro
// Convert (compile time) to wide slices to be compared easily.
pub const ID_HMAC_SECRET: &[u16] =
    unsafe { static_pcwstr_as_wide(WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET) };
pub const ID_CRED_PROTECT: &[u16] =
    unsafe { static_pcwstr_as_wide(WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT) };
pub const ID_CRED_BLOB: &[u16] =
    unsafe { static_pcwstr_as_wide(WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB) };
pub const ID_MIN_PIN_LENGTH: &[u16] =
    unsafe { static_pcwstr_as_wide(WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH) };

pub const CREDENTIAL_TYPE_PUBLIC_KEY: &[u16] =
    unsafe { static_pcwstr_as_wide(WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY) };
