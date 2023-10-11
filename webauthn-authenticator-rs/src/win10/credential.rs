//! Wrappers for [AllowCredentials] and [PublicKeyCredentialDescriptor].
use crate::prelude::WebauthnCError;
use base64urlsafedata::Base64UrlSafeData;
use std::pin::Pin;
use webauthn_rs_proto::{AllowCredentials, AuthenticatorTransport, PublicKeyCredentialDescriptor};

use super::WinWrapper;

use windows::{
    core::HSTRING,
    w,
    Win32::Networking::WindowsWebServices::{
        WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST,
        WEBAUTHN_CTAP_TRANSPORT_BLE, WEBAUTHN_CTAP_TRANSPORT_INTERNAL, WEBAUTHN_CTAP_TRANSPORT_NFC,
        WEBAUTHN_CTAP_TRANSPORT_TEST, WEBAUTHN_CTAP_TRANSPORT_USB,
    },
};

// Most constants are `&str`, but APIs expect `HSTRING`... there's no good work-around.
// https://github.com/microsoft/windows-rs/issues/2049
/// [windows::Win32::Networking::WindowsWebServices::WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY]
const CREDENTIAL_TYPE_PUBLIC_KEY: &HSTRING = w!("public-key");

/// Converts an [AuthenticatorTransport] into a value for
/// [WEBAUTHN_CREDENTIAL_EX::dwTransports]
fn transport_to_native(transport: &AuthenticatorTransport) -> u32 {
    match transport {
        AuthenticatorTransport::Ble => WEBAUTHN_CTAP_TRANSPORT_BLE,
        AuthenticatorTransport::Internal => WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
        AuthenticatorTransport::Nfc => WEBAUTHN_CTAP_TRANSPORT_NFC,
        AuthenticatorTransport::Test => WEBAUTHN_CTAP_TRANSPORT_TEST,
        AuthenticatorTransport::Usb => WEBAUTHN_CTAP_TRANSPORT_USB,
        // This transport has not platform equivalent on windows, mask to 0.
        AuthenticatorTransport::Hybrid | AuthenticatorTransport::Unknown => 0,
    }
}

/// Converts a bitmask of native transports into [AuthenticatorTransport].
pub fn native_to_transports(t: u32) -> Vec<AuthenticatorTransport> {
    let mut o: Vec<AuthenticatorTransport> = Vec::new();
    if t & WEBAUTHN_CTAP_TRANSPORT_BLE != 0 {
        o.push(AuthenticatorTransport::Ble);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_INTERNAL != 0 {
        o.push(AuthenticatorTransport::Internal);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_NFC != 0 {
        o.push(AuthenticatorTransport::Nfc);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_TEST != 0 {
        o.push(AuthenticatorTransport::Test);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_USB != 0 {
        o.push(AuthenticatorTransport::Usb);
    }
    o
}

/// Converts a [`Vec<AuthenticatorTransport>`] into a value for
/// [WEBAUTHN_CREDENTIAL_EX::dwTransports]
fn transports_to_bitmask(transports: &Option<Vec<AuthenticatorTransport>>) -> u32 {
    match transports {
        None => 0,
        Some(transports) => transports.iter().map(transport_to_native).sum(),
    }
}

/// Wrapper for [WEBAUTHN_CREDENTIAL_LIST] to ensure pointer lifetime, analogous to
/// [PublicKeyCredentialDescriptor] and [AllowCredentials].
pub struct WinCredentialList {
    /// Native structure, which points to everything else here.
    pub(crate) native: WEBAUTHN_CREDENTIAL_LIST,
    /// Pointer to _l, because [WEBAUTHN_CREDENTIAL_LIST::ppCredentials] is a double-pointer.
    _p: *const WEBAUTHN_CREDENTIAL_EX,
    /// List of credentials
    _l: Vec<WEBAUTHN_CREDENTIAL_EX>,
    /// List of credential IDs, referenced by [WEBAUTHN_CREDENTIAL_EX::pbId]
    _ids: Vec<Base64UrlSafeData>,
}

/// Trait to make [PublicKeyCredentialDescriptor] and [AllowCredentials] look the same.
trait CredentialType: std::fmt::Debug {
    fn type_(&self) -> String;
    fn id(&self) -> Base64UrlSafeData;
    fn transports(&self) -> u32;
}

impl CredentialType for PublicKeyCredentialDescriptor {
    fn type_(&self) -> String {
        self.type_.clone()
    }
    fn id(&self) -> Base64UrlSafeData {
        self.id.clone()
    }
    fn transports(&self) -> u32 {
        transports_to_bitmask(&self.transports)
    }
}

impl CredentialType for AllowCredentials {
    fn type_(&self) -> String {
        self.type_.clone()
    }
    fn id(&self) -> Base64UrlSafeData {
        self.id.clone()
    }
    fn transports(&self) -> u32 {
        transports_to_bitmask(&self.transports)
    }
}

impl<T: CredentialType> WinWrapper<Vec<T>> for WinCredentialList {
    type NativeType = WEBAUTHN_CREDENTIAL_LIST;
    fn new(credentials: &Vec<T>) -> Result<Pin<Box<Self>>, WebauthnCError> {
        // Check that all the credential types are supported.
        for c in credentials.iter() {
            let typ = c.type_();
            if typ != *"public-key" {
                error!("Unsupported credential type: {:?}", c);
                return Err(WebauthnCError::Internal);
            }
        }

        let len = credentials.len();
        let res = Self {
            native: Default::default(),
            _p: std::ptr::null(),
            _l: Vec::with_capacity(len),
            _ids: credentials.iter().map(|c| c.id()).collect(),
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        // Put in all the "native" values
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let mut_ptr = Pin::get_unchecked_mut(mut_ref);
            let l = &mut mut_ptr._l;
            let l_ptr = l.as_mut_ptr();
            for (i, credential) in credentials.iter().enumerate() {
                let id = &mut mut_ptr._ids[i];
                *l_ptr.add(i) = WEBAUTHN_CREDENTIAL_EX {
                    dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                    cbId: id.0.len() as u32,
                    pbId: id.0.as_mut_ptr() as *mut _,
                    pwszCredentialType: CREDENTIAL_TYPE_PUBLIC_KEY.into(),
                    dwTransports: credential.transports(),
                };
            }

            l.set_len(len);
        }

        // Add a pointer to the pointer...
        let p = boxed._l.as_ptr();
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref)._p = p;
        }

        let native = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: len as u32,
            ppCredentials: std::ptr::addr_of_mut!(boxed._p) as *mut *mut _,
        };

        // Drop in the native struct
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        // trace!(?boxed.native);

        Ok(boxed)
    }

    fn native_ptr(&self) -> &WEBAUTHN_CREDENTIAL_LIST {
        &self.native
    }
}
