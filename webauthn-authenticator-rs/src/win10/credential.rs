//! Wrappers for [AllowCredentials] and [PublicKeyCredentialDescriptor].
use crate::prelude::WebauthnCError;
use std::{marker::PhantomPinned, pin::Pin};
use webauthn_rs_proto::{AllowCredentials, AuthenticatorTransport, PublicKeyCredentialDescriptor};
use windows::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE,
    WEBAUTHN_CTAP_TRANSPORT_INTERNAL, WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_TEST,
    WEBAUTHN_CTAP_TRANSPORT_USB,
};

use super::{constants::CREDENTIAL_TYPE_PUBLIC_KEY, WinWrapper};

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
    pub(super) native: WEBAUTHN_CREDENTIAL_LIST,
    /// List of credentials
    l: Vec<Pin<Box<WEBAUTHN_CREDENTIAL_EX>>>,
    /// List of credential IDs, referenced by [WEBAUTHN_CREDENTIAL_EX::pbId]
    ids: Vec<Vec<u8>>,
    _pin: PhantomPinned,
}

/// Trait to make [PublicKeyCredentialDescriptor] and [AllowCredentials] look the same.
trait CredentialType: std::fmt::Debug {
    fn type_(&self) -> String;
    fn id(&self) -> Vec<u8>;
    fn transports(&self) -> u32;
}

impl CredentialType for PublicKeyCredentialDescriptor {
    fn type_(&self) -> String {
        self.type_.clone()
    }
    fn id(&self) -> Vec<u8> {
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
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn transports(&self) -> u32 {
        transports_to_bitmask(&self.transports)
    }
}

impl<T: CredentialType> WinWrapper<Vec<T>> for WinCredentialList {
    type NativeType = WEBAUTHN_CREDENTIAL_LIST;

    fn new(credentials: Vec<T>) -> Result<Pin<Box<Self>>, WebauthnCError> {
        // Check that all the credential types are supported.
        for c in credentials.iter() {
            let typ = c.type_();
            if typ != WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY {
                error!("Unsupported credential type: {c:?}");
                return Err(WebauthnCError::Internal);
            }
        }

        let len = credentials.len();

        let res = Self {
            ids: credentials.iter().map(|c| c.id()).collect(),
            native: WEBAUTHN_CREDENTIAL_LIST {
                cCredentials: len as u32,
                ppCredentials: std::ptr::null_mut(),
            },
            l: Vec::with_capacity(len),
            _pin: PhantomPinned,
        };

        let mut boxed = Box::new(res);

        // Put in all the "native" values
        for (credential, id) in credentials.iter().zip(boxed.ids.iter_mut()) {
            boxed.l.push(Box::pin(WEBAUTHN_CREDENTIAL_EX {
                dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_mut_ptr(),
                pwszCredentialType: CREDENTIAL_TYPE_PUBLIC_KEY.into(),
                dwTransports: credential.transports(),
            }));
        }

        // Each entry is in a `Box`, so C can treat the parent `Vec` an array of pointers to
        // `WEBAUTHN_CREDENTIAL_EX`.
        boxed.native.ppCredentials =
            Vec::as_mut_ptr(&mut boxed.l) as *mut *mut WEBAUTHN_CREDENTIAL_EX;

        Ok(Box::into_pin(boxed))
    }

    fn native_ptr(&self) -> &WEBAUTHN_CREDENTIAL_LIST {
        &self.native
    }
}

impl WinCredentialList {
    pub fn native(&self) -> *const WEBAUTHN_CREDENTIAL_LIST {
        &self.native
    }
}
