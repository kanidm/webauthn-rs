//! Wrappers for extensions.
use crate::prelude::WebauthnCError;
use std::ffi::c_void;
use std::pin::Pin;
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, CredProtect, RegistrationExtensionsClientOutputs,
    RequestRegistrationExtensions,
};

use super::WinWrapper;

use windows::{
    core::HSTRING,
    Win32::{Foundation::BOOL, Networking::WindowsWebServices::*},
};

/// Represents a single extension for MakeCredential requests, analogous to a
/// single [RequestRegistrationExtensions] field.
#[derive(Debug)]
pub(crate) enum WinExtensionMakeCredentialRequest {
    HmacSecret(BOOL),
    CredProtect(WEBAUTHN_CRED_PROTECT_EXTENSION_IN),
    MinPinLength(BOOL),
}

/// Represents a single extension for GetAssertion requests, analogous to a
/// single [RequestAuthenticationExtensions] field.
#[derive(Debug)]
pub(crate) enum WinExtensionGetAssertionRequest {}

/// Generic request extension trait, for abstracting between
/// [WinExtensionMakeCredentialRequest] and [WinExtensionGetAssertionRequest].
pub(crate) trait WinExtensionRequestType
where
    Self: Sized,
{
    /// Extension identier, as string.
    fn identifier(&self) -> &str;
    /// Length of the native data structure, in bytes.
    fn len(&self) -> u32;
    /// Pointer to the native data structure.
    fn ptr(&mut self) -> *mut c_void;
    /// The `webauthn-authenticator-rs` type which this wraps.
    type WrappedType;
    /// Converts the [Self::WrappedType] to a [Vec] of Windows API types.
    fn to_native(e: Self::WrappedType) -> Vec<Self>;
}

impl WinExtensionRequestType for WinExtensionMakeCredentialRequest {
    fn identifier(&self) -> &str {
        match self {
            Self::HmacSecret(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            Self::CredProtect(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT,
            Self::MinPinLength(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH,
        }
    }

    fn len(&self) -> u32 {
        (match self {
            Self::HmacSecret(_) => std::mem::size_of::<BOOL>(),
            Self::CredProtect(_) => std::mem::size_of::<WEBAUTHN_CRED_PROTECT_EXTENSION_IN>(),
            Self::MinPinLength(_) => std::mem::size_of::<BOOL>(),
        }) as u32
    }

    fn ptr(&mut self) -> *mut c_void {
        match self {
            Self::HmacSecret(v) => v as *mut _ as *mut c_void,
            Self::CredProtect(v) => v as *mut _ as *mut c_void,
            Self::MinPinLength(v) => v as *mut _ as *mut c_void,
        }
    }

    type WrappedType = RequestRegistrationExtensions;

    fn to_native(e: Self::WrappedType) -> Vec<Self> {
        let mut o: Vec<Self> = Vec::new();
        if let Some(c) = &e.cred_protect {
            o.push(c.into());
        }
        if let Some(h) = &e.hmac_create_secret {
            o.push(Self::HmacSecret(h.into()))
        }
        if let Some(x) = &e.min_pin_length {
            o.push(Self::MinPinLength(x.into()));
        }

        o
    }
}

/*
impl WinExtensionRequestType for WinExtensionGetAssertionRequest {
    fn identifier(&self) -> &str {
        todo!();
    }

    fn len(&self) -> u32 {
        todo!();
    }

    fn ptr(&mut self) -> *mut c_void {
        todo!();
    }

    type WrappedType = RequestAuthenticationExtensions;

    fn to_native(_e: &Self::WrappedType) -> Vec<Self> {
        let o: Vec<Self> = Vec::new();

        o
    }
}
*/

impl From<&CredProtect> for WinExtensionMakeCredentialRequest {
    /// Converts [CredProtect] into [WEBAUTHN_CRED_PROTECT_EXTENSION_IN].
    fn from(c: &CredProtect) -> Self {
        Self::CredProtect(WEBAUTHN_CRED_PROTECT_EXTENSION_IN {
            dwCredProtect: c.credential_protection_policy as u32,
            bRequireCredProtect: c
                .enforce_credential_protection_policy
                .unwrap_or(false)
                .into(),
        })
    }
}

/// Reads a [WEBAUTHN_EXTENSION] containing a Windows-specific primitive type,
/// converting it into a Rust datatype.
fn read_extension<'a, T: 'a, U: From<&'a T>>(
    e: &'a WEBAUTHN_EXTENSION,
) -> Result<U, WebauthnCError> {
    if (e.cbExtension as usize) < std::mem::size_of::<T>() {
        return Err(WebauthnCError::Internal);
    }
    let v = unsafe { (e.pvExtension as *mut T).as_ref() }.ok_or(WebauthnCError::Internal)?;
    Ok(v.into())
}

/// Reads and copies a [WEBAUTHN_EXTENSION] containing a primitive type.
fn read_extension2<'a, T: 'a + Clone>(e: &'a WEBAUTHN_EXTENSION) -> Result<T, WebauthnCError> {
    if (e.cbExtension as usize) < std::mem::size_of::<T>() {
        return Err(WebauthnCError::Internal);
    }
    let v = unsafe { (e.pvExtension as *mut T).as_ref() }.ok_or(WebauthnCError::Internal)?;
    Ok(v.clone())
}

/// Represents a single extension for MakeCredential responses, analogous to a
/// single [RegistrationExtensionsClientOutputs] field.
enum WinExtensionMakeCredentialResponse {
    HmacSecret(bool),
    CredProtect(u32),
    CredBlob,
    MinPinLength(u32),
}

impl TryFrom<&WEBAUTHN_EXTENSION> for WinExtensionMakeCredentialResponse {
    type Error = WebauthnCError;

    /// Reads a [WEBAUTHN_EXTENSION] for a response to a MakeCredential call.
    fn try_from(e: &WEBAUTHN_EXTENSION) -> Result<Self, WebauthnCError> {
        let id = unsafe {
            e.pwszExtensionIdentifier
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?
        };
        // let id = &HSTRING::from_wide(unsafe { e.pwszExtensionIdentifier.as_wide() });
        match id.as_str() {
            WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET => {
                read_extension::<'_, BOOL, _>(e).map(WinExtensionMakeCredentialResponse::HmacSecret)
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT => {
                read_extension2(e).map(WinExtensionMakeCredentialResponse::CredProtect)
            }
            // Value intentonally ignored
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB => Ok(Self::CredBlob),
            WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH => {
                read_extension2(e).map(WinExtensionMakeCredentialResponse::MinPinLength)
            }
            o => {
                error!("unknown extension: {:?}", o);
                Err(WebauthnCError::Internal)
            }
        }
    }
}

/// Converts [WEBAUTHN_EXTENSIONS] for a response to MakeCredential call into
/// a `webauthn-authenticator-rs` [RegistrationExtensionsClientOutputs] type.
pub fn native_to_registration_extensions(
    native: &WEBAUTHN_EXTENSIONS,
) -> Result<RegistrationExtensionsClientOutputs, WebauthnCError> {
    let mut o = RegistrationExtensionsClientOutputs::default();

    for i in 0..(native.cExtensions as usize) {
        let extn = unsafe { &*native.pExtensions.add(i) };
        let win = WinExtensionMakeCredentialResponse::try_from(extn)?;
        match win {
            WinExtensionMakeCredentialResponse::HmacSecret(v) => o.hmac_secret = Some(v),
            WinExtensionMakeCredentialResponse::CredProtect(v) => {
                o.cred_protect = (v as u8).try_into().ok();
            }
            WinExtensionMakeCredentialResponse::CredBlob => (),
            WinExtensionMakeCredentialResponse::MinPinLength(v) => {
                o.min_pin_length = Some(v);
            }
        }
    }

    Ok(o)
}

/// Represents a single extension for GetAssertion responses, analogous to a
/// single [AuthenticationExtensionsClientOutputs] field.
enum WinExtensionGetAssertionResponse {
    CredBlob,
}

impl TryFrom<&WEBAUTHN_EXTENSION> for WinExtensionGetAssertionResponse {
    type Error = WebauthnCError;

    /// Reads a [WEBAUTHN_EXTENSION] for a response to a GetAssertion call.
    fn try_from(e: &WEBAUTHN_EXTENSION) -> Result<Self, Self::Error> {
        let id = unsafe {
            e.pwszExtensionIdentifier
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?
        };

        match id.as_str() {
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB => Ok(Self::CredBlob),
            o => {
                error!("unknown extension: {:?}", o);
                Err(WebauthnCError::Internal)
            }
        }
    }
}

/// Converts [WEBAUTHN_EXTENSIONS] for a response to GetAssertion call into
/// a `webauthn-authenticator-rs` [AuthenticationExtensionsClientOutputs] type.
pub fn native_to_assertion_extensions(
    native: &WEBAUTHN_EXTENSIONS,
) -> Result<AuthenticationExtensionsClientOutputs, WebauthnCError> {
    let /* mut */ o = AuthenticationExtensionsClientOutputs::default();

    for i in 0..(native.cExtensions as usize) {
        let extn = unsafe { &*native.pExtensions.add(i) };
        let win = WinExtensionGetAssertionResponse::try_from(extn)?;
        match win {
            WinExtensionGetAssertionResponse::CredBlob => (),
        }
    }

    Ok(o)
}

pub(crate) struct WinExtensionsRequest<T>
where
    T: WinExtensionRequestType + std::fmt::Debug,
{
    native: WEBAUTHN_EXTENSIONS,
    native_list: Vec<WEBAUTHN_EXTENSION>,
    ids: Vec<HSTRING>,
    extensions: Vec<T>,
}

impl<T> Default for WinExtensionsRequest<T>
where
    T: WinExtensionRequestType + std::fmt::Debug,
{
    fn default() -> Self {
        Self {
            native: Default::default(),
            native_list: vec![],
            ids: vec![],
            extensions: vec![],
        }
    }
}

impl<T> WinWrapper<T::WrappedType> for WinExtensionsRequest<T>
where
    T: WinExtensionRequestType + std::fmt::Debug,
    T::WrappedType: std::fmt::Debug,
{
    type NativeType = WEBAUTHN_EXTENSIONS;
    fn native_ptr(&self) -> &WEBAUTHN_EXTENSIONS {
        &self.native
    }

    fn new(e: T::WrappedType) -> Result<Pin<Box<Self>>, WebauthnCError> {
        // Convert the extensions to a Windows-ish type
        // trace!(?e);
        let extensions = T::to_native(e);
        let len = extensions.len();

        let res = Self {
            native: Default::default(),
            native_list: Vec::with_capacity(len),
            ids: extensions.iter().map(|e| e.identifier().into()).collect(),
            extensions,
        };

        // trace!(?res.extensions);
        // Put our final struct on the heap
        let mut boxed = Box::pin(res);

        // Put in all the "native" values
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let mut_ptr = Pin::get_unchecked_mut(mut_ref);

            let l = &mut mut_ptr.native_list;
            let l_ptr = l.as_mut_ptr();
            for (i, extension) in mut_ptr.extensions.iter_mut().enumerate() {
                let id = &mut_ptr.ids[i];
                *l_ptr.add(i) = WEBAUTHN_EXTENSION {
                    pwszExtensionIdentifier: id.into(),
                    cbExtension: extension.len(),
                    pvExtension: extension.ptr(),
                };
            }

            l.set_len(len);
        }

        // Create the native list element
        let native = WEBAUTHN_EXTENSIONS {
            cExtensions: len as u32,
            pExtensions: boxed.native_list.as_ptr() as *mut _,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        Ok(boxed)
    }
}
