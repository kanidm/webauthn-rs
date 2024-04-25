//! Bindings for Windows 10 WebAuthn API.
//!
//! This API is available in Windows 10 bulid 1903 and later.
//!
//! ## API docs
//!
//! * [MSDN: WebAuthn API](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/)
//! * [webauthn.h](github.com/microsoft/webauthn) (describes versions)
//! * [windows-rs API](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WindowsWebServices/index.html)
#[cfg(feature = "win10")]
mod clientdata;
#[cfg(feature = "win10")]
mod cose;
#[cfg(feature = "win10")]
mod credential;
#[cfg(feature = "win10")]
mod extensions;
#[cfg(feature = "win10")]
mod gui;
#[cfg(feature = "win10")]
mod native;
#[cfg(feature = "win10")]
mod rp;
#[cfg(feature = "win10")]
mod user;

#[cfg(feature = "win10")]
use crate::win10::{
    clientdata::WinClientData,
    cose::WinCoseCredentialParameters,
    credential::{native_to_transports, WinCredentialList},
    extensions::{
        native_to_assertion_extensions, native_to_registration_extensions,
        WinExtensionMakeCredentialRequest, WinExtensionsRequest,
    },
    gui::Window,
    native::{WinPtr, WinWrapper},
    rp::WinRpEntityInformation,
    user::WinUserEntityInformation,
};
use crate::{
    error::WebauthnCError,
    util::{creation_to_clientdata, get_to_clientdata},
    AuthenticatorBackend, Url, BASE64_ENGINE,
};

use base64::Engine;
use base64urlsafedata::Base64UrlSafeData;
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttachment,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential, UserVerificationPolicy,
};

#[cfg(feature = "win10")]
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::{Foundation::BOOL, Networking::WindowsWebServices::*},
};

use std::slice::from_raw_parts;

/// Authenticator backend for Windows 10 WebAuthn API.
pub struct Win10 {}

impl Default for Win10 {
    fn default() -> Self {
        unsafe {
            trace!(
                "WebAuthNGetApiVersionNumber(): {}",
                WebAuthNGetApiVersionNumber()
            );
            match WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() {
                Ok(v) => trace!(
                    "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() = {:?}",
                    <_ as Into<bool>>::into(v)
                ),
                Err(e) => trace!("error requesting platform authenticator: {:?}", e),
            }
        }

        Self {}
    }
}

impl AuthenticatorBackend for Win10 {
    /// Perform a registration action using Windows WebAuth API.
    ///
    /// This wraps [WebAuthNAuthenticatorMakeCredential].
    ///
    /// [WebAuthnAuthenticatorMakeCredential]: https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatormakecredential
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let hwnd = Window::new()?;
        // let hwnd = get_hwnd().ok_or(WebauthnCError::CannotFindHWND)?;
        let rp = WinRpEntityInformation::new(options.rp)?;
        let userinfo = WinUserEntityInformation::new(options.user)?;
        let pubkeycredparams = WinCoseCredentialParameters::new(options.pub_key_cred_params)?;
        let clientdata =
            WinClientData::new(creation_to_clientdata(origin, options.challenge.clone()))?;

        let mut exclude_credentials = if let Some(e) = options.exclude_credentials {
            Some(WinCredentialList::new(e)?)
        } else {
            None
        };
        let extensions = match options.extensions {
            Some(e) => WinExtensionsRequest::new(e)?,
            None => Box::pin(WinExtensionsRequest::<WinExtensionMakeCredentialRequest>::default()),
        };
        // trace!("native extn: {:?}", extensions.native_ptr());

        let makecredopts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Superceded by pExcludeCredentialList for v3 (API v1, baseline)
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            Extensions: *extensions.native_ptr(),
            dwAuthenticatorAttachment: attachment_to_native(
                options
                    .authenticator_selection
                    .as_ref()
                    .map(|s| s.authenticator_attachment)
                    .unwrap_or(None),
            ),
            bRequireResidentKey: options
                .authenticator_selection
                .as_ref()
                .map(|s| s.require_resident_key)
                .unwrap_or(false)
                .into(),
            dwUserVerificationRequirement: user_verification_to_native(
                options
                    .authenticator_selection
                    .as_ref()
                    .map(|s| &s.user_verification),
            ),
            dwAttestationConveyancePreference: 0,
            dwFlags: 0,
            pCancellationId: std::ptr::null_mut(),
            pExcludeCredentialList: match &mut exclude_credentials {
                None => std::ptr::null(),
                Some(l) => &l.native,
            } as *mut _,
            dwEnterpriseAttestation: 0,
            dwLargeBlobSupport: 0,
            bPreferResidentKey: false.into(),
        };

        // trace!("WebAuthNAuthenticatorMakeCredential()");
        // trace!("native: {:?}", extensions.native_ptr());
        // trace!(?makecredopts);
        let a = unsafe {
            let r = WebAuthNAuthenticatorMakeCredential(
                &hwnd,
                rp.native_ptr(),
                userinfo.native_ptr(),
                pubkeycredparams.native_ptr(),
                clientdata.native_ptr(),
                Some(&makecredopts),
            )
            .map_err(|e| {
                // TODO: map error codes, if we learn them...
                error!("Error: {:?}", e);
                WebauthnCError::Internal
            })?;

            WinPtr::new(r, |a| WebAuthNFreeCredentialAttestation(Some(a)))
                .ok_or(WebauthnCError::Internal)?
        };
        // These needed to live until WebAuthNAuthenticatorMakeCredential returned.
        drop(extensions);
        drop(hwnd);

        // trace!("got result from WebAuthNAuthenticatorMakeCredential");
        // trace!("{:?}", (*a));

        unsafe {
            let cred_id = from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
            let attesation_object =
                from_raw_parts(a.pbAttestationObject, a.cbAttestationObject as usize).to_vec();
            let type_: String = a
                .pwszFormatType
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?;

            Ok(RegisterPublicKeyCredential {
                id: BASE64_ENGINE.encode(&cred_id),
                raw_id: cred_id.into(),
                type_,
                extensions: native_to_registration_extensions(&a.Extensions)?,
                response: AuthenticatorAttestationResponseRaw {
                    attestation_object: attesation_object.into(),
                    client_data_json: Base64UrlSafeData::from(
                        clientdata.client_data_json().as_bytes().to_vec(),
                    ),
                    transports: Some(native_to_transports(a.dwUsedTransport)),
                },
            })
        }
    }

    /// Perform an authentication action using Windows WebAuth API.
    ///
    /// This wraps [WebAuthNAuthenticatorGetAssertion].
    ///
    /// [WebAuthNAuthenticatorGetAssertion]: https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion
    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        trace!(?options);
        let hwnd = Window::new()?;
        let rp_id: HSTRING = options.rp_id.clone().into();
        let clientdata = WinClientData::new(get_to_clientdata(origin, options.challenge.clone()))?;

        let mut allow_credentials = WinCredentialList::new(options.allow_credentials)?;

        let app_id: Option<HSTRING> = options
            .extensions
            .as_ref()
            .and_then(|e| e.appid.as_ref())
            .map(|a| a.clone().into());
        // Used as a *return* value from GetAssertion as to whether the U2F AppId was used,
        // equivalent to [AuthenticationExtensionsClientOutputs::appid].
        //
        // Why here? Because for some reason, Windows' API decides to put a pointer for
        // mutable *return* value inside an `_In_opt_ *const ptr` *request* value
        // ([WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS]): `pbU2fAppId`.
        //
        // The documentation was very opaque here, but [Firefox's implementation][ffx]
        // appears to correctly deal with this nonsense.
        //
        // However, [Chromium's implementation][chr] appears to have misunderstood this field,
        // and always passes in pointers to `static BOOL` values `kUseAppIdTrue` or
        // `kUseAppIdFalse` (depending on whether the extension was present) and doesn't read
        // the response.
        //
        // Unfortunately, it looks like the WebAuthn API has been frozen for Windows 10, and
        // the new revisions are only on Windows 11. So it's unlikely this will ever be
        // properly fixed. 🙃
        //
        // [chr]: https://chromium.googlesource.com/chromium/src/+/f62b8f341c14be84c6c995133f485d76a58de090/device/fido/win/webauthn_api.cc#520
        // [ffx]: https://github.com/mozilla/gecko-dev/blob/620490a051a1fc72563e1c6bbecfe7346122a6bc/dom/webauthn/WinWebAuthnManager.cpp#L714-L716
        let mut app_id_used: BOOL = false.into();
        // let extensions = match &options.extensions {
        //     Some(e) => WinExtensionsRequest::new(e)?,
        //     None => Box::pin(WinExtensionsRequest::<WinExtensionGetAssertionRequest>::default()),
        // };

        let getassertopts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Supersceded by pAllowCredentialList in v4 (API v1, baseline)
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            // Extensions: *extensions.native_ptr(),
            Extensions: Default::default(),
            dwAuthenticatorAttachment: 0, // Not supported?
            dwUserVerificationRequirement: user_verification_to_native(Some(
                &options.user_verification,
            )),
            dwFlags: 0,
            pwszU2fAppId: match &app_id {
                None => PCWSTR::null(),
                Some(l) => l.into(),
            },
            pbU2fAppId: std::ptr::addr_of_mut!(app_id_used),
            pCancellationId: std::ptr::null_mut(),
            pAllowCredentialList: &mut allow_credentials.native,
            dwCredLargeBlobOperation: 0,
            cbCredLargeBlob: 0,
            pbCredLargeBlob: std::ptr::null_mut(),
        };

        // trace!("WebAuthNAuthenticatorGetAssertion()");
        let a = unsafe {
            let r = WebAuthNAuthenticatorGetAssertion(
                &hwnd,
                &rp_id,
                clientdata.native_ptr(),
                Some(&getassertopts),
            )
            .map_err(|e| {
                // TODO: map error codes, if we learn them...
                error!("Error: {:?}", e);
                WebauthnCError::Internal
            })?;

            WinPtr::new(r, WebAuthNFreeAssertion).ok_or(WebauthnCError::Internal)?
        };
        // This needed to live until WebAuthNAuthenticatorGetAssertion returned.
        drop(hwnd);
        // trace!("got result from WebAuthNAuthenticatorGetAssertion");

        unsafe {
            let user_id = from_raw_parts(a.pbUserId, a.cbUserId as usize).to_vec();
            let authenticator_data =
                from_raw_parts(a.pbAuthenticatorData, a.cbAuthenticatorData as usize).to_vec();
            let signature = from_raw_parts(a.pbSignature, a.cbSignature as usize).to_vec();

            let credential_id =
                from_raw_parts(a.Credential.pbId, a.Credential.cbId as usize).to_vec();
            let type_ = a
                .Credential
                .pwszCredentialType
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?;

            let mut extensions = if a.dwVersion >= 2 {
                native_to_assertion_extensions(&a.Extensions)?
            } else {
                Default::default()
            };
            extensions.appid = Some(app_id_used.into());

            Ok(PublicKeyCredential {
                id: BASE64_ENGINE.encode(&credential_id),
                raw_id: credential_id.into(),
                response: AuthenticatorAssertionResponseRaw {
                    authenticator_data: authenticator_data.into(),
                    client_data_json: Base64UrlSafeData::from(
                        clientdata.client_data_json().as_bytes().to_vec(),
                    ),
                    signature: signature.into(),
                    user_handle: Some(user_id.into()),
                },
                type_,
                extensions,
            })
        }
    }
}

#[cfg(feature = "win10")]
/// Converts an [AuthenticatorAttachment] into a value for
/// [WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwAuthenticatorAttachment]
fn attachment_to_native(attachment: Option<AuthenticatorAttachment>) -> u32 {
    use AuthenticatorAttachment::*;
    match attachment {
        None => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        Some(CrossPlatform) => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        Some(Platform) => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
    }
}

#[cfg(feature = "win10")]
/// Converts a [UserVerificationPolicy] into a value for
/// [WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwUserVerificationRequirement]
fn user_verification_to_native(policy: Option<&UserVerificationPolicy>) -> u32 {
    use UserVerificationPolicy::*;
    match policy {
        None => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
        Some(p) => match p {
            Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            Preferred => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
            Discouraged_DO_NOT_USE => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        },
    }
}
