//! Authenticator implementation using Mozilla's `authenticator-rs` library.
//!
//! This library only supports USB HID devices.
#[cfg(doc)]
use crate::stubs::*;

use crate::error::WebauthnCError;
use crate::AuthenticatorBackend;
use crate::Url;

use base64urlsafedata::Base64UrlSafeData;
use webauthn_rs_proto::PublicKeyCredentialCreationOptions;
use webauthn_rs_proto::{
    AuthenticatorAttestationResponseRaw, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs,
};

use webauthn_rs_proto::PublicKeyCredentialRequestOptions;
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, PublicKeyCredential,
};

use authenticator::{authenticatorservice::AuthenticatorService, StatusUpdate};

#[cfg(feature = "mozilla")]
use authenticator::{
    authenticatorservice::{
        CtapVersion, GetAssertionExtensions, GetAssertionOptions, MakeCredentialsExtensions,
        MakeCredentialsOptions, RegisterArgsCtap2, SignArgsCtap2,
    },
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, Transport, User,
    },
    ctap2::AssertionObject,
    errors::PinError,
    statecallback::StateCallback,
    COSEAlgorithm, Pin, RegisterResult, SignResult,
};

use std::sync::mpsc::{channel, RecvError, Sender};
use std::thread;

pub struct MozillaAuthenticator {
    status_tx: Sender<StatusUpdate>,
    _thread_handle: thread::JoinHandle<()>,
    manager: AuthenticatorService,
}

impl MozillaAuthenticator {
    pub fn new() -> Self {
        let mut manager = AuthenticatorService::new(CtapVersion::CTAP2)
            .expect("The auth service should initialize safely");

        manager.add_u2f_usb_hid_platform_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();

        let _thread_handle = thread::spawn(move || loop {
            match status_rx.recv() {
                Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                    println!("STATUS: device available: {}", dev_info)
                }
                Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                    println!("STATUS: device unavailable: {}", dev_info)
                }
                Ok(StatusUpdate::Success { dev_info }) => {
                    println!("STATUS: success using device: {}", dev_info);
                }
                Ok(StatusUpdate::SelectDeviceNotice) => {
                    println!("STATUS: Please select a device by touching one of them.");
                }
                Ok(StatusUpdate::DeviceSelected(dev_info)) => {
                    println!("STATUS: Continuing with device: {}", dev_info);
                }
                Ok(StatusUpdate::PinError(error, sender)) => match error {
                    PinError::PinRequired => {
                        let raw_pin = rpassword::prompt_password_stderr("Enter PIN: ")
                            .expect("Failed to read PIN");
                        sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                        continue;
                    }
                    PinError::InvalidPin(attempts) => {
                        println!(
                            "Wrong PIN! {}",
                            attempts.map_or("Try again.".to_string(), |a| format!(
                                "You have {} attempts left.",
                                a
                            ))
                        );
                        let raw_pin = rpassword::prompt_password_stderr("Enter PIN: ")
                            .expect("Failed to read PIN");
                        sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                        continue;
                    }
                    PinError::PinAuthBlocked => {
                        eprintln!("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.")
                    }
                    PinError::PinBlocked => {
                        eprintln!(
                            "Too many failed attempts. Your device has been blocked. Reset it."
                        )
                    }
                    e => {
                        eprintln!("Unexpected error: {:?}", e)
                    }
                },
                Err(RecvError) => {
                    println!("STATUS: end");
                    return;
                }
            }
        });

        MozillaAuthenticator {
            status_tx,
            _thread_handle,
            manager,
        }
    }
}

impl Default for MozillaAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticatorBackend for MozillaAuthenticator {
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let pub_cred_params = options
            .pub_key_cred_params
            .into_iter()
            .map(|param| {
                COSEAlgorithm::try_from(param.alg)
                    .map_err(|e| {
                        error!(?e, "error converting to COSEAlgorithm");
                        WebauthnCError::InvalidAlgorithm
                    })
                    .map(|alg| PublicKeyCredentialParameters { alg })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let ctap_args = RegisterArgsCtap2 {
            challenge: options.challenge.0,
            relying_party: RelyingParty {
                id: options.rp.id,
                name: Some(options.rp.name),
                icon: None,
            },
            origin: origin.to_string(),
            user: User {
                id: options.user.id.0,
                name: Some(options.user.name),
                display_name: Some(options.user.display_name),
                icon: None,
            },
            pub_cred_params,
            exclude_list: vec![],
            options: MakeCredentialsOptions {
                resident_key: None,
                user_verification: None,
            },
            extensions: MakeCredentialsExtensions {
                ..Default::default()
            },
            pin: None,
        };

        /* Actually call the library. */
        let (register_tx, register_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx
                .send(rv)
                .expect("Unable to proceed - state callback channel closed!");
        }));

        if let Err(_e) = self.manager.register(
            timeout_ms.into(),
            ctap_args.into(),
            self.status_tx.clone(),
            callback,
        ) {
            return Err(WebauthnCError::PlatformAuthenticator);
        };

        let register_result = register_rx
            .recv()
            .map_err(|_| WebauthnCError::PlatformAuthenticator)?;

        let (attestation_object, client_data) = match register_result {
            Ok(RegisterResult::CTAP1(_, _)) => return Err(WebauthnCError::PlatformAuthenticator),
            Ok(RegisterResult::CTAP2(a, c)) => {
                println!("Ok!");
                (a, c)
            }
            Err(_e) => return Err(WebauthnCError::PlatformAuthenticator),
        };

        trace!("{:?}", attestation_object);
        trace!("{:?}", client_data);

        // Warning! In the future this may change!
        // This currently relies on serde_json and serde_cbor_2 being deterministic, and has
        // been brought up with MS.

        let raw_id = if let Some(cred_data) = &attestation_object.auth_data.credential_data {
            Base64UrlSafeData(cred_data.credential_id.clone())
        } else {
            return Err(WebauthnCError::PlatformAuthenticator);
        };

        // Based on the request attestation format, provide it
        let attestation_object = serde_cbor_2::to_vec(&attestation_object)
            .map(Base64UrlSafeData)
            .map_err(|_| WebauthnCError::Cbor)?;

        let client_data_json = serde_json::to_vec(&client_data)
            .map(Base64UrlSafeData)
            .map_err(|_| WebauthnCError::Json)?;

        Ok(RegisterPublicKeyCredential {
            id: raw_id.to_string(),
            raw_id,
            response: AuthenticatorAttestationResponseRaw {
                // Turn into cbor,
                attestation_object,
                // Turn into json
                client_data_json,
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs {
                ..Default::default()
            },
        })
    }

    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        let allow_list = options
            .allow_credentials
            .iter()
            .map(|cred| {
                PublicKeyCredentialDescriptor {
                    id: cred.id.0.clone(),
                    // It appears we have to always specify the lower transport in this
                    // library due to discovered bugs
                    transports: vec![Transport::USB],
                }
            })
            .collect();

        let ctap_args = SignArgsCtap2 {
            challenge: options.challenge.0.clone(),
            origin: origin.to_string(),
            relying_party_id: options.rp_id,
            allow_list,
            options: GetAssertionOptions::default(),
            extensions: GetAssertionExtensions {
                ..Default::default()
            },
            pin: None,
        };

        let (sign_tx, sign_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx
                .send(rv)
                .expect("Unable to proceed - state callback channel closed!");
        }));

        if let Err(_e) = self.manager.sign(
            timeout_ms.into(),
            ctap_args.into(),
            self.status_tx.clone(),
            callback,
        ) {
            return Err(WebauthnCError::PlatformAuthenticator);
        }

        let sign_result = sign_rx
            .recv()
            .map_err(|_| WebauthnCError::PlatformAuthenticator)?;

        let (assertion_object, client_data) = match sign_result {
            Ok(SignResult::CTAP1(..)) => return Err(WebauthnCError::PlatformAuthenticator),
            Ok(SignResult::CTAP2(assertion_object, client_data)) => (assertion_object, client_data),
            Err(_e) => return Err(WebauthnCError::PlatformAuthenticator),
        };

        trace!("{:?}", assertion_object);
        trace!("{:?}", client_data);

        let AssertionObject(mut assertions) = assertion_object;
        let assertion = if let Some(a) = assertions.pop() {
            if assertions.is_empty() {
                a
            } else {
                return Err(WebauthnCError::InvalidAssertion);
            }
        } else {
            return Err(WebauthnCError::InvalidAssertion);
        };

        let raw_id = assertion
            .credentials
            .map(|pkdesc| Base64UrlSafeData(pkdesc.id))
            .ok_or(WebauthnCError::Internal)?;

        let id = raw_id.to_string();

        let user_handle = assertion.user.map(|u| Base64UrlSafeData(u.id));
        let signature = Base64UrlSafeData(assertion.signature);

        // let authenticator_data = serde_cbor_2::to_vec(&assertion.auth_data)
        let authenticator_data = assertion
            .auth_data
            .to_vec()
            .map(Base64UrlSafeData)
            .map_err(|_| WebauthnCError::Cbor)?;

        let client_data_json = serde_json::to_vec(&client_data)
            .map(Base64UrlSafeData)
            .map_err(|_| WebauthnCError::Json)?;

        Ok(PublicKeyCredential {
            id,
            raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data,
                client_data_json,
                signature,
                user_handle,
            },
            type_: "public-key".to_string(),
            extensions: AuthenticationExtensionsClientOutputs {
                ..Default::default()
            },
        })
    }
}
