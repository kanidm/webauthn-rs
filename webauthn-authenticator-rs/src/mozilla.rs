//! Authenticator implementation using Mozilla's `authenticator-rs` library.
//!
//! This library only supports USB HID devices.
#[cfg(doc)]
use crate::stubs::*;

use crate::error::WebauthnCError;
use crate::AuthenticatorBackend;
use crate::Url;
use crate::BASE64_ENGINE;

use base64::Engine;
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
    authenticatorservice::{RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::client_data::{ClientDataHash, CollectedClientData, WebauthnType},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, Transport, UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin, StatusPinUv,
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
        let mut manager =
            AuthenticatorService::new().expect("The auth service should initialize safely");

        manager.add_u2f_usb_hid_platform_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();

        let _thread_handle = thread::spawn(move || loop {
            match status_rx.recv() {
                Ok(StatusUpdate::SelectDeviceNotice) => {
                    info!("STATUS: Please select a device by touching one of them.");
                }
                Ok(StatusUpdate::PresenceRequired) => {
                    info!("STATUS: Please touch your device.");
                }

                Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                    error!("Unexpected State - SelectResultNotice");
                    return;
                }

                Ok(StatusUpdate::InteractiveManagement(..)) => {
                    error!("Unexpected State - InteractiveManagement");
                    return;
                }

                Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                    let raw_pin = rpassword::prompt_password_stderr("Enter PIN: ")
                        .expect("Failed to read PIN");
                    sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                    continue;
                }

                Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                    error!(
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

                Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                    error!(
                        "Invalid User Verification! {}",
                        attempts.map_or("Try again.".to_string(), |a| format!(
                            "You have {} attempts left.",
                            a
                        ))
                    );
                    continue;
                }

                Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                    error!("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.")
                }
                Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked))
                | Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                    error!("Too many failed attempts. Your device has been blocked. Reset it.")
                }

                Ok(StatusUpdate::PinUvError(e)) => {
                    error!("Unexpected error: {:?}", e)
                }

                Err(RecvError) => {
                    debug!("STATUS: end");
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
        let client_data = CollectedClientData {
            webauthn_type: WebauthnType::Create,
            challenge: options.challenge.to_vec().into(),
            origin: origin.to_string(),
            cross_origin: false,
            token_binding: None,
        };

        let ClientDataHash(client_data_hash) = client_data
            .hash()
            .map_err(|_| WebauthnCError::InvalidRegistration)?;

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

        let ctap_args = RegisterArgs {
            client_data_hash,
            relying_party: RelyingParty {
                id: options.rp.id,
                name: Some(options.rp.name),
            },
            origin: origin.to_string(),
            user: PublicKeyCredentialUserEntity {
                id: options.user.id.into(),
                name: Some(options.user.name),
                display_name: Some(options.user.display_name),
            },
            pub_cred_params,
            exclude_list: vec![],
            user_verification_req: UserVerificationRequirement::Required,
            resident_key_req: ResidentKeyRequirement::Discouraged,

            pin: None,
            extensions: AuthenticationExtensionsClientInputs {
                ..Default::default()
            },
            use_ctap1_fallback: false,
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
            // If the channel closes, the platform goes away.
            .map_err(|_| WebauthnCError::PlatformAuthenticator)?
            // If the registration failed
            .map_err(|_| WebauthnCError::InvalidRegistration)?;

        let attestation_object = register_result.att_obj;

        trace!(?attestation_object);
        trace!(?client_data);

        // Warning! In the future this may change!
        // This currently relies on serde_json and serde_cbor_2 being deterministic, and has
        // been brought up with MS.

        let raw_id = if let Some(cred_data) = &attestation_object.auth_data.credential_data {
            Base64UrlSafeData::from(cred_data.credential_id.clone())
        } else {
            return Err(WebauthnCError::PlatformAuthenticator);
        };

        // Based on the request attestation format, provide it
        let attestation_object =
            serde_cbor_2::to_vec(&attestation_object).map_err(|_| WebauthnCError::Cbor)?;

        let client_data_json =
            serde_json::to_vec(&client_data).map_err(|_| WebauthnCError::Json)?;

        Ok(RegisterPublicKeyCredential {
            id: BASE64_ENGINE.encode(&raw_id),
            raw_id,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object.into(),
                client_data_json: client_data_json.into(),
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
        let client_data = CollectedClientData {
            webauthn_type: WebauthnType::Get,
            challenge: options.challenge.to_vec().into(),
            origin: origin.to_string(),
            cross_origin: false,
            token_binding: None,
        };

        let ClientDataHash(client_data_hash) = client_data
            .hash()
            .map_err(|_| WebauthnCError::InvalidRegistration)?;

        let allow_list = options
            .allow_credentials
            .iter()
            .map(|cred| {
                PublicKeyCredentialDescriptor {
                    id: cred.id.clone().into(),
                    // It appears we have to always specify the lower transport in this
                    // library due to discovered bugs
                    transports: vec![Transport::USB],
                }
            })
            .collect();

        let ctap_args = SignArgs {
            client_data_hash,
            origin: origin.to_string(),
            relying_party_id: options.rp_id,
            allow_list,

            user_verification_req: UserVerificationRequirement::Required,
            user_presence_req: true,

            extensions: AuthenticationExtensionsClientInputs {
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
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
            .map_err(|_| WebauthnCError::PlatformAuthenticator)?
            .map_err(|_| WebauthnCError::InvalidAssertion)?;

        let assertion = sign_result.assertion;

        trace!(?assertion);
        trace!(?client_data);

        let raw_id = assertion
            .credentials
            .map(|pkdesc| Base64UrlSafeData::from(pkdesc.id))
            .ok_or(WebauthnCError::Internal)?;

        // let authenticator_data = serde_cbor_2::to_vec(&assertion.auth_data)
        let authenticator_data = assertion.auth_data.to_vec();

        let client_data_json =
            serde_json::to_vec(&client_data).map_err(|_| WebauthnCError::Json)?;

        Ok(PublicKeyCredential {
            id: BASE64_ENGINE.encode(&raw_id),
            raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: authenticator_data.into(),
                client_data_json: client_data_json.into(),
                signature: assertion.signature.into(),
                user_handle: assertion.user.map(|u| u.id.into()),
            },
            type_: "public-key".to_string(),
            extensions: AuthenticationExtensionsClientOutputs {
                ..Default::default()
            },
        })
    }
}
