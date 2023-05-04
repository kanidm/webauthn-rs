//! CTAP 2.1 Credential Management functionality.
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use std::ops::{Deref, DerefMut};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use async_trait::async_trait;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use webauthn_rs_proto::{RelyingParty, UserVerificationPolicy};

use crate::ui::UiCallback;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use crate::{
    error::{CtapError, WebauthnCError},
    transport::Token,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use super::{
    commands::{
        CredSubCommand, CredentialManagementRequestTrait, CredentialManagementResponse, Permissions,
    },
    ctap20::AuthSession,
    Ctap20Authenticator,
};

/// Trait to provide a [CredentialManagementAuthenticator] implementation.
pub trait CredentialManagementAuthenticatorInfo<U: UiCallback>: Sync + Send {
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Request type for credential management commands.
    type RequestType: CredentialManagementRequestTrait;

    /// Checks if the authenticator supports credential management commands.
    fn supports_credential_management(&self) -> bool;
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Internal support methods for credential management.
#[async_trait]
trait CredentialManagementAuthenticatorSupport<T, U, R>
where
    T: CredentialManagementAuthenticatorInfo<U, RequestType = R>,
    U: UiCallback,
    R: CredentialManagementRequestTrait,
{
    async fn cred_mgmt(
        &mut self,
        sub_command: CredSubCommand,
        needs_refresh: bool,
    ) -> Result<CredentialManagementResponse, WebauthnCError>;

    /// Send a [CredSubCommand] using a provided `pin_uv_auth_token` session.
    async fn cred_mgmt_with_session(
        &mut self,
        sub_command: CredSubCommand,
        auth_session: &AuthSession,
    ) -> Result<CredentialManagementResponse, WebauthnCError>;
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
#[async_trait]
impl<'a, K, T, U, R> CredentialManagementAuthenticatorSupport<T, U, R> for T
where
    K: Token,
    T: CredentialManagementAuthenticatorInfo<U, RequestType = R>
        + Deref<Target = Ctap20Authenticator<'a, K, U>>
        + DerefMut<Target = Ctap20Authenticator<'a, K, U>>,
    U: UiCallback + 'a,
    R: CredentialManagementRequestTrait,
{
    async fn cred_mgmt(
        &mut self,
        sub_command: CredSubCommand,
        needs_refresh: bool,
    ) -> Result<CredentialManagementResponse, WebauthnCError> {
        let (pin_uv_auth_proto, pin_uv_auth_param) = if sub_command.needs_auth() {
            self.get_pin_uv_auth_token(
                sub_command.prf().as_slice(),
                Permissions::CREDENTIAL_MANAGEMENT,
                None,
                UserVerificationPolicy::Required,
            )
            .await?
            .into_pin_uv_params()
        } else {
            (None, None)
        };

        let ui = self.ui_callback;
        let r = self
            .token
            .transmit(
                T::RequestType::new(sub_command, pin_uv_auth_proto, pin_uv_auth_param),
                ui,
            )
            .await?;
        if needs_refresh {
            self.refresh_info().await?;
        }
        Ok(r)
    }

    async fn cred_mgmt_with_session(
        &mut self,
        sub_command: CredSubCommand,
        auth_session: &AuthSession,
    ) -> Result<CredentialManagementResponse, WebauthnCError> {
        let client_data_hash = sub_command.prf();

        let (pin_uv_protocol, pin_uv_auth_param) = match (auth_session, sub_command.needs_auth()) {
            (AuthSession::InterfaceToken(iface, pin_token), true) => {
                let mut pin_uv_auth_param =
                    iface.authenticate(pin_token, client_data_hash.as_slice())?;
                pin_uv_auth_param.truncate(16);

                (Some(iface.get_pin_uv_protocol()), Some(pin_uv_auth_param))
            }

            _ => (None, None),
        };

        let ui = self.ui_callback;
        self.token
            .transmit(
                T::RequestType::new(sub_command, pin_uv_protocol, pin_uv_auth_param),
                ui,
            )
            .await
    }
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Biometric management commands for [Ctap21Authenticator][] and
/// [Ctap21PreAuthenticator][].
///
/// [Ctap21Authenticator]: super::Ctap21Authenticator
/// [Ctap21PreAuthenticator]: super::Ctap21PreAuthenticator
#[async_trait]
pub trait CredentialManagementAuthenticator {
    /// Checks that the device supports fingerprints.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// fingerprint authentication.
    fn check_credential_management_support(&mut self) -> Result<(), WebauthnCError>;

    async fn get_credentials_metadata(&mut self) -> Result<(u32, u32), WebauthnCError>;

    async fn enumerate_rps(&mut self) -> Result<Vec<(RelyingParty, Vec<u8>)>, WebauthnCError>;
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Implementation of credential management commands for [Ctap21Authenticator][]
/// and [Ctap21PreAuthenticator][].
///
/// This is provided for implementors of
/// [CredentialManagementAuthenticatorInfo][] and [Ctap20Authenticator][].
///
/// [Ctap21Authenticator]: super::Ctap21Authenticator
/// [Ctap21PreAuthenticator]: super::Ctap21PreAuthenticator
#[async_trait]
impl<'a, K, T, U, R> CredentialManagementAuthenticator for T
where
    K: Token,
    T: CredentialManagementAuthenticatorInfo<U, RequestType = R>
        + Deref<Target = Ctap20Authenticator<'a, K, U>>
        + DerefMut<Target = Ctap20Authenticator<'a, K, U>>,
    U: UiCallback + 'a,
    R: CredentialManagementRequestTrait,
{
    fn check_credential_management_support(&mut self) -> Result<(), WebauthnCError> {
        if !self.supports_credential_management() {
            return Err(WebauthnCError::NotSupported);
        }

        Ok(())
    }

    async fn get_credentials_metadata(&mut self) -> Result<(u32, u32), WebauthnCError> {
        self.check_credential_management_support()?;

        let r = self
            .cred_mgmt(CredSubCommand::GetCredsMetadata, false)
            .await?;

        Ok((
            r.existing_resident_credentials_count.unwrap_or_default(),
            r.max_possible_remaining_resident_credentials_count
                .unwrap_or_default(),
        ))
    }

    async fn enumerate_rps(&mut self) -> Result<Vec<(RelyingParty, Vec<u8>)>, WebauthnCError> {
        self.check_credential_management_support()?;
        let r = self
            .cred_mgmt(CredSubCommand::EnumerateRPsBegin, false)
            .await;

        // If no credentials exist on the authenticator...
        if matches!(r, Err(WebauthnCError::Ctap(CtapError::Ctap2NoCredentials))) {
            return Ok(Vec::new());
        }
        let r = r?;

        let total_rps = u32::max(1, r.total_rps.unwrap_or_default());
        let mut o = Vec::with_capacity(total_rps as usize);
        if let (Some(rp), Some(rp_id_hash)) = (r.rp, r.rp_id_hash) {
            o.push((rp, rp_id_hash));
        }
        
        for _ in 1..total_rps {
            let r = self.cred_mgmt(CredSubCommand::EnumerateRPsGetNextRP, false).await?;
            if let (Some(rp), Some(rp_id_hash)) = (r.rp, r.rp_id_hash) {
                o.push((rp, rp_id_hash));
            } else {
                break;
            }
        }


        Ok(o)
    }


    // async fn check_friendly_name(
    //     &mut self,
    //     friendly_name: String,
    // ) -> Result<String, WebauthnCError> {
    //     let ui = self.ui_callback;
    //     let r = self
    //         .token
    //         .transmit(R::GET_FINGERPRINT_SENSOR_INFO, ui)
    //         .await?;

    //     // Normalise into Normal Form C
    //     let friendly_name = friendly_name.nfc().collect::<String>();
    //     if friendly_name.as_bytes().len() > r.get_max_template_friendly_name() {
    //         return Err(WebauthnCError::FriendlyNameTooLong);
    //     }

    //     Ok(friendly_name)
    // }

    // async fn get_fingerprint_sensor_info(
    //     &mut self,
    // ) -> Result<BioEnrollmentResponse, WebauthnCError> {
    //     self.check_fingerprint_support().await?;
    //     let ui = self.ui_callback;
    //     self.token
    //         .transmit(R::GET_FINGERPRINT_SENSOR_INFO, ui)
    //         .await
    // }

    // async fn enroll_fingerprint(
    //     &mut self,
    //     timeout: Duration,
    //     friendly_name: Option<String>,
    // ) -> Result<Vec<u8>, WebauthnCError> {
    //     self.check_fingerprint_support().await?;
    //     let friendly_name = match friendly_name {
    //         Some(n) => Some(self.check_friendly_name(n).await?),
    //         None => None,
    //     };

    //     let session = self
    //         .get_pin_uv_auth_session(
    //             Permissions::BIO_ENROLLMENT,
    //             None,
    //             UserVerificationPolicy::Required,
    //         )
    //         .await?;

    //     let mut r = self
    //         .bio_with_session(BioSubCommand::FingerprintEnrollBegin(timeout), &session)
    //         .await?;

    //     trace!("began enrollment: {:?}", r);
    //     let id = r.template_id.ok_or(WebauthnCError::MissingRequiredField)?;

    //     let mut remaining_samples = r
    //         .remaining_samples
    //         .ok_or(WebauthnCError::MissingRequiredField)?;
    //     while remaining_samples > 0 {
    //         self.ui_callback
    //             .fingerprint_enrollment_feedback(remaining_samples, r.last_enroll_sample_status);

    //         r = self
    //             .bio_with_session(
    //                 BioSubCommand::FingerprintEnrollCaptureNextSample(id.clone(), timeout),
    //                 &session,
    //             )
    //             .await?;

    //         remaining_samples = r
    //             .remaining_samples
    //             .ok_or(WebauthnCError::MissingRequiredField)?;
    //     }

    //     // Now it's enrolled, give it a name.
    //     if friendly_name.is_some() {
    //         self.bio_with_session(
    //             BioSubCommand::FingerprintSetFriendlyName(TemplateInfo {
    //                 id: id.clone(),
    //                 friendly_name,
    //             }),
    //             &session,
    //         )
    //         .await?;
    //     }

    //     // This may have been the first enrolled fingerprint.
    //     self.refresh_info().await?;

    //     Ok(id)
    // }

    // async fn list_fingerprints(&mut self) -> Result<Vec<TemplateInfo>, WebauthnCError> {
    //     self.check_fingerprint_support().await?;
    //     if !self.configured_biometrics() {
    //         // Fingerprint authentication is supported, but not configured, ie:
    //         // there are no enrolled fingerprints and don't need to ask.
    //         //
    //         // When there is no PIN or UV auth available, then `bio()` would
    //         // throw UserVerificationRequired; so we short-cut this to be nice.
    //         trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
    //         return Ok(vec![]);
    //     }

    //     // works without authentication if alwaysUv = false?
    //     let templates = self
    //         .bio(BioSubCommand::FingerprintEnumerateEnrollments)
    //         .await;

    //     match templates {
    //         Ok(templates) => Ok(templates.template_infos),
    //         Err(e) => {
    //             if let WebauthnCError::Ctap(e) = &e {
    //                 if matches!(e, CtapError::Ctap2InvalidOption) {
    //                     // "If there are no enrollments existing on
    //                     // authenticator, it returns CTAP2_ERR_INVALID_OPTION."
    //                     // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enumerateEnrollments
    //                     return Ok(vec![]);
    //                 }
    //             }

    //             Err(e)
    //         }
    //     }
    // }

    // async fn rename_fingerprint(
    //     &mut self,
    //     id: Vec<u8>,
    //     friendly_name: String,
    // ) -> Result<(), WebauthnCError> {
    //     self.check_fingerprint_support().await?;
    //     if !self.configured_biometrics() {
    //         // "If there are no enrollments existing on authenticator for the
    //         // passed templateId, it returns CTAP2_ERR_INVALID_OPTION."
    //         trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
    //         return Err(CtapError::Ctap2InvalidOption.into());
    //     }

    //     let friendly_name = Some(self.check_friendly_name(friendly_name).await?);
    //     self.bio(BioSubCommand::FingerprintSetFriendlyName(TemplateInfo {
    //         id,
    //         friendly_name,
    //     }))
    //     .await?;
    //     Ok(())
    // }

    // async fn remove_fingerprint(&mut self, id: Vec<u8>) -> Result<(), WebauthnCError> {
    //     self.check_fingerprint_support().await?;
    //     if !self.configured_biometrics() {
    //         // "If there are no enrollments existing on authenticator for the
    //         // passed templateId, it returns CTAP2_ERR_INVALID_OPTION."
    //         trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
    //         return Err(CtapError::Ctap2InvalidOption.into());
    //     }

    //     self.bio(BioSubCommand::FingerprintRemoveEnrollment(id))
    //         .await?;

    //     // The previous command could have removed the last enrolled
    //     // fingerprint.
    //     self.refresh_info().await?;
    //     Ok(())
    // }

    // async fn remove_fingerprints(&mut self, ids: Vec<Vec<u8>>) -> Result<(), WebauthnCError> {
    //     self.check_fingerprint_support().await?;
    //     if !self.configured_biometrics() {
    //         // "If there are no enrollments existing on authenticator for the
    //         // passed templateId, it returns CTAP2_ERR_INVALID_OPTION."
    //         trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
    //         return Err(CtapError::Ctap2InvalidOption.into());
    //     }

    //     let session = self
    //         .get_pin_uv_auth_session(
    //             Permissions::BIO_ENROLLMENT,
    //             None,
    //             UserVerificationPolicy::Required,
    //         )
    //         .await?;

    //     for id in ids {
    //         self.bio_with_session(BioSubCommand::FingerprintRemoveEnrollment(id), &session)
    //             .await?;
    //     }

    //     // The previous command could have removed all enrolled fingerprints.
    //     self.refresh_info().await?;
    //     Ok(())
    // }
}
