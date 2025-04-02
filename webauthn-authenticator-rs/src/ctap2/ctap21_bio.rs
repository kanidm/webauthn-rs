//! CTAP 2.1 Biometrics functionality.
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use std::{
    ops::{Deref, DerefMut},
    time::Duration,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use async_trait::async_trait;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use unicode_normalization::UnicodeNormalization;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use webauthn_rs_proto::UserVerificationPolicy;

use crate::ui::UiCallback;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use crate::{
    error::{CtapError, WebauthnCError},
    transport::Token,
};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use super::{
    commands::{
        BioEnrollmentRequestTrait, BioEnrollmentResponse, BioSubCommand, Modality, Permissions,
        TemplateInfo,
    },
    ctap20::AuthSession,
    Ctap20Authenticator,
};

/// Trait to provide a [BiometricAuthenticator] implementation.
pub trait BiometricAuthenticatorInfo<U: UiCallback>: Sync + Send {
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Request type for biometric commands.
    type RequestType: BioEnrollmentRequestTrait;

    /// Checks if the authenticator supports and has configured biometric
    /// authentication.
    ///
    /// # Returns
    ///
    /// * `None`: if not supported.
    /// * `Some(false)`: if supported, but not configured.
    /// * `Some(true)`: if supported and configured.
    fn biometrics(&self) -> Option<bool>;

    /// Returns `true` if the authenticator supports biometric authentication.
    #[inline]
    fn supports_biometrics(&self) -> bool {
        self.biometrics().is_some()
    }

    /// Returns `true` if the authenticator has configured biometric
    /// authentication.
    #[inline]
    fn configured_biometrics(&self) -> bool {
        self.biometrics().unwrap_or_default()
    }
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Internal support methods for biometric authentication.
#[async_trait]
trait BiometricAuthenticatorSupport<T, U, R>
where
    T: BiometricAuthenticatorInfo<U, RequestType = R>,
    U: UiCallback,
    R: BioEnrollmentRequestTrait,
{
    async fn bio(
        &mut self,
        sub_command: BioSubCommand,
    ) -> Result<BioEnrollmentResponse, WebauthnCError>;

    /// Send a [BioSubCommand] using a provided `pin_uv_auth_token` session.
    async fn bio_with_session(
        &mut self,
        sub_command: BioSubCommand,
        auth_session: &AuthSession,
    ) -> Result<BioEnrollmentResponse, WebauthnCError>;
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
#[async_trait]
impl<'a, K, T, U, R> BiometricAuthenticatorSupport<T, U, R> for T
where
    K: Token,
    T: BiometricAuthenticatorInfo<U, RequestType = R>
        + Deref<Target = Ctap20Authenticator<'a, K, U>>
        + DerefMut<Target = Ctap20Authenticator<'a, K, U>>,
    U: UiCallback + 'a,
    R: BioEnrollmentRequestTrait,
{
    async fn bio(
        &mut self,
        sub_command: BioSubCommand,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        let (pin_uv_auth_proto, pin_uv_auth_param) = self
            .get_pin_uv_auth_token(
                sub_command.prf().as_slice(),
                Permissions::BIO_ENROLLMENT,
                None,
                UserVerificationPolicy::Required,
            )
            .await?
            .into_pin_uv_params();

        let ui = self.ui_callback;
        let r = self
            .token
            .transmit(
                T::RequestType::new(sub_command, pin_uv_auth_proto, pin_uv_auth_param),
                ui,
            )
            .await?;
        self.refresh_info().await?;
        Ok(r)
    }

    async fn bio_with_session(
        &mut self,
        sub_command: BioSubCommand,
        auth_session: &AuthSession,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        let client_data_hash = sub_command.prf();

        let (pin_uv_protocol, pin_uv_auth_param) = match auth_session {
            AuthSession::InterfaceToken(iface, pin_token) => {
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
pub trait BiometricAuthenticator {
    /// Checks that the device supports fingerprints.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// fingerprint authentication.
    async fn check_fingerprint_support(&mut self) -> Result<(), WebauthnCError>;

    /// Checks that a given `friendly_name` complies with authenticator limits,
    /// and returns the value in Unicode Normal Form C.
    ///
    /// Returns [WebauthnCError::FriendlyNameTooLong] if it does not comply with
    /// limits.
    async fn check_friendly_name(
        &mut self,
        friendly_name: String,
    ) -> Result<String, WebauthnCError>;

    /// Gets information about the token's fingerprint sensor.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// fingerprint authentication.
    async fn get_fingerprint_sensor_info(
        &mut self,
    ) -> Result<BioEnrollmentResponse, WebauthnCError>;

    /// Lists all enrolled fingerprints in the device.
    ///
    /// Returns an empty [Vec] if no fingerprints have been enrolled.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// fingerprint authentication.
    async fn list_fingerprints(&mut self) -> Result<Vec<TemplateInfo>, WebauthnCError>;

    /// Enrolls a fingerprint with the token.
    ///
    /// This generally takes multiple user interactions (touches or swipes) of
    /// the sensor.
    ///
    /// If enrollment is successful, returns the fingerprint ID.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// fingerprint authentication.
    async fn enroll_fingerprint(
        &mut self,
        timeout: Duration,
        friendly_name: Option<String>,
    ) -> Result<Vec<u8>, WebauthnCError>;

    /// Renames an enrolled fingerprint.
    async fn rename_fingerprint(
        &mut self,
        id: Vec<u8>,
        friendly_name: String,
    ) -> Result<(), WebauthnCError>;

    /// Removes an enrolled fingerprint.
    async fn remove_fingerprint(&mut self, id: Vec<u8>) -> Result<(), WebauthnCError>;

    /// Removes multiple enrolled fingerprints.
    ///
    /// **Warning:** this is not an atomic operation. If any command fails,
    /// further processing will stop, and the request may be incomplete.
    /// Call [Self::list_fingerprints] to check what was actually done.
    async fn remove_fingerprints(&mut self, ids: Vec<Vec<u8>>) -> Result<(), WebauthnCError>;
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Implementation of biometric management commands for [Ctap21Authenticator][]
/// and [Ctap21PreAuthenticator][].
///
/// [Ctap21Authenticator]: super::Ctap21Authenticator
/// [Ctap21PreAuthenticator]: super::Ctap21PreAuthenticator
#[async_trait]
impl<'a, K, T, U, R> BiometricAuthenticator for T
where
    K: Token,
    T: BiometricAuthenticatorInfo<U, RequestType = R>
        + Deref<Target = Ctap20Authenticator<'a, K, U>>
        + DerefMut<Target = Ctap20Authenticator<'a, K, U>>,
    U: UiCallback + 'a,
    R: BioEnrollmentRequestTrait,
{
    async fn check_fingerprint_support(&mut self) -> Result<(), WebauthnCError> {
        if !self.supports_biometrics() {
            return Err(WebauthnCError::NotSupported);
        }

        let ui = self.ui_callback;
        let r = self.token.transmit(R::GET_MODALITY, ui).await?;
        if r.modality != Some(Modality::Fingerprint) {
            return Err(WebauthnCError::NotSupported);
        }

        Ok(())
    }

    async fn check_friendly_name(
        &mut self,
        friendly_name: String,
    ) -> Result<String, WebauthnCError> {
        let ui = self.ui_callback;
        let r = self
            .token
            .transmit(R::GET_FINGERPRINT_SENSOR_INFO, ui)
            .await?;

        // Normalise into Normal Form C
        let friendly_name = friendly_name.nfc().collect::<String>();
        if friendly_name.len() > r.get_max_template_friendly_name() {
            return Err(WebauthnCError::FriendlyNameTooLong);
        }

        Ok(friendly_name)
    }

    async fn get_fingerprint_sensor_info(
        &mut self,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        self.check_fingerprint_support().await?;
        let ui = self.ui_callback;
        self.token
            .transmit(R::GET_FINGERPRINT_SENSOR_INFO, ui)
            .await
    }

    async fn enroll_fingerprint(
        &mut self,
        timeout: Duration,
        friendly_name: Option<String>,
    ) -> Result<Vec<u8>, WebauthnCError> {
        self.check_fingerprint_support().await?;
        let friendly_name = match friendly_name {
            Some(n) => Some(self.check_friendly_name(n).await?),
            None => None,
        };

        let session = self
            .get_pin_uv_auth_session(
                Permissions::BIO_ENROLLMENT,
                None,
                UserVerificationPolicy::Required,
            )
            .await?;

        let mut r = self
            .bio_with_session(BioSubCommand::FingerprintEnrollBegin(timeout), &session)
            .await?;

        trace!("began enrollment: {:?}", r);
        let id = r.template_id.ok_or(WebauthnCError::MissingRequiredField)?;

        let mut remaining_samples = r
            .remaining_samples
            .ok_or(WebauthnCError::MissingRequiredField)?;
        while remaining_samples > 0 {
            self.ui_callback
                .fingerprint_enrollment_feedback(remaining_samples, r.last_enroll_sample_status);

            r = self
                .bio_with_session(
                    BioSubCommand::FingerprintEnrollCaptureNextSample(id.clone(), timeout),
                    &session,
                )
                .await?;

            remaining_samples = r
                .remaining_samples
                .ok_or(WebauthnCError::MissingRequiredField)?;
        }

        // Now it's enrolled, give it a name.
        if friendly_name.is_some() {
            self.bio_with_session(
                BioSubCommand::FingerprintSetFriendlyName(TemplateInfo {
                    id: id.clone(),
                    friendly_name,
                }),
                &session,
            )
            .await?;
        }

        // This may have been the first enrolled fingerprint.
        self.refresh_info().await?;

        Ok(id)
    }

    async fn list_fingerprints(&mut self) -> Result<Vec<TemplateInfo>, WebauthnCError> {
        self.check_fingerprint_support().await?;
        if !self.configured_biometrics() {
            // Fingerprint authentication is supported, but not configured, ie:
            // there are no enrolled fingerprints and don't need to ask.
            //
            // When there is no PIN or UV auth available, then `bio()` would
            // throw UserVerificationRequired; so we short-cut this to be nice.
            trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
            return Ok(vec![]);
        }

        // works without authentication if alwaysUv = false?
        let templates = self
            .bio(BioSubCommand::FingerprintEnumerateEnrollments)
            .await;

        match templates {
            Ok(templates) => Ok(templates.template_infos),
            Err(e) => {
                if let WebauthnCError::Ctap(e) = &e {
                    if matches!(e, CtapError::Ctap2InvalidOption) {
                        // "If there are no enrollments existing on
                        // authenticator, it returns CTAP2_ERR_INVALID_OPTION."
                        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enumerateEnrollments
                        return Ok(vec![]);
                    }
                }

                Err(e)
            }
        }
    }

    async fn rename_fingerprint(
        &mut self,
        id: Vec<u8>,
        friendly_name: String,
    ) -> Result<(), WebauthnCError> {
        self.check_fingerprint_support().await?;
        if !self.configured_biometrics() {
            // "If there are no enrollments existing on authenticator for the
            // passed templateId, it returns CTAP2_ERR_INVALID_OPTION."
            trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
            return Err(CtapError::Ctap2InvalidOption.into());
        }

        let friendly_name = Some(self.check_friendly_name(friendly_name).await?);
        self.bio(BioSubCommand::FingerprintSetFriendlyName(TemplateInfo {
            id,
            friendly_name,
        }))
        .await?;
        Ok(())
    }

    async fn remove_fingerprint(&mut self, id: Vec<u8>) -> Result<(), WebauthnCError> {
        self.check_fingerprint_support().await?;
        if !self.configured_biometrics() {
            // "If there are no enrollments existing on authenticator for the
            // passed templateId, it returns CTAP2_ERR_INVALID_OPTION."
            trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
            return Err(CtapError::Ctap2InvalidOption.into());
        }

        self.bio(BioSubCommand::FingerprintRemoveEnrollment(id))
            .await?;

        // The previous command could have removed the last enrolled
        // fingerprint.
        self.refresh_info().await?;
        Ok(())
    }

    async fn remove_fingerprints(&mut self, ids: Vec<Vec<u8>>) -> Result<(), WebauthnCError> {
        self.check_fingerprint_support().await?;
        if !self.configured_biometrics() {
            // "If there are no enrollments existing on authenticator for the
            // passed templateId, it returns CTAP2_ERR_INVALID_OPTION."
            trace!("Fingerprint authentication is supported but not configured, ie: there no enrolled fingerprints, skipping request.");
            return Err(CtapError::Ctap2InvalidOption.into());
        }

        let session = self
            .get_pin_uv_auth_session(
                Permissions::BIO_ENROLLMENT,
                None,
                UserVerificationPolicy::Required,
            )
            .await?;

        for id in ids {
            self.bio_with_session(BioSubCommand::FingerprintRemoveEnrollment(id), &session)
                .await?;
        }

        // The previous command could have removed all enrolled fingerprints.
        self.refresh_info().await?;
        Ok(())
    }
}
