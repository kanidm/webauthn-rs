use std::{
    ops::{Deref, DerefMut},
    time::Duration,
};

use unicode_normalization::UnicodeNormalization;

use crate::{
    ctap2::commands::TemplateInfo, error::WebauthnCError, transport::Token, ui::UiCallback,
};

use super::{
    commands::{
        BioEnrollmentRequest, BioEnrollmentResponse, BioSubCommand, GetInfoResponse, Modality,
        Permissions, SelectionRequest, GET_FINGERPRINT_SENSOR_INFO, GET_MODALITY,
    },
    pin_uv::PinUvPlatformInterface,
    Ctap20Authenticator,
};

#[derive(Debug)]
pub struct Ctap21Authenticator<'a, T: Token, U: UiCallback> {
    authenticator: Ctap20Authenticator<'a, T, U>,
}

/// For backwards compatibility, pretend to be a CTAP 2.0 authenticator.
impl<'a, T: Token, U: UiCallback> Deref for Ctap21Authenticator<'a, T, U> {
    type Target = Ctap20Authenticator<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        &self.authenticator
    }
}

impl<'a, T: Token, U: UiCallback> DerefMut for Ctap21Authenticator<'a, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.authenticator
    }
}

impl<'a, T: Token, U: UiCallback> Ctap21Authenticator<'a, T, U> {
    pub(super) fn new(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self {
        Self {
            authenticator: Ctap20Authenticator::new(info, token, ui_callback),
        }
    }

    /// Requests user presence on a token.
    ///
    /// This feature is only available in `FIDO_V2_1`, and not available for NFC.
    pub async fn selection(&self) -> Result<(), WebauthnCError> {
        if !self.token.has_button() {
            // The token doesn't have a button on a transport level (ie: NFC),
            // so immediately mark this as the "selected" token.
            Ok(())
        } else {
            self.token
                .transmit(SelectionRequest {}, self.ui_callback)
                .await
                .map(|_| ())
        }
    }

    async fn bio(
        &self,
        sub_command: BioSubCommand,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        let (pin_uv_auth_proto, pin_uv_auth_param) = self
            .get_pin_uv_auth_token(
                sub_command.prf().as_slice(),
                Permissions::BIO_ENROLLMENT,
                None,
                false,
            )
            .await?;

        self.token
            .transmit(
                BioEnrollmentRequest::new(sub_command, pin_uv_auth_proto, pin_uv_auth_param),
                self.ui_callback,
            )
            .await
    }

    /// Send a [BioSubCommand] using a provided `pin_uv_auth_token` session.
    async fn bio_with_session(
        &self,
        sub_command: BioSubCommand,
        iface: Option<&PinUvPlatformInterface>,
        pin_uv_auth_token: Option<&Vec<u8>>,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        let client_data_hash = sub_command.prf();

        let (pin_uv_protocol, pin_uv_auth_param) = match (iface, pin_uv_auth_token) {
            (Some(iface), Some(pin_uv_auth_token)) => {
                let mut pin_uv_auth_param =
                    iface.authenticate(pin_uv_auth_token, client_data_hash.as_slice())?;
                pin_uv_auth_param.truncate(16);

                (iface.get_pin_uv_protocol(), Some(pin_uv_auth_param))
            }

            _ => (None, None),
        };

        self.token
            .transmit(
                BioEnrollmentRequest::new(sub_command, pin_uv_protocol, pin_uv_auth_param),
                self.ui_callback,
            )
            .await
    }

    /// Checks that the device supports fingerprints.
    async fn check_fingerprint_support(&self) -> Result<(), WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        if !self.info.supports_ctap21_biometrics() {
            return Err(WebauthnCError::NotSupported);
        }

        let r = self.token.transmit(GET_MODALITY, self.ui_callback).await?;
        if r.modality != Some(Modality::Fingerprint) {
            return Err(WebauthnCError::NotSupported);
        }

        Ok(())
    }

    /// Checks that a given `friendly_name` complies with authenticator limits, and returns the value in Unicode Normal Form C.
    async fn check_friendly_name(&self, friendly_name: String) -> Result<String, WebauthnCError> {
        let r = self
            .token
            .transmit(GET_FINGERPRINT_SENSOR_INFO, self.ui_callback)
            .await?;

        // Normalise into Normal Form C
        let friendly_name = friendly_name.nfc().collect::<String>();
        if friendly_name.as_bytes().len() > r.get_max_template_friendly_name() {
            return Err(WebauthnCError::FriendlyNameTooLong);
        }

        Ok(friendly_name)
    }

    /// Gets information about the token's fingerprint sensor.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support fingerprint authentication.
    pub async fn get_fingerprint_sensor_info(
        &self,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        self.check_fingerprint_support().await?;
        self.token
            .transmit(GET_FINGERPRINT_SENSOR_INFO, self.ui_callback)
            .await
    }

    /// Enrolls a fingerprint with the token.
    ///
    /// This generally takes multiple user interactions (touches or swipes) of the sensor.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support fingerprint authentication.
    pub async fn enroll_fingerprint(
        &self,
        timeout: Duration,
        friendly_name: Option<String>,
    ) -> Result<(), WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        self.check_fingerprint_support().await?;
        let friendly_name = match friendly_name {
            Some(n) => Some(self.check_friendly_name(n).await?),
            None => None,
        };

        let (iface, pin_uv_auth_token) = self
            .get_pin_uv_auth_session(Permissions::BIO_ENROLLMENT, None, false)
            .await?;

        let mut r = self
            .bio_with_session(
                BioSubCommand::FingerprintEnrollBegin(timeout),
                iface.as_ref(),
                pin_uv_auth_token.as_ref(),
            )
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
                    iface.as_ref(),
                    pin_uv_auth_token.as_ref(),
                )
                .await?;

            remaining_samples = r
                .remaining_samples
                .ok_or(WebauthnCError::MissingRequiredField)?;
        }

        // Now it's enrolled, give it a name.
        if friendly_name.is_some() {
            self.bio_with_session(
                BioSubCommand::FingerprintSetFriendlyName(TemplateInfo { id, friendly_name }),
                iface.as_ref(),
                pin_uv_auth_token.as_ref(),
            )
            .await?;
        }

        Ok(())
    }

    /// Lists all enrolled fingerprints in the device.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support fingerprint authentication.
    pub async fn list_fingerprints(&self) -> Result<Vec<TemplateInfo>, WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        self.check_fingerprint_support().await?;

        // works without authentication if alwaysUv = false?
        let templates = self
            .bio(BioSubCommand::FingerprintEnumerateEnrollments)
            .await?;

        Ok(templates.template_infos)
    }

    /// Renames an enrolled fingerprint.
    pub async fn rename_fingerprint(
        &self,
        id: Vec<u8>,
        friendly_name: String,
    ) -> Result<(), WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        self.check_fingerprint_support().await?;
        let friendly_name = Some(self.check_friendly_name(friendly_name).await?);
        self.bio(BioSubCommand::FingerprintSetFriendlyName(TemplateInfo {
            id,
            friendly_name,
        }))
        .await?;
        Ok(())
    }

    /// Removes an enrolled fingerprint.
    pub async fn remove_fingerprint(&self, id: Vec<u8>) -> Result<(), WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        self.check_fingerprint_support().await?;

        self.bio(BioSubCommand::FingerprintRemoveEnrollment(id))
            .await?;

        Ok(())
    }
}
