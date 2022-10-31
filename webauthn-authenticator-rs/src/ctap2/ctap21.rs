use std::ops::{Deref, DerefMut};

use crate::{error::WebauthnCError, transport::Token, ui::UiCallback};

use super::{
    commands::{
        BioEnrollmentRequest, BioEnrollmentResponse, BioSubCommand, GetInfoResponse, Permissions,
        SelectionRequest, GET_FINGERPRINT_SENSOR_INFO, GET_MODALITY,
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
                    iface.authenticate(pin_uv_auth_token, client_data_hash.as_slice());
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

    pub async fn get_fingerprint_sensor_info(
        &self,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        if !self.info.supports_ctap21_biometrics() {
            return Err(WebauthnCError::NotSupported);
        }

        self.token.transmit(GET_MODALITY, self.ui_callback).await?;
        self.token
            .transmit(GET_FINGERPRINT_SENSOR_INFO, self.ui_callback)
            .await
    }

    pub async fn enroll_fingerprint(&self) -> Result<(), WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        if !self.info.supports_ctap21_biometrics() {
            return Err(WebauthnCError::NotSupported);
        }

        // TODO
        let timeout = 30_000;

        let (iface, pin_uv_auth_token) = self
            .get_pin_uv_auth_session(Permissions::BIO_ENROLLMENT, None, false)
            .await?;

        let r = self
            .bio_with_session(
                BioSubCommand::FingerprintEnrollBegin(timeout),
                iface.as_ref(),
                pin_uv_auth_token.as_ref(),
            )
            .await?;

        println!("began enrollment: {:?}", r);
        let id = r.template_id.unwrap();

        // TODO: show feedback
        let mut remaining_samples = r.remaining_samples.unwrap_or_default();
        while remaining_samples > 0 {
            let r = self
                .bio_with_session(
                    BioSubCommand::FingerprintEnrollCaptureNextSample(id.clone(), timeout),
                    iface.as_ref(),
                    pin_uv_auth_token.as_ref(),
                )
                .await?;

            remaining_samples = r.remaining_samples.unwrap_or_default();
        }

        Ok(())
    }
}
