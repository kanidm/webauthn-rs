use crate::{
    ctap2::{
        commands::GetInfoResponse, ctap21_bio::BiometricAuthenticatorInfo,
        ctap21_cred::CredentialManagementAuthenticatorInfo, internal::CtapAuthenticatorVersion,
        Ctap20Authenticator,
    },
    transport::Token,
    ui::UiCallback,
};
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use crate::{
    ctap2::{
        commands::{
            BioEnrollmentRequest, ConfigRequest, ConfigSubCommand, CredSubCommand,
            CredentialManagementRequest, Permissions, PublicKeyCredentialDescriptorCM,
            SetMinPinLengthParams, UserCM,
        },
        ctap21_cred::CredentialManagementAuthenticatorSupport,
        CredentialManagementAuthenticator,
    },
    error::WebauthnCError,
};
use std::ops::{Deref, DerefMut};
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use webauthn_rs_proto::UserVerificationPolicy;

/// CTAP 2.1 protocol implementation.
///
/// This contains only CTAP 2.1-specific functionality. All CTAP 2.0
/// functionality is avaliable via a [Deref] to [Ctap20Authenticator].
#[derive(Debug)]
pub struct Ctap21Authenticator<'a, T: Token, U: UiCallback> {
    authenticator: Ctap20Authenticator<'a, T, U>,
}

/// For backwards compatibility, pretend to be a
/// [CTAP 2.0 authenticator][Ctap20Authenticator].
impl<'a, T: Token, U: UiCallback> Deref for Ctap21Authenticator<'a, T, U> {
    type Target = Ctap20Authenticator<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        &self.authenticator
    }
}

impl<T: Token, U: UiCallback> DerefMut for Ctap21Authenticator<'_, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.authenticator
    }
}

impl<'a, T: Token, U: UiCallback> CtapAuthenticatorVersion<'a, T, U>
    for Ctap21Authenticator<'a, T, U>
{
    const VERSION: &'static str = "FIDO_2_1";
    fn new_with_info(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self {
        Self {
            authenticator: Ctap20Authenticator::new_with_info(info, token, ui_callback),
        }
    }
}

impl<'a, T: Token, U: UiCallback> Ctap21Authenticator<'a, T, U> {
    /// Returns `true` if the authenticator supports configuration commands.
    ///
    /// # See also
    ///
    /// * [`enable_enterprise_attestation()`][Self::enable_enterprise_attestation]
    /// * [`set_min_pin_length()`][Self::set_min_pin_length]
    /// * [`toggle_always_uv()`][Self::toggle_always_uv]
    #[inline]
    pub fn supports_config(&self) -> bool {
        self.info.supports_config()
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    async fn config(
        &mut self,
        sub_command: ConfigSubCommand,
        toggle_always_uv: bool,
    ) -> Result<(), WebauthnCError> {
        if !self.supports_config() {
            return Err(WebauthnCError::NotSupported);
        }

        let ui_callback = self.ui_callback;

        let (pin_uv_auth_proto, pin_uv_auth_param) = self
            .get_pin_uv_auth_token(
                sub_command.prf().as_slice(),
                Permissions::AUTHENTICATOR_CONFIGURATION,
                None,
                if toggle_always_uv {
                    UserVerificationPolicy::Discouraged_DO_NOT_USE
                } else {
                    UserVerificationPolicy::Required
                },
            )
            .await?
            .into_pin_uv_params();

        // TODO: handle complex result type
        self.token
            .transmit(
                ConfigRequest::new(sub_command, pin_uv_auth_proto, pin_uv_auth_param),
                ui_callback,
            )
            .await?;

        self.refresh_info().await
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Toggles the state of the [Always Require User Verification][0] feature.
    ///
    /// This is only available on authenticators which
    /// [support configuration][Self::supports_config].
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#toggle-alwaysUv
    pub async fn toggle_always_uv(&mut self) -> Result<(), WebauthnCError> {
        self.config(ConfigSubCommand::ToggleAlwaysUv, true).await
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Sets a [minimum PIN length policy][0].
    ///
    /// This is only available on authenticators which
    /// [support configuration][Self::supports_config].
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setMinPINLength
    pub async fn set_min_pin_length(
        &mut self,
        new_min_pin_length: Option<u32>,
        min_pin_length_rpids: Vec<String>,
        force_change_pin: Option<bool>,
    ) -> Result<(), WebauthnCError> {
        self.config(
            ConfigSubCommand::SetMinPinLength(SetMinPinLengthParams {
                new_min_pin_length,
                min_pin_length_rpids,
                force_change_pin,
            }),
            false,
        )
        .await
    }

    /// Returns `true` if the authenticator supports
    /// [enterprise attestation][0].
    ///
    /// # See also
    ///
    /// * [`enable_enterprise_attestation()`][Self::enable_enterprise_attestation]
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn
    #[inline]
    pub fn supports_enterprise_attestation(&self) -> bool {
        self.info.supports_enterprise_attestation()
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Enables the [Enterprise Attestation][0] feature.
    ///
    /// This is only available on authenticators which support
    /// [configuration][Self::supports_config] and
    /// [enterprise attestation][Self::supports_enterprise_attestation].
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn
    pub async fn enable_enterprise_attestation(&mut self) -> Result<(), WebauthnCError> {
        if !self.supports_enterprise_attestation() || !self.supports_config() {
            return Err(WebauthnCError::NotSupported);
        }
        self.config(ConfigSubCommand::EnableEnterpriseAttestation, false)
            .await
    }

    /// Returns `true` if the authenticator supports
    /// [CTAP 2.1 credential management][0].
    ///
    /// ## See also
    ///
    /// * [`CredentialManagementAuthenticator`][]
    /// * [`update_credential_user`][Self::update_credential_user]
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
    #[inline]
    pub fn supports_ctap21_credential_management(&self) -> bool {
        self.info.ctap21_credential_management()
    }

    /// Updates user information for a discoverable credential.
    ///
    /// This is only available on authenticators which support
    /// [CTAP 2.1 credential management][Self::supports_ctap21_credential_management],
    /// otherwise it returns [`WebauthnCError::NotSupported`].
    ///
    /// ## Note
    ///
    /// This function does not provide a "permissions RP ID" with the request,
    /// as it only works correctly with authenticators supporting the
    /// `pinUvAuthToken` feature.
    ///
    /// ## See also
    ///
    /// * [`CredentialManagementAuthenticator`] trait
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    pub async fn update_credential_user(
        &mut self,
        credential_id: PublicKeyCredentialDescriptorCM,
        user: UserCM,
    ) -> Result<(), WebauthnCError> {
        self.check_credential_management_support()?;

        self.cred_mgmt(CredSubCommand::UpdateUserInformation(credential_id, user))
            .await
            .map(|_| ())
    }
}

impl<T: Token, U: UiCallback> BiometricAuthenticatorInfo<U> for Ctap21Authenticator<'_, T, U> {
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    type RequestType = BioEnrollmentRequest;

    #[inline]
    fn biometrics(&self) -> Option<bool> {
        self.info.ctap21_biometrics()
    }
}

impl<T: Token, U: UiCallback> CredentialManagementAuthenticatorInfo<U>
    for Ctap21Authenticator<'_, T, U>
{
    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    type RequestType = CredentialManagementRequest;
    // HACK: type RequestType = super::commands::PrototypeCredentialManagementRequest;

    #[inline]
    fn supports_credential_management(&self) -> bool {
        self.supports_ctap21_credential_management()
    }
}
