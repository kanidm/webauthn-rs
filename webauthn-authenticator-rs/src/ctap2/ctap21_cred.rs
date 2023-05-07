//! CTAP 2.1 Credential Management functionality.
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use std::ops::{Deref, DerefMut};

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use async_trait::async_trait;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use webauthn_rs_proto::UserVerificationPolicy;

use crate::ui::UiCallback;

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use crate::{
    crypto::SHA256Hash,
    ctap2::{
        commands::{
            CredSubCommand, CredentialManagementRequestTrait, CredentialManagementResponse,
            DiscoverableCredential, Permissions, PublicKeyCredentialDescriptorCM, RelyingPartyCM,
        },
        ctap20::AuthSession,
        Ctap20Authenticator,
    },
    error::{CtapError, WebauthnCError},
    transport::Token,
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
    /// Checks that the device supports credential management.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// credential management.
    fn check_credential_management_support(&mut self) -> Result<(), WebauthnCError>;

    async fn get_credentials_metadata(&mut self) -> Result<(u32, u32), WebauthnCError>;

    async fn enumerate_rps(&mut self) -> Result<Vec<(RelyingPartyCM, SHA256Hash)>, WebauthnCError>;

    async fn enumerate_credentials_by_hash(
        &mut self,
        rp_id_hash: SHA256Hash,
    ) -> Result<Vec<DiscoverableCredential>, WebauthnCError>;

    /// Deletes a credential from an authenticator.
    ///
    /// ## Note
    ///
    /// This function does not provide a "permissions RP ID" with the request,
    /// as it only works correctly with authenticators supporting the
    /// `pinUvAuthToken` feature.
    async fn delete_credential(
        &mut self,
        credential_id: PublicKeyCredentialDescriptorCM,
    ) -> Result<(), WebauthnCError>;
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

        let r = self.cred_mgmt(CredSubCommand::GetCredsMetadata).await?;

        Ok((
            r.existing_resident_credentials_count.unwrap_or_default(),
            r.max_possible_remaining_resident_credentials_count
                .unwrap_or_default(),
        ))
    }

    async fn enumerate_rps(&mut self) -> Result<Vec<(RelyingPartyCM, SHA256Hash)>, WebauthnCError> {
        self.check_credential_management_support()?;
        let r = self.cred_mgmt(CredSubCommand::EnumerateRPsBegin).await;

        // "If no discoverable credentials exist on the authenticator, return
        // CTAP2_ERR_NO_CREDENTIALS."
        if matches!(r, Err(WebauthnCError::Ctap(CtapError::Ctap2NoCredentials))) {
            return Ok(Vec::new());
        }
        let r = r?;

        // Feitian doesn't return an error when there are zero keys, and instead
        // sends an empty CredentialManagementResponse (ie: no fields set), so
        // we can't require that total_rps is set.
        //
        // Token2 and Yubikey also doesn't return an error when there are zero
        // keys, but at least sets `total_rps = 0`.
        let total_rps = r.total_rps.unwrap_or_default();
        let mut o = Vec::with_capacity(total_rps as usize);

        if total_rps == 0 {
            return Ok(o);
        }

        if let (Some(rp), Some(rp_id_hash)) = (r.rp, r.rp_id_hash) {
            o.push((rp, rp_id_hash));
        } else {
            return Err(WebauthnCError::MissingRequiredField);
        };

        for _ in 1..total_rps {
            let r = self
                .cred_mgmt(CredSubCommand::EnumerateRPsGetNextRP)
                .await?;
            if let (Some(rp), Some(rp_id_hash)) = (r.rp, r.rp_id_hash) {
                o.push((rp, rp_id_hash));
            } else {
                break;
            }
        }

        Ok(o)
    }

    async fn enumerate_credentials_by_hash(
        &mut self,
        rp_id_hash: SHA256Hash,
    ) -> Result<Vec<DiscoverableCredential>, WebauthnCError> {
        self.check_credential_management_support()?;

        let r = self
            .cred_mgmt(CredSubCommand::EnumerateCredentialsBegin(rp_id_hash))
            .await;

        // "If no discoverable credentials for this RP ID hash exist on this
        // authenticator, return CTAP2_ERR_NO_CREDENTIALS."
        if matches!(r, Err(WebauthnCError::Ctap(CtapError::Ctap2NoCredentials))) {
            return Ok(Vec::new());
        }
        let r = r?;

        let total_creds = r.total_credentials.unwrap_or_default();
        let mut o = Vec::with_capacity(total_creds as usize);

        if total_creds == 0 {
            return Ok(o);
        }

        o.push(r.discoverable_credential);

        for _ in 1..total_creds {
            let r = self
                .cred_mgmt(CredSubCommand::EnumerateCredentialsGetNextCredential)
                .await?;
            o.push(r.discoverable_credential);
        }

        Ok(o)
    }

    async fn delete_credential(
        &mut self,
        credential_id: PublicKeyCredentialDescriptorCM,
    ) -> Result<(), WebauthnCError> {
        self.check_credential_management_support()?;

        self.cred_mgmt(CredSubCommand::DeleteCredential(credential_id))
            .await
            .map(|_| ())
    }
}
