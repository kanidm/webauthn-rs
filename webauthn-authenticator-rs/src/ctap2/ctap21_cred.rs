//! CTAP 2.1-PRE / 2.1 Credential Management functionality.
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
            CredentialStorageMetadata, DiscoverableCredential, Permissions,
            PublicKeyCredentialDescriptorCM, RelyingPartyCM,
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
pub(super) trait CredentialManagementAuthenticatorSupport<T, U, R>
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
    #[allow(dead_code)]
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
        let (pin_uv_auth_proto, pin_uv_auth_param) = self
            .get_pin_uv_auth_token(
                sub_command.prf().as_slice(),
                Permissions::CREDENTIAL_MANAGEMENT,
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

        Ok(r)
    }

    async fn cred_mgmt_with_session(
        &mut self,
        sub_command: CredSubCommand,
        auth_session: &AuthSession,
    ) -> Result<CredentialManagementResponse, WebauthnCError> {
        let (pin_uv_protocol, pin_uv_auth_param) = match auth_session {
            AuthSession::InterfaceToken(iface, pin_token) => {
                let mut pin_uv_auth_param =
                    iface.authenticate(pin_token, sub_command.prf().as_slice())?;
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
/// [CTAP 2.1] and [2.1-PRE] discoverable credential management commands.
///
/// All methods return [`WebauthnCError::NotSupported`] if the authenticator
/// does not support credential management.
///
/// ## See also
///
/// * [`Ctap21Authenticator::update_credential_user()`][update]
///
/// [CTAP 2.1]: super::Ctap21Authenticator
/// [2.1-PRE]: super::Ctap21PreAuthenticator
/// [update]: super::Ctap21Authenticator::update_credential_user
#[async_trait]
pub trait CredentialManagementAuthenticator {
    /// Checks that the device supports credential management.
    ///
    /// Returns [WebauthnCError::NotSupported] if the token does not support
    /// credential management.
    fn check_credential_management_support(&self) -> Result<(), WebauthnCError>;

    /// Gets metadata about the authenticator's discoverable credential storage.
    ///
    /// See [CredentialStorageMetadata] for more details.
    async fn get_credentials_metadata(
        &mut self,
    ) -> Result<CredentialStorageMetadata, WebauthnCError>;

    /// Enumerates a list of all relying parties with discoverable credentials
    /// stored on this authenticator.
    ///
    /// ## Note
    ///
    /// To iterate over all credentials for a relying party, pass the
    /// [`RelyingPartyCM::hash`] to [`enumerate_credentials_by_hash`][0].
    ///
    /// [`RelyingPartyCM::id`] [might be truncated][1] by the authenticator.
    ///
    /// [0]: CredentialManagementAuthenticator::enumerate_credentials_by_hash
    /// [1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
    async fn enumerate_rps(&mut self) -> Result<Vec<RelyingPartyCM>, WebauthnCError>;

    /// Enumerates all discoverable credentials on the authenticator for a
    /// relying party, by the SHA-256 hash of the relying party ID.
    ///
    /// ## Note
    ///
    /// This does not provide a "permissions RP ID" with the request, as it only
    /// works correctly with authenticators supporting the `pinUvAuthToken`
    /// feature.
    async fn enumerate_credentials_by_hash(
        &mut self,
        rp_id_hash: SHA256Hash,
    ) -> Result<Vec<DiscoverableCredential>, WebauthnCError>;

    /// Enumerates all discoverable credentials on the authenticator for a
    /// relying party, by the relying party ID.
    ///
    /// ## Note
    ///
    /// This does not provide a "permissions RP ID" with the request, as it only
    /// works correctly with authenticators supporting the `pinUvAuthToken`
    /// feature.
    async fn enumerate_credentials_by_rpid(
        &mut self,
        rpid: &str,
    ) -> Result<Vec<DiscoverableCredential>, WebauthnCError>;

    /// Deletes a discoverable credential from the authenticator.
    ///
    /// ## Note
    ///
    /// This does not provide a "permissions RP ID" with the request, as it only
    /// works correctly with authenticators supporting the `pinUvAuthToken`
    /// feature.
    ///
    /// ## Warning
    ///
    /// This does not garbage-collect associated large blob storage.
    async fn delete_credential(
        &mut self,
        credential_id: PublicKeyCredentialDescriptorCM,
    ) -> Result<(), WebauthnCError>;
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Implementation of credential management commands for [Ctap21Authenticator][]
/// and [Ctap21PreAuthenticator][].
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
    fn check_credential_management_support(&self) -> Result<(), WebauthnCError> {
        if !self.supports_credential_management() {
            return Err(WebauthnCError::NotSupported);
        }

        Ok(())
    }

    async fn get_credentials_metadata(
        &mut self,
    ) -> Result<CredentialStorageMetadata, WebauthnCError> {
        self.check_credential_management_support()?;

        let r = self.cred_mgmt(CredSubCommand::GetCredsMetadata).await?;

        r.storage_metadata
            .ok_or(WebauthnCError::MissingRequiredField)
    }

    async fn enumerate_rps(&mut self) -> Result<Vec<RelyingPartyCM>, WebauthnCError> {
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

        if let Some(rp) = r.rp {
            o.push(rp);
        } else {
            return Err(WebauthnCError::MissingRequiredField);
        };

        let ui = self.ui_callback;
        for _ in 1..total_rps {
            let r = self.token.transmit(R::ENUMERATE_RPS_GET_NEXT, ui).await?;
            if let Some(rp) = r.rp {
                o.push(rp);
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
        enumerate_credentials_impl(self, CredSubCommand::EnumerateCredentialsBegin(rp_id_hash))
            .await
    }

    async fn enumerate_credentials_by_rpid(
        &mut self,
        rp_id: &str,
    ) -> Result<Vec<DiscoverableCredential>, WebauthnCError> {
        self.check_credential_management_support()?;
        enumerate_credentials_impl(self, CredSubCommand::enumerate_credentials_by_rpid(rp_id)).await
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

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
#[doc(hidden)]
async fn enumerate_credentials_impl<'a, K, T, U, R>(
    self_: &mut T,
    sub_command: CredSubCommand,
) -> Result<Vec<DiscoverableCredential>, WebauthnCError>
where
    K: Token,
    T: CredentialManagementAuthenticatorInfo<U, RequestType = R>
        + Deref<Target = Ctap20Authenticator<'a, K, U>>
        + DerefMut<Target = Ctap20Authenticator<'a, K, U>>,
    U: UiCallback + 'a,
    R: CredentialManagementRequestTrait,
{
    let r = self_.cred_mgmt(sub_command).await;

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

    let ui = self_.ui_callback;
    for _ in 1..total_creds {
        let r = self_
            .token
            .transmit(R::ENUMERATE_CREDENTIALS_GET_NEXT, ui)
            .await?;
        o.push(r.discoverable_credential);
    }

    Ok(o)
}
