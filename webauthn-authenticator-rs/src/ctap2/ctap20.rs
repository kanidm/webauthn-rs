use std::{collections::BTreeMap, fmt::Debug};

#[cfg(feature = "ctap2-management")]
use crate::util::check_pin;
use crate::{
    authenticator_hashed::AuthenticatorBackendHashedClientData,
    ctap2::{commands::*, pin_uv::*},
    error::WebauthnCError,
    transport::Token,
    ui::UiCallback,
};

use base64urlsafedata::Base64UrlSafeData;
use futures::executor::block_on;

use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, UserVerificationPolicy,
};

#[derive(Debug, Clone)]
pub(super) enum AuthToken {
    /// No authentication token to be supplied
    None,
    /// `pinUvAuthProtocol`, `pinUvAuthToken`
    ProtocolToken(u32, Vec<u8>),
    /// Send request with `uv = true`
    UvTrue,
}

impl AuthToken {
    pub fn into_pin_uv_params(self) -> (Option<u32>, Option<Vec<u8>>) {
        match self {
            Self::ProtocolToken(p, t) => (Some(p), Some(t)),
            _ => (None, None),
        }
    }
}

#[derive(Debug)]
pub(super) enum AuthSession {
    None,
    /// `iface`, `pinToken`
    InterfaceToken(PinUvPlatformInterface, Vec<u8>),
    UvTrue,
}

/// CTAP 2.0 protocol implementation.
#[derive(Debug)]
pub struct Ctap20Authenticator<'a, T: Token, U: UiCallback> {
    pub(super) info: GetInfoResponse,
    pub(super) token: T,
    pub(super) ui_callback: &'a U,
}

impl<'a, T: Token, U: UiCallback> Ctap20Authenticator<'a, T, U> {
    pub(super) fn new(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self {
        Self {
            info,
            token,
            ui_callback,
        }
    }

    /// Gets cached information about the authenticator.
    ///
    /// This does not transmit to the token.
    pub fn get_info(&self) -> &GetInfoResponse {
        &self.info
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Perform a factory reset of the token, deleting all data.
    pub async fn factory_reset(&mut self) -> Result<(), WebauthnCError> {
        let ui_callback = self.ui_callback;
        self.token
            .transmit(ResetRequest {}, ui_callback)
            .await
            .map(|_| ())
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Refreshes the cached [GetInfoResponse].
    ///
    /// This needs to be called (internally) after sending a command which
    /// could invalidate its content.
    pub(super) async fn refresh_info(&mut self) -> Result<(), WebauthnCError> {
        let ui_callback = self.ui_callback;
        self.info = self.token.transmit(GetInfoRequest {}, ui_callback).await?;
        Ok(())
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Checks whether a provided PIN follows the rules defined by the
    /// authenticator. This does not share the PIN with the authenticator.
    pub fn validate_pin(&self, pin: &str) -> Result<String, WebauthnCError> {
        check_pin(pin, self.info.get_min_pin_length())
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Sets a PIN on a device which does not already have one.
    ///
    /// To change a PIN, use [`change_pin()`][Self::change_pin].
    pub async fn set_new_pin(&mut self, pin: &str) -> Result<(), WebauthnCError> {
        let ui_callback = self.ui_callback;
        let pin = self.validate_pin(pin)?;

        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())?;

        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or(WebauthnCError::Internal)?;
        trace!(?key_agreement);

        // The platform calls encapsulate with the public key that the authenticator
        // returned in order to generate the platform key-agreement key and the shared secret.
        let shared_secret = iface.encapsulate(key_agreement)?;
        trace!(?shared_secret);

        let set_pin = iface.set_pin_cmd(padded_pin, shared_secret.as_slice())?;
        let ret = self.token.transmit(set_pin, ui_callback).await?;
        trace!(?ret);

        // Setting a PIN invalidates info.
        self.refresh_info().await?;
        Ok(())
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Changes a PIN on a device.
    ///
    /// To set a PIN for the first time, use [`set_new_pin()`][Self::set_new_pin].
    pub async fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), WebauthnCError> {
        let ui_callback = self.ui_callback;

        // TODO: we actually really only need this in normal form C
        let old_pin = self.validate_pin(old_pin)?;
        let new_pin = self.validate_pin(new_pin)?;
        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..new_pin.len()].copy_from_slice(new_pin.as_bytes());

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())?;

        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or(WebauthnCError::Internal)?;
        let shared_secret = iface.encapsulate(key_agreement)?;

        let change_pin = iface.change_pin_cmd(&old_pin, padded_pin, &shared_secret)?;
        let ret = self.token.transmit(change_pin, ui_callback).await?;
        trace!(?ret);

        // Changing a PIN invalidates forcePinChange option.
        self.refresh_info().await?;
        Ok(())
    }

    /// Gets a PIN/UV auth token, if required.
    ///
    /// This automatically selects an appropriate verification mode.
    ///
    /// Arguments:
    /// * `client_data_hash`: the SHA256 hash of the client data JSON.
    /// * `permissions`: a bitmask of permissions to request. This is only
    ///   effective when the authenticator supports
    ///   `getPinUvAuthToken...WithPermissions`. If this is not set, this
    ///   will use (legacy) `getPinToken` instead.
    /// * `rp_id`: the Relying Party to associate with the request. This is
    ///   required for `GetAssertion` and `MakeCredential` requests, and
    ///   optional for `CredentialManagement` requests. This is only effective
    ///   when the authenticator supports `getPinUvAuthToken...WithPermissions`.
    /// * `user_verification_policy`: how to verify the user.
    ///
    /// Returns:
    /// * `Option<u32>`: the `pin_uv_auth_protocol`
    /// * `Option<Vec<u8>>`: the `pin_uv_auth_param`
    /// * `Ok((None, None))` if PIN and/or UV auth is not required.
    /// * `Err(UserVerificationRequired)` if user verification was required, but
    ///   was not available.
    /// * `Err` for errors from the token.
    ///
    /// References:
    /// * <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#gettingPinUvAuthToken>
    pub(super) async fn get_pin_uv_auth_token(
        &mut self,
        client_data_hash: &[u8],
        permissions: Permissions,
        rp_id: Option<String>,
        user_verification_policy: UserVerificationPolicy,
    ) -> Result<AuthToken, WebauthnCError> {
        let session = self
            .get_pin_uv_auth_session(permissions, rp_id, user_verification_policy)
            .await?;

        Ok(match session {
            AuthSession::InterfaceToken(iface, pin_token) => {
                let pin_uv_auth_param =
                    iface.authenticate(pin_token.as_slice(), client_data_hash)?;
                AuthToken::ProtocolToken(iface.get_pin_uv_protocol(), pin_uv_auth_param)
            }

            AuthSession::None => AuthToken::None,
            AuthSession::UvTrue => AuthToken::UvTrue,
        })
    }

    pub(super) async fn get_pin_uv_auth_session(
        &mut self,
        permissions: Permissions,
        rp_id: Option<String>,
        user_verification_policy: UserVerificationPolicy,
    ) -> Result<AuthSession, WebauthnCError> {
        #[derive(Debug)]
        enum PlannedOperation {
            UvAuthTokenUsingUvWithPermissions,
            UvAuthTokenUsingPinWithPermissions,
            Token,
        }

        if permissions.intersects(Permissions::MAKE_CREDENTIAL | Permissions::GET_ASSERTION)
            && rp_id.is_none()
        {
            error!("rp_id is required for MakeCredential and GetAssertion requests");
            return Err(WebauthnCError::Internal);
        }

        trace!("Authenticator options: {:?}", self.info.options);
        let ui_callback = self.ui_callback;
        let client_pin = self.info.get_option("clientPin").unwrap_or_default();
        let mut always_uv = self.info.get_option("alwaysUv").unwrap_or_default();
        let make_cred_uv_not_required = self.info.make_cred_uv_not_required();
        let pin_uv_auth_token = self.info.get_option("pinUvAuthToken").unwrap_or_default();
        let uv = self.info.get_option("uv").unwrap_or_default();
        // requesting the acfg permission when invoking
        // getPinUvAuthTokenUsingUvWithPermissions is supported.
        let uv_acfg = self.info.get_option("uvAcfg").unwrap_or_default();
        // requesting the be permission when invoking
        // getPinUvAuthTokenUsingUvWithPermissions is supported.
        let uv_bio_enroll = self.info.get_option("uvBioEnroll").unwrap_or_default();
        // TODO: noMcGaPermissionsWithClientPin means those can only run with biometric auth
        // TODO: rp_options.uv_required == true > makeCredUvNotRqd == true
        // TODO: discoverable credentials should bypass makeCredUvNotRqd == true

        // Allow toggleAlwaysUv to bypass alwaysUv if no user verification is
        // configured, to allow for initial configuration.
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorConfig
        if permissions == Permissions::AUTHENTICATOR_CONFIGURATION
            && user_verification_policy == UserVerificationPolicy::Discouraged_DO_NOT_USE
            && !client_pin
            && !uv
            && always_uv
        {
            trace!(
                "Pretending alwaysUv = false to allow for initial configuration of toggleAlwaysUv"
            );
            always_uv = false;
        }

        let requires_pin = (permissions.intersects(Permissions::BIO_ENROLLMENT) && !uv_bio_enroll)
            || (permissions.intersects(Permissions::AUTHENTICATOR_CONFIGURATION) && !uv_acfg)
            || permissions.intersects(Permissions::CREDENTIAL_MANAGEMENT);
        trace!("Permissions: {permissions:?}, uvBioEnroll: {uv_bio_enroll:?}, uvAcfg: {uv_acfg:?}, requiresPin: {requires_pin:?}");
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-platf-actions
        // 1. If the authenticator is protected by some form of user
        // verification, or the Relying Party prefers enforcing user
        // verification (e.g., by setting
        // options.authenticatorSelection.userVerification to "required", or
        // "preferred" in the WebAuthn API):

        trace!("uvPolicy: {user_verification_policy:?}, clientPin: {client_pin:?}, uv: {uv:?}, alwaysUv: {always_uv:?}, makeCredUvNotRequired: {make_cred_uv_not_required:?}");
        if user_verification_policy == UserVerificationPolicy::Required
            || user_verification_policy == UserVerificationPolicy::Preferred
            || client_pin
            || uv
            // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-alwaysUv
            || always_uv
        // TODO: Implement makeCredUvNotReqd when this supports discoverable creds
        {
            // Skip step 1 (we don't already have a parameter)
            // 2. Otherwise, the platform examines various option IDs in the
            // authenticatorGetInfo response to determine its course of action:

            let planned_operation = if uv && !requires_pin {
                // 1. If the uv option ID is present and set to true:
                if pin_uv_auth_token {
                    // If the pinUvAuthToken option ID is present and true then
                    // plan to use getPinUvAuthTokenUsingUvWithPermissions to
                    // obtain a pinUvAuthToken, and let it be the selected
                    // operation. Go to Step 1.1.2.3.
                    PlannedOperation::UvAuthTokenUsingUvWithPermissions
                } else {
                    trace!("pinUvAuthToken not supported, planning to use uv=true");
                    return Ok(AuthSession::UvTrue);
                }
            } else {
                // 2. Else (implying the uv option ID is present and set to
                // false or absent):
                if pin_uv_auth_token {
                    // 1. If the pinUvAuthToken option ID is present and true:
                    // To continue, ensure the clientPin option ID is present
                    // and true. Plan to use
                    // getPinUvAuthTokenUsingPinWithPermissions to obtain a
                    // pinUvAuthToken, and let it be the selected operation. Go
                    // to Step 1.1.2.3.
                    if !client_pin {
                        error!(
                            "Client PIN not set, and user verification is preferred or required"
                        );
                        return Err(WebauthnCError::UserVerificationRequired);
                    }

                    PlannedOperation::UvAuthTokenUsingPinWithPermissions
                } else {
                    // 2. Else (implying the pinUvAuthToken option ID is absent):
                    // To continue, ensure the clientPin option ID is present
                    // and true. Plan to use getPinToken to obtain a
                    // pinUvAuthToken, and let it be the selected operation.
                    if !client_pin {
                        error!(
                            "Client PIN not set, and user verification is preferred or required"
                        );
                        return Err(WebauthnCError::UserVerificationRequired);
                    }
                    PlannedOperation::Token
                }
            };

            trace!(?planned_operation);

            // Step 1.1.2.3: In preparation for obtaining pinUvAuthToken, the
            // platform:
            let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())?;

            // 1. Obtains a shared secret
            // 6.5.5.4: Obtaining the shared secret
            let p = iface.get_key_agreement_cmd();
            let ret = self.token.transmit(p, ui_callback).await?;
            let key_agreement = ret.key_agreement.ok_or(WebauthnCError::Internal)?;
            trace!(?key_agreement);

            // The platform calls encapsulate with the public key that the authenticator
            // returned in order to generate the platform key-agreement key and the shared secret.
            let shared_secret = iface.encapsulate(key_agreement)?;
            trace!(?shared_secret);

            // Then the platform obtains a pinUvAuthToken from the
            // authenticator, with the mc (and likely also with the ga)
            // permission (see "pre-flight", mentioned above), using the
            // selected operation. If successful, the platform creates the
            // pinUvAuthParam parameter by calling authenticate(pinUvAuthToken,
            // clientDataHash), and goes to Step 1.1.1.
            let p = match planned_operation {
                PlannedOperation::UvAuthTokenUsingUvWithPermissions => {
                    // 6.5.5.7.3. Getting pinUvAuthToken using getPinUvAuthTokenUsingUvWithPermissions (built-in user verification methods)
                    iface.get_pin_uv_auth_token_using_uv_with_permissions_cmd(permissions, rp_id)
                }
                PlannedOperation::UvAuthTokenUsingPinWithPermissions => {
                    // 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)
                    let pin = self.request_pin(iface.get_pin_uv_protocol()).await?;
                    iface.get_pin_uv_auth_token_using_pin_with_permissions_cmd(
                        &pin,
                        shared_secret.as_slice(),
                        permissions,
                        rp_id,
                    )?
                }
                PlannedOperation::Token => {
                    // 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)
                    let pin = self.request_pin(iface.get_pin_uv_protocol()).await?;
                    iface.get_pin_token_cmd(&pin, shared_secret.as_slice())?
                }
            };

            let ret = self.token.transmit(p, ui_callback).await?;
            trace!(?ret);
            let pin_token = ret
                .pin_uv_auth_token
                .ok_or(WebauthnCError::MissingRequiredField)?;
            // Decrypt the pin_token
            let pin_token = iface.decrypt(shared_secret.as_slice(), pin_token.as_slice())?;
            trace!(?pin_token);
            Ok(AuthSession::InterfaceToken(iface, pin_token))
        } else {
            // Otherwise, implying the authenticator is not presently protected
            // by some form of user verification, or the Relying Party wants to
            // create a non-discoverable credential and not require user
            // verification (e.g., by setting
            // options.authenticatorSelection.userVerification to "discouraged"
            // in the WebAuthn API), the platform invokes the
            // authenticatorMakeCredential operation using the marshalled input
            // parameters along with the "uv" option key set to false and
            // terminate these steps.
            trace!("User verification disabled");
            Ok(AuthSession::None)
        }
    }

    async fn request_pin(&mut self, pin_uv_protocol: u32) -> Result<String, WebauthnCError> {
        let p = ClientPinRequest {
            pin_uv_protocol: Some(pin_uv_protocol),
            sub_command: ClientPinSubCommand::GetPinRetries,
            ..Default::default()
        };

        let ui_callback = self.ui_callback;
        let ret = self.token.transmit(p, ui_callback).await?;
        trace!(?ret);

        // TODO: handle lockouts

        ui_callback.request_pin().ok_or(WebauthnCError::Cancelled)
    }
}

impl<'a, T: Token, U: UiCallback> AuthenticatorBackendHashedClientData
    for Ctap20Authenticator<'a, T, U>
{
    fn perform_register(
        &mut self,
        client_data_hash: Vec<u8>,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, crate::prelude::WebauthnCError>
    {
        let authenticator_selection = options.authenticator_selection.unwrap_or_default();
        let auth_token = block_on(self.get_pin_uv_auth_token(
            client_data_hash.as_slice(),
            Permissions::MAKE_CREDENTIAL,
            Some(options.rp.id.clone()),
            authenticator_selection.user_verification,
        ))?;

        let req_options = if let AuthToken::UvTrue = auth_token {
            // No pin_uv_auth_param, but verification is configured, so use it
            Some(BTreeMap::from([("uv".to_owned(), true)]))
        } else {
            None
        };
        let (pin_uv_auth_proto, pin_uv_auth_param) = auth_token.into_pin_uv_params();

        let mc = MakeCredentialRequest {
            client_data_hash,
            rp: options.rp,
            user: options.user,
            pub_key_cred_params: options.pub_key_cred_params,
            exclude_list: options.exclude_credentials.unwrap_or_default(),

            options: req_options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
            enterprise_attest: None,
        };

        let ret = block_on(self.token.transmit(mc, self.ui_callback))?;
        trace!(?ret);

        // The obvious thing to do here would be to pass the raw authenticator
        // data back, but it seems like everything expects a Map<String, Value>
        // here, rather than a Map<u32, Value>... so we need to re-serialize
        // that data!
        //
        // Alternatively, it may be possible to do this "more cheaply" by
        // remapping the keys of the map.
        let raw = serde_cbor::to_vec(&ret).map_err(|e| {
            error!("MakeCredentialResponse re-serialization: {:?}", e);
            WebauthnCError::Cbor
        })?;

        // HACK: parsing out the real ID is complicated, and other parts of the
        // library will do it for us, so we'll put in empty data here.
        let cred_id = vec![];
        let id = String::new();

        let type_ = ret.fmt.ok_or(WebauthnCError::InvalidAlgorithm)?;

        Ok(RegisterPublicKeyCredential {
            id,
            raw_id: Base64UrlSafeData(cred_id),
            type_,
            extensions: RegistrationExtensionsClientOutputs::default(), // TODO
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(raw),
                client_data_json: Base64UrlSafeData(vec![]),
                // All transports the token supports, as opposed to the
                // transport which was actually used.
                transports: self.info.get_transports(),
            },
        })
    }

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, crate::prelude::WebauthnCError> {
        trace!("trying to authenticate...");
        let auth_token = block_on(self.get_pin_uv_auth_token(
            client_data_hash.as_slice(),
            Permissions::GET_ASSERTION,
            Some(options.rp_id.clone()),
            options.user_verification,
        ))?;

        let req_options = if let AuthToken::UvTrue = auth_token {
            // No pin_uv_auth_param, but verification is configured, so use it
            Some(BTreeMap::from([("uv".to_owned(), true)]))
        } else {
            None
        };
        let (pin_uv_auth_proto, pin_uv_auth_param) = auth_token.into_pin_uv_params();

        let ga = GetAssertionRequest {
            rp_id: options.rp_id,
            client_data_hash,
            allow_list: options.allow_credentials,
            options: req_options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
        };

        trace!(?ga);
        let ret = block_on(self.token.transmit(ga, self.ui_callback))?;
        trace!(?ret);

        let raw_id = ret
            .credential
            .as_ref()
            .map(|c| c.id.to_owned())
            .ok_or(WebauthnCError::Cbor)?;
        let id = raw_id.to_string();
        let type_ = ret
            .credential
            .map(|c| c.type_)
            .ok_or(WebauthnCError::Cbor)?;
        let signature = Base64UrlSafeData(ret.signature.ok_or(WebauthnCError::Cbor)?);
        let authenticator_data = Base64UrlSafeData(ret.auth_data.ok_or(WebauthnCError::Cbor)?);

        Ok(PublicKeyCredential {
            id,
            raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data,
                client_data_json: Base64UrlSafeData(vec![]),
                signature,
                // TODO
                user_handle: None,
            },
            // TODO
            extensions: AuthenticationExtensionsClientOutputs::default(),
            type_,
        })
    }
}

#[cfg(test)]
mod tests {
    // TODO
}
