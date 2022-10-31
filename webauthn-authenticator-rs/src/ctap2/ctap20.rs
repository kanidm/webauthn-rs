use std::fmt::Debug;

use crate::{
    ctap2::{commands::*, pin_uv::*},
    error::WebauthnCError,
    transport::Token,
    ui::UiCallback,
    util::{check_pin, compute_sha256, creation_to_clientdata, get_to_clientdata, CheckPinResult},
    AuthenticatorBackend,
};

use base64urlsafedata::Base64UrlSafeData;
use futures::{executor::block_on, StreamExt};

use url::Url;
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs,
};

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

    pub fn get_info(&self) -> &GetInfoResponse {
        &self.info
    }

    pub async fn factory_reset(&self) -> Result<(), WebauthnCError> {
        self.token
            .transmit(ResetRequest {}, self.ui_callback)
            .await
            .map(|_| ())
    }

    async fn config(
        &self,
        sub_command: ConfigSubCommand,
        bypass_always_uv: bool,
    ) -> Result<(), WebauthnCError> {
        let (pin_uv_auth_proto, pin_uv_auth_param) = self
            .get_pin_uv_auth_token(
                sub_command.prf().as_slice(),
                Permissions::AUTHENTICATOR_CONFIGURATION,
                None,
                bypass_always_uv,
            )
            .await?;

        // TODO: handle complex result type
        self.token
            .transmit(
                ConfigRequest::new(sub_command, pin_uv_auth_proto, pin_uv_auth_param),
                self.ui_callback,
            )
            .await
            .map(|_| ())
    }

    /// Toggles the state of the "Always Require User Verification" feature.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#toggle-alwaysUv>
    pub async fn toggle_always_uv(&self) -> Result<(), WebauthnCError> {
        self.config(ConfigSubCommand::ToggleAlwaysUv, true).await
    }

    /// Sets the minimum PIN length policy.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setMinPINLength>
    pub async fn set_min_pin_length(
        &self,
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

    /// Enables the Enterprise Attestation feature.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn>
    pub async fn enable_enterprise_attestation(&self) -> Result<(), WebauthnCError> {
        if self.info.get_option("ep").is_none() {
            return Err(WebauthnCError::NotSupported);
        }
        self.config(ConfigSubCommand::EnableEnterpriseAttestation, false)
            .await
    }

    /// Checks whether a provided PIN follows the rules defined by the
    /// authenticator. This does not share the PIN with the authenticator.
    pub fn validate_pin(&self, pin: &str) -> CheckPinResult {
        let min_length = self.info.min_pin_length.unwrap_or(4);
        check_pin(pin, min_length)
    }

    pub async fn set_new_pin(&self, pin: &str) -> Result<(), WebauthnCError> {
        let pin = match self.validate_pin(pin) {
            CheckPinResult::Ok(p) => p,
            _ => return Err(WebauthnCError::InvalidPin),
        };

        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())?;

        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, self.ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or(WebauthnCError::Internal)?;
        trace!(?key_agreement);

        // The platform calls encapsulate with the public key that the authenticator
        // returned in order to generate the platform key-agreement key and the shared secret.
        let shared_secret = iface.encapsulate(key_agreement)?;
        trace!(?shared_secret);

        let set_pin = iface.set_pin_cmd(padded_pin, shared_secret.as_slice());
        let ret = self.token.transmit(set_pin, self.ui_callback).await?;
        trace!(?ret);
        Ok(())
    }

    pub async fn change_pin(&self, old_pin: &str, new_pin: &str) -> Result<(), WebauthnCError> {
        // TODO: we actually really only need this in normal form C
        let old_pin = match self.validate_pin(old_pin) {
            CheckPinResult::Ok(p) => p,
            _ => return Err(WebauthnCError::InvalidPin),
        };
        let new_pin = match self.validate_pin(new_pin) {
            CheckPinResult::Ok(p) => p,
            _ => return Err(WebauthnCError::InvalidPin),
        };
        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..new_pin.len()].copy_from_slice(new_pin.as_bytes());

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())?;

        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, self.ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or(WebauthnCError::Internal)?;
        let shared_secret = iface.encapsulate(key_agreement)?;

        let change_pin = iface.change_pin_cmd(&old_pin, padded_pin, &shared_secret);
        let ret = self.token.transmit(change_pin, self.ui_callback).await?;
        trace!(?ret);
        Ok(())
    }

    /// Gets a PIN/UV auth token, if required.
    ///
    /// This automatically selects an appropriate verification mode.
    ///
    /// Parameters:
    /// * `client_data_hash`: the SHA256 hash of the client data JSON.
    /// * `permissions`: a bitmask of permissions to request. This is only
    ///   effective when the authenticator supports
    ///   `getPinUvAuthToken...WithPermissions`.
    /// * `rp_id`: the Relying Party to associate with the request. This is
    ///   required for `GetAssertion` and `MakeCredential` requests, and
    ///   optional for `CredentialManagement` requests. This is only effective
    ///   when the authenticator supports `getPinUvAuthToken...WithPermissions`.
    ///
    /// Returns:
    /// * `Option<u32>`: the `pin_uv_auth_protocol`
    /// * `Option<Vec<u8>>`: the `pin_uv_auth_param`
    /// * `Ok((None, None))` if PIN and/or UV auth is not required.
    /// * `Err` for errors from the token.
    ///
    /// References:
    /// * <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#gettingPinUvAuthToken>
    pub(super) async fn get_pin_uv_auth_token(
        &self,
        client_data_hash: &[u8],
        permissions: Permissions,
        rp_id: Option<String>,
        bypass_always_uv: bool,
    ) -> Result<(Option<u32>, Option<Vec<u8>>), WebauthnCError> {
        let (iface, pin_token) = self
            .get_pin_uv_auth_session(permissions, rp_id, bypass_always_uv)
            .await?;

        Ok(match (iface, pin_token) {
            (Some(iface), Some(pin_token)) => {
                let mut pin_uv_auth_param =
                    iface.authenticate(pin_token.as_slice(), client_data_hash);
                pin_uv_auth_param.truncate(16);

                (iface.get_pin_uv_protocol(), Some(pin_uv_auth_param))
            }

            _ => (None, None),
        })
    }

    pub(super) async fn get_pin_uv_auth_session(
        &self,
        permissions: Permissions,
        rp_id: Option<String>,
        bypass_always_uv: bool,
    ) -> Result<(Option<PinUvPlatformInterface>, Option<Vec<u8>>), WebauthnCError> {
        if permissions.is_empty() {
            error!("no permissions were requested");
            return Err(WebauthnCError::Internal);
        }
        if permissions.intersects(Permissions::MAKE_CREDENTIAL | Permissions::GET_ASSERTION)
            && rp_id == None
        {
            error!("rp_id is required for MakeCredential and GetAssertion requests");
            return Err(WebauthnCError::Internal);
        }

        let client_pin = self.info.get_option("clientPin");
        let always_uv = self.info.get_option("alwaysUv");
        let make_cred_uv_not_required = self.info.get_option("makeCredUvNotRqd");
        let pin_uv_auth_token = self.info.get_option("pinUvAuthToken");
        let uv = self.info.get_option("uv");
        let _bio_enroll = self.info.get_option("bioEnroll");
        let _bio_enroll_preview = self.info.get_option("userVerificationMgmtPreview");

        if client_pin != Some(true) && always_uv != Some(true) {
            trace!("Skipping PIN and UV auth because they are disabled");
            return Ok((None, None));
        }

        if make_cred_uv_not_required == Some(true) && permissions == Permissions::MAKE_CREDENTIAL {
            trace!("Skipping UV because makeCredUvNotRqd = true and this is a MakeCredential only request");
            return Ok((None, None));
        }

        if pin_uv_auth_token == Some(true) {
            if uv == Some(true) {
                trace!("UV with in-built verification (biometrics) supported");
            }

            if client_pin == Some(true) {
                trace!("UV with client pin supported");
            }
        }

        if always_uv == Some(true) && uv != Some(true) && client_pin != Some(true) {
            if bypass_always_uv {
                trace!("Bypassing alwaysUv check (bypass_always_uv = true)");
                return Ok((None, None));
            } else {
                // TODO: this will need to change once we can enroll biometrics
                error!("alwaysUv = true, but built-in user verification (biometrics) and PIN are both unconfigured. Set one (or both) of them before continuing.");
                return Err(WebauthnCError::Security);
            }
        }

        // TODO: handle cancels, timeouts
        // TODO: handle lockouts

        // Get pin retries
        trace!("supported pin protocols = {:?}", self.info.pin_protocols);
        if let Some(protocols) = &self.info.pin_protocols {
            for protocol in protocols {
                let p = ClientPinRequest {
                    pin_uv_protocol: Some(*protocol),
                    sub_command: ClientPinSubCommand::GetPinRetries,
                    ..Default::default()
                };

                let ret = self.token.transmit(p, self.ui_callback).await?;
                trace!(?ret);

                // TODO: handle lockouts
            }
        }

        let pin = self
            .ui_callback
            .request_pin()
            .ok_or(WebauthnCError::Cancelled)?;

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())?;

        // 6.5.5.4: Obtaining the shared secret
        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, self.ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or(WebauthnCError::Internal)?;
        trace!(?key_agreement);

        // The platform calls encapsulate with the public key that the authenticator
        // returned in order to generate the platform key-agreement key and the shared secret.
        let shared_secret = iface.encapsulate(key_agreement)?;
        trace!(?shared_secret);

        let requires_pin = permissions
            .intersects(Permissions::BIO_ENROLLMENT | Permissions::AUTHENTICATOR_CONFIGURATION);
        let p = match (requires_pin, uv, client_pin, pin_uv_auth_token) {
            (false, Some(true), _, Some(true)) => {
                // 6.5.5.7.3. Getting pinUvAuthToken using getPinUvAuthTokenUsingUvWithPermissions (built-in user verification methods)
                iface.get_pin_uv_auth_token_using_uv_with_permissions_cmd(permissions, rp_id)
            }
            (_, _, Some(true), Some(true)) => {
                // 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)
                iface.get_pin_uv_auth_token_using_pin_with_permissions_cmd(
                    &pin,
                    shared_secret.as_slice(),
                    permissions,
                    rp_id,
                )
            }
            _ => {
                // 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)
                iface.get_pin_token_cmd(&pin, shared_secret.as_slice())
            }
        };

        let ret = self.token.transmit(p, self.ui_callback).await?;
        trace!(?ret);
        let pin_token = ret.pin_uv_auth_token.unwrap();
        // Decrypt the pin_token
        let pin_token = iface.decrypt(shared_secret.as_slice(), pin_token.as_slice())?;
        trace!(?pin_token);

        Ok((Some(iface), Some(pin_token)))
    }
}

impl<'a, T: Token, U: UiCallback> AuthenticatorBackend for Ctap20Authenticator<'a, T, U> {
    fn perform_register(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, crate::prelude::WebauthnCError>
    {
        let client_data = creation_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();

        let (pin_uv_auth_proto, pin_uv_auth_param) = block_on(self.get_pin_uv_auth_token(
            client_data_hash.as_slice(),
            Permissions::MAKE_CREDENTIAL,
            Some(options.rp.id.clone()),
            false,
        ))?;

        let mc = MakeCredentialRequest {
            client_data_hash,
            rp: options.rp,
            user: options.user,
            pub_key_cred_params: options.pub_key_cred_params,
            exclude_list: options.exclude_credentials.unwrap_or_default(),

            options: None,
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
                client_data_json: Base64UrlSafeData(client_data),
                // All transports the token supports, as opposed to the
                // transport which was actually used.
                transports: self.info.get_transports(),
            },
        })
    }

    fn perform_auth(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, crate::prelude::WebauthnCError> {
        trace!("trying to authenticate...");
        let client_data = get_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();

        let (pin_uv_auth_proto, pin_uv_auth_param) = block_on(self.get_pin_uv_auth_token(
            client_data_hash.as_slice(),
            Permissions::GET_ASSERTION,
            Some(options.rp_id.clone()),
            false,
        ))?;

        let ga = GetAssertionRequest {
            rp_id: options.rp_id,
            client_data_hash,
            allow_list: options.allow_credentials,
            options: None, // TODO
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
                client_data_json: Base64UrlSafeData(client_data),
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
