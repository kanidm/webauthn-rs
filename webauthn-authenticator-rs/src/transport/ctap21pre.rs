use std::{fmt::Debug, ops::Deref};

use crate::{
    cbor::*,
    error::WebauthnCError,
    transport::Token,
    ui::UiCallback,
    util::{check_pin, compute_sha256, creation_to_clientdata, get_to_clientdata, CheckPinResult},
    AuthenticatorBackend,
};

use base64urlsafedata::Base64UrlSafeData;
use futures::executor::block_on;
use openssl::{
    bn,
    ec::{self, EcKey, EcKeyRef},
    hash,
    md::Md,
    nid,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    sign, symm,
};
use url::Url;
use webauthn_rs_core::proto::{COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, COSEAlgorithm, PublicKeyCredential,
    RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs,
};

pub struct Ctap21PreAuthenticator<'a, T: Token, U: UiCallback> {
    info: GetInfoResponse,
    token: T,
    ui_callback: &'a U,
}

impl<'a, T: Token, U: UiCallback> Ctap21PreAuthenticator<'a, T, U> {
    pub fn new(info: GetInfoResponse, token: T, ui_callback: &'a U) -> Self {
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
        let (pin_uv_auth_proto, pin_uv_auth_param) = self.get_pin_uv_auth_token(
            sub_command.prf().as_slice(),
            Permissions::AUTHENTICATOR_CONFIGURATION,
            None,
            bypass_always_uv,
        ).await?;

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
        ).await
    }

    /// Enables the Enterprise Attestation feature.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn>
    pub async fn enable_enterprise_attestation(&self) -> Result<(), WebauthnCError> {
        if self.info.get_option("ep").is_none() {
            return Err(WebauthnCError::NotSupported);
        }
        self.config(ConfigSubCommand::EnableEnterpriseAttestation, false).await
    }

    async fn bio(
        &self,
        sub_command: BioSubCommand,
    ) -> Result<BioEnrollmentResponse, WebauthnCError> {
        let (pin_uv_auth_proto, pin_uv_auth_param) = self.get_pin_uv_auth_token(
            sub_command.prf().as_slice(),
            Permissions::BIO_ENROLLMENT,
            None,
            false,
        ).await?;

        self.token.transmit(
            BioEnrollmentRequest::new(sub_command, pin_uv_auth_proto, pin_uv_auth_param),
            self.ui_callback,
        ).await
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
                let mut pin_uv_auth_param = iface
                    .protocol
                    .authenticate(pin_uv_auth_token, client_data_hash.as_slice());
                pin_uv_auth_param.truncate(16);

                (
                    iface.protocol.get_pin_uv_protocol(),
                    Some(pin_uv_auth_param),
                )
            }

            _ => (None, None),
        };

        self.token.transmit(BioEnrollmentRequest::new(sub_command, pin_uv_protocol, pin_uv_auth_param), self.ui_callback).await
    }

    pub async fn get_fingerprint_sensor_info(&self) -> Result<BioEnrollmentResponse, WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        if self.info.get_option("bioEnroll").is_none() {
            return Err(WebauthnCError::NotSupported);
        }

        self.token.transmit(GET_MODALITY, self.ui_callback).await?;
        self.token
            .transmit(GET_FINGERPRINT_SENSOR_INFO, self.ui_callback).await
    }

    pub async fn enroll_fingerprint(&self) -> Result<(), WebauthnCError> {
        // TODO: handle CTAP_2_1_PRE version too
        if self.info.get_option("bioEnroll").is_none() {
            return Err(WebauthnCError::NotSupported);
        }

        // TODO
        let timeout = 30_000;

        let (iface, pin_uv_auth_token) =
            self.get_pin_uv_auth_session(Permissions::BIO_ENROLLMENT, None, false).await?;

        let r = self.bio_with_session(BioSubCommand::FingerprintEnrollBegin(timeout), iface.as_ref(), pin_uv_auth_token.as_ref()).await?;

        println!("began enrollment: {:?}", r);
        let id = r.template_id.unwrap();

        // TODO: show feedback
        let mut remaining_samples = r.remaining_samples.unwrap_or_default();
        while remaining_samples > 0 {
            let r = self.bio_with_session(BioSubCommand::FingerprintEnrollCaptureNextSample(id.clone(), timeout), iface.as_ref(), pin_uv_auth_token.as_ref()).await?;

            remaining_samples = r.remaining_samples.unwrap_or_default();
        }

        Ok(())
    }

    // pub fn select_pin_protocol(&self) -> Option<Box<dyn PinUvPlatformInterface>> {
    //     self.info.pin_protocols.as_ref().and_then(|protocols| {
    //         for p in protocols.iter() {
    //             match p {
    //                 1 => return Some(PinUvPlatformInterfaceProtocolOne::default()),
    //                 2 => return Some(PinUvPlatformInterfaceProtocolTwo::default()),
    //                 // Ignore unsupported protocols
    //                 _ => (),
    //             }
    //         }

    //         // No protocols supported
    //         None
    //     }).map(|i| Box::new(i))
    // }

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

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())
            .ok_or(WebauthnCError::Unknown)?; // TODO

        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, self.ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or_else(|| WebauthnCError::Internal)?;
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

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())
            .ok_or(WebauthnCError::Unknown)?; // TODO

        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, self.ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or_else(|| WebauthnCError::Internal)?;
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
    async fn get_pin_uv_auth_token(
        &self,
        client_data_hash: &[u8],
        permissions: Permissions,
        rp_id: Option<String>,
        bypass_always_uv: bool,
    ) -> Result<(Option<u32>, Option<Vec<u8>>), WebauthnCError> {
        let (iface, pin_token) =
            self.get_pin_uv_auth_session(permissions, rp_id, bypass_always_uv).await?;

        Ok(match (iface, pin_token) {
            (Some(iface), Some(pin_token)) => {
                let mut pin_uv_auth_param = iface
                    .protocol
                    .authenticate(pin_token.as_slice(), client_data_hash);
                pin_uv_auth_param.truncate(16);

                (
                    iface.protocol.get_pin_uv_protocol(),
                    Some(pin_uv_auth_param),
                )
            }

            _ => (None, None),
        })
    }

    async fn get_pin_uv_auth_session(
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
        let bio_enroll = self.info.get_option("bioEnroll");
        let bio_enroll_preview = self.info.get_option("userVerificationMgmtPreview");

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

        // TODO: handle getPinUvAuthTokenUsingPinWithPermissions
        // TODO: handle biometric auth
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

                // let p = ClientPinRequest {
                //     pin_uv_protocol: Some(*protocol),
                //     sub_command: ClientPinSubCommand::GetUvRetries,
                //     ..Default::default()
                // };

                // let ret = self.token.transmit(p)?;
                // trace!(?ret);
            }
        }

        let pin = self
            .ui_callback
            .request_pin()
            .ok_or(WebauthnCError::Cancelled)?;

        let iface = PinUvPlatformInterface::select_protocol(self.info.pin_protocols.as_ref())
            .ok_or(WebauthnCError::Unknown)?; // TODO

        // 6.5.5.4: Obtaining the shared secret
        let p = iface.get_key_agreement_cmd();
        let ret = self.token.transmit(p, self.ui_callback).await?;
        let key_agreement = ret.key_agreement.ok_or_else(|| WebauthnCError::Internal)?;
        trace!(?key_agreement);

        // The platform calls encapsulate with the public key that the authenticator
        // returned in order to generate the platform key-agreement key and the shared secret.
        let shared_secret = iface.encapsulate(key_agreement)?;
        trace!(?shared_secret);
        // todo!();

        let p = match (uv, client_pin, pin_uv_auth_token) {
            (Some(true), _, Some(true)) => {
                // 6.5.5.7.3. Getting pinUvAuthToken using getPinUvAuthTokenUsingUvWithPermissions (built-in user verification methods)
                ClientPinRequest {
                    pin_uv_protocol: iface.get_pin_uv_protocol(),
                    sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions,
                    key_agreement:  Some(iface.public_key.clone()),
                    permissions,
                    rp_id,
                    ..Default::default()
                }
            }
            (_, Some(true), Some(true)) => {
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
        let pin_token = iface
            .protocol
            .decrypt(shared_secret.as_slice(), pin_token.as_slice())?;
        trace!(?pin_token);

        Ok((Some(iface), Some(pin_token)))
    }

    /// Requests user presence on a token.
    /// 
    /// This feature is only available in `FIDO_V2_1`.
    pub async fn selection(&self) -> Result<(), WebauthnCError> {
        self.token.transmit(SelectionRequest {}, self.ui_callback).await.map(|_| ())
    }
}

impl<'a, T: Token, U: UiCallback> AuthenticatorBackend for Ctap21PreAuthenticator<'a, T, U> {
    fn perform_register(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
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

        let type_ = ret.fmt.clone().ok_or(WebauthnCError::InvalidAlgorithm)?;

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
        timeout_ms: u32,
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

pub(crate) struct PinUvPlatformInterface {
    protocol: Box<dyn PinUvPlatformInterfaceProtocol>,
    /// A cached [COSEKey] representation of `private_key`.
    public_key: COSEKey,
    /// The platform private key used for this session.
    private_key: EcKey<Private>,
}

impl Debug for PinUvPlatformInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinUvPlatformInterface")
            .field(
                "protocol.pin_uv_protocol",
                &self.protocol.get_pin_uv_protocol(),
            )
            .finish()
    }
}

/// Makes [PinUvPlatformInterface] act like [PinUvPlatformInterfaceProtocol] for easier access to trait methods.
impl Deref for PinUvPlatformInterface {
    type Target = dyn PinUvPlatformInterfaceProtocol;

    fn deref(&self) -> &Self::Target {
        self.protocol.deref()
    }
}

impl PinUvPlatformInterface {
    /// Creates a [PinUvPlatformInterface] for a specific protocol, and generates a new private key.
    fn new<T: PinUvPlatformInterfaceProtocol + Default + 'static>() -> Self {
        let private_key = regenerate().expect("generating key");
        Self::__new_with_private_key::<T>(private_key)
    }

    /// Creates a [PinUvPlatformInterface] for a specific protocol, with a given private key.
    ///
    /// This interface is only exposed for tests.
    fn __new_with_private_key<T: PinUvPlatformInterfaceProtocol + Default + 'static>(
        private_key: EcKey<Private>,
    ) -> Self {
        let public_key = get_public_key(&private_key);
        Self {
            protocol: Box::new(T::default()),
            public_key,
            private_key,
        }
    }

    /// Creates a [PinUvPlatformInterface] given a list of supported protocols. The first supported
    /// protocol will be used.
    ///
    /// Returns `None` if no protocols are supported.
    fn select_protocol(protocols: Option<&Vec<u32>>) -> Option<Self> {
        protocols.and_then(|protocols| {
            for p in protocols.iter() {
                match p {
                    1 => return Some(Self::new::<PinUvPlatformInterfaceProtocolOne>()),
                    2 => return Some(Self::new::<PinUvPlatformInterfaceProtocolTwo>()),
                    // Ignore unsupported protocols
                    _ => (),
                }
            }
            None
        })
    }

    fn ecdh(&self, peer_cose_key: COSEKey) -> Result<Vec<u8>, WebauthnCError> {
        // Defined in protocol one, but also used in protocol two.

        // 1. Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
        //    If unsuccessful, or if the resulting point is not on the curve, return error.

        // 2. Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y,
        //    with the local private key agreement key.)
        // 3. Let Z be the 32-byte, big-endian encoding of the x-coordinate of the shared point.
        let mut z: [u8; 32] = [0; 32];
        if let COSEKeyType::EC_EC2(ec) = peer_cose_key.key {
            ecdh(self.private_key.as_ref(), &ec, &mut z).map_err(|_| WebauthnCError::OpenSSL)?;
        } else {
            error!("Unexpected peer key type: {:?}", peer_cose_key);
            return Err(WebauthnCError::OpenSSL);
        }

        // 4. Return kdf(Z).
        Ok(self.kdf(&z))
    }

    /// Generates an encapsulation for the authenticator's public key and returns the shared secret.
    fn encapsulate(&self, peer_cose_key: COSEKey) -> Result<Vec<u8>, WebauthnCError> {
        // Let sharedSecret be the result of calling ecdh(peerCoseKey). Return any resulting error.
        let shared_secret = self.ecdh(peer_cose_key)?;

        // Return (getPublicKey(), sharedSecret)
        Ok(shared_secret)
    }

    /// Generates a `getKeyAgreement` command.
    fn get_key_agreement_cmd(&self) -> ClientPinRequest {
        ClientPinRequest {
            pin_uv_protocol: self.get_pin_uv_protocol(),
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            ..Default::default()
        }
    }

    /// Generates a `getPinToken` command.
    fn get_pin_token_cmd(&self, pin: &str, shared_secret: &[u8]) -> ClientPinRequest {
        ClientPinRequest {
            pin_uv_protocol: self.get_pin_uv_protocol(),
            sub_command: ClientPinSubCommand::GetPinToken,
            key_agreement: Some(self.public_key.clone()),
            pin_hash_enc: Some(
                self.encrypt(shared_secret, &(compute_sha256(pin.as_bytes()))[..16]),
            ),
            ..Default::default()
        }
    }

    /// Generates a `getPinUvAuthTokenUsingPinWithPermissions` command.
    fn get_pin_uv_auth_token_using_pin_with_permissions_cmd(
        &self,
        pin: &str,
        shared_secret: &[u8],
        permissions: Permissions,
        rp_id: Option<String>,
    ) -> ClientPinRequest {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
        ClientPinRequest {
            pin_uv_protocol: self.get_pin_uv_protocol(),
            sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(self.public_key.clone()),
            pin_hash_enc: Some(
                self.encrypt(shared_secret, &(compute_sha256(pin.as_bytes()))[..16]),
            ),
            permissions,
            rp_id,
            ..Default::default()
        }
    }

    /// Generates a `setPin` command.
    fn set_pin_cmd(&self, padded_pin: [u8; 64], shared_secret: &[u8]) -> ClientPinRequest {
        let new_pin_enc = self.encrypt(shared_secret, &padded_pin);
        let pin_uv_auth_param = Some(self.authenticate(shared_secret, new_pin_enc.as_slice()));
        ClientPinRequest {
            pin_uv_protocol: self.get_pin_uv_protocol(),
            sub_command: ClientPinSubCommand::SetPin,
            key_agreement: Some(self.public_key.clone()),
            new_pin_enc: Some(new_pin_enc),
            pin_uv_auth_param,
            ..Default::default()
        }
    }

    /// Generates a `changePin` command.
    fn change_pin_cmd(
        &self,
        old_pin: &str,
        new_padded_pin: [u8; 64],
        shared_secret: &[u8],
    ) -> ClientPinRequest {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#changingExistingPin
        let pin_hash_enc = self.encrypt(shared_secret, &(compute_sha256(old_pin.as_bytes()))[..16]);
        let new_pin_enc = self.encrypt(shared_secret, &new_padded_pin);

        let mut pin_uv_auth_param = Vec::with_capacity(pin_hash_enc.len() + new_pin_enc.len());
        pin_uv_auth_param.extend_from_slice(new_pin_enc.as_slice());
        pin_uv_auth_param.extend_from_slice(pin_hash_enc.as_slice());
        let pin_uv_auth_param =
            Some(self.authenticate(shared_secret, pin_uv_auth_param.as_slice()));

        ClientPinRequest {
            pin_uv_protocol: self.get_pin_uv_protocol(),
            sub_command: ClientPinSubCommand::ChangePin,
            key_agreement: Some(self.public_key.clone()),
            pin_hash_enc: Some(pin_hash_enc),
            new_pin_enc: Some(new_pin_enc),
            pin_uv_auth_param,
            ..Default::default()
        }
    }
}

/// Encrypts some data using AES-256-CBC, with no padding.
///
/// `plaintext.len()` must be a multiple of the cipher's blocksize.
fn encrypt(key: &[u8], iv: Option<&[u8]>, plaintext: &[u8]) -> Vec<u8> {
    let cipher = symm::Cipher::aes_256_cbc();
    let mut ct = vec![0; plaintext.len() + cipher.block_size()];
    let mut c = symm::Crypter::new(cipher, symm::Mode::Encrypt, &key, iv).unwrap();
    c.pad(false);
    let l = c.update(&plaintext, &mut ct).unwrap();
    let l = l + c.finalize(&mut ct[l..]).unwrap();
    ct.truncate(l);
    ct
}

fn decrypt(key: &[u8], iv: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    if ciphertext.len() % cipher.block_size() != 0 {
        error!(
            "ciphertext length {} is not a multiple of {} bytes",
            ciphertext.len(),
            cipher.block_size()
        );
        return Err(WebauthnCError::OpenSSL);
    }

    let mut pt = vec![0; ciphertext.len() + cipher.block_size()];
    let mut c = symm::Crypter::new(cipher, symm::Mode::Decrypt, &key, iv).unwrap();
    c.pad(false);
    let l = c.update(&ciphertext, &mut pt).unwrap();
    let l = l + c.finalize(&mut pt[l..]).unwrap();
    pt.truncate(l);
    Ok(pt)
}

pub(crate) trait PinUvPlatformInterfaceProtocol {
    fn kdf(&self, z: &[u8]) -> Vec<u8>;

    /// Encrypts a `plaintext` to produce a ciphertext, which may be longer than
    /// the `plaintext`. The `plaintext` is restricted to being a multiple of
    /// the AES block size (16 bytes) in length.
    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Vec<u8>;

    /// Decrypts a `ciphertext` and returns the plaintext.
    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError>;

    /// Computes a MAC of the given `message`.
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8>;

    /// Gets the numeric identifier for this [PinUvPlatformInterfaceProtocol].
    fn get_pin_uv_protocol(&self) -> Option<u32>;
}

#[derive(Default)]
struct PinUvPlatformInterfaceProtocolOne {}

impl PinUvPlatformInterfaceProtocol for PinUvPlatformInterfaceProtocolOne {
    fn kdf(&self, z: &[u8]) -> Vec<u8> {
        // Return SHA-256(Z)
        compute_sha256(z).to_vec()
    }

    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Vec<u8> {
        // Return the AES-256-CBC encryption of demPlaintext using an all-zero IV.
        // (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        encrypt(key, None, dem_plaintext)
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError> {
        // If the size of demCiphertext is not a multiple of the AES block length, return error.
        // Otherwise return the AES-256-CBC decryption of demCiphertext using an all-zero IV.
        decrypt(key, None, ciphertext)
    }

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        // Return the first 16 bytes of the result of computing HMAC-SHA-256
        // with the given key and message.
        let key = PKey::hmac(&key).unwrap();
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &key).unwrap();
        signer.update(&message).unwrap();
        let mut o = signer.sign_to_vec().unwrap();
        o.truncate(16);
        o
    }

    fn get_pin_uv_protocol(&self) -> Option<u32> {
        Some(1)
    }
}

#[derive(Default)]
struct PinUvPlatformInterfaceProtocolTwo {}

impl PinUvPlatformInterfaceProtocol for PinUvPlatformInterfaceProtocolTwo {
    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Vec<u8> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key
        //    portion of the shared secret.)
        let key = &key[32..];

        // 2. Let iv be a 16-byte, random bytestring.
        let mut iv: [u8; 16] = [0; 16];
        rand_bytes(&mut iv).expect("encrypt::iv");

        // 3. Let ct be the AES-256-CBC encryption of demPlaintext using key and
        //    iv. (No padding is performed as the size of demPlaintext is
        //    required to be a multiple of the AES block length.)
        let ct = encrypt(key, Some(iv.as_slice()), dem_plaintext);

        // 4. Return iv || ct.
        let mut o = iv.to_vec();
        o.extend_from_slice(ct.as_slice());

        o
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let key = &key[32..];

        // 2. If demPlaintext is less than 16 bytes in length, return an error
        // THIS IS AN ERROR, should be demCiphertext
        if ciphertext.len() < 16 {
            error!("ciphertext too short");
            return Err(WebauthnCError::MessageTooShort);
        }
        // 3. Split demPlaintext after the 16th byte to produce two subspans, iv and ct.
        // ALSO AN ERROR, as above
        let (iv, ct) = ciphertext.split_at(16);

        // 4. Return the AES-256-CBC decryption of ct using key and iv.
        decrypt(key, Some(iv), ct)
    }

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        // 1. If key is longer than 32 bytes, discard the excess.
        //    (This selects the HMAC-key portion of the shared secret. When key is the
        //    pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
        let key = PKey::hmac(&key[..32]).unwrap();

        // 2. Return the result of computing HMAC-SHA-256 on key and message.
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &key).unwrap();
        signer.update(&message).unwrap();
        signer.sign_to_vec().unwrap()
    }

    fn kdf(&self, z: &[u8]) -> Vec<u8> {
        // Return
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
        // (see [RFC5869] for the definition of HKDF).
        let mut o: Vec<u8> = vec![0; 64];
        let zero: [u8; 32] = [0; 32];
        hkdf_sha_256(&zero, z, b"CTAP2 HMAC key", &mut o[0..32]).expect("hkdf_sha_256");
        hkdf_sha_256(&zero, z, b"CTAP2 AES key", &mut o[32..64]).expect("hkdf_sha_256");

        o
    }

    fn get_pin_uv_protocol(&self) -> Option<u32> {
        Some(2)
    }
}

fn hkdf_sha_256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    let mut ctx = PkeyCtx::new_id(openssl::pkey::Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.add_hkdf_info(info)?;
    ctx.derive(Some(output))?;
    Ok(())
}

fn ecdh(
    private_key: &EcKeyRef<Private>,
    peer_key: &COSEEC2Key,
    output: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    // let mut ctx = BigNumContext::new()?;

    // let mut x = BigNum::new()?;
    // let mut y = BigNum::new()?;
    // let peer_key: EcKey<Public> = peer_key.into();
    // let peer_key_pub = peer_key.public_key();

    // let pk = private_key.private_key();
    // let group = private_key.group();

    // let mut pt = EcPoint::new(group)?;
    // pt.mul(group, peer_key_pub, pk, &ctx)?;
    // pt.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

    // let buflen = (group.degree() + 7) / 8;
    // trace!(?buflen);
    // let x = x.to_vec();
    // trace!(?x);
    //output.copy_from_slice(x.as_slice());

    // Both the low level and high level return same outputs.
    let peer_key = PKey::from_ec_key(peer_key.into())?;
    let pkey = PKey::from_ec_key(private_key.to_owned())?;
    let mut ctx = PkeyCtx::new(&pkey)?;
    ctx.derive_init()?;
    ctx.derive_set_peer(&peer_key)?;
    ctx.derive(Some(output))?;
    // trace!(?output);

    Ok(())
}

/// Generate a fresh, random P-256 private key, x, and compute the associated public point.
fn regenerate() -> Result<EcKey<Private>, openssl::error::ErrorStack> {
    // Create a new key.
    let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)?;
    let eckey = ec::EcKey::generate(&ecgroup)?;

    Ok(eckey)
}

/// Gets the public key for a private key as [COSEKey].
fn get_public_key(private_key: &EcKeyRef<Private>) -> COSEKey {
    let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).unwrap();
    // Extract the public x and y coords.
    let ecpub_points = private_key.public_key();

    let mut bnctx = bn::BigNumContext::new().unwrap();
    let mut xbn = bn::BigNum::new().unwrap();
    let mut ybn = bn::BigNum::new().unwrap();

    ecpub_points
        .affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)
        .unwrap();

    COSEKey {
        type_: COSEAlgorithm::PinUvProtocol,
        key: COSEKeyType::EC_EC2(COSEEC2Key {
            curve: ECDSACurve::SECP256R1,
            x: xbn.to_vec().into(),
            y: ybn.to_vec().into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use base64urlsafedata::Base64UrlSafeData;

    use super::*;

    #[test]
    fn hkdf() {
        let salt: Vec<u8> = (0..0x0d).collect();
        let ikm: [u8; 22] = [0x0b; 22];
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0xa, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x0, 0x72, 0x8, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut output: [u8; 42] = [0; 42];

        hkdf_sha_256(salt.as_slice(), &ikm, info.as_slice(), &mut output)
            .expect("hkdf_sha_256 fail");
        assert_eq!(expected, output);
    }

    #[test]
    fn pin_encryption_and_hashing() {
        // https://github.com/mozilla/authenticator-rs/blob/f2d255c48d3e3762a27873b270520072bf501d0e/src/crypto/mod.rs#L833
        let pin = "1234";

        let shared_secret = vec![
            0x82, 0xE3, 0xD8, 0x41, 0xE2, 0x5C, 0x5C, 0x13, 0x46, 0x2C, 0x12, 0x3C, 0xC3, 0xD3,
            0x98, 0x78, 0x65, 0xBA, 0x3D, 0x20, 0x46, 0x74, 0xFB, 0xED, 0xD4, 0x7E, 0xF5, 0xAB,
            0xAB, 0x8D, 0x13, 0x72,
        ];
        let expected_new_pin_enc = vec![
            0x70, 0x66, 0x4B, 0xB5, 0x81, 0xE2, 0x57, 0x45, 0x1A, 0x3A, 0xB9, 0x1B, 0xF1, 0xAA,
            0xD8, 0xE4, 0x5F, 0x6C, 0xE9, 0xB5, 0xC3, 0xB0, 0xF3, 0x2B, 0x5E, 0xCD, 0x62, 0xD0,
            0xBA, 0x3B, 0x60, 0x5F, 0xD9, 0x18, 0x31, 0x66, 0xF6, 0xC5, 0xFA, 0xF3, 0xE4, 0xDA,
            0x24, 0x81, 0x50, 0x2C, 0xD0, 0xCE, 0xE0, 0x15, 0x8B, 0x35, 0x1F, 0xC3, 0x92, 0x08,
            0xA7, 0x7C, 0xB2, 0x74, 0x4B, 0xD4, 0x3C, 0xF9,
        ];
        let expected_pin_auth = vec![
            0x8E, 0x7F, 0x01, 0x69, 0x97, 0xF3, 0xB0, 0xA2, 0x7B, 0xA4, 0x34, 0x7A, 0x0E, 0x49,
            0xFD, 0xF5,
        ];

        // Padding to 64 bytes
        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let t = PinUvPlatformInterface::new::<PinUvPlatformInterfaceProtocolOne>();

        let new_pin_enc = t.encrypt(&shared_secret, &padded_pin);
        assert_eq!(new_pin_enc, expected_new_pin_enc);

        let pin_auth = t.authenticate(&shared_secret, &new_pin_enc);
        assert_eq!(pin_auth[0..16], expected_pin_auth);

        let decrypted_pin = t
            .decrypt(&shared_secret, expected_new_pin_enc.as_slice())
            .expect("decrypt error");
        assert_eq!(decrypted_pin, padded_pin.to_vec());
    }

    // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L274
    #[test]
    fn shared_secret() {
        let expected_secret = vec![
            0xc4, 0x2a, 0x3, 0x9d, 0x54, 0x81, 0x0, 0xdf, 0xba, 0x52, 0x1e, 0x48, 0x7d, 0xeb, 0xcb,
            0xbb, 0x8b, 0x66, 0xbb, 0x74, 0x96, 0xf8, 0xb1, 0x86, 0x2a, 0x7a, 0x39, 0x5e, 0xd8,
            0x3e, 0x1a, 0x1c,
        ];
        let dev_public_key = COSEKey {
            type_: COSEAlgorithm::PinUvProtocol,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: Base64UrlSafeData::from(vec![
                    0x5, 0x1, 0xd5, 0xbc, 0x78, 0xda, 0x92, 0x52, 0x56, 0xa, 0x26, 0xcb, 0x8, 0xfc,
                    0xc6, 0xc, 0xbe, 0xb, 0x6d, 0x3b, 0x8e, 0x1d, 0x1f, 0xce, 0xe5, 0x14, 0xfa,
                    0xc0, 0xaf, 0x67, 0x51, 0x68,
                ]),
                y: Base64UrlSafeData::from(vec![
                    0xd5, 0x51, 0xb3, 0xed, 0x46, 0xf6, 0x65, 0x73, 0x1f, 0x95, 0xb4, 0x53, 0x29,
                    0x39, 0xc2, 0x5d, 0x91, 0xdb, 0x7e, 0xb8, 0x44, 0xbd, 0x96, 0xd4, 0xab, 0xd4,
                    0x8, 0x37, 0x85, 0xf8, 0xdf, 0x47,
                ]),
            }),
        };

        let mut ctx = bn::BigNumContext::new().unwrap();
        let group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).unwrap();
        let x = bn::BigNum::from_hex_str(
            "44D78D7989B97E62EA993496C9EF6E8FD58B8B00715F9A89153DDD9C4657E47F",
        )
        .unwrap();
        let y = bn::BigNum::from_hex_str(
            "EC802EE7D22BD4E100F12E48537EB4E7E96ED3A47A0A3BD5F5EEAB65001664F9",
        )
        .unwrap();
        // let ec_pub = ec::EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
        let mut ec_pub = ec::EcPoint::new(&group).unwrap();
        ec_pub
            .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
            .unwrap();
        let ec_priv = bn::BigNum::from_hex_str(
            "7452E599FEE739D8A653F6A507343D12D382249108A651402520B72F24FE7684",
        )
        .unwrap();
        let ec_priv = ec::EcKey::from_private_components(&group, &ec_priv, &ec_pub).unwrap();

        let t = PinUvPlatformInterface::__new_with_private_key::<PinUvPlatformInterfaceProtocolOne>(
            ec_priv,
        );

        let shared_secret = t.encapsulate(dev_public_key).unwrap();
        assert_eq!(expected_secret, shared_secret);

        // Get PIN token
        // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L293
        let expected = ClientPinRequest {
            sub_command: ClientPinSubCommand::GetPinToken,
            key_agreement: Some(t.public_key.clone()),
            pin_uv_protocol: Some(1),
            pin_hash_enc: Some(vec![
                0xaf, 0xe8, 0x32, 0x7c, 0xe4, 0x16, 0xda, 0x8e, 0xe3, 0xd0, 0x57, 0x58, 0x9c, 0x2c,
                0xe1, 0xa9,
            ]),
            ..Default::default()
        };

        assert_eq!(expected, t.get_pin_token_cmd("1234", &shared_secret));

        // Set PIN
        // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L307
        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..4].copy_from_slice("1234".as_bytes());
        let expected = ClientPinRequest {
            sub_command: ClientPinSubCommand::SetPin,
            key_agreement: Some(t.public_key.clone()),
            pin_uv_protocol: Some(1),
            pin_uv_auth_param: Some(vec![
                0x7b, 0x40, 0xc0, 0x84, 0xcc, 0xc5, 0x79, 0x41, 0x94, 0x18, 0x9a, 0xb5, 0x78, 0x36,
                0x47, 0x5f,
            ]),
            new_pin_enc: Some(vec![
                0x02, 0x22, 0xfc, 0x42, 0xc6, 0xdd, 0x76, 0xa2, 0x74, 0xa7, 0x05, 0x78, 0x58, 0xb9,
                0xb2, 0x9d, 0x98, 0xe8, 0xa7, 0x22, 0xec, 0x2d, 0xc6, 0x66, 0x84, 0x76, 0x16, 0x8c,
                0x53, 0x20, 0x47, 0x3c, 0xec, 0x99, 0x07, 0xb4, 0xcd, 0x76, 0xce, 0x79, 0x43, 0xc9,
                0x6b, 0xa5, 0x68, 0x39, 0x43, 0x21, 0x1d, 0x84, 0x47, 0x1e, 0x64, 0xd9, 0xc5, 0x1e,
                0x54, 0x76, 0x34, 0x88, 0xcd, 0x66, 0x52, 0x6a,
            ]),
            ..Default::default()
        };

        assert_eq!(expected, t.set_pin_cmd(padded_pin, &shared_secret));

        // Change PIN
        // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L325
        let mut new_padded_pin: [u8; 64] = [0; 64];
        new_padded_pin[..4].copy_from_slice("4321".as_bytes());
        let expected = ClientPinRequest {
            sub_command: ClientPinSubCommand::ChangePin,
            key_agreement: Some(t.public_key.clone()),
            pin_uv_protocol: Some(1),
            pin_uv_auth_param: Some(vec![
                0xfb, 0x97, 0xe9, 0x2f, 0x37, 0x24, 0xd7, 0xc8, 0x5e, 0x0, 0x1d, 0x7f, 0x93, 0xe6,
                0x49, 0xa,
            ]),
            new_pin_enc: Some(vec![
                0x42, 0x80, 0xe1, 0x4a, 0xac, 0x4f, 0xcb, 0xf0, 0x2d, 0xd0, 0x79, 0x98, 0x5f, 0x0c,
                0x0f, 0xfc, 0x9e, 0xa7, 0xd5, 0xf9, 0xc1, 0x73, 0xfd, 0x1a, 0x4c, 0x84, 0x38, 0x26,
                0xf7, 0x59, 0x0c, 0xb3, 0xc2, 0xd0, 0x80, 0xc6, 0x92, 0x3e, 0x2f, 0xe6, 0xd7, 0xa5,
                0x2c, 0x31, 0xea, 0x13, 0x09, 0xd3, 0xfc, 0xca, 0x3d, 0xed, 0xae, 0x8a, 0x2e, 0xf1,
                0x4b, 0x63, 0x30, 0xca, 0xfc, 0x79, 0x33, 0x9e,
            ]),
            pin_hash_enc: Some(vec![
                0xaf, 0xe8, 0x32, 0x7c, 0xe4, 0x16, 0xda, 0x8e, 0xe3, 0xd0, 0x57, 0x58, 0x9c, 0x2c,
                0xe1, 0xa9,
            ]),
            ..Default::default()
        };

        assert_eq!(
            expected,
            t.change_pin_cmd("1234", new_padded_pin, &shared_secret)
        );
    }

    #[test]
    fn select() {
        let t = PinUvPlatformInterface::select_protocol(None);
        assert!(t.is_none());

        // Single supported protocol
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![1])).unwrap();
        assert_eq!(Some(1), t.get_pin_uv_protocol());

        let t = PinUvPlatformInterface::select_protocol(Some(&vec![2])).unwrap();
        assert_eq!(Some(2), t.get_pin_uv_protocol());

        // Always choose the first supported protocol (even if it is lower)
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![2, 1])).unwrap();
        assert_eq!(Some(2), t.get_pin_uv_protocol());

        let t = PinUvPlatformInterface::select_protocol(Some(&vec![1, 2])).unwrap();
        assert_eq!(Some(1), t.get_pin_uv_protocol());

        // Newer, unknown protocol should fall back to first one we support
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![9999, 2, 1])).unwrap();
        assert_eq!(Some(2), t.get_pin_uv_protocol());

        // Unknown protocol
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![9999]));
        assert!(t.is_none());
    }
}
