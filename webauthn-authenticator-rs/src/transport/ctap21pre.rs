use crate::{
    cbor::*,
    error::WebauthnCError,
    transport::Token,
    util::{compute_sha256, creation_to_clientdata, get_to_clientdata},
    AuthenticatorBackend,
};

use url::Url;

pub struct Ctap21PreAuthenticator<T: Token> {
    info: GetInfoResponse,
    token: T,
}

impl<T: Token> Ctap21PreAuthenticator<T> {
    pub fn new(info: GetInfoResponse, token: T) -> Self {
        Self { info, token }
    }
}

impl<T: Token> AuthenticatorBackend for Ctap21PreAuthenticator<T> {
    fn perform_register(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, crate::prelude::WebauthnCError>
    {
        let client_data = creation_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> =
            serde_json::to_string(&client_data).map_err(|_| WebauthnCError::Json)?.into();
        let client_data_hash = compute_sha256(&client_data).to_vec();

        // Get pin retries
        trace!("supported pin protocols = {:?}", self.info.pin_protocols);
        if let Some(protocols) = &self.info.pin_protocols {
            for protocol in protocols {
                let p = ClientPinRequest {
                    pin_uv_protocol: Some(*protocol),
                    sub_command: ClientPinSubCommand::GetPinRetries,
                    ..Default::default()
                };

                let ret = self.token.transmit(p)?;
                trace!(?ret);
            }
        }
        
        // TODO: select protocol wisely
        let p = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            ..Default::default()
        };
        let ret = self.token.transmit(p)?;
        trace!("keyagreement = {:?}", ret);


        // TODO: implement PINs
        // let mc = MakeCredentialRequest {
        //     client_data_hash,
        //     rp: options.rp,
        //     user: options.user,
        //     pub_key_cred_params: options.pub_key_cred_params,

        //     options: None,
        //     pin_uv_auth_param: None,
        //     pin_uv_auth_proto: None,
        //     enterprise_attest: None,
        // };

        // let ret = self.token.transmit(mc);
        // trace!(?ret);

        todo!();
    }
    fn perform_auth(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, crate::prelude::WebauthnCError> {
        let clientdata = get_to_clientdata(origin, options.challenge.clone());

        todo!();
    }
}
