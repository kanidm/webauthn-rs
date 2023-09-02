use url::Url;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::{
    AuthenticationResult, Base64UrlSafeData, CreationChallengeResponse, Credential,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs_core::proto::{AuthenticationState, RegistrationState};

use webauthn_rs::{prelude::Uuid, Webauthn, WebauthnBuilder};
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_demo_shared::*;

use webauthn_rs::prelude::{
    AttestedPasskey, AttestedPasskeyAuthentication, AttestedPasskeyRegistration, Passkey,
    PasskeyAuthentication, PasskeyRegistration, SecurityKey, SecurityKeyAuthentication,
    SecurityKeyRegistration,
};

use webauthn_rs::prelude::{
    AttestationCaList, AttestedResidentKey, AttestedResidentKeyRegistration,
    DiscoverableAuthentication,
};

use webauthn_rs_device_catalog::Data;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RegistrationTypedState {
    Passkey(PasskeyRegistration),
    SecurityKey(SecurityKeyRegistration),
    AttestedPasskey(AttestedPasskeyRegistration),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthenticationTypedState {
    Passkey(PasskeyAuthentication),
    SecurityKey(SecurityKeyAuthentication),
    AttestedPasskey(AttestedPasskeyAuthentication),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TypedCredential {
    Passkey(Passkey),
    SecurityKey(SecurityKey),
    AttestedPasskey(AttestedPasskey),
}

pub struct WebauthnActor {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: Url,
    /// Used for testing with compat.
    wan: WebauthnCore,
    /// For demoing the simple cases.
    swan: Webauthn,
}

impl WebauthnActor {
    pub fn new(rp_name: &str, rp_origin: &str, rp_id: &str) -> Self {
        let rp_name = rp_name.to_string();
        let rp_id = rp_id.to_string();
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse origin");
        let wan = WebauthnCore::new_unsafe_experts_only(
            &rp_name,
            &rp_id,
            vec![rp_origin.to_owned()],
            None,
            None,
            None,
        );

        let swan = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Invalid rp id or origin")
            .rp_name(&rp_name)
            .build()
            .expect("Failed to build swan");

        WebauthnActor {
            rp_name,
            rp_id,
            rp_origin,
            wan,
            swan,
        }
    }

    pub async fn demo_start_register(
        &self,
        user_unique_id: Uuid,
        username: String,
        reg_settings: RegisterWithType,
    ) -> WebauthnResult<(CreationChallengeResponse, RegistrationTypedState)> {
        debug!("handle ChallengeRegister -> {:?}", username);

        let (ccr, rs) = match reg_settings {
            RegisterWithType::Passkey => self
                .swan
                .start_passkey_registration(
                    user_unique_id,
                    &username,
                    &username,
                    Some(vec![Base64UrlSafeData(vec![0x00, 0x01, 0x02, 0x03])]),
                )
                .map(|(ccr, rs)| (ccr, RegistrationTypedState::Passkey(rs)))?,
            RegisterWithType::AttestedPasskey(strict) => {
                let att_ca: Option<_> = strict.into();
                self.swan
                    .start_attested_passkey_registration(
                        user_unique_id,
                        &username,
                        &username,
                        None,
                        att_ca.unwrap(),
                        None,
                    )
                    .map(|(ccr, rs)| (ccr, RegistrationTypedState::AttestedPasskey(rs)))?
            }
            RegisterWithType::SecurityKey(strict) => self
                .swan
                .start_securitykey_registration(
                    user_unique_id,
                    &username,
                    &username,
                    None,
                    strict.into(),
                    None,
                )
                .map(|(ccr, rs)| (ccr, RegistrationTypedState::SecurityKey(rs)))?,
        };

        debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok((ccr, rs))
    }

    pub async fn demo_finish_register(
        &self,
        username: &String,
        reg: &RegisterPublicKeyCredential,
        rs: RegistrationTypedState,
    ) -> WebauthnResult<TypedCredential> {
        debug!(
            "handle Register -> (username: {:?}, reg: {:?})",
            username, reg
        );

        let r = match rs {
            RegistrationTypedState::Passkey(rs) => self
                .swan
                .finish_passkey_registration(reg, &rs)
                .map(TypedCredential::Passkey),
            RegistrationTypedState::AttestedPasskey(rs) => self
                .swan
                .finish_attested_passkey_registration(reg, &rs)
                .map(TypedCredential::AttestedPasskey),
            RegistrationTypedState::SecurityKey(rs) => self
                .swan
                .finish_securitykey_registration(reg, &rs)
                .map(TypedCredential::SecurityKey),
        };

        debug!("complete Register -> {:?}", r);
        r
    }

    pub async fn demo_start_login(
        &self,
        username: &String,
        creds: Vec<TypedCredential>,
        auth_settings: AuthenticateWithType,
    ) -> WebauthnResult<(RequestChallengeResponse, AuthenticationTypedState)> {
        debug!("handle ChallengeAuthenticate -> {:?}", username);

        let (acr, st) = match auth_settings {
            AuthenticateWithType::Passkey => {
                let creds: Vec<_> = creds
                    .iter()
                    .filter_map(|c| match c {
                        TypedCredential::Passkey(sk) => Some(sk.clone()),
                        _ => None,
                    })
                    .collect();
                self.swan
                    .start_passkey_authentication(&creds)
                    .map(|(acr, ast)| (acr, AuthenticationTypedState::Passkey(ast)))?
            }
            AuthenticateWithType::AttestedPasskey => {
                let creds: Vec<_> = creds
                    .iter()
                    .filter_map(|c| match c {
                        TypedCredential::AttestedPasskey(sk) => Some(sk.clone()),
                        _ => None,
                    })
                    .collect();
                self.swan
                    .start_attested_passkey_authentication(&creds)
                    .map(|(acr, ast)| (acr, AuthenticationTypedState::AttestedPasskey(ast)))?
            }
            AuthenticateWithType::SecurityKey => {
                let creds: Vec<_> = creds
                    .iter()
                    .filter_map(|c| match c {
                        TypedCredential::SecurityKey(sk) => Some(sk.clone()),
                        _ => None,
                    })
                    .collect();
                self.swan
                    .start_securitykey_authentication(&creds)
                    .map(|(acr, ast)| (acr, AuthenticationTypedState::SecurityKey(ast)))?
            }
        };

        debug!("complete ChallengeAuthenticate -> {:?}", acr);
        Ok((acr, st))
    }

    pub async fn demo_finish_login(
        &self,
        username: &str,
        lgn: &PublicKeyCredential,
        st: AuthenticationTypedState,
    ) -> WebauthnResult<AuthenticationResult> {
        debug!(
            "handle Authenticate -> (username: {:?}, lgn: {:?})",
            username, lgn
        );

        let r = match st {
            AuthenticationTypedState::Passkey(ast) => {
                self.swan.finish_passkey_authentication(lgn, &ast)
            }
            AuthenticationTypedState::AttestedPasskey(ast) => {
                self.swan.finish_attested_passkey_authentication(lgn, &ast)
            }
            AuthenticationTypedState::SecurityKey(ast) => {
                self.swan.finish_securitykey_authentication(lgn, &ast)
            }
        };

        debug!("complete Authenticate -> {:?}", r);
        r
    }

    pub async fn compat_start_register(
        &self,
        reg_settings: RegisterWithSettings,
    ) -> WebauthnResult<(CreationChallengeResponse, RegistrationState)> {
        let RegisterWithSettings {
            username,
            uv,
            attachment,
            algorithm,
            attestation,
            extensions,
        } = reg_settings;

        debug!("handle ChallengeRegister -> {:?}", username);

        let user_unique_id = Uuid::new_v4();

        let (ccr, rs) = self.wan.generate_challenge_register_options(
            user_unique_id.as_bytes(),
            &username,
            &username,
            attestation.unwrap_or(AttestationConveyancePreference::None),
            uv,
            None,
            extensions,
            algorithm.unwrap_or_else(|| vec![COSEAlgorithm::ES256, COSEAlgorithm::RS256]),
            false,
            attachment,
            false,
        )?;

        debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok((ccr, rs))
    }

    pub async fn compat_start_login(
        &self,
        creds: Vec<Credential>,
        auth_settings: AuthenticateWithSettings,
    ) -> WebauthnResult<(RequestChallengeResponse, AuthenticationState)> {
        let AuthenticateWithSettings {
            username,
            use_cred_id,
            uv,
            extensions,
        } = auth_settings;

        debug!("handle ChallengeAuthenticate -> {:?}", username);

        // If use_cred_id is set, only allow this cred to be used. This also allows
        // some extra "stuff".

        let (acr, st) = match use_cred_id {
            Some(use_cred_id) => {
                let cred = creds
                    .into_iter()
                    .find(|c| c.cred_id == use_cred_id)
                    .ok_or(WebauthnError::CredentialNotFound)?;

                self.wan
                    .generate_challenge_authenticate_credential(cred, uv, extensions)
            }
            None => self.wan.generate_challenge_authenticate(creds, extensions),
        }?;

        debug!("complete ChallengeAuthenticate -> {:?}", acr);
        Ok((acr, st))
    }

    pub async fn compat_finish_register(
        &self,
        username: &String,
        reg: &RegisterPublicKeyCredential,
        rs: RegistrationState,
    ) -> WebauthnResult<Credential> {
        debug!(
            "handle Register -> (username: {:?}, reg: {:?})",
            username, reg
        );

        let r = self.wan.register_credential(reg, &rs, None);
        debug!("complete Register -> {:?}", r);
        r
    }

    pub async fn compat_finish_login(
        &self,
        username: &String,
        lgn: &PublicKeyCredential,
        st: AuthenticationState,
        mut creds: Vec<Credential>,
    ) -> WebauthnResult<(Vec<Credential>, AuthenticationResult)> {
        debug!(
            "handle Authenticate -> (username: {:?}, lgn: {:?})",
            username, lgn
        );

        let r = self
            .wan
            .authenticate_credential(lgn, &st)
            .map(|auth_result| {
                creds
                    .iter_mut()
                    .filter(|cred| auth_result.cred_id() == &cred.cred_id)
                    .for_each(|cred| cred.counter = auth_result.counter());
                (creds, auth_result)
            });
        debug!("complete Authenticate -> {:?}", r);
        r
    }

    pub async fn condui_start_register(
        &self,
        user_unique_id: Uuid,
        username: String,
    ) -> WebauthnResult<(CreationChallengeResponse, AttestedResidentKeyRegistration)> {
        // ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        debug!("handle ChallengeRegister -> {:?}", username);

        let att_ca_list: AttestationCaList = (&Data::strict())
            .try_into()
            .map_err(WebauthnError::OpenSSLError)?;

        let (ccr, rs) = self.swan.start_attested_resident_key_registration(
            user_unique_id,
            &username,
            &username,
            None,
            att_ca_list,
            // Some(AuthenticatorAttachment::None),
            None,
        )?;
        /*
        let (ccr, rs) = self.swan
            .start_passkey_registration(
                user_unique_id,
                &username,
                &username,
                None,
            )?;
        */

        debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok((ccr, rs))
    }

    pub async fn condui_finish_register(
        &self,
        reg: &RegisterPublicKeyCredential,
        rs: AttestedResidentKeyRegistration,
        // rs: PasskeyRegistration,
    ) -> WebauthnResult<AttestedResidentKey> {
        // ) -> WebauthnResult<Passkey> {
        debug!("handle Register -> (reg: {:?})", reg);

        /*
        let r = self.swan
            .finish_passkey_registration(reg, &rs);
        */
        let r = self
            .swan
            .finish_attested_resident_key_registration(reg, &rs);

        debug!("complete Register -> {:?}", r);
        r
    }

    pub async fn condui_start_login(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        // ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        debug!("handle ChallengeAuthenticate");

        let (acr, st) = self.swan.start_discoverable_authentication()?;
        /*
        let (acr, st) = self.swan
            .start_discoverable_passkey_authentication()?;
        */

        debug!("complete ChallengeAuthenticate -> {:?}", acr);
        Ok((acr, st))
    }

    pub async fn condui_finish_login(
        &self,
        cred_map: &BTreeMap<Uuid, Vec<AttestedResidentKey>>,
        lgn: &PublicKeyCredential,
        st: DiscoverableAuthentication,
        // st: PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        debug!("handle Authenticate -> (lgn: {:?})", lgn);

        // Find the credentials
        let (unique_id, _) = self.swan.identify_discoverable_authentication(lgn)?;

        let creds = cred_map
            .get(&unique_id)
            .ok_or(WebauthnError::InvalidUserUniqueId)?;

        let creds: Vec<_> = creds.iter().map(|x| x.into()).collect();

        let r = self
            .swan
            .finish_discoverable_authentication(lgn, st, &creds);

        debug!("complete Authenticate -> {:?}", r);
        r
    }
}
