use url::Url;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::{
    AuthenticationResult, CreationChallengeResponse, Credential, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs_core::proto::{AuthenticationState, RegistrationState};

use webauthn_rs::{prelude::Uuid, Webauthn, WebauthnBuilder};
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_demo_shared::*;

use webauthn_rs::prelude::{
    PassKey, PassKeyAuthentication, PassKeyRegistration, PasswordlessKey,
    PasswordlessKeyAuthentication, PasswordlessKeyRegistration, SecurityKey,
    SecurityKeyAuthentication, SecurityKeyRegistration,
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RegistrationTypedState {
    PassKey(PassKeyRegistration),
    SecurityKey(SecurityKeyRegistration),
    Passwordless(PasswordlessKeyRegistration),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthenticationTypedState {
    PassKey(PassKeyAuthentication),
    SecurityKey(SecurityKeyAuthentication),
    Passwordless(PasswordlessKeyAuthentication),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TypedCredential {
    PassKey(PassKey),
    SecurityKey(SecurityKey),
    Passwordless(PasswordlessKey),
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
        let wan =
            WebauthnCore::new_unsafe_experts_only(&rp_name, &rp_id, &rp_origin, None, None, None);

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
            RegisterWithType::PassKey => self
                .swan
                .start_passkey_registration(user_unique_id, &username, None)
                .map(|(ccr, rs)| (ccr, RegistrationTypedState::PassKey(rs)))?,
            RegisterWithType::Passwordless(strict) => {
                let att_ca: Option<_> = strict.into();
                self.swan
                    .start_passwordlesskey_registration(
                        user_unique_id,
                        &username,
                        None,
                        false,
                        att_ca.unwrap(),
                        // Some(AuthenticatorAttachment::None),
                        None,
                    )
                    .map(|(ccr, rs)| (ccr, RegistrationTypedState::Passwordless(rs)))?
            }
            RegisterWithType::SecurityKey(strict) => self
                .swan
                .start_securitykey_registration(user_unique_id, &username, None, strict.into())
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
            RegistrationTypedState::PassKey(rs) => self
                .swan
                .finish_passkey_registration(reg, &rs)
                .map(|sk| TypedCredential::PassKey(sk)),
            RegistrationTypedState::Passwordless(rs) => self
                .swan
                .finish_passwordlesskey_registration(reg, &rs)
                .map(|sk| TypedCredential::Passwordless(sk)),
            RegistrationTypedState::SecurityKey(rs) => self
                .swan
                .finish_securitykey_registration(reg, &rs)
                .map(|sk| TypedCredential::SecurityKey(sk)),
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
            AuthenticateWithType::PassKey => {
                let creds: Vec<_> = creds
                    .iter()
                    .filter_map(|c| match c {
                        TypedCredential::PassKey(sk) => Some(sk.clone()),
                        _ => None,
                    })
                    .collect();
                self.swan
                    .start_passkey_authentication(&creds)
                    .map(|(acr, ast)| (acr, AuthenticationTypedState::PassKey(ast)))?
            }
            AuthenticateWithType::Passwordless => {
                let creds: Vec<_> = creds
                    .iter()
                    .filter_map(|c| match c {
                        TypedCredential::Passwordless(sk) => Some(sk.clone()),
                        _ => None,
                    })
                    .collect();
                self.swan
                    .start_passwordlesskey_authentication(&creds)
                    .map(|(acr, ast)| (acr, AuthenticationTypedState::Passwordless(ast)))?
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
            AuthenticationTypedState::PassKey(ast) => {
                self.swan.finish_passkey_authentication(lgn, &ast)
            }
            AuthenticationTypedState::Passwordless(ast) => {
                self.swan.finish_passwordlesskey_authentication(lgn, &ast)
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

        /*
        let exts = RequestRegistrationExtensions::builder()
            .cred_blob(vec![0xde, 0xad, 0xbe, 0xef])
            .build();
        */

        let user_unique_id = Uuid::new_v4();

        let (ccr, rs) = self.wan.generate_challenge_register_options(
            user_unique_id.as_bytes(),
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

        /*
        let exts = RequestAuthenticationExtensions::builder()
            .get_cred_blob(true)
            .build();
        */

        // If use_cred_id is set, only allow this cred to be used. This also allows
        // some extra "stuff".

        let (acr, st) = match use_cred_id {
            Some(use_cred_id) => {
                let cred = creds
                    .into_iter()
                    .filter(|c| c.cred_id == use_cred_id)
                    .next()
                    .ok_or(WebauthnError::CredentialNotFound)?;

                self.wan
                    .generate_challenge_authenticate_credential(cred, uv, extensions)
            }
            None => self
                .wan
                .generate_challenge_authenticate_options(creds, extensions),
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
                    .filter(|cred| &auth_result.cred_id == &cred.cred_id)
                    .for_each(|cred| cred.counter = auth_result.counter);
                (creds, auth_result)
            });
        debug!("complete Authenticate -> {:?}", r);
        r
    }
}
