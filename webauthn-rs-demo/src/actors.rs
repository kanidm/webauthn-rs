use crate::config::{WebauthnAuthConfig, WebauthnRegistrationConfig};
use url::Url;
use webauthn_rs::error::{WebauthnError, WebauthnResult};
use webauthn_rs::proto::{
    Authentication, AuthenticatorData, CreationChallengeResponse, Credential, CredentialID,
    PublicKeyCredential, RegisterPublicKeyCredential, Registration, RequestChallengeResponse,
    UserId,
};
use webauthn_rs::proto::{RequestAuthenticationExtensions, RequestRegistrationExtensions};
use webauthn_rs::{AuthenticationState, RegistrationState, Webauthn};
use webauthn_rs_demo_shared::*;

pub struct WebauthnActor {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: Url,
    base_wan: Webauthn<WebauthnAuthConfig>,
}

impl WebauthnActor {
    pub fn new(rp_name: &str, rp_origin: &str, rp_id: &str) -> Self {
        let rp_name = rp_name.to_string();
        let rp_id = rp_id.to_string();
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse origin");
        let base_wan = Webauthn::new(WebauthnAuthConfig {
            rp_name: rp_name.clone(),
            rp_id: rp_id.clone(),
            rp_origin: rp_origin.clone(),
        });
        WebauthnActor {
            rp_name,
            rp_id,
            rp_origin,
            base_wan,
        }
    }

    pub async fn challenge_register(
        &self,
        username: String,
        reg_settings: RegisterWithSettings,
    ) -> WebauthnResult<(CreationChallengeResponse, RegistrationState)> {
        debug!("handle ChallengeRegister -> {:?}", username);

        let RegisterWithSettings {
            uv,
            attachment,
            algorithm,
            attestation,
            extensions,
        } = reg_settings;

        let wan = Webauthn::new(WebauthnRegistrationConfig {
            rp_name: self.rp_name.clone(),
            rp_id: self.rp_id.clone(),
            rp_origin: self.rp_origin.clone(),
            attachment,
            algorithms: algorithm
                .unwrap_or_else(|| vec![COSEAlgorithm::ES256, COSEAlgorithm::RS256]),
            attestation: attestation.unwrap_or(AttestationConveyancePreference::None),
        });

        /*
        let exts = RequestRegistrationExtensions::builder()
            .cred_blob(vec![0xde, 0xad, 0xbe, 0xef])
            .build();
        */

        let (ccr, rs) = wan.generate_challenge_register_options(
            username.as_bytes().to_vec(),
            username.to_string(),
            username.to_string(),
            None,
            uv,
            None,
        )?;

        debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok((ccr, rs))
    }

    pub async fn challenge_authenticate(
        &self,
        username: &String,
        creds: Vec<Credential>,
        auth_settings: AuthenticateWithSettings,
    ) -> WebauthnResult<(RequestChallengeResponse, AuthenticationState)> {
        debug!("handle ChallengeAuthenticate -> {:?}", username);

        let AuthenticateWithSettings {
            use_cred_id,

            uv,
            extensions,
        } = auth_settings;

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

                self.base_wan
                    .generate_challenge_authenticate_credential(cred, uv, None)
            }
            None => self
                .base_wan
                .generate_challenge_authenticate_options(creds, None),
        }?;

        debug!("complete ChallengeAuthenticate -> {:?}", acr);
        Ok((acr, st))
    }

    pub async fn register(
        &self,
        username: &String,
        reg: &RegisterPublicKeyCredential,
        rs: RegistrationState,
    ) -> WebauthnResult<(Credential, AuthenticatorData<Registration>)> {
        debug!(
            "handle Register -> (username: {:?}, reg: {:?})",
            username, reg
        );

        let username = username.as_bytes().to_vec();

        let r = self.base_wan.register_credential(reg, &rs, |_| Ok(false));
        debug!("complete Register -> {:?}", r);
        r
    }

    pub async fn authenticate(
        &self,
        username: &String,
        lgn: &PublicKeyCredential,
        st: AuthenticationState,
        mut creds: Vec<Credential>,
    ) -> WebauthnResult<(
        Vec<Credential>,
        CredentialID,
        AuthenticatorData<Authentication>,
    )> {
        debug!(
            "handle Authenticate -> (username: {:?}, lgn: {:?})",
            username, lgn
        );

        let username = username.as_bytes().to_vec();

        let r = self
            .base_wan
            .authenticate_credential(lgn, &st)
            .map(|(cred_id, auth_data)| {
                creds
                    .iter_mut()
                    .filter(|cred| &cred.cred_id == cred_id)
                    .for_each(|cred| cred.counter = auth_data.counter);
                (creds, cred_id.clone(), auth_data)
            });
        debug!("complete Authenticate -> {:?}", r);
        r
    }
}
