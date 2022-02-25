use url::Url;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::{
    Authentication, AuthenticationResult, CreationChallengeResponse, Credential, CredentialID,
    PublicKeyCredential, RegisterPublicKeyCredential, Registration, RequestChallengeResponse,
};
use webauthn_rs_core::proto::{
    AuthenticationState, RegistrationState, RequestAuthenticationExtensions,
    RequestRegistrationExtensions,
};

use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_demo_shared::*;

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
        let wan = unsafe { WebauthnCore::new(&rp_name, &rp_id, &rp_origin, None, None) };

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

    pub async fn compat_start_register(
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

        /*
        let exts = RequestRegistrationExtensions::builder()
            .cred_blob(vec![0xde, 0xad, 0xbe, 0xef])
            .build();
        */

        let (ccr, rs) = self.wan.generate_challenge_register_options(
            username.to_string(),
            username.to_string(),
            attestation.unwrap_or(AttestationConveyancePreference::None),
            uv,
            None,
            None,
            algorithm.unwrap_or_else(|| vec![COSEAlgorithm::ES256, COSEAlgorithm::RS256]),
            false,
            attachment,
        )?;

        debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok((ccr, rs))
    }

    pub async fn compat_start_login(
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

                self.wan
                    .generate_challenge_authenticate_credential(cred, uv, None)
            }
            None => self
                .wan
                .generate_challenge_authenticate_options(creds, None),
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

        let username = username.as_bytes().to_vec();

        let r = self.wan.register_credential(reg, &rs);
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

        let username = username.as_bytes().to_vec();

        let r = self
            .wan
            .authenticate_credential(lgn, &st)
            .map(|(auth_result)| {
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
