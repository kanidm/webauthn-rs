use webauthn_rs::error::WebauthnError;
use webauthn_rs::proto::{
    Authentication, AuthenticatorData, CreationChallengeResponse, Credential, CredentialID,
    PublicKeyCredential, RegisterPublicKeyCredential, Registration, RequestChallengeResponse,
    UserId,
};
use webauthn_rs::{
    ephemeral::WebauthnEphemeralConfig,
    proto::{RequestAuthenticationExtensions, RequestRegistrationExtensions},
};
use webauthn_rs::{AuthenticationState, RegistrationState, Webauthn};

type WebauthnResult<T> = core::result::Result<T, WebauthnError>;

pub struct WebauthnActor {
    wan: Webauthn<WebauthnEphemeralConfig>,
    // reg_chals: Mutex<LruCache<UserId, RegistrationState>>,
    // auth_chals: Mutex<LruCache<UserId, AuthenticationState>>,
    // creds: Mutex<BTreeMap<UserId, BTreeMap<CredentialID, Credential>>>,
}

impl WebauthnActor {
    pub fn new(config: WebauthnEphemeralConfig) -> Self {
        WebauthnActor {
            wan: Webauthn::new(config),
        }
    }

    pub async fn challenge_register(
        &self,
        username: String,
    ) -> WebauthnResult<(CreationChallengeResponse, RegistrationState)> {
        debug!("handle ChallengeRegister -> {:?}", username);

        let exts = RequestRegistrationExtensions::builder()
            .cred_blob(vec![0xde, 0xad, 0xbe, 0xef])
            .build();

        let (ccr, rs) = self.wan.generate_challenge_register_options(
            username.as_bytes().to_vec(),
            username.to_string(),
            username.to_string(),
            None,
            Some(webauthn_rs::proto::UserVerificationPolicy::Discouraged),
            Some(exts),
        )?;

        debug!("complete ChallengeRegister -> {:?}", ccr);
        Ok((ccr, rs))
    }

    pub async fn challenge_authenticate(
        &self,
        username: &String,
        creds: Vec<Credential>,
    ) -> WebauthnResult<(RequestChallengeResponse, AuthenticationState)> {
        debug!("handle ChallengeAuthenticate -> {:?}", username);

        let exts = RequestAuthenticationExtensions::builder()
            .get_cred_blob(true)
            .build();

        let (acr, st) = self
            .wan
            .generate_challenge_authenticate_options(creds, Some(exts))?;

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

        let r = self.wan.register_credential(reg, &rs, |_| Ok(false));
        debug!("complete Register -> {:?}", r);
        r
    }

    pub async fn authenticate(
        &self,
        username: &String,
        lgn: &PublicKeyCredential,
        st: AuthenticationState,
        mut creds: Vec<Credential>,
    ) -> WebauthnResult<(Vec<Credential>, AuthenticatorData<Authentication>)> {
        debug!(
            "handle Authenticate -> (username: {:?}, lgn: {:?})",
            username, lgn
        );

        let username = username.as_bytes().to_vec();

        let r = self
            .wan
            .authenticate_credential(lgn, &st)
            .map(|(cred_id, auth_data)| {
                creds
                    .iter_mut()
                    .filter(|cred| &cred.cred_id == cred_id)
                    .for_each(|cred| cred.counter = auth_data.counter);
                (creds, auth_data)
            });
        debug!("complete Authenticate -> {:?}", r);
        r
    }
}
