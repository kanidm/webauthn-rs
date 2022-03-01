#[macro_use]
extern crate tracing;

mod interface;

use url::Url;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::*;
use webauthn_rs_core::WebauthnCore;

use crate::interface::*;

pub mod prelude {
    pub use crate::interface::*;
    pub use crate::{Webauthn, WebauthnBuilder};
    pub use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
}

#[derive(Debug)]
pub struct WebauthnBuilder<'a> {
    rp_name: Option<&'a str>,
    rp_id: &'a str,
    rp_origin: &'a Url,
    allow_subdomains: bool,
    algorithms: Vec<COSEAlgorithm>,
}

#[derive(Debug)]
pub struct Webauthn {
    core: WebauthnCore,
}

impl<'a> WebauthnBuilder<'a> {
    pub fn new(rp_id: &'a str, rp_origin: &'a Url) -> WebauthnResult<Self> {
        // Check the rp_name and rp_id.
        let valid = rp_origin
            .domain()
            .map(|effective_domain| {
                // We need to prepend the '.' here to ensure that myexample.com != example.com,
                // rather than just ends with.
                effective_domain.ends_with(&format!(".{}", rp_id)) || effective_domain == rp_id
            })
            .unwrap_or(false);

        if valid {
            Ok(WebauthnBuilder {
                rp_name: None,
                rp_id,
                rp_origin,
                allow_subdomains: false,
                algorithms: COSEAlgorithm::secure_algs(),
            })
        } else {
            error!("rp_id is not an effective_domain of rp_origin");
            Err(WebauthnError::Configuration)
        }
    }

    pub fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    pub fn rp_name(mut self, rp_name: &'a str) -> Self {
        self.rp_name = Some(rp_name);
        self
    }

    pub fn build(self) -> WebauthnResult<Webauthn> {
        Ok(Webauthn {
            core: unsafe {
                WebauthnCore::new(
                    self.rp_name.unwrap_or(self.rp_id),
                    self.rp_id,
                    self.rp_origin,
                    None,
                    Some(self.allow_subdomains),
                )
            },
        })
    }
}

impl Webauthn {
    pub fn start_securitykey_registration(
        &self,
        user_name: &str,
        user_display_name: Option<&str>,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_ca_list: Option<AttestationCaList>,
        // extensions
    ) -> WebauthnResult<(CreationChallengeResponse, SecurityKeyRegistration)> {
        let attestation = if attestation_ca_list.is_some() {
            AttestationConveyancePreference::Direct
        } else {
            AttestationConveyancePreference::None
        };
        let extensions = None;
        let credential_algorithms = COSEAlgorithm::secure_algs();
        let require_resident_key = false;
        let authenticator_attachment = None;
        let policy = Some(UserVerificationPolicy::Preferred);

        self.core
            .generate_challenge_register_options(
                user_name.to_string(),
                user_display_name.unwrap_or(user_name).to_string(),
                attestation,
                policy,
                exclude_credentials,
                extensions,
                credential_algorithms,
                require_resident_key,
                authenticator_attachment,
            )
            .map(|(ccr, rs)| {
                (
                    ccr,
                    SecurityKeyRegistration {
                        rs,
                        ca_list: attestation_ca_list,
                    },
                )
            })
    }

    pub fn finish_securitykey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &SecurityKeyRegistration,
    ) -> WebauthnResult<SecurityKey> {
        // TODO: Check the AttestationCa List!!
        self.core
            .register_credential(reg, &state.rs, state.ca_list.as_ref())
            .map(|cred| SecurityKey { cred })
    }

    pub fn start_securitykey_authentication(
        &self,
        creds: &[&SecurityKey],
    ) -> WebauthnResult<(RequestChallengeResponse, SecurityKeyAuthentication)> {
        let extensions = None;
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, SecurityKeyAuthentication { ast }))
    }

    pub fn finish_securitykey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &SecurityKeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.core.authenticate_credential(reg, &state.ast)
    }

    pub fn start_passwordlesskey_registration(
        &self,
        user_name: &str,
        user_display_name: Option<&str>,
        exclude_credentials: Option<Vec<CredentialID>>,
        attestation_ca_list: Option<AttestationCaList>,
        authenticator_attachment: Option<AuthenticatorAttachment>,
        // extensions
    ) -> WebauthnResult<(CreationChallengeResponse, PasswordlessKeyRegistration)> {
        let attestation = AttestationConveyancePreference::Direct;
        let extensions = None;
        let credential_algorithms = COSEAlgorithm::secure_algs();
        let require_resident_key = false;
        let policy = Some(UserVerificationPolicy::Required);

        self.core
            .generate_challenge_register_options(
                user_name.to_string(),
                user_display_name.unwrap_or(user_name).to_string(),
                attestation,
                policy,
                exclude_credentials,
                extensions,
                credential_algorithms,
                require_resident_key,
                authenticator_attachment,
            )
            .map(|(ccr, rs)| {
                (
                    ccr,
                    PasswordlessKeyRegistration {
                        rs,
                        ca_list: attestation_ca_list,
                    },
                )
            })
    }

    pub fn finish_passwordlesskey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasswordlessKeyRegistration,
    ) -> WebauthnResult<PasswordlessKey> {
        // TODO: Check the AttestationCa List!!
        self.core
            .register_credential(reg, &state.rs, state.ca_list.as_ref())
            .map(|cred| PasswordlessKey { cred })
    }

    pub fn start_passwordlesskey_authentication(
        &self,
        creds: &[&PasswordlessKey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasswordlessKeyAuthentication)> {
        let extensions = None;
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();

        self.core
            .generate_challenge_authenticate_options(creds, extensions)
            .map(|(rcr, ast)| (rcr, PasswordlessKeyAuthentication { ast }))
    }

    pub fn finish_passwordlesskey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &PasswordlessKeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.core.authenticate_credential(reg, &state.ast)
    }

    /*
    // Register a password-less credential, needs attestation
    /// * Must be verified
    /// * Must be attested
    /// * May request a pin length
    /// * Must return what TYPE of UV (?)
    /// * Any attachment type
    /// * Optional - RK

    // Register a trusted device credential
    /// * Must be verified
    /// * Must be attested
    /// * Must be a DEVICE (platform) credential
    /// * May request a pin length
    /// * Must return what TYPE of UV (?)
    /// * Must be platform attached
    /// * Need to use credProps
    /// * Optional - RK

    */

    // Authenticate ^
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
