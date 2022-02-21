use url::Url;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AuthenticatorAttachment, COSEAlgorithm,
};
use webauthn_rs_core::WebauthnConfig;

#[derive(Debug)]
pub(crate) struct WebauthnRegistrationConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: Url,
    pub attachment: Option<AuthenticatorAttachment>,
    pub algorithms: Vec<COSEAlgorithm>,
    pub attestation: AttestationConveyancePreference,
}

impl WebauthnConfig for WebauthnRegistrationConfig {
    fn get_relying_party_name(&self) -> &str {
        &self.rp_name
    }

    fn get_relying_party_id(&self) -> &str {
        &self.rp_id
    }

    fn get_origin(&self) -> &Url {
        &self.rp_origin
    }

    fn get_authenticator_attachment(&self) -> Option<AuthenticatorAttachment> {
        self.attachment.clone()
    }

    fn get_attestation_preference(&self) -> AttestationConveyancePreference {
        self.attestation.clone()
    }

    fn get_credential_algorithms(&self) -> Vec<COSEAlgorithm> {
        self.algorithms.clone()
    }
}

#[derive(Debug)]
pub(crate) struct WebauthnAuthConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: Url,
}

impl WebauthnConfig for WebauthnAuthConfig {
    fn get_relying_party_name(&self) -> &str {
        &self.rp_name
    }

    fn get_relying_party_id(&self) -> &str {
        &self.rp_id
    }

    fn get_origin(&self) -> &Url {
        &self.rp_origin
    }

    fn get_authenticator_attachment(&self) -> Option<AuthenticatorAttachment> {
        unreachable!();
    }

    fn get_attestation_preference(&self) -> AttestationConveyancePreference {
        unreachable!();
    }

    fn get_credential_algorithms(&self) -> Vec<COSEAlgorithm> {
        unreachable!();
    }
}
