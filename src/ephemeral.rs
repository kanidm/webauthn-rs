//! An implementation of an Ephemeral (in-memory) webauthn configuration provider
//! This stores all challenges and credentials in memory - IE they are lost on
//! service restart. It's only really useful for demo-sites, testing and as an
//! example/reference implementation of the WebauthnConfig trait.
//!
//! IMPORTANT: DO NOT USE THIS IN PRODUCTION. YOU MUST IMPLEMENT YOUR OWN STRUCT
//! DERIVING `WebauthnConfig`!!! This structure WILL be removed in a future release!
//!
//! By default this implementation advertises support for all possible authenticators
//! EVEN if they are NOT supported. This to is aid in test vector collection.

use crate::crypto::COSEContentType;
use crate::proto::AttestationConveyancePreference;
use crate::proto::AuthenticatorAttachment;
use crate::WebauthnConfig;

/// An implementation of an Ephemeral (in-memory) webauthn configuration provider
/// This stores all challenges and credentials in memory - IE they are lost on
/// service restart. It's only really useful for demo-sites, testing and as an
/// example/reference implementation of the WebauthnConfig trait.
///
/// IMPORTANT: DO NOT USE THIS IN PRODUCTION. YOU MUST IMPLEMENT YOUR OWN STRUCT
/// DERIVING `WebauthnConfig`!!! This structure WILL be removed in a future release!
///
/// By default this implementation advertises support for all possible authenticators
/// EVEN if they are NOT supported. This to is aid in test vector collection.
pub struct WebauthnEphemeralConfig {
    rp_name: String,
    rp_id: String,
    rp_origin: String,
    attachment: Option<AuthenticatorAttachment>,
}

impl std::fmt::Debug for WebauthnEphemeralConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "WebauthnEphemeralConfig{{ rp_name: {:?}, rp_id: {:?}, rp_origin: {:?} }}",
            self.rp_name, self.rp_id, self.rp_origin
        )
    }
}

impl WebauthnConfig for WebauthnEphemeralConfig {
    /// Returns the relying party name. See the trait documentation for more.
    fn get_relying_party_name(&self) -> String {
        self.rp_name.clone()
    }

    /// Returns the relying party id. See the trait documentation for more.
    fn get_relying_party_id(&self) -> String {
        self.rp_id.clone()
    }

    /// Retrieve the relying party origin. See the trait documentation for more.
    fn get_origin(&self) -> &String {
        &self.rp_origin
    }

    /// Retrieve the authenticator attachment hint. See the trait documentation for more.
    fn get_authenticator_attachment(&self) -> Option<AuthenticatorAttachment> {
        self.attachment
    }

    /// Retrieve the authenticator attestation preference. See the trait documentation for more.
    fn get_attestation_preference(&self) -> AttestationConveyancePreference {
        AttestationConveyancePreference::Direct
    }

    /// Retrieve the list of support algorithms.
    ///
    /// WARNING: This returns *all* possible algorithms, not just SUPPORTED ones. This
    /// is so that
    fn get_credential_algorithms(&self) -> Vec<COSEContentType> {
        vec![
            COSEContentType::ECDSA_SHA256,
            COSEContentType::ECDSA_SHA384,
            COSEContentType::ECDSA_SHA512,
            COSEContentType::RS256,
            COSEContentType::RS384,
            COSEContentType::RS512,
            COSEContentType::PS256,
            COSEContentType::PS384,
            COSEContentType::PS512,
            COSEContentType::EDDSA,
        ]
    }
}

impl WebauthnEphemeralConfig {
    /// Create a new Webauthn Ephemeral instance. This requires a provided relying party
    /// name, origin and id. See the trait documentation for more detail on relying party
    /// name, origin and id.
    pub fn new(
        rp_name: &str,
        rp_origin: &str,
        rp_id: &str,
        attachment: Option<AuthenticatorAttachment>,
    ) -> Self {
        WebauthnEphemeralConfig {
            rp_name: rp_name.to_string(),
            rp_id: rp_id.to_string(),
            rp_origin: rp_origin.to_string(),
            attachment,
        }
    }
}
