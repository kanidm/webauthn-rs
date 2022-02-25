#[macro_use]
extern crate tracing;

use url::Url;
use webauthn_rs_core::error::{WebauthnError, WebauthnResult};
use webauthn_rs_core::proto::COSEAlgorithm;
use webauthn_rs_core::WebauthnCore;

pub mod prelude {
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
    fn new(rp_id: &'a str, rp_origin: &'a Url) -> WebauthnResult<Self> {
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

    fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    fn rp_name(mut self, rp_name: &'a str) -> Self {
        self.rp_name = Some(rp_name);
        self
    }

    fn build(self) -> WebauthnResult<Webauthn> {
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
    // Register A simple credential.

    // Register a password-less credential, needs attestation

    // Register a trusted device credential

    // Authenticate ^
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
