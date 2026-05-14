use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, ValueHint};
use std::path::PathBuf;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Parser)]
pub struct ServerArgs {
    /// Path to the server's public key (certificate) in PEM format.
    #[clap(
        long,
        env = "TLS_PUBLIC_KEY",
        value_name = "PEM",
        value_hint = ValueHint::FilePath,
    )]
    tls_public_key: PathBuf,

    /// Path to the server's private key in PEM format.
    #[clap(
        long,
        env = "TLS_PRIVATE_KEY",
        value_name = "PEM",
        value_hint = ValueHint::FilePath,
    )]
    tls_private_key: PathBuf,

    /// Relying party ID.
    ///
    /// This must be set to the effective domain of the site's Origin (eg: `example.net` for
    /// `https://example.net:8443/`), or a registerable domain suffix thereof.
    ///
    /// If not set, this defaults to the exact hostname of the RP origin.
    ///
    /// <https://www.w3.org/TR/webauthn-3/#rp-id>
    #[clap(
        long,
        env = "RP_ID",
        value_name = "HOSTNAME",
        value_hint = ValueHint::Hostname,
    )]
    rp_id: Option<String>,

    /// Server origin.
    ///
    /// This must be a URL with served over `https://`, and match where the application will be
    /// served from, including its port (eg: `https://webauthn-rs.example:8443`).
    #[clap(
        long,
        env = "RP_ORIGIN",
        value_name = "URL",
        value_hint = ValueHint::Url,
    )]
    rp_origin: Url,

    /// Relying party name.
    ///
    /// This may be shown to users when enrolling and using WebAuthn credentials.
    #[clap(long, env = "RP_NAME")]
    rp_name: Option<String>,
}

impl ServerArgs {
    /// Get a [RustlsConfig][] for the server.
    pub async fn rustls_config(&self) -> std::io::Result<RustlsConfig> {
        RustlsConfig::from_pem_file(&self.tls_public_key, &self.tls_private_key).await
    }

    /// Setup `webauthn-rs` with RP config options.
    pub fn setup_webauthn(&self) -> Result<Webauthn, WebauthnError> {
        let rp_id = if let Some(rp_id) = &self.rp_id {
            rp_id
        } else if let Some(host) = self.rp_origin.host_str() {
            host
        } else {
            return Err(WebauthnError::InvalidRPOrigin);
        };

        if !self.rp_origin.username().is_empty()
            || self.rp_origin.password().is_some()
            || self.rp_origin.scheme() != "https"
            || self.rp_origin.path() != "/"
            || self.rp_origin.query().is_some()
            || self.rp_origin.fragment().is_some()
        {
            return Err(WebauthnError::InvalidRPOrigin);
        }

        let mut builder = WebauthnBuilder::new(rp_id, &self.rp_origin)?;

        if let Some(rp_name) = &self.rp_name {
            builder = builder.rp_name(rp_name);
        }

        builder.build()
    }
}
