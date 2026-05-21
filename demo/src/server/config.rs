use crate::server::{ServerError, ServerResult};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, ValueHint};
use sea_orm::{Database, DatabaseConnection};
use std::path::PathBuf;
use tracing::error;
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
    tls_public_key: Option<PathBuf>,

    /// Path to the server's private key in PEM format.
    #[clap(
        long,
        env = "TLS_PRIVATE_KEY",
        value_name = "PEM",
        value_hint = ValueHint::FilePath,
    )]
    tls_private_key: Option<PathBuf>,

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

    /// SQLite database path.
    #[clap(long, env = "DB_PATH", value_hint = ValueHint::FilePath)]
    db_path: PathBuf,
}

impl ServerArgs {
    /// Get a [RustlsConfig][] for the server.
    pub async fn rustls_config(&self) -> ServerResult<Option<RustlsConfig>> {
        match (&self.tls_public_key, &self.tls_private_key) {
            // Absolute paths required due to https://github.com/leptos-rs/cargo-leptos/issues/649
            (Some(cert), Some(key)) => {
                if !cert.is_absolute() {
                    Err(ServerError::PathIsNotAbsolute(cert.to_path_buf()))
                } else if !key.is_absolute() {
                    Err(ServerError::PathIsNotAbsolute(key.to_path_buf()))
                } else {
                    Ok(Some(RustlsConfig::from_pem_chain_file(cert, key).await?))
                }
            }

            (None, None) => Ok(None),

            _ => Err(ServerError::TlsNeedsPublicAndPrivateKey),
        }
    }

    /// Setup `webauthn-rs` with RP config options.
    pub fn setup_webauthn(&self) -> ServerResult<Webauthn> {
        let rp_id = if let Some(rp_id) = &self.rp_id {
            rp_id
        } else if let Some(host) = self.rp_origin.host_str() {
            host
        } else {
            return Err(ServerError::InvalidRelyingPartyID);
        };

        if !self.rp_origin.username().is_empty()
            || self.rp_origin.password().is_some()
            || (self.rp_origin.scheme() != "http" && self.rp_origin.scheme() != "https")
            || self.rp_origin.path() != "/"
            || self.rp_origin.query().is_some()
            || self.rp_origin.fragment().is_some()
        {
            error!(
                "RP origin must not contain username, password, path, query or fragments, and must be http or https; got: {:?}",
                self.rp_origin.as_str(),
            );
            return Err(ServerError::InvalidRelyingPartyOrigin);
        }

        let mut builder = WebauthnBuilder::new(rp_id, &self.rp_origin)?;

        if let Some(rp_name) = &self.rp_name {
            builder = builder.rp_name(rp_name);
        }

        Ok(builder.build()?)
    }

    pub fn rp_origin(&self) -> &Url {
        &self.rp_origin
    }

    pub async fn connect_sqlite(&self) -> ServerResult<DatabaseConnection> {
        // let Some(db_path) = &self.db_path else {
        //     warn!("Using in-memory SQLite database for user data - this is not persistent!");
        //     return Ok(sea_orm::Database::connect("sqlite::memory:").await?);
        // };

        if !self.db_path.is_absolute() {
            return Err(ServerError::PathIsNotAbsolute(self.db_path.to_path_buf()));
        }

        let url = format!("sqlite:{}", self.db_path.to_str().unwrap());
        Ok(Database::connect(url).await?)
    }
}
