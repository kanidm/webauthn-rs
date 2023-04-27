use std::{fs::read, net::SocketAddr, path::PathBuf};

use clap::{Args, ValueHint};
use hyper::{http::uri::Builder, Uri};
use tokio_native_tls::{
    native_tls::{self, Certificate, Identity, Protocol},
    TlsAcceptor, TlsConnector,
};

#[derive(thiserror::Error, Debug)]
pub enum TlsConfigError {
    #[error(
        "server was configured with a TLS public and/or private key, but HTTP mode is enabled"
    )]
    InsecureHttpWithKeys,
    #[error("server was configured to use TLS, but public and/or private keys were not provided")]
    TlsServerRequiresPublicAndPrivateKeys,
    #[error("backend connection was configured with a trusted CA, but HTTP mode is enabled")]
    InsecureHttpWithTrust,
    #[error("backend connection was configured with a trust domain, but HTTP mode is enabled")]
    InsecureHttpWithDomain,
    #[error("problem reading key file: {0}")]
    IoError(std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(native_tls::Error),
}

impl From<std::io::Error> for TlsConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<native_tls::Error> for TlsConfigError {
    fn from(e: native_tls::Error) -> Self {
        Self::TlsError(e)
    }
}

#[derive(Debug, Clone, Args)]
pub struct ServerTransportProtocol {
    /// Runs an unencrypted HTTP server, rather than HTTPS. This is not suitable
    /// for use with ordinary caBLE clients.
    #[clap(long, conflicts_with_all(&["tls_public_key", "tls_private_key"]))]
    insecure_http_server: bool,

    /// Path to the server's public key (certificate) in PEM format.
    #[clap(long, value_name = "PEM", value_hint = ValueHint::FilePath)]
    tls_public_key: Option<PathBuf>,

    /// Path to the server's private key in PEM format.
    #[clap(long, value_name = "PEM", value_hint = ValueHint::FilePath)]
    tls_private_key: Option<PathBuf>,
}

impl ServerTransportProtocol {
    /// Returns a [TlsAcceptor] for this [ServerTransportProtocol]
    ///
    /// Returns `None` if insecure HTTP connections should be used.
    pub fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>, TlsConfigError> {
        if self.insecure_http_server {
            if self.tls_public_key.is_some() || self.tls_private_key.is_some() {
                return Err(TlsConfigError::InsecureHttpWithKeys);
            }

            warn!("Using unencrypted HTTP to serve requests. This is insecure, and won't work with ordinary caBLE clients!");
            return Ok(None);
        }

        let (tls_public_key, tls_private_key) = match (&self.tls_public_key, &self.tls_private_key)
        {
            (Some(p), Some(q)) => (p, q),
            _ => {
                return Err(TlsConfigError::TlsServerRequiresPublicAndPrivateKeys);
            }
        };

        let pem = read(tls_public_key)?;
        let key = read(tls_private_key)?;
        let identity = Identity::from_pkcs8(&pem, &key)?;
        Ok(Some(TlsAcceptor::from(
            native_tls::TlsAcceptor::builder(identity)
                // We only support TLS 1.2 and later, because all caBLE clients support it.
                //
                // We don't care about breaking things like exceptionally ancient versions of Android.
                .min_protocol_version(Some(Protocol::Tlsv12))
                .build()?,
        )))
    }

    /// Returns a `http` or `https` URI for this [ServerTransportProtocol] for a
    /// given [SocketAddr].
    pub fn uri(&self, addr: &SocketAddr) -> Result<Uri, hyper::http::Error> {
        Builder::new()
            .scheme(if self.insecure_http_server {
                "http"
            } else {
                "https"
            })
            .authority(addr.to_string())
            .path_and_query("/")
            .build()
    }
}

#[derive(Debug, Clone, Args)]
pub struct BackendClientOptions {
    /// Uses unencrypted HTTP to connect to backend tasks, rather than HTTPS.
    #[clap(long, conflicts_with_all(&["trusted_ca", "domain"]))]
    insecure_http_backend: bool,

    /// Public key of the root CA to trust when connecting to a backend task,
    /// instead of using the system's built-in certificate trust store.
    #[clap(long, value_name = "PEM", value_hint = ValueHint::FilePath)]
    trusted_ca: Option<PathBuf>,

    /// If set, use this domain name to validate the server-provided certificate
    /// against, rather than the IP of the backend.
    #[clap(long, value_name = "DOMAIN", value_hint = ValueHint::Hostname)]
    pub domain: Option<String>,
}

impl BackendClientOptions {
    /// Creates a [TlsConnector] for the [BackendClientOptions].
    ///
    /// Returns `None` if insecure HTTP connections should be used.
    pub fn tls_connector(&self) -> Result<Option<TlsConnector>, TlsConfigError> {
        if self.insecure_http_backend {
            if self.trusted_ca.is_some() {
                return Err(TlsConfigError::InsecureHttpWithTrust);
            }

            if self.domain.is_some() {
                return Err(TlsConfigError::InsecureHttpWithDomain);
            }

            warn!("Using unencrypted HTTP to connect to backend tasks. This is insecure!");
            return Ok(None);
        }

        let mut b = native_tls::TlsConnector::builder();
        b.min_protocol_version(Some(Protocol::Tlsv12));

        if let Some(trusted_ca) = &self.trusted_ca {
            let trusted_ca = read(trusted_ca)?;
            let certificate = Certificate::from_pem(&trusted_ca)?;

            b.disable_built_in_roots(true)
                .add_root_certificate(certificate);
        }

        Ok(Some(TlsConnector::from(b.build()?)))
    }
}
