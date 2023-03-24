use std::{error::Error as StdError, fs::read, net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand};
use hyper::{http::uri::Builder, Uri};
use tokio_native_tls::{
    native_tls::{self, Certificate, Identity, Protocol},
    TlsAcceptor, TlsConnector,
};

#[derive(Debug, Clone, Subcommand)]
pub enum ServerTransportProtocol {
    /// Serve unencrypted HTTP. This is not suitable for use with ordinary caBLE
    /// clients.
    Http,
    /// Serve HTTPS.
    Https(TlsServerOptions),
}

#[derive(Debug, Clone, Args)]
pub struct TlsServerOptions {
    /// Path to the server's public key (certificate) in PEM format.
    #[clap(long, value_name = "PEM")]
    tls_public_key: PathBuf,

    /// Path to the server's private key in PEM format.
    #[clap(long, value_name = "PEM")]
    tls_private_key: PathBuf,
}

impl ServerTransportProtocol {
    pub fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>, Box<dyn StdError>> {
        match &self {
            Self::Http => Ok(None),
            Self::Https(flags) => {
                let pem = read(&flags.tls_public_key)?;
                let key = read(&flags.tls_private_key)?;
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
        }
    }

    pub fn uri(&self, addr: &SocketAddr) -> Result<Uri, hyper::http::Error> {
        Builder::new()
            .scheme(match self {
                Self::Http => "http",
                Self::Https(_) => "https",
            })
            .authority(addr.to_string())
            .path_and_query("/")
            .build()
    }
}

#[derive(Debug, Clone, Args)]
pub struct BackendClientOptions {
    /// Uses unencrypted HTTP to connect to backend tasks, rather than HTTPS.
    #[clap(long)]
    insecure_http_backend: bool,

    /// Public key of the root CA to trust when connecting to a backend task,
    /// instead of using the system's built-in certificate trust store.
    #[clap(long, value_name = "PEM")]
    trusted_ca: Option<PathBuf>,

    /// If set, use this domain name to validate the server-provided certificate
    /// against, rather than the IP of the backend.
    #[clap(long, value_name = "DOMAIN")]
    pub domain: Option<String>,
}

impl BackendClientOptions {
    pub fn tls_connector(&self) -> Result<Option<TlsConnector>, Box<dyn StdError>> {
        if self.insecure_http_backend {
            if self.trusted_ca.is_some() {
                return Err(Box::new(clap::Error::raw(
                    clap::ErrorKind::ArgumentConflict,
                    "Cannot set both --insecure-http-backend and --trusted-ca flags",
                )));
            }

            if self.domain.is_some() {
                return Err(Box::new(clap::Error::raw(
                    clap::ErrorKind::ArgumentConflict,
                    "Cannot set both --insecure-http-backend and --domain flags",
                )));
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
