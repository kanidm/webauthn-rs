use std::{fs::read, net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand};
use hyper::{http::uri::Builder, Uri};
use tokio_native_tls::{
    native_tls::{self, Identity, Protocol},
    TlsAcceptor,
};

#[derive(Debug, Clone, Subcommand)]
pub enum TransportProtocol {
    /// Serve unencrypted HTTP. This is not suitable for use with ordinary 
    Http,
    /// Serve HTTPS.
    Https(HttpsOptions),
}

#[derive(Debug, Clone, Args)]
pub struct HttpsOptions {
    /// Path to the server's public key (certificate) in PEM format.
    #[clap(long, value_name = "PEM")]
    tls_public_key: PathBuf,

    /// Path to the server's private key in PEM format.
    #[clap(long, value_name = "PEM")]
    tls_private_key: PathBuf,
}

impl TransportProtocol {
    pub fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>, Box<dyn std::error::Error>> {
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
