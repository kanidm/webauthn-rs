use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rusqlite error: {0}")]
    LeptosConfig(#[from] leptos_config::errors::LeptosConfigError),

    #[error("Rusqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    
    #[error("WebAuthn error: {0}")]
    Webauthn(#[from] webauthn_rs::prelude::WebauthnError),

    #[error("Path is not absolute: {0}")]
    PathIsNotAbsolute(PathBuf),
    
    #[error("TLS config needs both public and private key, or neither to disable it")]
    TlsNeedsPublicAndPrivateKey,
    
    #[error("Invalid RP ID")]
    InvalidRelyingPartyID,

    #[error("Invalid RP origin")]
    InvalidRelyingPartyOrigin,
}
