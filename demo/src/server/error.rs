use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] compact_jwt::JwtError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Rusqlite error: {0}")]
    LeptosConfig(#[from] leptos_config::errors::LeptosConfigError),

    #[error("ORM error: {0}")]
    Orm(#[from] sea_orm::DbErr),

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

    #[error("Cookie expired")]
    CookieExpired,
}
