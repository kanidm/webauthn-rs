use actix_session::{SessionGetError, SessionInsertError};
use std::fmt::{Display, Formatter};

use actix_web::http::StatusCode;
use webauthn_rs::prelude::WebauthnError;

pub(crate) mod auth;
pub(crate) mod index;
pub(crate) mod serve_wasm;

/**
Type alias for Errors that implement [actix_web::ResponseError] through [Error]
*/
type WebResult<T> = Result<T, Error>;

/**
Unified errors for simpler Responses
*/
#[derive(Debug)]
pub(crate) enum Error {
    Unknown(WebauthnError),
    SessionGet(SessionGetError),
    SessionInsert(SessionInsertError),
    CorruptSession,
    BadRequest(WebauthnError),
    UserNotFound,
    UserHasNoCredentials,
}

impl From<SessionGetError> for Error {
    fn from(value: SessionGetError) -> Self {
        Self::SessionGet(value)
    }
}

impl From<SessionInsertError> for Error {
    fn from(value: SessionInsertError) -> Self {
        Self::SessionInsert(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unknown(_) => write!(f, "Unknown webauthn error"),
            Error::SessionGet(_) | Error::SessionInsert(_) => write!(f, "Corrupt session"),
            Error::BadRequest(_) => write!(f, "Bad request"),
            Error::UserNotFound => write!(f, "User not found"),
            Error::UserHasNoCredentials => write!(f, "User has no credentials"),
            Error::CorruptSession => write!(f, "Corrupt session"),
        }
    }
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}
