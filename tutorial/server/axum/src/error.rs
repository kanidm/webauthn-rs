use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
}
impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let body = match self {
            WebauthnError::CorruptSession => "Corrupt Session",
            WebauthnError::UserNotFound => "User Not Found",
            WebauthnError::Unknown => "Unknown Error",
            WebauthnError::UserHasNoCredentials => "User Has No Credentials",
        };

        // its often easiest to implement `IntoResponse` by calling other implementations
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
