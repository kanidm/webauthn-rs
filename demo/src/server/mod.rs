use axum::http::{header::ORIGIN, HeaderMap, HeaderValue, Request, StatusCode};
use leptos::{context::use_context, server_fn::ServerFnError};
use leptos_axum::{extract, ResponseOptions};
use tower_http::request_id::{MakeRequestId, RequestId};
use webauthn_rs::prelude::*;

pub mod config;
mod error;
pub mod models;
pub mod state;

pub use self::error::ServerError;
pub type ServerResult<T = ()> = std::result::Result<T, ServerError>;

/// Checks an API request's `Origin` header against policies.
///
/// Returns [`ServerFnError`][] on errors.
pub async fn check_api_request(webauthn: &Webauthn) -> Result<(), ServerFnError> {
    let headers: HeaderMap = extract().await?;
    let Some(origin_v) = headers.get(ORIGIN) else {
        set_http_response_code(StatusCode::FORBIDDEN);
        return Err(ServerFnError::new("Missing Origin"));
    };

    let Ok(origin) = origin_v.to_str() else {
        set_http_response_code(StatusCode::BAD_REQUEST);
        return Err(ServerFnError::new("Malformed Origin"));
    };

    let Ok(origin) = Url::parse(origin) else {
        set_http_response_code(StatusCode::BAD_REQUEST);
        return Err(ServerFnError::new("Malformed Origin"));
    };

    if !webauthn
        .get_allowed_origins()
        .iter()
        .any(|allowed_origin| allowed_origin == &origin)
    {
        set_http_response_code(StatusCode::FORBIDDEN);
        return Err(ServerFnError::new("Incorrect Origin"));
    }

    Ok(())
}

/// Sets the HTTP response code for an API request.
pub fn set_http_response_code(status_code: StatusCode) {
    if let Some(response) = use_context::<ResponseOptions>() {
        response.set_status(status_code);
    }
}

/// Request ID is a randomly-generated UUID.
#[derive(Clone, Copy)]
pub struct RandomUuidRequestId;

impl MakeRequestId for RandomUuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let u = Uuid::new_v4();
        Some(RequestId::new(HeaderValue::from_str(&u.to_string()).ok()?))
    }
}
