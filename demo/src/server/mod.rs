use axum::http::{
    header::{ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN},
    HeaderMap, StatusCode,
};
use leptos::{context::use_context, server_fn::ServerFnError};
use leptos_axum::{extract, ResponseOptions};
use webauthn_rs::prelude::*;

pub mod config;
pub mod state;

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

    if let Some(response) = use_context::<ResponseOptions>() {
        response.insert_header(ACCESS_CONTROL_ALLOW_ORIGIN, origin_v.clone());
    }

    Ok(())
}

/// Sets the HTTP response code for an API request.
pub fn set_http_response_code(status_code: StatusCode) {
    if let Some(response) = use_context::<ResponseOptions>() {
        response.set_status(status_code);
    }
}
