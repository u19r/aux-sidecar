use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use sidecar_core::SidecarError;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: &'static str,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_reason: Option<&'static str>,
}

pub fn sidecar_error_response(error: SidecarError) -> axum::response::Response {
    let challenge = error.oauth_challenge();
    let status =
        StatusCode::from_u16(error.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (
        status,
        Json(ErrorResponse {
            code: error.code,
            message: error.message,
            redirect_url: error.redirect_url,
            redirect_reason: error.redirect_reason,
        }),
    )
        .into_response();
    if let Some(challenge) = challenge
        && let Ok(value) = challenge.parse()
    {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    response
}
