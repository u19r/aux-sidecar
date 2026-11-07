use sidecar_core::SidecarResult;

use crate::transport_helpers::decode_json_body;

pub(super) async fn decode_oauth_response<Response: serde::de::DeserializeOwned>(
    response: http_request::reqwest::Response,
) -> SidecarResult<Response> {
    let status = response.status();
    if status.is_success() {
        return decode_json_body(response, "oauth_token_decode_failed").await;
    }
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let payload = if status.as_u16() == 429 || !status.is_client_error() {
        serde_json::Value::Null
    } else {
        decode_json_body(response, "oauth_token_decode_failed").await?
    };
    Err(sidecar_core::oauth_token::decode_oauth_failure(
        status.as_u16(),
        payload,
        retry_after,
    ))
}
