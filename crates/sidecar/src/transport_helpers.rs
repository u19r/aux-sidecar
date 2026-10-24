use std::path::PathBuf;

use sidecar_contract::RequestContext;
use sidecar_core::{SidecarError, SidecarResult};

pub(crate) use crate::constants::X_FORWARDED_FOR;
use crate::constants::{
    MAX_UPSTREAM_RESPONSE_BYTES, TRACEPARENT, TRACEPARENT_FLAGS_LEN, TRACEPARENT_FORBIDDEN_VERSION,
    TRACEPARENT_PARENT_ID_LEN, TRACEPARENT_PARTS, TRACEPARENT_TRACE_ID_LEN,
    TRACEPARENT_VERSION_LEN, TRACEPARENT_ZERO_PARENT_ID, TRACEPARENT_ZERO_TRACE_ID, TRACESTATE,
    TRACESTATE_MAX_LEN,
};

pub fn with_context_headers(
    mut request: http_request::reqwest::RequestBuilder,
    context: &RequestContext,
    configured_tenant_domain: Option<&str>,
) -> http_request::reqwest::RequestBuilder {
    if let Some(tenant_domain) = configured_tenant_domain {
        request = request.header(http_request::reqwest::header::HOST, tenant_domain);
    }
    if let Some(traceparent) = context
        .traceparent
        .as_deref()
        .filter(|value| valid_traceparent(value))
    {
        request = request.header(TRACEPARENT, traceparent);
    }
    if let Some(tracestate) = context
        .tracestate
        .as_deref()
        .filter(|value| valid_tracestate(value))
    {
        request = request.header(TRACESTATE, tracestate);
    }
    request
}

pub async fn decode_success<T>(
    response: http_request::reqwest::Response,
    upstream_code: &'static str,
    decode_code: &'static str,
) -> SidecarResult<T>
where
    T: serde::de::DeserializeOwned,
{
    if !response.status().is_success() {
        let status = response.status();
        return Err(SidecarError::bad_gateway(
            upstream_code,
            format!("upstream returned non-success status {status}"),
        ));
    }

    decode_json_body(response, decode_code).await
}

pub async fn decode_json_body<T>(
    response: http_request::reqwest::Response,
    decode_code: &'static str,
) -> SidecarResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > MAX_UPSTREAM_RESPONSE_BYTES as u64) {
        return Err(SidecarError::bad_gateway(
            decode_code,
            "upstream response body exceeds the configured byte limit",
        ));
    }
    let mut response = response;
    let mut body = Vec::with_capacity(
        content_length
            .unwrap_or_default()
            .min(MAX_UPSTREAM_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response.chunk().await.map_err(|_err| {
        SidecarError::bad_gateway(decode_code, "upstream response body could not be read")
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_UPSTREAM_RESPONSE_BYTES {
            return Err(SidecarError::bad_gateway(
                decode_code,
                "upstream response body exceeds the configured byte limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|_err| {
        SidecarError::bad_gateway(
            decode_code,
            "upstream response body could not be decoded as JSON",
        )
    })
}

pub fn valid_traceparent(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != TRACEPARENT_PARTS {
        return false;
    }
    let [version, trace_id, parent_id, flags] = parts.as_slice() else {
        return false;
    };
    version.len() == TRACEPARENT_VERSION_LEN
        && *version != TRACEPARENT_FORBIDDEN_VERSION
        && is_lower_hex(version)
        && trace_id.len() == TRACEPARENT_TRACE_ID_LEN
        && *trace_id != TRACEPARENT_ZERO_TRACE_ID
        && is_lower_hex(trace_id)
        && parent_id.len() == TRACEPARENT_PARENT_ID_LEN
        && *parent_id != TRACEPARENT_ZERO_PARENT_ID
        && is_lower_hex(parent_id)
        && flags.len() == TRACEPARENT_FLAGS_LEN
        && is_lower_hex(flags)
}

pub fn valid_tracestate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= TRACESTATE_MAX_LEN
        && !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn load_config_from_file<T>(config_path: &PathBuf) -> SidecarResult<T>
where T: serde::de::DeserializeOwned {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|err| SidecarError::internal("config_read_failed", err.to_string()))?;
    serde_json::from_str(&raw)
        .map_err(|err| SidecarError::internal("config_parse_failed", err.to_string()))
}

pub fn tenant_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}
