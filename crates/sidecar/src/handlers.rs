use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sidecar_contract::{
    ApiEvaluationRequest, BeginHostedLoginRequest, CompleteHostedLoginRequest,
    EntitlementEvaluateRequest, RateLimitAcquireLeaseRequest, RateLimitCheckRequest,
    RateLimitGiveBackLeaseRequest, RefreshHostedLoginRequest, RequestContext,
    RuntimeBlocklistDecisionRequest, RuntimePolicyDecisionRequest, RuntimeSyncRequest,
    ValidateAuthnJwtRequest, ValidateOAuthAccessTokenRequest,
};

use crate::{
    client_ip::extract_client_ip,
    constants::{TRACEPARENT, TRACESTATE},
    errors::sidecar_error_response,
    state::SidecarState,
    transport_helpers::{valid_traceparent, valid_tracestate},
};

#[derive(Debug, Serialize)]
pub struct AuthzShadowMetricsResponse {
    attempts: u64,
    matches: u64,
    mismatches: u64,
    errors: u64,
}

#[derive(Debug, Deserialize)]
pub struct SidecarLeaseRequest {
    pub request: RateLimitAcquireLeaseRequest,
}

#[derive(Debug, Deserialize)]
pub struct SidecarGiveBackRequest {
    pub request: RateLimitGiveBackLeaseRequest,
}

pub async fn live(State(state): State<Arc<SidecarState>>) -> impl IntoResponse {
    (StatusCode::OK, Json(state.engine.live()))
}

pub async fn ready(State(state): State<Arc<SidecarState>>) -> impl IntoResponse {
    let mut ready = state.engine.ready();
    if state.upstream_url.is_some()
        && !matches!(
            state.engine.state().revocation_snapshot_state(
                &state.whole_upstream_audiences,
                sidecar_core::current_time_millis(),
            ),
            sidecar_core::RevocationSnapshotState::Fresh
                | sidecar_core::RevocationSnapshotState::Stale
        )
    {
        ready.ready = false;
        if !ready
            .reason_codes
            .contains(&"revocation_snapshot_unavailable")
        {
            ready.reason_codes.push("revocation_snapshot_unavailable");
        }
    }
    let status = if ready.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(ready))
}

pub async fn status(State(state): State<Arc<SidecarState>>) -> impl IntoResponse {
    (StatusCode::OK, Json(state.engine.status()))
}

#[path = "proxy_forward.rs"]
mod proxy_forward;
#[path = "proxy_handlers.rs"]
mod proxy_handlers;

pub use proxy_forward::proxy_request;
pub use proxy_handlers::proxy_check;

pub async fn authz_shadow_metrics(State(state): State<Arc<SidecarState>>) -> impl IntoResponse {
    let metrics = state.engine.state().authz_shadow_metrics();
    (
        StatusCode::OK,
        Json(AuthzShadowMetricsResponse {
            attempts: metrics.attempts,
            matches: metrics.matches,
            mismatches: metrics.mismatches,
            errors: metrics.errors,
        }),
    )
}

pub async fn rate_limit_config(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.get_rate_limit_config(&context).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn sync_runtime(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<RuntimeSyncRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.sync_runtime(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn acquire_lease(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<SidecarLeaseRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state
        .engine
        .acquire_leases(&context, &request.request)
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn check_rate_limit(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<RateLimitCheckRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.check_rate_limit(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn give_back(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<SidecarGiveBackRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state
        .engine
        .give_back_leases(&context, &request.request)
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn authz_evaluate(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<ApiEvaluationRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.evaluate_authz(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn blocklist_decision(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<RuntimeBlocklistDecisionRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.decide_blocklist(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn policy_decision(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<RuntimePolicyDecisionRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.decide_policy(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn entitlements_evaluate(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<EntitlementEvaluateRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.evaluate_entitlements(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn validate_authn_jwt(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<ValidateAuthnJwtRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.validate_authn_jwt(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn validate_oauth_access_token(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<ValidateOAuthAccessTokenRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state
        .engine
        .validate_oauth_access_token(&context, &request)
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn begin_hosted_login(
    State(state): State<Arc<SidecarState>>,
    Json(request): Json<BeginHostedLoginRequest>,
) -> impl IntoResponse {
    match state.engine.begin_hosted_login(&request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn complete_hosted_login(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<CompleteHostedLoginRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.complete_hosted_login(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

pub async fn refresh_hosted_login(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
    Json(request): Json<RefreshHostedLoginRequest>,
) -> impl IntoResponse {
    let context = request_context(&headers);
    match state.engine.refresh_hosted_login(&context, &request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sidecar_error_response(error),
    }
}

fn request_context(headers: &HeaderMap) -> RequestContext {
    RequestContext {
        authorization: header_string(headers, AUTHORIZATION.as_str()),
        client_ip: extract_client_ip(headers).map(|ip| ip.to_string()),
        tenant_domain: None,
        traceparent: trace_header(headers, TRACEPARENT, valid_traceparent),
        tracestate: trace_header(headers, TRACESTATE, valid_tracestate),
    }
}

/// Cedar receives only the structural access-token projection.  Sidecar
/// predicates evaluate the complete verified claim tree separately; passing
/// arbitrary tenant claims into the platform PDP would let custom data alter
/// platform authority or create an unbounded policy input.
fn safe_jwt_context(claims: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    const SAFE_CLAIMS: &[&str] = &[
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "client_id",
        "scope",
        "tenant",
        "token_type",
        "principal_type",
        "auth_time",
        "acr",
        "amr",
        "azp",
    ];
    claims
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(name, _)| SAFE_CLAIMS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn trace_header(
    headers: &HeaderMap,
    name: &str,
    validator: impl Fn(&str) -> bool,
) -> Option<String> {
    header_string(headers, name).filter(|value| validator(value))
}
