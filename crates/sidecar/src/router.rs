use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::{constants::MAX_REQUEST_BODY_BYTES, handlers, state::SidecarState};

pub fn build_router(state: Arc<SidecarState>) -> Router {
    let proxy_enabled = matches!(state.engine.preset(), sidecar_core::DeploymentPreset::Proxy);
    let router = Router::new()
        .route("/sidecar/live", get(handlers::live))
        .route("/sidecar/ready", get(handlers::ready))
        .route("/sidecar/status", get(handlers::status))
        .route("/sidecar/health", get(handlers::live))
        .route(
            "/sidecar/authz/shadow_metrics",
            get(handlers::authz_shadow_metrics),
        )
        .route(
            "/sidecar/rate_limit/config",
            get(handlers::rate_limit_config),
        )
        .route("/sidecar/sync", post(handlers::sync_runtime))
        .route("/sidecar/rate_limit/lease", post(handlers::acquire_lease))
        .route(
            "/sidecar/rate_limit/check",
            post(handlers::check_rate_limit),
        )
        .route("/sidecar/rate_limit/return", post(handlers::give_back))
        .route("/sidecar/authz/evaluate", post(handlers::authz_evaluate))
        .route(
            "/sidecar/blocklist/decision",
            post(handlers::blocklist_decision),
        )
        .route("/sidecar/policy/decision", post(handlers::policy_decision))
        .route(
            "/sidecar/entitlements/evaluate",
            post(handlers::entitlements_evaluate),
        )
        .route(
            "/sidecar/authn/validate_jwt",
            post(handlers::validate_authn_jwt),
        )
        .route(
            "/sidecar/oauth/validate_access_token",
            post(handlers::validate_oauth_access_token),
        )
        .route(
            "/sidecar/hosted_login/begin",
            post(handlers::begin_hosted_login),
        )
        .route(
            "/sidecar/hosted_login/complete",
            post(handlers::complete_hosted_login),
        )
        .route(
            "/sidecar/hosted_login/refresh",
            post(handlers::refresh_hosted_login),
        );
    let router = router.layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES));
    let route_proxy_enabled = state.upstream_url.is_some();
    let router = if proxy_enabled {
        router.route("/sidecar/proxy/check", get(handlers::proxy_check))
    } else {
        router
    };
    let router = if route_proxy_enabled {
        router.fallback(handlers::proxy_request)
    } else {
        router
    };
    router.with_state(state)
}
