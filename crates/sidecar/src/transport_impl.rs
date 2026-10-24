use std::{path::PathBuf, time::Duration};

use sidecar_contract::{
    ApiEvaluationRequest, AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest,
    AuthzPolicySnapshot, AuthzPolicyVersionSnapshot, EntitlementEvaluateRequest,
    EntitlementEvaluateResponse, RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseResponse,
    RateLimitConfig, RateLimitConfigResponse, RateLimitGiveBackLeaseRequest,
    RateLimitGiveBackLeaseResponse, RequestContext, RuntimeBlocklistDecisionRequest,
    RuntimeBlocklistDecisionResponse, RuntimePolicyDecisionRequest, RuntimePolicyDecisionResponse,
    RuntimeSyncRequest, RuntimeSyncResponse, TokenResponse, UpstreamAuthzResponse,
};
use sidecar_core::{SidecarEngineConfig, SidecarError, SidecarFuture, SidecarTransport};

use crate::{
    constants::UPSTREAM_REQUEST_TIMEOUT_SECONDS,
    transport_helpers::{
        X_FORWARDED_FOR, decode_json_body, decode_success, load_config_from_file, tenant_url,
        with_context_headers,
    },
};

#[path = "oauth_exchange.rs"]
mod oauth_exchange;
use oauth_exchange::exchange_oauth_token;

#[derive(Debug, Clone)]
pub struct NativeSidecarTransport {
    pub(crate) http: http_request::reqwest::Client,
    config_path: Option<PathBuf>,
}

impl NativeSidecarTransport {
    pub fn new(config_path: Option<PathBuf>) -> Self {
        Self::with_timeout(
            config_path,
            Duration::from_secs(UPSTREAM_REQUEST_TIMEOUT_SECONDS),
        )
    }

    pub(crate) fn with_timeout(config_path: Option<PathBuf>, timeout: Duration) -> Self {
        Self {
            http: http_request::reqwest::Client::builder()
                .connect_timeout(timeout)
                .timeout(timeout)
                .redirect(http_request::reqwest::redirect::Policy::none())
                .build()
                .expect("native sidecar HTTP client configuration is valid"),
            config_path,
        }
    }
}

impl SidecarTransport for NativeSidecarTransport {
    fn sync_runtime<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimeSyncRequest,
    ) -> SidecarFuture<'a, RuntimeSyncResponse> {
        Box::pin(async move {
            let response = with_context_headers(
                self.http
                    .post(tenant_url(&config.base_url, "/runtime/local/sync"))
                    .header("x-api-key", &config.api_key)
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("runtime_sync_upstream_error", err.to_string())
            })?;
            if matches!(
                response.status(),
                http_request::reqwest::StatusCode::NOT_FOUND
                    | http_request::reqwest::StatusCode::METHOD_NOT_ALLOWED
            ) {
                return Err(SidecarError::bad_gateway(
                    "runtime_sync_unavailable",
                    "upstream does not expose runtime synchronization",
                ));
            }
            decode_success(
                response,
                "runtime_sync_upstream_failure",
                "runtime_sync_decode_failed",
            )
            .await
        })
    }

    fn acquire_leases<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, RateLimitAcquireLeaseResponse> {
        Box::pin(async move {
            let client_ip = context.require_client_ip()?;
            let response = with_context_headers(
                self.http
                    .post(tenant_url(
                        &config.base_url,
                        "/rate-limit/runtime/leases/acquire",
                    ))
                    .header("x-api-key", &config.api_key)
                    .header(X_FORWARDED_FOR, client_ip.to_string())
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("rate_limit_upstream_error", err.to_string())
            })?;

            decode_success(
                response,
                "rate_limit_upstream_failure",
                "rate_limit_decode_failed",
            )
            .await
        })
    }

    fn give_back_leases<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, RateLimitGiveBackLeaseResponse> {
        Box::pin(async move {
            let client_ip = context.require_client_ip()?;
            let response = with_context_headers(
                self.http
                    .post(tenant_url(
                        &config.base_url,
                        "/rate-limit/runtime/leases/giveback",
                    ))
                    .header("x-api-key", &config.api_key)
                    .header(X_FORWARDED_FOR, client_ip.to_string())
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("rate_limit_upstream_error", err.to_string())
            })?;

            decode_success(
                response,
                "rate_limit_upstream_failure",
                "rate_limit_decode_failed",
            )
            .await
        })
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, RateLimitConfig> {
        Box::pin(async move {
            if let Some(path) = self.config_path.as_ref() {
                return load_config_from_file(path);
            }

            let client_ip = context.require_client_ip()?;
            let response = with_context_headers(
                self.http
                    .get(tenant_url(&config.base_url, "/rate-limit/runtime/config"))
                    .header("x-api-key", &config.api_key)
                    .header(X_FORWARDED_FOR, client_ip.to_string()),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("rate_limit_upstream_error", err.to_string())
            })?;

            let payload: RateLimitConfigResponse = decode_success(
                response,
                "rate_limit_upstream_failure",
                "rate_limit_decode_failed",
            )
            .await?;
            Ok(payload.into_rate_limit_config())
        })
    }

    fn decide_blocklist<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, RuntimeBlocklistDecisionResponse> {
        Box::pin(async move {
            let client_ip = context.require_client_ip()?;
            let response = with_context_headers(
                self.http
                    .post(tenant_url(&config.base_url, "/blocklist/runtime/decision"))
                    .header("x-api-key", &config.api_key)
                    .header(X_FORWARDED_FOR, client_ip.to_string())
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("blocklist_upstream_error", err.to_string())
            })?;

            decode_success(
                response,
                "blocklist_upstream_failure",
                "blocklist_decode_failed",
            )
            .await
        })
    }

    fn decide_policy<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, RuntimePolicyDecisionResponse> {
        Box::pin(async move {
            let client_ip = context.require_client_ip()?;
            let response = with_context_headers(
                self.http
                    .post(tenant_url(
                        &config.base_url,
                        "/rate-limit/runtime/policy/decision",
                    ))
                    .header("x-api-key", &config.api_key)
                    .header(X_FORWARDED_FOR, client_ip.to_string())
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| SidecarError::bad_gateway("policy_upstream_error", err.to_string()))?;

            decode_success(response, "policy_upstream_failure", "policy_decode_failed").await
        })
    }

    fn evaluate_authz<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a ApiEvaluationRequest,
    ) -> SidecarFuture<'a, UpstreamAuthzResponse> {
        Box::pin(async move {
            let mut outbound = self
                .http
                .post(tenant_url(&config.base_url, "/authz/runtime/evaluation"))
                .header("x-api-key", &config.api_key)
                .json(&sidecar_contract::authz::RuntimeEvaluationRequest::from(
                    request,
                ));

            if let Some(authorization) = context.authorization.as_deref() {
                outbound =
                    outbound.header(http_request::reqwest::header::AUTHORIZATION, authorization);
            }
            if let Some(client_ip) = context.client_ip.as_deref() {
                outbound = outbound.header(X_FORWARDED_FOR, client_ip);
            }
            outbound = with_context_headers(outbound, context, config.tenant_domain.as_deref());

            let response = outbound.send().await.map_err(|err| {
                SidecarError::bad_gateway("authz_upstream_error", err.to_string())
            })?;
            let status = response.status();
            let www_authenticate = response
                .headers()
                .get(http_request::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            if !(status == http_request::StatusCode::OK
                || status == http_request::StatusCode::UNAUTHORIZED)
            {
                return Err(SidecarError::bad_gateway(
                    "authz_upstream_failure",
                    format!("upstream returned non-success status {status}"),
                ));
            }

            let response = decode_json_body(response, "authz_decode_failed").await?;

            Ok(UpstreamAuthzResponse {
                status_code: status.as_u16(),
                response,
                www_authenticate,
            })
        })
    }

    fn load_authz_policy_version<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, AuthzPolicyVersionSnapshot> {
        Box::pin(async move {
            let response = with_context_headers(
                self.http
                    .get(tenant_url(
                        &config.base_url,
                        "/authz/runtime/local/policy-version",
                    ))
                    .header("x-api-key", &config.api_key),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("authz_snapshot_upstream_error", err.to_string())
            })?;

            decode_success(
                response,
                "authz_snapshot_upstream_failure",
                "authz_snapshot_decode_failed",
            )
            .await
        })
    }

    fn load_authz_policy_snapshot<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        version: Option<u64>,
    ) -> SidecarFuture<'a, AuthzPolicySnapshot> {
        Box::pin(async move {
            let mut request = self
                .http
                .get(tenant_url(
                    &config.base_url,
                    "/authz/runtime/local/policy-snapshot",
                ))
                .header("x-api-key", &config.api_key);
            if let Some(version) = version {
                request = request.query(&[("version", version)]);
            }
            let response = with_context_headers(request, context, config.tenant_domain.as_deref())
                .send()
                .await
                .map_err(|err| {
                    SidecarError::bad_gateway("authz_snapshot_upstream_error", err.to_string())
                })?;

            decode_success(
                response,
                "authz_snapshot_upstream_failure",
                "authz_snapshot_decode_failed",
            )
            .await
        })
    }

    fn load_authz_evaluation_data<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a AuthzEvaluationDataSnapshotRequest,
    ) -> SidecarFuture<'a, AuthzEvaluationDataSnapshot> {
        Box::pin(async move {
            let response = with_context_headers(
                self.http
                    .post(tenant_url(
                        &config.base_url,
                        "/authz/runtime/local/evaluation-data",
                    ))
                    .header("x-api-key", &config.api_key)
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| {
                SidecarError::bad_gateway("authz_snapshot_upstream_error", err.to_string())
            })?;

            decode_success(
                response,
                "authz_snapshot_upstream_failure",
                "authz_snapshot_decode_failed",
            )
            .await
        })
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, EntitlementEvaluateResponse> {
        Box::pin(async move {
            let client_ip = context.require_client_ip()?;
            let mut outbound = with_context_headers(
                self.http
                    .post(tenant_url(&config.base_url, "/entitlements/evaluate"))
                    .header("x-api-key", &config.api_key)
                    .header(X_FORWARDED_FOR, client_ip.to_string())
                    .json(request),
                context,
                config.tenant_domain.as_deref(),
            );

            if let Some(authorization) = context.authorization.as_deref() {
                outbound =
                    outbound.header(http_request::reqwest::header::AUTHORIZATION, authorization);
            }

            let response = outbound.send().await.map_err(|err| {
                SidecarError::bad_gateway("entitlements_upstream_error", err.to_string())
            })?;
            decode_success(
                response,
                "entitlements_upstream_failure",
                "entitlements_decode_failed",
            )
            .await
        })
    }

    fn fetch_jwks<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        Box::pin(async move {
            let response = with_context_headers(
                self.http
                    .get(tenant_url(&config.base_url, "/.well-known/jwks.json")),
                context,
                config.tenant_domain.as_deref(),
            )
            .send()
            .await
            .map_err(|err| SidecarError::bad_gateway("jwks_upstream_error", err.to_string()))?;

            decode_success(response, "jwks_upstream_failure", "jwks_decode_failed").await
        })
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, TokenResponse> {
        exchange_oauth_token(self, config, context, form_fields)
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, TokenResponse> {
        exchange_oauth_token(self, config, context, form_fields)
    }
}
