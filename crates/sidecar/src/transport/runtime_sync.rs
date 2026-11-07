use sidecar_contract::{RequestContext, RuntimeSyncRequest, RuntimeSyncResponse};
use sidecar_core::{SidecarEngineConfig, SidecarError, SidecarFuture};

use super::NativeSidecarTransport;
use crate::transport_helpers::{decode_success, tenant_url, with_context_headers};

pub(super) fn fetch_runtime_sync<'a>(
    transport: &'a NativeSidecarTransport,
    config: &'a SidecarEngineConfig,
    context: &'a RequestContext,
    request: &'a RuntimeSyncRequest,
) -> SidecarFuture<'a, RuntimeSyncResponse> {
    Box::pin(async move {
        let response = with_context_headers(
            transport
                .http
                .post(tenant_url(&config.base_url, "/runtime/local/sync"))
                .header("x-api-key", &config.api_key)
                .json(request),
            context,
            config.tenant_domain.as_deref(),
        )
        .send()
        .await
        .map_err(|err| SidecarError::bad_gateway("runtime_sync_upstream_error", err.to_string()))?;
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
