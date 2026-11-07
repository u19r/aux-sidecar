use sidecar_contract::{
    RequestContext,
    hosted_recovery::{NativeRecoveryStage, NativeRecoveryStageRequest},
};
use sidecar_core::{SidecarEngineConfig, SidecarError, SidecarFuture};

use super::{NativeSidecarTransport, oauth_response::decode_oauth_response};
use crate::transport_helpers::{tenant_url, with_context_headers};

pub(super) fn stage_oauth_recovery<'a>(
    transport: &'a NativeSidecarTransport,
    config: &'a SidecarEngineConfig,
    context: &'a RequestContext,
    request: &'a NativeRecoveryStageRequest,
) -> SidecarFuture<'a, NativeRecoveryStage> {
    Box::pin(async move {
        let response = with_context_headers(
            transport
                .http
                .post(tenant_url(&config.base_url, "/oauth2/recovery/stage"))
                .json(request),
            context,
            config.tenant_domain.as_deref(),
        )
        .send()
        .await
        .map_err(|_| {
            SidecarError::bad_gateway(
                "oauth_recovery_stage_unavailable",
                "native recovery stage is unavailable",
            )
        })?;
        decode_oauth_response(response).await
    })
}
