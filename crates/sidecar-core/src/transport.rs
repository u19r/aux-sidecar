use std::{future::Future, pin::Pin};

use sidecar_contract::{
    ApiEvaluationRequest, AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest,
    AuthzPolicySnapshot, AuthzPolicyVersionSnapshot, EntitlementEvaluateRequest,
    EntitlementEvaluateResponse, RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseResponse,
    RateLimitConfig, RateLimitGiveBackLeaseRequest, RateLimitGiveBackLeaseResponse, RequestContext,
    RuntimeBlocklistDecisionRequest, RuntimeBlocklistDecisionResponse,
    RuntimePolicyDecisionRequest, RuntimePolicyDecisionResponse, RuntimeSyncRequest,
    RuntimeSyncResponse, TokenResponse, UpstreamAuthzResponse,
};

use crate::{SidecarEngineConfig, SidecarError, SidecarResult};

#[cfg(target_arch = "wasm32")]
pub type SidecarFuture<'a, T> = Pin<Box<dyn Future<Output = SidecarResult<T>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub type SidecarFuture<'a, T> = Pin<Box<dyn Future<Output = SidecarResult<T>> + Send + 'a>>;

/// Native transports cross executor threads; WASM host capabilities remain
/// isolate-local.
#[cfg(not(target_arch = "wasm32"))]
pub trait TransportThreadSafety: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> TransportThreadSafety for T {}

#[cfg(target_arch = "wasm32")]
pub trait TransportThreadSafety {}
#[cfg(target_arch = "wasm32")]
impl<T> TransportThreadSafety for T {}

pub trait SidecarTransport: TransportThreadSafety {
    fn host_available(&self) -> bool {
        true
    }

    fn sync_runtime<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a RuntimeSyncRequest,
    ) -> SidecarFuture<'a, RuntimeSyncResponse> {
        Box::pin(async {
            Err(SidecarError::bad_gateway(
                "runtime_sync_unavailable",
                "transport does not implement runtime synchronization",
            ))
        })
    }

    fn acquire_leases<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, RateLimitAcquireLeaseResponse>;

    fn give_back_leases<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, RateLimitGiveBackLeaseResponse>;

    fn load_rate_limit_config<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, RateLimitConfig>;

    fn decide_blocklist<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, RuntimeBlocklistDecisionResponse>;

    fn decide_policy<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, RuntimePolicyDecisionResponse>;

    fn evaluate_authz<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a ApiEvaluationRequest,
    ) -> SidecarFuture<'a, UpstreamAuthzResponse>;

    fn load_authz_policy_version<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, AuthzPolicyVersionSnapshot> {
        Box::pin(authz_snapshot_transport_unimplemented())
    }

    fn load_authz_policy_snapshot<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _version: Option<u64>,
    ) -> SidecarFuture<'a, AuthzPolicySnapshot> {
        Box::pin(authz_snapshot_transport_unimplemented())
    }

    fn load_authz_evaluation_data<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a AuthzEvaluationDataSnapshotRequest,
    ) -> SidecarFuture<'a, AuthzEvaluationDataSnapshot> {
        Box::pin(authz_snapshot_transport_unimplemented())
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, EntitlementEvaluateResponse>;

    fn fetch_jwks<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value>;

    fn exchange_oauth_code<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, TokenResponse>;

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, TokenResponse>;
}

async fn authz_snapshot_transport_unimplemented<T>() -> SidecarResult<T> {
    Err(SidecarError::internal(
        "authz_snapshot_transport_unimplemented",
        "transport does not implement local AuthZ snapshot fetching",
    ))
}
