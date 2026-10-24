use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use sidecar_contract::{
    RequestContext, RuntimeSyncArtifact, RuntimeSyncCapabilities, RuntimeSyncRequest,
    RuntimeSyncResponse, SyncArtifactKind,
};

use crate::{
    SidecarEngineConfig, SidecarFuture, SidecarTransport, runtime_sync_test_support::unused,
};

#[derive(Debug)]
pub(crate) struct SyncTestTransport {
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) legacy_rate_config_calls: Arc<AtomicUsize>,
    pub(crate) legacy_blocklist_calls: Arc<AtomicUsize>,
    pub(crate) legacy_entitlement_calls: Arc<AtomicUsize>,
    pub(crate) lease_calls: Arc<AtomicUsize>,
}

impl SidecarTransport for SyncTestTransport {
    fn sync_runtime<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        request: &'a RuntimeSyncRequest,
    ) -> SidecarFuture<'a, RuntimeSyncResponse> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let mut artifacts = request
                .want
                .contains(&SyncArtifactKind::RateLimitConfig)
                .then(|| RuntimeSyncArtifact {
                    kind: SyncArtifactKind::RateLimitConfig,
                    key: "tenant".to_string(),
                    version: "1".to_string(),
                    etag: "sha256:rate-config".to_string(),
                    immutable: false,
                    max_age_ms: Some(5_000),
                    payload: serde_json::json!({
                        "config": {
                            "defaults": {
                                "routes": {
                                    "GET /v1/items": {"limit": 10, "period": "second", "burst": 20}
                                },
                                "route_groups": {}
                            },
                            "named": {},
                            "entitlement_overrides": {},
                            "org_overrides": {}
                        },
                        "resolved": null
                    }),
                })
                .into_iter()
                .collect::<Vec<_>>();
            if request.want.contains(&SyncArtifactKind::Blocklist) {
                artifacts.push(RuntimeSyncArtifact {
                    kind: SyncArtifactKind::Blocklist,
                    key: "tenant".to_string(),
                    version: "1".to_string(),
                    etag: "sha256:blocklist".to_string(),
                    immutable: false,
                    max_age_ms: Some(5_000),
                    payload: serde_json::json!({
                        "builtin_ip_ranges": [{"ip_range": "10.0.0.0/8"}],
                        "tenant_ip_ranges": [],
                        "builtin_regions": [],
                        "tenant_regions": []
                    }),
                });
            }
            if request.want.contains(&SyncArtifactKind::Entitlements) {
                artifacts.push(RuntimeSyncArtifact {
                    kind: SyncArtifactKind::Entitlements,
                    key: "org_fixture".to_string(),
                    version: "1".to_string(),
                    etag: "sha256:entitlements".to_string(),
                    immutable: false,
                    max_age_ms: Some(5_000),
                    payload: serde_json::json!({
                        "response": {"items": [{
                            "key": "feature.enabled",
                            "decision": {"decision": "granted", "value": true},
                            "used_entitlements": []
                        }]},
                        "valid_until_ms": 4_102_444_800_000_i64,
                        "requested_keys": ["feature.enabled"]
                    }),
                });
            }
            Ok(RuntimeSyncResponse {
                protocol_version: 1,
                server_time: "2026-07-11T12:00:00Z".to_string(),
                refresh_after_ms: 5_000,
                artifacts,
                unchanged: vec![SyncArtifactKind::Jwks],
                capabilities: RuntimeSyncCapabilities::default(),
            })
        })
    }

    fn acquire_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        request: &'a sidecar_contract::RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitAcquireLeaseResponse> {
        self.lease_calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(sidecar_contract::RateLimitAcquireLeaseResponse {
                results: request
                    .leases
                    .iter()
                    .map(|item| sidecar_contract::RateLimitAcquireLeaseResult {
                        key: item.key.clone(),
                        lease: Some(sidecar_contract::RateLimitLease {
                            key: item.key.clone(),
                            lease_id: "lease_fixture".to_string(),
                            granted_tokens: item.requested_tokens,
                            expires_at_ms: 4_102_444_800_000,
                        }),
                        retry_after_ms: None,
                    })
                    .collect(),
            })
        })
    }

    fn give_back_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitGiveBackLeaseResponse> {
        unused()
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitConfig> {
        self.legacy_rate_config_calls
            .fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(sidecar_contract::RateLimitConfig::default()) })
    }

    fn decide_blocklist<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimeBlocklistDecisionResponse> {
        self.legacy_blocklist_calls.fetch_add(1, Ordering::Relaxed);
        unused()
    }

    fn decide_policy<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimePolicyDecisionResponse> {
        unused()
    }

    fn evaluate_authz<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::ApiEvaluationRequest,
    ) -> SidecarFuture<'a, sidecar_contract::UpstreamAuthzResponse> {
        unused()
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, sidecar_contract::EntitlementEvaluateResponse> {
        self.legacy_entitlement_calls
            .fetch_add(1, Ordering::Relaxed);
        unused()
    }

    fn fetch_jwks<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        unused()
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unused()
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unused()
    }
}
