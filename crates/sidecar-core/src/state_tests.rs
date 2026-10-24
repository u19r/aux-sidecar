use std::{collections::BTreeMap, hint::black_box, sync::Arc, time::Duration};

use futures::FutureExt;
use sidecar_contract::{
    AuthzPolicySnapshot, AuthzPolicyVersionSnapshot, AuthzSubjectAccessSnapshotRequest,
    RuntimeSyncArtifact, RuntimeSyncCapabilities, RuntimeSyncResponse, SyncArtifactKind,
};

use crate::{
    AuthzCachedValueState, AuthzRefreshKey, AuthzSubjectCacheKey, CachedValue, SidecarState,
    constants::TEST_AUTHZ_POLICY_VERSION,
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
    state::{RuntimeSyncSnapshot, SyncFlightFuture},
};

const TEST_AUTHZ_TENANT_ID: &str = "tenant_123";

#[path = "state_boundary_cases_tests.rs"]
mod state_boundary_cases;
#[path = "state_cases_tests.rs"]
mod state_cases;

pub(crate) fn policy_snapshot(version: u64) -> AuthzPolicySnapshot {
    AuthzPolicySnapshot {
        tenant_id: "tenant_test".to_string(),
        policy_version: version,
        config_hash: format!("hash_{version}"),
        config: serde_json::json!({}),
        compiled_bundle: serde_json::json!({}),
        generated_at_ms: 1_000,
        max_age_seconds: None,
    }
}

fn sync_request(index: usize) -> sidecar_contract::RuntimeSyncRequest {
    sidecar_contract::RuntimeSyncRequest {
        protocol_version: 1,
        known: sidecar_contract::RuntimeSyncKnownVersions::default(),
        want: vec![sidecar_contract::SyncArtifactKind::Entitlements],
        authz: None,
        entitlements: vec![sidecar_contract::EntitlementEvaluateRequest {
            org_id: format!("org_{index}"),
            at_time: None,
            keys: None,
        }],
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    }
}

fn sync_flight_future() -> SyncFlightFuture {
    async { Ok(None) }.boxed().shared()
}
pub(crate) fn sync_artifact(version: &str, etag: &str) -> RuntimeSyncArtifact {
    RuntimeSyncArtifact {
        kind: SyncArtifactKind::RateLimitConfig,
        key: "tenant".to_string(),
        version: version.to_string(),
        etag: etag.to_string(),
        immutable: false,
        max_age_ms: Some(5_000),
        payload: serde_json::json!({}),
    }
}

pub(crate) fn sync_response(artifacts: Vec<RuntimeSyncArtifact>) -> RuntimeSyncResponse {
    RuntimeSyncResponse {
        protocol_version: 1,
        server_time: "2026-07-11T12:00:00Z".to_string(),
        refresh_after_ms: 5_000,
        artifacts,
        unchanged: Vec::new(),
        capabilities: RuntimeSyncCapabilities::default(),
    }
}
