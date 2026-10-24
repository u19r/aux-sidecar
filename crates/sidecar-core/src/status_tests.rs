use std::time::Duration;

use sidecar_contract::{
    RuntimeSyncArtifact, RuntimeSyncCapabilities, RuntimeSyncResponse, SyncArtifactKind,
};

use crate::{
    DeploymentPreset, LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngineConfig, SidecarState,
    status,
};

#[test]
fn readiness_given_required_fresh_state_then_is_ready() {
    let state = SidecarState::new();
    state.apply_runtime_sync(response(10_000)).unwrap();

    let ready = status::ready(&config(Duration::from_secs(1)), &state, true);

    assert!(ready.ready);
    assert!(ready.reason_codes.is_empty());
}

#[test]
fn readiness_given_expired_required_state_then_reports_stable_reason() {
    let state = SidecarState::new();
    state.apply_runtime_sync(response(0)).unwrap();
    std::thread::sleep(Duration::from_millis(2));

    let ready = status::ready(&config(Duration::ZERO), &state, true);

    assert!(!ready.ready);
    assert_eq!(ready.reason_codes, ["required_state_expired"]);
}

#[test]
fn readiness_given_state_inside_stale_window_then_remains_ready() {
    let state = SidecarState::new();
    state.apply_runtime_sync(response(0)).unwrap();
    std::thread::sleep(Duration::from_millis(2));

    let ready = status::ready(&config(Duration::from_secs(1)), &state, true);

    assert!(ready.ready);
}

#[test]
fn readiness_given_missing_host_transport_then_reports_unavailable() {
    let state = SidecarState::new();

    let ready = status::ready(&config(Duration::from_secs(1)), &state, false);

    assert!(!ready.ready);
    assert!(ready.reason_codes.contains(&"host_transport_unavailable"));
}

#[test]
fn readiness_given_newer_required_capability_then_reports_incompatible() {
    let state = SidecarState::new();
    let mut sync = response(10_000);
    sync.capabilities.authz = 2;
    state.apply_runtime_sync(sync).unwrap();

    let ready = status::ready(&config(Duration::from_secs(1)), &state, true);

    assert!(!ready.ready);
    assert_eq!(ready.reason_codes, ["capability_version_incompatible"]);
}

fn response(max_age_ms: u64) -> RuntimeSyncResponse {
    let kinds = [
        SyncArtifactKind::AuthzPolicy,
        SyncArtifactKind::AuthzEvaluationData,
        SyncArtifactKind::RateLimitConfig,
        SyncArtifactKind::Blocklist,
    ];
    RuntimeSyncResponse {
        protocol_version: 1,
        server_time: "2026-07-11T12:00:00Z".to_string(),
        refresh_after_ms: 1_000,
        artifacts: kinds
            .into_iter()
            .map(|kind| RuntimeSyncArtifact {
                key: "tenant".to_string(),
                version: "1".to_string(),
                etag: format!("etag-{}", kind.as_str()),
                immutable: matches!(kind, SyncArtifactKind::AuthzPolicy),
                max_age_ms: (!matches!(kind, SyncArtifactKind::AuthzPolicy)).then_some(max_age_ms),
                payload: match kind {
                    SyncArtifactKind::AuthzPolicy => serde_json::to_value(crate::state_tests::policy_snapshot(1)).unwrap(),
                    SyncArtifactKind::AuthzEvaluationData => serde_json::json!({"tenant_id":"tenant_test","policy_version":1,"generated_at_ms":1000}),
                    _ => serde_json::json!({}),
                },
                kind,
            })
            .collect(),
        unchanged: Vec::new(),
        capabilities: RuntimeSyncCapabilities {
            authz: 1,
            rate_limit: 1,
            entitlements: 1,
            blocklist: 1,
            combined_policy: 1,
            revocations: 1,
        },
    }
}

fn config(stale_cache_ttl: Duration) -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: DeploymentPreset::Kubernetes,
        base_url: "https://tenant.example.test".to_string(),
        api_key: "redacted".to_string(),
        tenant_domain: None,
        cache_ttl: Duration::from_secs(10),
        stale_cache_ttl,
        authz_local_mode: LocalAuthzMode::Enforced,
        authz_cache_ttl: Duration::from_secs(10),
        authz_stale_cache_ttl: stale_cache_ttl,
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::Never,
        jwt_validation: None,
    }
}
