use std::{collections::BTreeMap, sync::Arc, time::Duration};

use sidecar_contract::SyncArtifactKind;

use crate::{
    SidecarState,
    state_tests::{sync_artifact, sync_response},
};

#[test]
fn runtime_sync_known_versions_given_narrow_request_then_only_returns_requested_state() {
    let mut org_a = sync_artifact("ent-a", "etag-ent-a");
    org_a.kind = SyncArtifactKind::Entitlements;
    org_a.key = "org-a".to_string();
    let mut org_b = sync_artifact("ent-b", "etag-ent-b");
    org_b.kind = SyncArtifactKind::Entitlements;
    org_b.key = "org-b".to_string();
    let mut jwks = sync_artifact("jwks", "etag-jwks");
    jwks.kind = SyncArtifactKind::Jwks;
    let state = SidecarState::new();
    state
        .apply_runtime_sync(sync_response(vec![org_a, org_b, jwks]))
        .unwrap();
    let request = sidecar_contract::RuntimeSyncRequest {
        protocol_version: 1,
        known: sidecar_contract::RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::Entitlements],
        authz: None,
        entitlements: vec![sidecar_contract::EntitlementEvaluateRequest {
            org_id: "org-b".to_string(),
            at_time: None,
            keys: None,
        }],
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    };

    let known = state.runtime_sync_known_versions_for(&request);

    assert_eq!(
        known.entitlements,
        BTreeMap::from([("org-b".to_string(), "ent-b".to_string())])
    );
    assert!(known.jwks.is_none());
}

#[test]
fn runtime_sync_unchanged_kind_then_refreshes_age_without_replacing_artifact() {
    let state = SidecarState::new();
    let mut artifact = sync_artifact("v1", "etag-v1");
    artifact.kind = SyncArtifactKind::Blocklist;
    state
        .apply_runtime_sync(sync_response(vec![artifact]))
        .unwrap();
    let (before, before_ms) = state
        .shared_runtime_sync_artifact_with_age(SyncArtifactKind::Blocklist, "tenant")
        .unwrap();
    std::thread::sleep(Duration::from_millis(2));
    let mut refresh = sync_response(Vec::new());
    refresh.server_time = "2026-07-11T12:00:01Z".to_string();
    refresh.unchanged = vec![SyncArtifactKind::Blocklist];
    state.apply_runtime_sync(refresh).unwrap();
    let (after, after_ms) = state
        .shared_runtime_sync_artifact_with_age(SyncArtifactKind::Blocklist, "tenant")
        .unwrap();

    assert!(Arc::ptr_eq(&before, &after));
    assert!(after_ms > before_ms);
}

#[test]
fn runtime_sync_distinct_artifacts_are_evicted_at_the_aggregate_bound() {
    let state = SidecarState::new();

    for index in 0..=crate::constants::MAX_RUNTIME_SYNC_ARTIFACTS {
        let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
        artifact.kind = SyncArtifactKind::Entitlements;
        artifact.key = format!("org-{index}");
        state
            .apply_runtime_sync(sync_response(vec![artifact]))
            .expect("distinct runtime artifact should apply");
    }

    assert_eq!(
        state.runtime_sync_snapshot().artifact_count(),
        crate::constants::MAX_RUNTIME_SYNC_ARTIFACTS
    );
}
