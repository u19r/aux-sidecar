use crate::{
    SidecarState,
    state_tests::{sync_artifact, sync_response},
};

#[test]
fn runtime_sync_given_immutable_identity_changes_then_rejects_conflict() {
    let state = SidecarState::new();
    let mut first = sync_artifact("42", "etag-a");
    first.kind = sidecar_contract::SyncArtifactKind::AuthzPolicy;
    first.payload = serde_json::to_value(crate::state_tests::policy_snapshot(42)).unwrap();
    first.immutable = true;
    first.max_age_ms = None;
    state
        .apply_runtime_sync(sync_response(vec![first.clone()]))
        .unwrap();
    first.etag = "etag-b".to_string();

    let error = state
        .apply_runtime_sync(sync_response(vec![first]))
        .unwrap_err();

    assert_eq!(error.code, "runtime_sync_immutable_conflict");
}

#[test]
fn runtime_sync_given_out_of_order_response_then_preserves_newer_visible_state() {
    let state = SidecarState::new();
    let mut newer = sync_response(vec![sync_artifact("new", "etag-new")]);
    newer.server_time = "2026-07-11T12:00:01Z".to_string();
    state.apply_runtime_sync(newer).unwrap();
    let before = state.runtime_sync_snapshot();
    let mut older = sync_response(vec![sync_artifact("old", "etag-old")]);
    older.server_time = "2026-07-11T12:00:00Z".to_string();

    let error = state.apply_runtime_sync(older).unwrap_err();

    assert_eq!(error.code, "runtime_sync_out_of_order");
    assert_eq!(state.runtime_sync_snapshot(), before);
}

#[test]
fn runtime_sync_given_invalid_initial_server_time_then_rejects_before_state_change() {
    let state = SidecarState::new();
    let mut response = sync_response(vec![sync_artifact("v1", "etag-v1")]);
    response.server_time = "not-a-timestamp".to_string();

    let error = state.apply_runtime_sync(response).unwrap_err();

    assert_eq!(error.code, "runtime_sync_invalid");
    assert_eq!(state.runtime_sync_snapshot(), Default::default());
}
