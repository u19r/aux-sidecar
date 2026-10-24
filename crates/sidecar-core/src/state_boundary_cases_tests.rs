use super::*;
#[test]
fn authz_subject_cache_key_given_different_token_context_then_keys_are_reused() {
    let first = AuthzSubjectCacheKey::from_request(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &AuthzSubjectAccessSnapshotRequest {
            subject_type: "user".to_string(),
            id: "u_123".to_string(),
            include_principal_id: true,
        },
    );
    let second = AuthzSubjectCacheKey::from_request(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &AuthzSubjectAccessSnapshotRequest {
            subject_type: "user".to_string(),
            id: "u_123".to_string(),
            include_principal_id: true,
        },
    );

    assert_eq!(first, second);
}

#[test]
fn authz_subject_cache_key_given_different_tenant_then_keys_are_distinct() {
    let request = AuthzSubjectAccessSnapshotRequest {
        subject_type: "user".to_string(),
        id: "u_123".to_string(),
        include_principal_id: false,
    };
    let first = AuthzSubjectCacheKey::from_request(
        "tenant_a".to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &request,
    );
    let second = AuthzSubjectCacheKey::from_request(
        "tenant_b".to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &request,
    );

    assert_ne!(first, second);
}

#[test]
fn authz_subject_cache_key_given_principal_id_projection_difference_then_keys_are_distinct() {
    let without_principal_id = AuthzSubjectCacheKey::from_request(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &AuthzSubjectAccessSnapshotRequest {
            subject_type: "user".to_string(),
            id: "u_123".to_string(),
            include_principal_id: false,
        },
    );
    let with_principal_id = AuthzSubjectCacheKey::from_request(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &AuthzSubjectAccessSnapshotRequest {
            subject_type: "user".to_string(),
            id: "u_123".to_string(),
            include_principal_id: true,
        },
    );

    assert_ne!(without_principal_id, with_principal_id);
}

#[test]
fn authz_cached_value_reports_refresh_due_after_configured_percent() {
    let cached = CachedValue::new_with_refresh_after(
        "value",
        Duration::from_secs(10),
        Duration::from_secs(30),
        50,
        1_000,
    );

    assert_eq!(
        cached.authz_value(5_999).map(|(_, state)| state),
        Some(AuthzCachedValueState::Fresh)
    );
    assert_eq!(
        cached.authz_value(6_001).map(|(_, state)| state),
        Some(AuthzCachedValueState::RefreshDue)
    );
    assert_eq!(
        cached.authz_value(11_001).map(|(_, state)| state),
        Some(AuthzCachedValueState::Stale)
    );
    assert!(cached.authz_value(41_001).is_none());
}

#[test]
fn policy_pointer_refresh_jitter_stays_inside_safe_percentage_bounds() {
    for configured in [1, 50, 100] {
        for _ in 0..100 {
            let jittered = crate::state::jittered_policy_pointer_refresh_percent(configured);
            assert!((1..=100).contains(&jittered));
            assert!(i16::from(jittered).abs_diff(i16::from(configured)) <= 10);
        }
    }
}

#[test]
fn runtime_sync_given_invalid_later_artifact_then_applies_nothing() {
    let state = SidecarState::new();
    let valid = sync_artifact("v1", "etag-v1");
    state
        .apply_runtime_sync(sync_response(vec![valid]))
        .unwrap();
    let before = state.runtime_sync_snapshot();
    let mut invalid = sync_artifact("v2", "etag-v2");
    invalid.max_age_ms = None;

    assert!(
        state
            .apply_runtime_sync(sync_response(
                vec![sync_artifact("v2", "etag-v2"), invalid,]
            ))
            .is_err()
    );
    assert_eq!(state.runtime_sync_snapshot(), before);
}

#[test]
fn runtime_sync_atomic_apply_property_rejects_invalid_artifact_in_every_position() {
    for invalid_position in 0..4 {
        let state = SidecarState::new();
        state
            .apply_runtime_sync(sync_response(vec![sync_artifact("baseline", "baseline")]))
            .unwrap();
        let before = state.runtime_sync_snapshot();
        let mut artifacts = (0..4)
            .map(|index| {
                let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
                artifact.key = format!("tenant-{index}");
                artifact
            })
            .collect::<Vec<_>>();
        artifacts[invalid_position].max_age_ms = None;

        assert!(state.apply_runtime_sync(sync_response(artifacts)).is_err());
        assert_eq!(state.runtime_sync_snapshot(), before);
    }
}
