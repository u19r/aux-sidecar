use super::*;
#[test]
#[ignore = "performance harness; run isolated with --ignored --test-threads=1"]
fn runtime_sync_apply_perf_loop_keeps_move_into_state() {
    let response = sync_response(
        (0..128)
            .map(|index| {
                let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
                artifact.key = format!("tenant-{index}");
                artifact.payload = serde_json::json!({"values": vec!["x"; 16]});
                artifact
            })
            .collect(),
    );
    let baseline = measure_allocations("baseline_runtime_sync_clone_next_snapshot", || {
        for _ in 0..100 {
            let next = RuntimeSyncSnapshot::from_response(None, response.clone()).expect("sync");
            black_box(next.clone());
        }
    });
    let optimized = measure_allocations("optimized_runtime_sync_move_next_snapshot", || {
        for _ in 0..100 {
            let next = RuntimeSyncSnapshot::from_response(None, response.clone()).expect("sync");
            black_box(next);
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            let next = RuntimeSyncSnapshot::from_response(None, response.clone()).expect("sync");
            black_box(next.clone());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            let next = RuntimeSyncSnapshot::from_response(None, response.clone()).expect("sync");
            black_box(next);
        }
    });
    println!(
        "runtime_sync_apply_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(optimized_cpu <= baseline_cpu);
}

#[test]
fn runtime_sync_artifact_lookup_perf_loop_prefers_nested_map() {
    let kind = SyncArtifactKind::Entitlements;
    let flat = (0..128)
        .map(|index| ((kind.clone(), format!("org-{index:03}")), index))
        .collect::<BTreeMap<_, _>>();
    let nested = BTreeMap::from([(
        kind.clone(),
        (0..128)
            .map(|index| (format!("org-{index:03}"), index))
            .collect::<BTreeMap<_, _>>(),
    )]);
    let key = "org-127";
    let baseline = measure_allocations("baseline_runtime_sync_flat_lookup", || {
        for _ in 0..100_000 {
            black_box(flat.get(&(kind.clone(), key.to_owned())));
        }
    });
    let optimized = measure_allocations("optimized_runtime_sync_nested_lookup", || {
        for _ in 0..100_000 {
            black_box(nested.get(&kind).and_then(|values| values.get(key)));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..100_000 {
            black_box(flat.get(&(kind.clone(), key.to_owned())));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100_000 {
            black_box(nested.get(&kind).and_then(|values| values.get(key)));
        }
    });
    println!(
        "runtime_sync_artifact_lookup_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn immutable_policy_snapshot_given_time_beyond_mutable_ttls_then_remains_cached() {
    let state = SidecarState::new();
    let snapshot = policy_snapshot(TEST_AUTHZ_POLICY_VERSION);
    state.store_authz_policy_snapshot(snapshot);

    let cached = state.authz_policy_snapshot(TEST_AUTHZ_POLICY_VERSION, i64::MAX);
    let missing = state.authz_policy_snapshot(TEST_AUTHZ_POLICY_VERSION + 1, i64::MAX);

    assert!(
        cached.is_some(),
        "immutable snapshot retention is not TTL-bound"
    );
    assert!(missing.is_none());
    let metrics = state.authz_cache_metrics();
    assert_eq!(metrics.policy.hits, 1);
    assert_eq!(metrics.policy.misses, 1);
}

#[test]
fn immutable_policy_cache_given_capacity_pressure_then_evicts_lru_version_only() {
    let state = SidecarState::new();
    for version in 1..=64 {
        state.store_authz_policy_snapshot(policy_snapshot(version));
    }
    assert!(state.authz_policy_snapshot(1, i64::MAX).is_some());

    state.store_authz_policy_snapshot(policy_snapshot(65));

    assert!(state.authz_policy_snapshot(1, i64::MAX).is_some());
    assert!(state.authz_policy_snapshot(2, i64::MAX).is_none());
    assert!(state.authz_policy_snapshot(65, i64::MAX).is_some());
    assert_eq!(state.authz_cache_metrics().policy.evictions, 1);
}

#[test]
fn current_policy_version_change_selects_new_immutable_key_and_preserves_old_version() {
    let state = SidecarState::new();
    state.store_authz_policy_snapshot(policy_snapshot(42));
    state.store_authz_policy_snapshot(policy_snapshot(43));
    for version in [42, 43] {
        state.store_authz_policy_version(
            AuthzPolicyVersionSnapshot {
                tenant_id: "tenant_test".to_string(),
                current_policy_version: version,
                generated_at_ms: 1_000,
            },
            Duration::from_secs(10),
            Duration::from_secs(30),
            50,
        );
    }

    let current = state
        .authz_policy_version(crate::state::current_time_millis())
        .expect("current version");

    assert_eq!(current.0.current_policy_version, 43);
    assert!(state.authz_policy_snapshot(42, i64::MAX).is_some());
    assert!(state.authz_policy_snapshot(43, i64::MAX).is_some());
}

#[test]
fn immutable_evaluation_runtime_given_time_advance_then_reuses_same_arc() {
    let state = SidecarState::new();
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![],
        permissions: vec![],
        roles: vec![],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: std::collections::HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
    .into_validated()
    .expect("valid empty config");
    let bundle = authz_cedar::compile_policy_bundle(&config, TEST_AUTHZ_POLICY_VERSION)
        .expect("empty bundle");
    let runtime = Arc::new(
        authz_runtime::EvaluationRuntime::build(config, &bundle).expect("evaluation runtime"),
    );
    state.store_authz_evaluation_runtime(TEST_AUTHZ_POLICY_VERSION, Arc::clone(&runtime));

    let cached = state
        .authz_evaluation_runtime(TEST_AUTHZ_POLICY_VERSION, i64::MAX)
        .expect("immutable runtime");

    assert!(Arc::ptr_eq(&runtime, &cached.0));
    assert_eq!(cached.1, AuthzCachedValueState::Fresh);
}

#[test]
fn authz_refresh_guard_allows_one_in_flight_refresh_per_key() {
    let state = SidecarState::new();
    let key = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::new(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        "user".to_string(),
        "u_123".to_string(),
        true,
    ));

    assert!(state.try_begin_authz_refresh(key.clone()));
    assert!(!state.try_begin_authz_refresh(key.clone()));

    state.finish_authz_refresh(&key);

    assert!(state.try_begin_authz_refresh(key));
}

#[test]
fn authz_refresh_guard_tracks_subject_and_resource_independently() {
    let state = SidecarState::new();
    let subject = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::from_request(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &AuthzSubjectAccessSnapshotRequest {
            subject_type: "user".to_string(),
            id: "u_123".to_string(),
            include_principal_id: false,
        },
    ));
    let resource_request = sidecar_contract::AuthzResourceAccessSnapshotRequest {
        resource_type: "document".to_string(),
        id: "doc_123".to_string(),
    };
    let resource = AuthzRefreshKey::Resource(crate::AuthzResourceCacheKey::from_request(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        &resource_request,
    ));

    assert!(state.try_begin_authz_refresh(subject.clone()));
    assert!(state.try_begin_authz_refresh(resource.clone()));
    assert!(!state.try_begin_authz_refresh(subject.clone()));
    assert!(!state.try_begin_authz_refresh(resource.clone()));

    state.finish_authz_refresh(&subject);
    state.finish_authz_refresh(&resource);
    assert!(state.try_begin_authz_refresh(subject));
    assert!(state.try_begin_authz_refresh(resource));
}

#[test]
fn authz_refresh_guard_rejects_new_keys_at_the_bound() {
    let state = SidecarState::new();

    for index in 0..crate::constants::MAX_AUTHZ_REFRESHES {
        let key = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::new(
            TEST_AUTHZ_TENANT_ID.to_string(),
            TEST_AUTHZ_POLICY_VERSION,
            "user".to_string(),
            format!("u_{index}"),
            false,
        ));
        assert!(state.try_begin_authz_refresh(key));
    }

    let extra = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::new(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        "user".to_string(),
        "u_extra".to_string(),
        false,
    ));
    assert!(!state.try_begin_authz_refresh(extra.clone()));

    let released = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::new(
        TEST_AUTHZ_TENANT_ID.to_string(),
        TEST_AUTHZ_POLICY_VERSION,
        "user".to_string(),
        "u_0".to_string(),
        false,
    ));
    state.finish_authz_refresh(&released);
    assert!(state.try_begin_authz_refresh(extra));
}

#[test]
fn sync_flight_registry_rejects_new_keys_at_the_bound() {
    let state = SidecarState::new();

    for index in 0..crate::constants::MAX_ACTIVE_SYNC_FLIGHTS {
        let (id, _) = state.sync_flight((Arc::new(sync_request(index)), false), sync_flight_future);
        assert_ne!(id, 0);
    }
    assert_eq!(
        state.active_sync_flight_count(),
        crate::constants::MAX_ACTIVE_SYNC_FLIGHTS
    );

    let (id, _) = state.sync_flight(
        (Arc::new(sync_request(usize::MAX)), false),
        sync_flight_future,
    );
    assert_eq!(id, 0);
    assert_eq!(
        state.active_sync_flight_count(),
        crate::constants::MAX_ACTIVE_SYNC_FLIGHTS
    );

    state.finish_sync_flight(1);
    let (id, _) = state.sync_flight(
        (Arc::new(sync_request(usize::MAX - 1)), false),
        sync_flight_future,
    );
    assert_ne!(id, 0);
}
