use std::{collections::BTreeMap, hint::black_box};

use sidecar_contract::{
    EntitlementDecision, EntitlementEvaluateRequest, EntitlementEvaluationResult,
    RuntimeSyncKnownVersions, RuntimeSyncRequest, SyncArtifactKind,
};

use crate::{
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
    state::RuntimeSyncSnapshot,
    state_tests::{sync_artifact, sync_response},
};

#[test]
fn runtime_sync_snapshot_clone_perf_loop_keeps_shared_artifacts() {
    let artifacts = (0..128)
        .map(|index| {
            let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
            artifact.kind = SyncArtifactKind::Entitlements;
            artifact.key = format!("org-{index:03}");
            artifact.payload = serde_json::json!({"values": vec!["x"; 16]});
            artifact
        })
        .collect::<Vec<_>>();
    let baseline = BTreeMap::from([(
        SyncArtifactKind::Entitlements,
        artifacts
            .iter()
            .cloned()
            .map(|artifact| (artifact.key.clone(), artifact))
            .collect::<BTreeMap<_, _>>(),
    )]);
    let snapshot =
        RuntimeSyncSnapshot::from_response(None, sync_response(artifacts)).expect("sync");

    let baseline_allocations = measure_allocations("baseline_owned_runtime_sync_artifacts", || {
        for _ in 0..100 {
            black_box(baseline.clone());
        }
    });
    let optimized_allocations =
        measure_allocations("optimized_shared_runtime_sync_artifacts", || {
            for _ in 0..100 {
                black_box(snapshot.clone());
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(baseline.clone());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(snapshot.clone());
        }
    });
    println!(
        "runtime_sync_snapshot_clone_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
#[ignore = "performance harness; run isolated with --ignored --test-threads=1"]
fn runtime_sync_internal_apply_perf_loop_avoids_discarded_response_clone() {
    let response = sync_response(
        (0..128)
            .map(|index| {
                let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
                artifact.kind = SyncArtifactKind::Entitlements;
                artifact.key = format!("org-{index:03}");
                artifact.payload = serde_json::json!({"values": vec!["x"; 16]});
                artifact
            })
            .collect(),
    );
    let baseline_allocations =
        measure_allocations("baseline_discarded_sync_response_clone", || {
            for _ in 0..100 {
                let returned = response.clone();
                let next =
                    RuntimeSyncSnapshot::from_response(None, returned.clone()).expect("sync");
                black_box((returned, next));
            }
        });
    let optimized_allocations =
        measure_allocations("optimized_consumed_internal_sync_response", || {
            for _ in 0..100 {
                let next =
                    RuntimeSyncSnapshot::from_response(None, response.clone()).expect("sync");
                black_box(next);
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            let returned = response.clone();
            let next = RuntimeSyncSnapshot::from_response(None, returned.clone()).expect("sync");
            black_box((returned, next));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            let next = RuntimeSyncSnapshot::from_response(None, response.clone()).expect("sync");
            black_box(next);
        }
    });
    println!(
        "runtime_sync_internal_apply_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn runtime_sync_large_artifact_read_perf_loop_keeps_payload_shared() {
    let mut artifact = sync_artifact("v1", "etag-large");
    artifact.kind = SyncArtifactKind::Entitlements;
    artifact.key = "org-large".to_string();
    artifact.payload = serde_json::json!({
        "response": {
            "items": (0..10_000)
                .map(|index| EntitlementEvaluationResult {
                    key: format!("feature.{index:05}"),
                    decision: EntitlementDecision::NotEntitled,
                    used_entitlements: Vec::new(),
                })
                .collect::<Vec<_>>()
        },
        "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": null
    });
    let state = crate::SidecarState::new();
    state
        .apply_runtime_sync(sync_response(vec![artifact]))
        .expect("sync");

    let baseline_allocations = measure_allocations("baseline_owned_large_artifact_read", || {
        for _ in 0..100 {
            black_box(state.runtime_sync_artifact(SyncArtifactKind::Entitlements, "org-large"));
        }
    });
    let optimized_allocations = measure_allocations("optimized_shared_large_artifact_read", || {
        for _ in 0..100 {
            black_box(
                state.shared_runtime_sync_artifact(SyncArtifactKind::Entitlements, "org-large"),
            );
        }
    });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(state.runtime_sync_artifact(SyncArtifactKind::Entitlements, "org-large"));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(
                state.shared_runtime_sync_artifact(SyncArtifactKind::Entitlements, "org-large"),
            );
        }
    });
    println!(
        "runtime_sync_large_artifact_read_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn runtime_sync_narrow_known_versions_perf_loop_skips_unrequested_catalogs() {
    let mut artifacts = (0..10_000)
        .map(|index| {
            let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
            artifact.kind = SyncArtifactKind::Entitlements;
            artifact.key = format!("org-{index:05}");
            artifact
        })
        .collect::<Vec<_>>();
    let mut jwks = sync_artifact("jwks-v1", "jwks-etag");
    jwks.kind = SyncArtifactKind::Jwks;
    artifacts.push(jwks);
    let snapshot =
        RuntimeSyncSnapshot::from_response(None, sync_response(artifacts)).expect("sync");
    let request = RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::Jwks],
        authz: None,
        entitlements: Vec::<EntitlementEvaluateRequest>::new(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    };

    let baseline_allocations = measure_allocations("baseline_all_known_versions", || {
        for _ in 0..100 {
            black_box(snapshot.known_versions());
        }
    });
    let optimized_allocations = measure_allocations("optimized_requested_known_versions", || {
        for _ in 0..100 {
            black_box(snapshot.known_versions_for(&request));
        }
    });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(snapshot.known_versions());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(snapshot.known_versions_for(&request));
        }
    });
    println!(
        "runtime_sync_narrow_known_versions_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn runtime_sync_unrelated_update_perf_loop_shares_unchanged_kind_map() {
    let entitlement_artifacts = (0..10_000)
        .map(|index| {
            let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
            artifact.kind = SyncArtifactKind::Entitlements;
            artifact.key = format!("org-{index:05}");
            artifact
        })
        .collect::<Vec<_>>();
    let baseline = BTreeMap::from([(
        SyncArtifactKind::Entitlements,
        entitlement_artifacts
            .iter()
            .cloned()
            .map(|artifact| (artifact.key.clone(), std::sync::Arc::new(artifact)))
            .collect::<BTreeMap<_, _>>(),
    )]);
    let snapshot = RuntimeSyncSnapshot::from_response(None, sync_response(entitlement_artifacts))
        .expect("sync");
    let mut jwks = sync_artifact("jwks-v2", "jwks-etag-v2");
    jwks.kind = SyncArtifactKind::Jwks;
    let response = sync_response(vec![jwks]);

    let baseline_allocations =
        measure_allocations("baseline_clone_all_kind_maps_for_update", || {
            for _ in 0..100 {
                let mut next = baseline.clone();
                next.entry(SyncArtifactKind::Jwks).or_default();
                black_box(next);
            }
        });
    let optimized_allocations = measure_allocations("optimized_share_unchanged_kind_maps", || {
        for _ in 0..100 {
            black_box(
                RuntimeSyncSnapshot::from_response(Some(&snapshot), response.clone())
                    .expect("update"),
            );
        }
    });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            let mut next = baseline.clone();
            next.entry(SyncArtifactKind::Jwks).or_default();
            black_box(next);
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(
                RuntimeSyncSnapshot::from_response(Some(&snapshot), response.clone())
                    .expect("update"),
            );
        }
    });
    println!(
        "runtime_sync_unrelated_update_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn runtime_sync_unchanged_kind_perf_loop_refreshes_once_per_kind() {
    let entitlement_artifacts = (0..10_000)
        .map(|index| {
            let mut artifact = sync_artifact(&format!("v{index}"), &format!("etag-{index}"));
            artifact.kind = SyncArtifactKind::Entitlements;
            artifact.key = format!("org-{index:05}");
            artifact
        })
        .collect::<Vec<_>>();
    let baseline = entitlement_artifacts
        .iter()
        .cloned()
        .map(|artifact| (artifact.key.clone(), (std::sync::Arc::new(artifact), 1_i64)))
        .collect::<BTreeMap<_, _>>();
    let snapshot = RuntimeSyncSnapshot::from_response(None, sync_response(entitlement_artifacts))
        .expect("sync");
    let mut response = sync_response(Vec::new());
    response.unchanged = vec![SyncArtifactKind::Entitlements];

    let baseline_allocations =
        measure_allocations("baseline_refresh_every_unchanged_artifact", || {
            for _ in 0..100 {
                let mut next = baseline.clone();
                for stored in next.values_mut() {
                    stored.1 = 2;
                }
                black_box(next);
            }
        });
    let optimized_allocations =
        measure_allocations("optimized_refresh_unchanged_kind_once", || {
            for _ in 0..100 {
                black_box(
                    RuntimeSyncSnapshot::from_response(Some(&snapshot), response.clone())
                        .expect("refresh"),
                );
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            let mut next = baseline.clone();
            for stored in next.values_mut() {
                stored.1 = 2;
            }
            black_box(next);
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(
                RuntimeSyncSnapshot::from_response(Some(&snapshot), response.clone())
                    .expect("refresh"),
            );
        }
    });
    println!(
        "runtime_sync_unchanged_kind_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn runtime_sync_large_flight_key_perf_loop_shares_request() {
    let request = RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::Entitlements],
        authz: None,
        entitlements: (0..256)
            .map(|org| EntitlementEvaluateRequest {
                org_id: format!("org-{org:03}"),
                at_time: None,
                keys: Some((0..100).map(|key| format!("feature.{key:03}")).collect()),
            })
            .collect(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    };
    let shared = std::sync::Arc::new(request.clone());

    let baseline_allocations = measure_allocations("baseline_clone_large_sync_flight_key", || {
        for _ in 0..100 {
            black_box(request.clone());
        }
    });
    let optimized_allocations =
        measure_allocations("optimized_share_large_sync_flight_key", || {
            for _ in 0..100 {
                black_box(std::sync::Arc::clone(&shared));
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(request.clone());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(std::sync::Arc::clone(&shared));
        }
    });
    println!(
        "runtime_sync_large_flight_key_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}
