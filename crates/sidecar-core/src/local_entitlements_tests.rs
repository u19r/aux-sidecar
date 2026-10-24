use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
};

use sidecar_contract::{
    EntitlementDecision, EntitlementEvaluateRequest, EntitlementEvaluationResult,
};

use crate::{
    local_entitlements::LocalEntitlementSnapshot,
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
};

#[test]
fn entitlement_filter_perf_loop_keeps_borrowed_lookup() {
    let items = (0..128)
        .map(|index| EntitlementEvaluationResult {
            key: format!("feature.{index:03}"),
            decision: EntitlementDecision::NotEntitled,
            used_entitlements: Vec::new(),
        })
        .collect::<Vec<_>>();
    let requested = ["feature.003", "feature.064", "feature.127"];
    let snapshot = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {"items": items.clone()}, "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": null,
    }))
    .expect("compiled entitlement snapshot");
    let request = EntitlementEvaluateRequest {
        org_id: "org_perf".into(),
        at_time: None,
        keys: Some(requested.iter().map(|key| (*key).to_string()).collect()),
    };
    let expected = requested
        .iter()
        .map(|key| items.iter().find(|item| item.key == *key).unwrap().clone())
        .collect::<Vec<_>>();
    assert_eq!(snapshot.evaluate(&request).items, expected);

    let baseline = measure_allocations("baseline_entitlement_owned_btree", || {
        for _ in 0..1_000 {
            let mut lookup = items
                .iter()
                .cloned()
                .map(|item| (item.key.clone(), item))
                .collect::<BTreeMap<_, _>>();
            black_box(
                requested
                    .iter()
                    .map(|key| lookup.remove(*key).expect("item"))
                    .collect::<Vec<_>>(),
            );
        }
    });
    let optimized = measure_allocations("optimized_entitlement_compiled_index", || {
        for _ in 0..1_000 {
            black_box(snapshot.evaluate(&request));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            let mut lookup = items
                .iter()
                .cloned()
                .map(|item| (item.key.clone(), item))
                .collect::<BTreeMap<_, _>>();
            for key in &requested {
                black_box(lookup.remove(*key));
            }
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            black_box(snapshot.evaluate(&request));
        }
    });
    println!(
        "entitlement_filter_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(optimized.allocated_bytes < baseline.allocated_bytes);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn entitlement_coverage_perf_loop_keeps_sorted_vector() {
    let keys = (0..128)
        .rev()
        .map(|index| format!("feature.{index:03}"))
        .collect::<Vec<_>>();
    let baseline = measure_allocations("baseline_entitlement_coverage_btree", || {
        for _ in 0..1_000 {
            black_box(keys.iter().cloned().collect::<BTreeSet<_>>());
        }
    });
    let optimized = measure_allocations("optimized_entitlement_coverage_sorted_vec", || {
        for _ in 0..1_000 {
            let mut sorted = keys.clone();
            sorted.sort_unstable();
            sorted.dedup();
            black_box(sorted);
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            black_box(keys.iter().cloned().collect::<BTreeSet<_>>());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            let mut sorted = keys.clone();
            sorted.sort_unstable();
            sorted.dedup();
            black_box(sorted);
        }
    });
    println!(
        "entitlement_coverage_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn entitlement_large_catalog_perf_loop_keeps_compiled_index() {
    const ITEMS: usize = 10_000;
    const ITERATIONS: usize = 100;
    let items = (0..ITEMS)
        .map(|index| EntitlementEvaluationResult {
            key: format!("feature.{index:05}"),
            decision: EntitlementDecision::NotEntitled,
            used_entitlements: Vec::new(),
        })
        .collect::<Vec<_>>();
    let snapshot = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {"items": items.clone()},
        "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": null
    }))
    .expect("large entitlement snapshot");
    let request = EntitlementEvaluateRequest {
        org_id: "org_perf".to_string(),
        at_time: None,
        keys: Some(vec![
            "feature.00003".to_string(),
            "feature.05000".to_string(),
            "feature.09999".to_string(),
        ]),
    };

    let baseline_allocations = measure_allocations("baseline_large_entitlement_reindex", || {
        for _ in 0..ITERATIONS {
            let lookup = items
                .iter()
                .map(|item| (item.key.as_str(), item))
                .collect::<std::collections::HashMap<_, _>>();
            black_box(
                request
                    .keys
                    .as_ref()
                    .expect("keys")
                    .iter()
                    .filter_map(|key| lookup.get(key.as_str()).copied().cloned())
                    .collect::<Vec<_>>(),
            );
        }
    });
    let optimized_allocations =
        measure_allocations("optimized_large_entitlement_compiled_index", || {
            for _ in 0..ITERATIONS {
                black_box(snapshot.evaluate(&request));
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..ITERATIONS {
            let lookup = items
                .iter()
                .map(|item| (item.key.as_str(), item))
                .collect::<std::collections::HashMap<_, _>>();
            black_box(lookup.get("feature.09999"));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..ITERATIONS {
            black_box(snapshot.evaluate(&request));
        }
    });
    println!(
        "entitlement_large_catalog_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn local_entitlements_given_scoped_snapshot_then_returns_grants_and_missing_denials() {
    let snapshot = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {
            "items": [{
                "key": "feature.enabled",
                "decision": {"decision": "granted", "value": true},
                "used_entitlements": []
            }]
        },
        "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": ["feature.enabled", "feature.missing"]
    }))
    .unwrap();
    let request = EntitlementEvaluateRequest {
        org_id: "org_fixture".to_string(),
        at_time: None,
        keys: Some(vec![
            "feature.enabled".to_string(),
            "feature.missing".to_string(),
        ]),
    };

    let response = snapshot.evaluate(&request);

    assert!(matches!(
        response.items[0].decision,
        EntitlementDecision::Granted { .. }
    ));
    assert_eq!(response.items[1].decision, EntitlementDecision::NotEntitled);
    assert!(snapshot.covers(&request));
}

#[test]
fn local_entitlements_given_expired_snapshot_then_reports_invalid_for_warm_use() {
    let snapshot = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {"items": []},
        "valid_until_ms": 100,
        "requested_keys": null
    }))
    .unwrap();

    assert!(!snapshot.is_valid(101));
}

#[test]
fn local_entitlements_given_partial_key_snapshot_then_rejects_uncovered_request() {
    let snapshot = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {"items": []},
        "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": ["feature.a"]
    }))
    .unwrap();
    let request = EntitlementEvaluateRequest {
        org_id: "org_fixture".to_string(),
        at_time: None,
        keys: Some(vec!["feature.a".to_string(), "feature.b".to_string()]),
    };

    assert!(!snapshot.covers(&request));
}

#[test]
fn local_entitlements_given_invalid_expiry_then_fails_closed_during_compile() {
    let error = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {"items": []},
        "valid_until_ms": 0,
        "requested_keys": null
    }))
    .unwrap_err();

    assert_eq!(error.code, "runtime_sync_entitlements_invalid");
}

#[test]
fn local_entitlements_given_duplicate_response_key_then_fails_closed_during_compile() {
    let error = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {
            "items": [
                {"key": "feature.same", "decision": "not_entitled", "used_entitlements": []},
                {"key": "feature.same", "decision": "denied", "used_entitlements": []}
            ]
        },
        "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": null
    }))
    .unwrap_err();

    assert_eq!(error.code, "runtime_sync_entitlements_invalid");
}

#[test]
fn local_entitlements_given_duplicate_requested_key_then_fails_closed_during_compile() {
    let error = LocalEntitlementSnapshot::compile(serde_json::json!({
        "response": {"items": []},
        "valid_until_ms": 4_102_444_800_000_i64,
        "requested_keys": ["feature.same", "feature.same"]
    }))
    .unwrap_err();

    assert_eq!(error.code, "runtime_sync_entitlements_invalid");
}
