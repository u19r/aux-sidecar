use std::hint::black_box;

use sidecar_contract::{EntitlementDecision, EntitlementEvaluationResult};

use crate::{
    local_blocklist::LocalBlocklistRuntime,
    local_entitlements::LocalEntitlementSnapshot,
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
};

#[test]
fn entitlement_large_artifact_compile_perf_loop_deserializes_borrowed_payload() {
    let payload = serde_json::json!({
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
    let baseline_allocations =
        measure_allocations("baseline_clone_then_compile_entitlements", || {
            for _ in 0..10 {
                black_box(LocalEntitlementSnapshot::compile(payload.clone()).expect("compile"));
            }
        });
    let optimized_allocations =
        measure_allocations("optimized_borrow_compile_entitlements", || {
            for _ in 0..10 {
                black_box(
                    LocalEntitlementSnapshot::compile_borrowed(&payload).expect("compile borrowed"),
                );
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..10 {
            black_box(LocalEntitlementSnapshot::compile(payload.clone()).expect("compile"));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..10 {
            black_box(
                LocalEntitlementSnapshot::compile_borrowed(&payload).expect("compile borrowed"),
            );
        }
    });
    println!(
        "entitlement_large_artifact_compile_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocated_bytes < baseline_allocations.allocated_bytes);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn blocklist_large_artifact_compile_perf_loop_deserializes_borrowed_payload() {
    let payload = serde_json::json!({
        "builtin_ip_ranges": (0..10_000)
            .map(|index| serde_json::json!({
                "ip_range": format!("10.{}.{}.{}/32", index / 65_536, (index / 256) % 256, index % 256)
            }))
            .collect::<Vec<_>>(),
        "tenant_ip_ranges": [],
        "builtin_regions": [],
        "tenant_regions": []
    });
    let baseline_allocations = measure_allocations("baseline_clone_then_compile_blocklist", || {
        for _ in 0..10 {
            black_box(LocalBlocklistRuntime::compile(payload.clone()).expect("compile"));
        }
    });
    let optimized_allocations = measure_allocations("optimized_borrow_compile_blocklist", || {
        for _ in 0..10 {
            black_box(LocalBlocklistRuntime::compile_borrowed(&payload).expect("compile borrowed"));
        }
    });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..10 {
            black_box(LocalBlocklistRuntime::compile(payload.clone()).expect("compile"));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..10 {
            black_box(LocalBlocklistRuntime::compile_borrowed(&payload).expect("compile borrowed"));
        }
    });
    println!(
        "blocklist_large_artifact_compile_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocated_bytes < baseline_allocations.allocated_bytes);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
#[ignore = "performance harness; run as one isolated release test"]
fn blocklist_large_artifact_compile_perf_loop_consumes_rule_strings() {
    let payload = serde_json::json!({
        "builtin_ip_ranges": (0..10_000)
            .map(|index| serde_json::json!({
                "ip_range": format!("10.{}.{}.{}/32", index / 65_536, (index / 256) % 256, index % 256)
            }))
            .collect::<Vec<_>>(),
        "tenant_ip_ranges": [],
        "builtin_regions": [],
        "tenant_regions": []
    });
    let baseline_allocations = measure_allocations("baseline_blocklist_clone_rule_strings", || {
        for _ in 0..10 {
            black_box(
                LocalBlocklistRuntime::compile_borrowed_legacy(&payload).expect("legacy compile"),
            );
        }
    });
    let optimized_allocations =
        measure_allocations("optimized_blocklist_consume_rule_strings", || {
            for _ in 0..10 {
                black_box(LocalBlocklistRuntime::compile_borrowed(&payload).expect("compile"));
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..10 {
            black_box(
                LocalBlocklistRuntime::compile_borrowed_legacy(&payload).expect("legacy compile"),
            );
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..10 {
            black_box(LocalBlocklistRuntime::compile_borrowed(&payload).expect("compile"));
        }
    });
    println!(
        "blocklist_large_artifact_consume_strings_cpu baseline_ns={} optimized_ns={} \
         improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(optimized_allocations.allocated_bytes < baseline_allocations.allocated_bytes);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
#[ignore = "performance harness; run as one isolated release test"]
fn blocklist_large_region_compile_perf_loop_uses_sorted_countries() {
    let countries = (0..1_296)
        .map(|index| {
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            format!(
                "{}{}",
                char::from(alphabet[index / alphabet.len()]),
                char::from(alphabet[index % alphabet.len()])
            )
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "builtin_ip_ranges": [],
        "tenant_ip_ranges": [],
        "builtin_regions": countries
            .iter()
            .map(|country| serde_json::json!({"region_country": country}))
            .collect::<Vec<_>>(),
        "tenant_regions": []
    });
    let baseline_allocations =
        measure_allocations("baseline_blocklist_country_normalize_copy", || {
            for _ in 0..100 {
                black_box(
                    LocalBlocklistRuntime::compile_borrowed_legacy(&payload)
                        .expect("legacy region compile"),
                );
            }
        });
    let optimized_allocations =
        measure_allocations("optimized_blocklist_country_normalize_owned", || {
            for _ in 0..100 {
                black_box(
                    LocalBlocklistRuntime::compile_borrowed(&payload).expect("region compile"),
                );
            }
        });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(
                LocalBlocklistRuntime::compile_borrowed_legacy(&payload)
                    .expect("legacy region compile"),
            );
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100 {
            black_box(LocalBlocklistRuntime::compile_borrowed(&payload).expect("region compile"));
        }
    });
    println!(
        "blocklist_large_region_compile_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}
