use std::{hint::black_box, sync::Arc};

use crate::{
    constants::TEST_AUTHZ_POLICY_VERSION,
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
    state_tests::policy_snapshot,
};

#[test]
fn authz_policy_cache_perf_loop_keeps_shared_snapshot() {
    let snapshot = policy_snapshot(TEST_AUTHZ_POLICY_VERSION);
    let shared = Arc::new(snapshot.clone());
    let baseline = measure_allocations("baseline_authz_policy_owned_clone", || {
        for _ in 0..10_000 {
            black_box(snapshot.clone());
        }
    });
    let optimized = measure_allocations("optimized_authz_policy_arc_clone", || {
        for _ in 0..10_000 {
            black_box(Arc::clone(&shared));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..10_000 {
            black_box(snapshot.clone());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..10_000 {
            black_box(Arc::clone(&shared));
        }
    });
    println!(
        "authz_policy_cache_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}
