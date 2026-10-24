use std::{hint::black_box, sync::Arc, time::Duration};

use sidecar_contract::RequestContext;

use crate::{
    LocalAuthzMode, SidecarState, local_authz,
    local_authz_tests::support::{SnapshotTransport, config, evaluation_request},
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
};

#[tokio::test]
async fn evaluation_data_given_subject_and_resource_refresh_due_then_batches_one_refresh() {
    let transport = Arc::new(SnapshotTransport::new());
    let state = Arc::new(SidecarState::new());
    let mut config = config(LocalAuthzMode::RemoteOnly);
    config.authz_cache_ttl = Duration::from_millis(100);
    config.authz_stale_cache_ttl = Duration::from_millis(100);
    config.authz_refresh_after_percent = 1;
    let context = RequestContext::default();
    let request = evaluation_request();

    local_authz::evaluate(&config, &state, &transport, &context, &request)
        .await
        .expect("prime snapshots");
    tokio::time::sleep(Duration::from_millis(5)).await;
    local_authz::evaluate(&config, &state, &transport, &context, &request)
        .await
        .expect("refresh-due evaluation");

    for _ in 0..50 {
        if transport.evaluation_data_count() >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        transport.evaluation_data_count(),
        2,
        "subject and resource refresh must share one evaluation-data request",
    );
}

#[test]
fn evaluation_data_cache_perf_loop_keeps_shared_snapshots() {
    let transport = SnapshotTransport::new();
    let subject = transport.subject_snapshot();
    let resource = transport.resource_snapshot();
    let shared_subject = Arc::new(subject.clone());
    let shared_resource = Arc::new(resource.clone());
    let baseline = measure_allocations("baseline_evaluation_data_owned_clones", || {
        for _ in 0..10_000 {
            black_box((subject.clone(), resource.clone()));
        }
    });
    let optimized = measure_allocations("optimized_evaluation_data_arc_clones", || {
        for _ in 0..10_000 {
            black_box((Arc::clone(&shared_subject), Arc::clone(&shared_resource)));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..10_000 {
            black_box((subject.clone(), resource.clone()));
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..10_000 {
            black_box((Arc::clone(&shared_subject), Arc::clone(&shared_resource)));
        }
    });
    println!(
        "evaluation_data_cache_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}
