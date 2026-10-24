use std::{hint::black_box, sync::Arc};

use authz_runtime::EffectiveRoleAssignment;
use authz_types::ConfigurationModel;
use serde::Deserialize;
use sidecar_contract::{CacheStatus, RequestContext};

use crate::{
    SidecarEngine, SidecarState, local_authz,
    performance_support_tests::{
        best_of_three, best_of_three_async, measure_allocations, measure_allocations_async,
        percent_improvement,
    },
};

mod support;

use support::{AuthzFixture, PerfSnapshotTransport, evaluation_request, local_authz_config};

const WARM_ITERATIONS: usize = 32;
const CONVERSION_ITERATIONS: usize = 128;

#[test]
fn local_authz_json_conversion_perf_loop_keeps_borrowed_deserialization() {
    let fixture = AuthzFixture::new();
    let assignment = fixture
        .evaluation_data
        .subjects
        .first()
        .and_then(|subject| subject.assignments.first())
        .expect("assignment fixture");

    let baseline = measure_allocations("baseline_owned_authz_json_conversion", || {
        for _ in 0..CONVERSION_ITERATIONS {
            let config: ConfigurationModel =
                serde_json::from_value(fixture.policy_snapshot.config.clone()).expect("config");
            let bundle: authz_cedar::CompiledBundle =
                serde_json::from_value(fixture.policy_snapshot.compiled_bundle.clone())
                    .expect("bundle");
            let assignment: EffectiveRoleAssignment =
                serde_json::from_value(assignment.clone()).expect("assignment");
            black_box((config, bundle, assignment));
        }
    });
    let optimized = measure_allocations("optimized_borrowed_authz_json_conversion", || {
        for _ in 0..CONVERSION_ITERATIONS {
            let config = ConfigurationModel::deserialize(&fixture.policy_snapshot.config)
                .expect("borrowed config");
            let bundle =
                authz_cedar::CompiledBundle::deserialize(&fixture.policy_snapshot.compiled_bundle)
                    .expect("borrowed bundle");
            let assignment =
                EffectiveRoleAssignment::deserialize(assignment).expect("borrowed assignment");
            black_box((config, bundle, assignment));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..CONVERSION_ITERATIONS {
            black_box(
                serde_json::from_value::<ConfigurationModel>(
                    fixture.policy_snapshot.config.clone(),
                )
                .expect("config"),
            );
            black_box(
                serde_json::from_value::<authz_cedar::CompiledBundle>(
                    fixture.policy_snapshot.compiled_bundle.clone(),
                )
                .expect("bundle"),
            );
            black_box(
                serde_json::from_value::<EffectiveRoleAssignment>(assignment.clone())
                    .expect("assignment"),
            );
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..CONVERSION_ITERATIONS {
            black_box(
                ConfigurationModel::deserialize(&fixture.policy_snapshot.config).expect("config"),
            );
            black_box(
                authz_cedar::CompiledBundle::deserialize(&fixture.policy_snapshot.compiled_bundle)
                    .expect("bundle"),
            );
            black_box(EffectiveRoleAssignment::deserialize(assignment).expect("assignment"));
        }
    });
    println!(
        "authz_json_conversion_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(optimized.allocated_bytes < baseline.allocated_bytes);
    assert!(optimized_cpu <= baseline_cpu);
}

#[tokio::test]
async fn local_authz_performance_warm_cache_reports_allocations_and_cpu() {
    let config = local_authz_config();
    let state = Arc::new(SidecarState::new());
    let transport = Arc::new(PerfSnapshotTransport::new());
    let context = RequestContext::default();
    let request = evaluation_request();

    local_authz::evaluate(&config, &state, &transport, &context, &request)
        .await
        .expect("warm local authz cache");

    let warm = measure_allocations_async("sidecar_local_authz_warm_cache", async {
        for _ in 0..WARM_ITERATIONS {
            let response = local_authz::evaluate(&config, &state, &transport, &context, &request)
                .await
                .expect("warm local authz evaluation");
            assert!(response.response.decision);
            assert_eq!(response.cache_status, CacheStatus::Fresh);
        }
    })
    .await;

    alloc_counter::emit_report(&warm).expect("allocation report must be emitted");

    let cold_cpu = best_of_three_async(|| async {
        let state = Arc::new(SidecarState::new());
        local_authz::evaluate(&config, &state, &transport, &context, &request)
            .await
            .expect("cold local authz evaluation");
    })
    .await;
    let warm_cpu = best_of_three_async(|| async {
        local_authz::evaluate(&config, &state, &transport, &context, &request)
            .await
            .expect("warm local authz evaluation");
    })
    .await;

    println!(
        "sidecar_local_authz_cpu_ns cold={} warm={} improvement_percent={:.2}",
        cold_cpu.as_nanos(),
        warm_cpu.as_nanos(),
        percent_improvement(cold_cpu, warm_cpu),
    );
}

#[tokio::test]
#[ignore = "performance receipt; run in isolation with --ignored --nocapture --test-threads=1"]
async fn remote_authz_performance_reports_transport_round_trip_path() {
    const ITERATIONS: usize = 500;
    let config = local_authz_config();
    let transport = PerfSnapshotTransport::new();
    let remote_count = Arc::clone(&transport.remote_count);
    let engine = SidecarEngine::new(config, transport);
    let context = RequestContext::default();
    let request = evaluation_request();

    let started = std::time::Instant::now();
    for _ in 0..ITERATIONS {
        let result = engine
            .evaluate_authz(&context, &request)
            .await
            .expect("remote AuthZ evaluation");
        assert!(result.response.decision);
        black_box(result);
    }
    let elapsed_ns = started.elapsed().as_nanos();
    let remote_calls = remote_count.load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "sidecar_remote_authz_perf iterations={ITERATIONS} elapsed_ns={elapsed_ns} \
         remote_calls={remote_calls}"
    );
    assert_eq!(remote_calls, ITERATIONS);
}

#[tokio::test]
#[ignore = "Samply harness; run as one isolated release test"]
async fn local_authz_samply_profile_warm_cache() {
    const PROFILE_ITERATIONS: usize = 100_000;
    let config = local_authz_config();
    let state = Arc::new(SidecarState::new());
    let transport = Arc::new(PerfSnapshotTransport::new());
    let context = RequestContext::default();
    let request = evaluation_request();

    local_authz::evaluate(&config, &state, &transport, &context, &request)
        .await
        .expect("warm local authz cache");
    for _ in 0..PROFILE_ITERATIONS {
        black_box(
            local_authz::evaluate(&config, &state, &transport, &context, &request)
                .await
                .expect("warm local authz evaluation"),
        );
    }
}
