use std::sync::{Arc, atomic::AtomicUsize};

use sidecar_contract::RequestContext;

use crate::{
    SidecarEngine,
    runtime_sync_test_support::config,
    runtime_sync_tests::{SyncTestTransport, registry_policy_request},
};

#[tokio::test]
async fn rate_limit_distinct_misses_perf_loop_keeps_network_calls_parallel() {
    const REQUESTS: usize = 8;
    let baseline_engine = SidecarEngine::new(config(), transport());
    let baseline_started = std::time::Instant::now();
    for index in 0..REQUESTS {
        let request = rate_limit_request(format!("tenant:route:{index}"));
        assert!(
            baseline_engine
                .check_rate_limit(&RequestContext::default(), &request)
                .await
                .expect("sequential rate limit check")
                .allowed
        );
    }
    let baseline = baseline_started.elapsed();

    let optimized_engine = Arc::new(SidecarEngine::new(config(), transport()));
    let optimized_started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for index in 0..REQUESTS {
        let engine = Arc::clone(&optimized_engine);
        tasks.push(tokio::spawn(async move {
            let request = rate_limit_request(format!("tenant:route:{index}"));
            engine
                .check_rate_limit(&RequestContext::default(), &request)
                .await
        }));
    }
    for task in tasks {
        assert!(task.await.expect("join").expect("parallel check").allowed);
    }
    let optimized = optimized_started.elapsed();
    println!(
        "rate_limit_distinct_misses baseline_ms={} optimized_ms={} improvement={:.2}%",
        baseline.as_millis(),
        optimized.as_millis(),
        crate::performance_support_tests::percent_improvement(baseline, optimized),
    );
    assert!(crate::performance_support_tests::percent_improvement(baseline, optimized) >= 15.0);
}

#[tokio::test]
async fn combined_policy_perf_loop_keeps_independent_limits_parallel() {
    let baseline_engine = SidecarEngine::new(config(), transport());
    let baseline_started = std::time::Instant::now();
    for key in ["organization", "network"] {
        baseline_engine
            .check_rate_limit(
                &RequestContext::default(),
                &rate_limit_request(format!("policy:{key}")),
            )
            .await
            .expect("sequential limit");
    }
    let baseline = baseline_started.elapsed();

    let optimized_engine = SidecarEngine::new(config(), transport());
    let optimized_started = std::time::Instant::now();
    assert!(
        optimized_engine
            .decide_policy(&RequestContext::default(), &registry_policy_request())
            .await
            .expect("parallel combined policy")
            .allowed
    );
    let optimized = optimized_started.elapsed();
    println!(
        "combined_policy_limits baseline_ms={} optimized_ms={} improvement={:.2}%",
        baseline.as_millis(),
        optimized.as_millis(),
        crate::performance_support_tests::percent_improvement(baseline, optimized),
    );
    assert!(crate::performance_support_tests::percent_improvement(baseline, optimized) >= 15.0);
}

#[tokio::test]
async fn runtime_sync_interleaved_keys_perf_loop_keeps_each_key_coalesced() {
    let calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::clone(&calls),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    let first = crate::engine::runtime_sync_request(vec![sidecar_contract::SyncArtifactKind::Jwks]);
    let second = crate::engine::runtime_sync_request(vec![
        sidecar_contract::SyncArtifactKind::RateLimitConfig,
    ]);
    let context = RequestContext::default();
    let started = std::time::Instant::now();
    let (first_result, second_result, duplicate_result) = tokio::join!(
        engine.sync_runtime(&context, &first),
        engine.sync_runtime(&context, &second),
        engine.sync_runtime(&context, &first),
    );
    first_result.expect("first key");
    second_result.expect("second key");
    duplicate_result.expect("coalesced first key");
    println!(
        "runtime_sync_interleaved_keys network_calls_baseline=3 network_calls_optimized={} \
         elapsed_ms={}",
        calls.load(std::sync::atomic::Ordering::Relaxed),
        started.elapsed().as_millis(),
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
}

fn transport() -> SyncTestTransport {
    SyncTestTransport {
        calls: Arc::new(AtomicUsize::new(0)),
        legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
        legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
        legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
        lease_calls: Arc::new(AtomicUsize::new(0)),
    }
}

fn rate_limit_request(key: String) -> sidecar_contract::RateLimitCheckRequest {
    sidecar_contract::RateLimitCheckRequest {
        params: sidecar_contract::RateLimitParameters {
            limit_per_second: 100,
            burst: 0,
            lease_duration_ms: 1_000,
            estimated_nodes: 1,
            giveback_grace_ms: 0,
        },
        key,
        cost: 1,
    }
}
