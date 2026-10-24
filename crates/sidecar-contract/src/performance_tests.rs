use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use crate::{
    REGISTRY_PULL_TOTAL, RegistryMetricDimensions, RegistryPrometheusRollupLabels,
    RegistryRateLimitAction, RegistryRateLimitDefaults, RegistryRateLimitRequest,
    RuntimeBlocklistDecisionRequest, RuntimeBlocklistPolicyRef, RuntimePolicyDecisionRequest,
    rate_limit::RateLimitNetworkIdentity,
};

const ITERATIONS: usize = 1_000;

#[test]
#[ignore = "performance baseline; run with --ignored --nocapture --test-threads=1"]
fn perf_phase13_registry_helpers_report_runtime_and_allocations() {
    let fixtures = Fixtures::new();
    measure_fixture("sidecar_policy_request_assembly", || {
        black_box(
            RuntimePolicyDecisionRequest::from_registry_context(
                fixtures.tenant_id.clone(),
                fixtures.rate_limit.clone(),
                fixtures.blocklist_policies.clone(),
                fixtures.metric_dimensions.clone(),
            )
            .unwrap(),
        );
    });
    measure_fixture("sidecar_policy_request_serialization", || {
        black_box(serde_json::to_vec(&fixtures.policy_request).unwrap());
    });
    measure_fixture("sidecar_blocklist_request_validation", || {
        fixtures.blocklist_request.validate().unwrap();
        black_box(());
    });
    measure_fixture("sidecar_metric_dimension_validation", || {
        fixtures.metric_dimensions.validate().unwrap();
        fixtures.rollup_labels.validate().unwrap();
        black_box(());
    });
}

struct Fixtures {
    tenant_id: String,
    rate_limit: RegistryRateLimitRequest,
    blocklist_policies: Vec<RuntimeBlocklistPolicyRef>,
    metric_dimensions: RegistryMetricDimensions,
    policy_request: RuntimePolicyDecisionRequest,
    blocklist_request: RuntimeBlocklistDecisionRequest,
    rollup_labels: RegistryPrometheusRollupLabels,
}

impl Fixtures {
    fn new() -> Self {
        let tenant_id = "tenant-a".to_string();
        let rate_limit = RegistryRateLimitRequest {
            repository: "team/service-api".to_string(),
            user_id: "user_123".to_string(),
            organization_id: "org_acme".to_string(),
            client_ip: "198.51.100.10".to_string(),
            action: RegistryRateLimitAction::Pull,
            cost: 1,
            defaults: RegistryRateLimitDefaults {
                pull_limit_per_hour: 1_000,
                push_limit_per_hour: 100,
            },
        };
        let blocklist_policies = vec![RuntimeBlocklistPolicyRef {
            name: "registry-staging-deny".to_string(),
            reason: Some("staging deny-path fixture".to_string()),
        }];
        let metric_dimensions = RegistryMetricDimensions {
            repository: rate_limit.repository.clone(),
            user_id: rate_limit.user_id.clone(),
            organization_id: rate_limit.organization_id.clone(),
            action: rate_limit.action,
            status_class: "2xx".to_string(),
            bytes: None,
        };
        let policy_request = RuntimePolicyDecisionRequest::from_registry_context(
            tenant_id.clone(),
            rate_limit.clone(),
            blocklist_policies.clone(),
            metric_dimensions.clone(),
        )
        .unwrap();
        let blocklist_request = RuntimeBlocklistDecisionRequest {
            tenant_id: tenant_id.clone(),
            org_id: rate_limit.organization_id.clone(),
            product_domain: "registry".to_string(),
            resource: rate_limit.repository.clone(),
            action: rate_limit.action,
            client_ip: rate_limit.client_ip.clone(),
            network_identity: RateLimitNetworkIdentity::from_client_ip(&rate_limit.client_ip)
                .unwrap(),
            country: Some("US".to_string()),
            policy_refs: blocklist_policies.clone(),
        };
        let rollup_labels = RegistryPrometheusRollupLabels {
            environment: "staging".to_string(),
            action: RegistryRateLimitAction::Pull,
            status_class: "2xx".to_string(),
        };
        assert_eq!(REGISTRY_PULL_TOTAL, "aux_registry_pull_total");
        Self {
            tenant_id,
            rate_limit,
            blocklist_policies,
            metric_dimensions,
            policy_request,
            blocklist_request,
            rollup_labels,
        }
    }
}

fn measure_fixture(label: &'static str, mut run: impl FnMut()) {
    let report = measure_allocations(label, || {
        for _ in 0..ITERATIONS {
            run();
        }
    });
    alloc_counter::emit_report(&report).expect("allocation report must be emitted");
    emit_cpu_report(
        label,
        best_of_three(|| {
            for _ in 0..ITERATIONS {
                run();
            }
        }),
    );
}

fn measure_allocations(
    label: &'static str,
    run: impl FnOnce(),
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run();
    guard.finish()
}

fn best_of_three(mut run: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        run();
        best = best.min(started.elapsed());
    }
    best
}

fn emit_cpu_report(label: &str, duration: Duration) {
    println!(
        "{{\"event\":\"cpu_report\",\"crate\":\"sidecar-contract\",\"label\":\"{label}\",\"\
         iterations\":{ITERATIONS},\"best_nanos\":{}}}",
        duration.as_nanos()
    );
}
