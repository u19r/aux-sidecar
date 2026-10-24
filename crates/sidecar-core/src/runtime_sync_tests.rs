use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use sidecar_contract::RequestContext;

pub(crate) use crate::runtime_sync_transport_tests::SyncTestTransport;
use crate::{
    SidecarEngine,
    runtime_sync_test_support::{combined_request, config, request},
};

#[tokio::test]
async fn runtime_sync_given_concurrent_identical_misses_then_performs_one_transport_call() {
    let calls = Arc::new(AtomicUsize::new(0));
    let engine = Arc::new(SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::clone(&calls),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::new(AtomicUsize::new(0)),
        },
    ));
    let request = request();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let engine = Arc::clone(&engine);
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            engine
                .sync_runtime(&RequestContext::default(), &request)
                .await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(engine.state().runtime_sync_snapshot().generation, 1);
}

#[tokio::test]
async fn rate_limit_config_given_sync_capability_then_does_not_call_legacy_transport() {
    let calls = Arc::new(AtomicUsize::new(0));
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::clone(&calls),
            legacy_rate_config_calls: Arc::clone(&legacy_calls),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::new(AtomicUsize::new(0)),
        },
    );

    let first = engine
        .get_rate_limit_config(&RequestContext::default())
        .await
        .unwrap();
    let second = engine
        .get_rate_limit_config(&RequestContext::default())
        .await
        .unwrap();

    assert_eq!(first.cache_status, sidecar_contract::CacheStatus::Miss);
    assert_eq!(second.cache_status, sidecar_contract::CacheStatus::Fresh);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(legacy_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn blocklist_given_warm_synchronized_state_then_makes_zero_additional_transport_calls() {
    let sync_calls = Arc::new(AtomicUsize::new(0));
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::clone(&sync_calls),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::clone(&legacy_calls),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    let request = sidecar_contract::RuntimeBlocklistDecisionRequest {
        tenant_id: "tenant_fixture".to_string(),
        org_id: "org_fixture".to_string(),
        product_domain: "registry".to_string(),
        resource: "team/service".to_string(),
        action: sidecar_contract::RegistryRateLimitAction::Pull,
        client_ip: "10.1.2.3".to_string(),
        network_identity: sidecar_contract::RateLimitNetworkIdentity::from_client_ip("10.1.2.3")
            .unwrap(),
        country: None,
        policy_refs: Vec::new(),
    };

    assert!(
        engine
            .decide_blocklist(&RequestContext::default(), &request)
            .await
            .unwrap()
            .blocked
    );
    assert!(
        engine
            .decide_blocklist(&RequestContext::default(), &request)
            .await
            .unwrap()
            .blocked
    );

    assert_eq!(sync_calls.load(Ordering::Relaxed), 1);
    assert_eq!(legacy_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn entitlements_given_warm_synchronized_state_then_makes_zero_additional_transport_calls() {
    let sync_calls = Arc::new(AtomicUsize::new(0));
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::clone(&sync_calls),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::clone(&legacy_calls),
            lease_calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    let request = sidecar_contract::EntitlementEvaluateRequest {
        org_id: "org_fixture".to_string(),
        at_time: None,
        keys: Some(vec!["feature.enabled".to_string()]),
    };

    let first = engine
        .evaluate_entitlements(&RequestContext::default(), &request)
        .await
        .unwrap();
    let second = engine
        .evaluate_entitlements(&RequestContext::default(), &request)
        .await
        .unwrap();

    assert_eq!(first.cache_status, sidecar_contract::CacheStatus::Miss);
    assert_eq!(second.cache_status, sidecar_contract::CacheStatus::Fresh);
    assert_eq!(sync_calls.load(Ordering::Relaxed), 1);
    assert_eq!(legacy_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn rate_limit_check_given_concurrent_consumers_then_never_exceeds_granted_tokens() {
    let lease_calls = Arc::new(AtomicUsize::new(0));
    let engine = Arc::new(SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::clone(&lease_calls),
        },
    ));
    let request = sidecar_contract::RateLimitCheckRequest {
        params: sidecar_contract::RateLimitParameters {
            limit_per_second: 100,
            burst: 0,
            lease_duration_ms: 1_000,
            estimated_nodes: 1,
            giveback_grace_ms: 0,
        },
        key: "tenant:route".to_string(),
        cost: 1,
    };
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let engine = Arc::clone(&engine);
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            engine
                .check_rate_limit(&RequestContext::default(), &request)
                .await
        }));
    }
    for task in tasks {
        assert!(task.await.unwrap().unwrap().allowed);
    }

    assert_eq!(lease_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn combined_policy_given_repeated_requests_then_enforces_locally() {
    let lease_calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::clone(&lease_calls),
        },
    );
    let request = registry_policy_request();

    assert!(
        engine
            .decide_policy(&RequestContext::default(), &request)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine
            .decide_policy(&RequestContext::default(), &request)
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(lease_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn combined_policy_given_hourly_quota_then_denies_after_the_window_budget() {
    let lease_calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::clone(&lease_calls),
        },
    );
    let mut request = registry_policy_request();
    for limit in &mut request.rate_limit.limits {
        limit.limit = 100;
    }

    for _ in 0..100 {
        assert!(
            engine
                .decide_policy(&RequestContext::default(), &request)
                .await
                .unwrap()
                .allowed
        );
    }
    let denied = engine
        .decide_policy(&RequestContext::default(), &request)
        .await
        .unwrap();

    assert!(!denied.allowed);
    assert_eq!(denied.reason, "rate_limited");
    assert_eq!(lease_calls.load(Ordering::Relaxed), 0);
}

pub(crate) fn registry_policy_request() -> sidecar_contract::RuntimePolicyDecisionRequest {
    sidecar_contract::RuntimePolicyDecisionRequest::from_registry_context(
        "tenant_fixture".to_string(),
        sidecar_contract::RegistryRateLimitRequest {
            repository: "team/service".to_string(),
            user_id: "user_fixture".to_string(),
            organization_id: "org_fixture".to_string(),
            client_ip: "203.0.113.9".to_string(),
            action: sidecar_contract::RegistryRateLimitAction::Pull,
            cost: 1,
            defaults: sidecar_contract::RegistryRateLimitDefaults {
                pull_limit_per_hour: 360_000,
                push_limit_per_hour: 360_000,
            },
        },
        Vec::new(),
        sidecar_contract::RegistryMetricDimensions {
            repository: "team/service".to_string(),
            user_id: "user_fixture".to_string(),
            organization_id: "org_fixture".to_string(),
            action: sidecar_contract::RegistryRateLimitAction::Pull,
            status_class: "2xx".to_string(),
            bytes: None,
        },
    )
    .expect("registry policy request")
}

#[tokio::test]
async fn combined_policy_given_blocklist_deny_then_does_not_allow_or_consume_lease() {
    let lease_calls = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        SyncTestTransport {
            calls: Arc::new(AtomicUsize::new(0)),
            legacy_rate_config_calls: Arc::new(AtomicUsize::new(0)),
            legacy_blocklist_calls: Arc::new(AtomicUsize::new(0)),
            legacy_entitlement_calls: Arc::new(AtomicUsize::new(0)),
            lease_calls: Arc::clone(&lease_calls),
        },
    );
    let mut request = combined_request("10.1.2.3");
    request.blocklist.enabled = true;
    request.blocklist.policies = vec![sidecar_contract::RuntimeBlocklistPolicyRef {
        name: "safety".to_string(),
        reason: Some("blocked".to_string()),
    }];

    let response = engine
        .decide_policy(&RequestContext::default(), &request)
        .await
        .unwrap();

    assert!(!response.allowed);
    assert_eq!(response.reason, "blocklisted");
    assert_eq!(lease_calls.load(Ordering::Relaxed), 0);
}
