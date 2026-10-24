use crate::{
    REGISTRY_PULL_TOTAL, RegistryMetricDimensions, RegistryRateLimitAction,
    RegistryRateLimitDefaults, RegistryRateLimitRequest, RuntimeBlocklistPolicyRef,
    RuntimePolicyDecisionRequest,
};

#[test]
fn policy_request_from_registry_context_builds_combined_auxfn_shape() {
    let request = RuntimePolicyDecisionRequest::from_registry_context(
        "t_registry".to_string(),
        RegistryRateLimitRequest {
            repository: "team/service-api".to_string(),
            user_id: "user_123".to_string(),
            organization_id: "org_acme".to_string(),
            client_ip: "2001:db8:1234:5678:abcd::1".to_string(),
            action: RegistryRateLimitAction::Pull,
            cost: 1,
            defaults: RegistryRateLimitDefaults {
                pull_limit_per_hour: 1_000,
                push_limit_per_hour: 100,
            },
        },
        vec![RuntimeBlocklistPolicyRef {
            name: "tenant-country-deny".to_string(),
            reason: Some("regional policy".to_string()),
        }],
        RegistryMetricDimensions {
            repository: "team/service-api".to_string(),
            user_id: "user_123".to_string(),
            organization_id: "org_acme".to_string(),
            action: RegistryRateLimitAction::Pull,
            status_class: "2xx".to_string(),
            bytes: Some(4096),
        },
    )
    .expect("policy request should build");

    assert_eq!(request.tenant_id, "t_registry");
    assert_eq!(request.resource.id, "team/service-api");
    assert_eq!(request.rate_limit.limits.len(), 2);
    assert_eq!(
        request.rate_limit.limits[0].descriptor.scope,
        "organization"
    );
    assert_eq!(request.rate_limit.limits[1].descriptor.scope, "network");
    assert_eq!(request.rate_limit.limits[0].limit, 1_000);
    assert_eq!(
        request.rate_limit.limits[1]
            .descriptor
            .network_identity
            .as_str(),
        "2001:db8:1234:5678::/64"
    );
    assert_eq!(request.metrics.dimensions.repository, "team/service-api");
    assert_eq!(REGISTRY_PULL_TOTAL, "aux_registry_pull_total");
}

#[test]
fn policy_request_given_too_many_rate_limits_then_rejects_before_materialization() {
    let request = policy_request();
    let mut value = serde_json::to_value(request).expect("policy request JSON");
    let limit = value["rate_limit"]["limits"][0].clone();
    value["rate_limit"]["limits"] =
        serde_json::json!((0..101).map(|_| limit.clone()).collect::<Vec<_>>());

    assert!(serde_json::from_value::<RuntimePolicyDecisionRequest>(value).is_err());
}

#[test]
fn policy_request_given_too_many_blocklist_policies_then_rejects_before_materialization() {
    let request = policy_request();
    let mut value = serde_json::to_value(request).expect("policy request JSON");
    value["blocklist"]["policies"] = serde_json::json!(
        (0..101)
            .map(|index| serde_json::json!({"name": format!("policy-{index}")}))
            .collect::<Vec<_>>()
    );

    assert!(serde_json::from_value::<RuntimePolicyDecisionRequest>(value).is_err());
}

fn policy_request() -> RuntimePolicyDecisionRequest {
    RuntimePolicyDecisionRequest::from_registry_context(
        "t_registry".to_string(),
        RegistryRateLimitRequest {
            repository: "team/service-api".to_string(),
            user_id: "user_123".to_string(),
            organization_id: "org_acme".to_string(),
            client_ip: "2001:db8:1234:5678:abcd::1".to_string(),
            action: RegistryRateLimitAction::Pull,
            cost: 1,
            defaults: RegistryRateLimitDefaults {
                pull_limit_per_hour: 1_000,
                push_limit_per_hour: 100,
            },
        },
        Vec::new(),
        RegistryMetricDimensions {
            repository: "team/service-api".to_string(),
            user_id: "user_123".to_string(),
            organization_id: "org_acme".to_string(),
            action: RegistryRateLimitAction::Pull,
            status_class: "2xx".to_string(),
            bytes: Some(4096),
        },
    )
    .expect("policy request should build")
}
