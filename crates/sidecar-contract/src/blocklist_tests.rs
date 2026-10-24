use crate::{
    RateLimitNetworkIdentity, RegistryRateLimitAction, RuntimeBlocklistDecisionRequest,
    RuntimeBlocklistPolicyRef,
};

#[test]
fn blocklist_response_given_legacy_auxfn_shape_then_rejects_it() {
    let result =
        serde_json::from_value::<crate::RuntimeBlocklistDecisionResponse>(serde_json::json!({
            "allowed": false,
            "matched": {"kind": "ip_cidr", "policy_name": "builtin"}
        }));

    assert!(result.is_err());
}

#[test]
fn blocklist_request_given_registry_context_then_validates() {
    let request = blocklist_request();

    request
        .validate()
        .expect("blocklist request should validate");
}

#[test]
fn blocklist_request_given_noncanonical_network_identity_then_rejects() {
    let mut request = blocklist_request();
    request.network_identity =
        RateLimitNetworkIdentity::from_client_ip("203.0.113.9").expect("network identity");

    assert!(request.validate().is_err());
}

#[test]
fn blocklist_request_given_too_many_policy_refs_then_rejects_before_materialization() {
    let mut value = serde_json::to_value(blocklist_request()).expect("request JSON");
    value["policy_refs"] = serde_json::json!(
        (0..101)
            .map(|index| serde_json::json!({"name": format!("policy-{index}")}))
            .collect::<Vec<_>>()
    );

    assert!(serde_json::from_value::<RuntimeBlocklistDecisionRequest>(value).is_err());
}

#[test]
fn blocklist_response_given_too_many_matches_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "blocked": true,
        "matches": (0..101)
            .map(|index| serde_json::json!({"kind": "country", "value": format!("C{index}")}))
            .collect::<Vec<_>>()
    });

    assert!(serde_json::from_value::<crate::RuntimeBlocklistDecisionResponse>(value).is_err());
}

fn blocklist_request() -> RuntimeBlocklistDecisionRequest {
    RuntimeBlocklistDecisionRequest {
        tenant_id: "t_registry".to_string(),
        org_id: "org_acme".to_string(),
        product_domain: "registry".to_string(),
        resource: "team/service-api".to_string(),
        action: RegistryRateLimitAction::Pull,
        client_ip: "2001:db8:1234:5678:abcd::1".to_string(),
        network_identity: RateLimitNetworkIdentity::from_client_ip("2001:db8:1234:5678:abcd::1")
            .expect("network identity"),
        country: Some("GB".to_string()),
        policy_refs: vec![RuntimeBlocklistPolicyRef {
            name: "tenant-country-deny".to_string(),
            reason: Some("regional policy".to_string()),
        }],
    }
}
