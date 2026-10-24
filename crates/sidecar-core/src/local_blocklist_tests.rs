use sidecar_contract::{
    RateLimitNetworkIdentity, RegistryRateLimitAction, RuntimeBlocklistDecisionRequest,
    RuntimeBlocklistPolicyRef,
};

use crate::local_blocklist::LocalBlocklistRuntime;

#[test]
fn local_blocklist_given_ipv4_ipv6_and_country_rules_then_matches_boundaries() {
    let runtime = LocalBlocklistRuntime::compile(serde_json::json!({
        "builtin_ip_ranges": [{"ip_range": "10.0.0.0/8"}],
        "tenant_ip_ranges": [{"ip_range": "2001:db8::/32"}],
        "builtin_regions": [{"region_country": "GB"}],
        "tenant_regions": []
    }))
    .unwrap();

    assert!(
        runtime
            .evaluate(&request("10.255.255.255", None))
            .unwrap()
            .blocked
    );
    assert!(
        runtime
            .evaluate(&request("2001:db8::ffff", None))
            .unwrap()
            .blocked
    );
    assert!(
        runtime
            .evaluate(&request("203.0.113.9", Some("gb")))
            .unwrap()
            .blocked
    );
    assert!(
        !runtime
            .evaluate(&request("11.0.0.1", Some("US")))
            .unwrap()
            .blocked
    );
}

#[test]
fn local_blocklist_given_malformed_cidr_then_fails_before_state_is_visible() {
    let error = LocalBlocklistRuntime::compile(serde_json::json!({
        "builtin_ip_ranges": [{"ip_range": "10.0.0.0/99"}],
        "tenant_ip_ranges": [],
        "builtin_regions": [],
        "tenant_regions": []
    }))
    .unwrap_err();

    assert_eq!(error.code, "runtime_sync_blocklist_invalid");
}

#[test]
fn local_blocklist_given_ipv6_64_then_matches_only_inside_prefix_boundary() {
    let runtime = LocalBlocklistRuntime::compile(serde_json::json!({
        "builtin_ip_ranges": [{"ip_range": "2001:db8:abcd:12::/64"}],
        "tenant_ip_ranges": [],
        "builtin_regions": [],
        "tenant_regions": []
    }))
    .unwrap();

    assert!(
        runtime
            .evaluate(&request("2001:db8:abcd:12:ffff::1", None))
            .unwrap()
            .blocked
    );
    assert!(
        !runtime
            .evaluate(&request("2001:db8:abcd:13::1", None))
            .unwrap()
            .blocked
    );
}

#[test]
fn local_blocklist_given_multiple_policy_refs_then_preserves_each_explicit_reason() {
    let runtime = LocalBlocklistRuntime::compile(serde_json::json!({
        "builtin_ip_ranges": [{"ip_range": "192.0.2.0/24"}],
        "tenant_ip_ranges": [],
        "builtin_regions": [],
        "tenant_regions": []
    }))
    .unwrap();
    let mut request = request("192.0.2.4", None);
    request.policy_refs.push(RuntimeBlocklistPolicyRef {
        name: "compliance".to_string(),
        reason: Some("restricted_network".to_string()),
    });

    let response = runtime.evaluate(&request).unwrap();

    assert_eq!(response.matches.len(), 2);
    assert_eq!(response.matches[1].policy.as_deref(), Some("compliance"));
    assert_eq!(
        response.matches[1].reason.as_deref(),
        Some("restricted_network")
    );
}

#[test]
fn local_blocklist_given_empty_policies_then_effective_snapshot_still_applies() {
    let runtime = LocalBlocklistRuntime::compile(serde_json::json!({
        "builtin_ip_ranges": [{"ip_range": "192.0.2.0/24"}],
        "tenant_ip_ranges": [],
        "builtin_regions": [],
        "tenant_regions": []
    }))
    .unwrap();
    let mut request = request("192.0.2.4", None);
    request.policy_refs.clear();

    let response = runtime.evaluate(&request).unwrap();

    assert!(response.blocked);
    assert_eq!(response.matches[0].policy, None);
}

fn request(client_ip: &str, country: Option<&str>) -> RuntimeBlocklistDecisionRequest {
    RuntimeBlocklistDecisionRequest {
        tenant_id: "tenant_fixture".to_string(),
        org_id: "org_fixture".to_string(),
        product_domain: "registry".to_string(),
        resource: "team/service".to_string(),
        action: RegistryRateLimitAction::Pull,
        client_ip: client_ip.to_string(),
        network_identity: RateLimitNetworkIdentity::from_client_ip(client_ip).unwrap(),
        country: country.map(str::to_string),
        policy_refs: vec![RuntimeBlocklistPolicyRef {
            name: "runtime".to_string(),
            reason: Some("safety".to_string()),
        }],
    }
}
