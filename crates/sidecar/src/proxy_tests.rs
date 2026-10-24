use axum::http::{HeaderMap, HeaderValue};

use crate::proxy::ProxyPolicyConfig;

#[test]
fn proxy_mapping_given_trusted_headers_then_builds_canonical_policy_request() {
    let config = config();
    let headers = headers();

    let request = config.request(&headers, "user-from-token").unwrap();

    assert_eq!(request.subject.id, "user-from-token");
    assert_eq!(request.resource.id, "/v2/repository/manifests/latest");
    assert_eq!(request.network.client_ip, "2001:db8::1");
    assert_eq!(request.network.country.as_deref(), Some("GB"));
    assert_eq!(request.policy_generation, "proxy-v1");
}

#[test]
fn proxy_mapping_given_spoofed_context_header_then_rejects_request() {
    let config = config();
    let mut headers = headers();
    headers.insert("x-aux-admin", HeaderValue::from_static("true"));

    let error = config.request(&headers, "user-from-token").unwrap_err();

    assert_eq!(error, "untrusted proxy context header");
}

fn config() -> ProxyPolicyConfig {
    ProxyPolicyConfig {
        tenant_id: "tenant-1".to_string(),
        organization_id: "org-1".to_string(),
        policy_generation: "proxy-v1".to_string(),
        pull_limit_per_hour: 100,
        push_limit_per_hour: 10,
        blocklist_policies: Vec::new(),
        entitlement_keys: Vec::new(),
        trusted_context_headers: vec!["x-aux-country".to_string()],
    }
}

fn headers() -> HeaderMap {
    HeaderMap::from_iter([
        (
            "authorization".parse().unwrap(),
            HeaderValue::from_static("Bearer fixture"),
        ),
        (
            "x-original-method".parse().unwrap(),
            HeaderValue::from_static("GET"),
        ),
        (
            "x-original-uri".parse().unwrap(),
            HeaderValue::from_static("/v2/repository/manifests/latest"),
        ),
        (
            "x-original-host".parse().unwrap(),
            HeaderValue::from_static("registry.example"),
        ),
        (
            "x-original-client-ip".parse().unwrap(),
            HeaderValue::from_static("2001:db8::1"),
        ),
        (
            "x-aux-country".parse().unwrap(),
            HeaderValue::from_static("GB"),
        ),
    ])
}
