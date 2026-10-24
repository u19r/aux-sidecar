use crate::rate_limit::{
    RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseRequestItem, RateLimitAcquireLeaseResponse,
    RateLimitAcquireLeaseResult, RateLimitConfigResponse, RateLimitGiveBackLeaseRequest,
    RateLimitGiveBackLeaseRequestItem, RateLimitGiveBackLeaseResponse,
    RateLimitGiveBackLeaseResult, RateLimitLease, RateLimitNetworkIdentity, RateLimitParameters,
    RegistryRateLimitAction, RegistryRateLimitDefaults, RegistryRateLimitRequest,
};

fn params() -> RateLimitParameters {
    RateLimitParameters {
        limit_per_second: 10,
        burst: 5,
        lease_duration_ms: 1_000,
        estimated_nodes: 1,
        giveback_grace_ms: 0,
    }
}

#[test]
fn validate_acquire_given_valid_lease_then_accepts_request() {
    let request = RateLimitAcquireLeaseRequest {
        params: params(),
        leases: vec![RateLimitAcquireLeaseRequestItem {
            key: "route:user".to_string(),
            requested_tokens: 2,
            min_grant_tokens: 1,
        }],
    };

    assert!(request.validate().is_ok());
}

#[test]
fn validate_acquire_given_empty_batch_then_rejects_request() {
    let request = RateLimitAcquireLeaseRequest {
        params: params(),
        leases: Vec::new(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn validate_acquire_given_duplicate_key_then_rejects_request() {
    let request = RateLimitAcquireLeaseRequest {
        params: params(),
        leases: vec![
            RateLimitAcquireLeaseRequestItem {
                key: "route:user".to_string(),
                requested_tokens: 2,
                min_grant_tokens: 1,
            },
            RateLimitAcquireLeaseRequestItem {
                key: "route:user".to_string(),
                requested_tokens: 2,
                min_grant_tokens: 1,
            },
        ],
    };

    assert!(request.validate().is_err());
}

#[test]
fn validate_giveback_given_missing_lease_id_then_rejects_request() {
    let request = RateLimitGiveBackLeaseRequest {
        params: params(),
        leases: vec![RateLimitGiveBackLeaseRequestItem {
            key: "route:user".to_string(),
            lease_id: " ".to_string(),
            return_tokens: 1,
        }],
    };

    assert!(request.validate().is_err());
}

#[test]
fn deserialize_acquire_response_given_openapi_expires_at_then_accepts_rfc3339() {
    let response: RateLimitAcquireLeaseResponse = serde_json::from_value(serde_json::json!({
        "results": [{
            "key": "route:user",
            "lease": {
                "key": "route:user",
                "lease_id": "rls_018bcfe5-1234-7abc-8def-1234567890ab",
                "granted_tokens": 2,
                "expires_at": "2025-01-01T00:00:00Z"
            }
        }]
    }))
    .expect("decode acquire response");

    let lease = response.results[0]
        .lease
        .as_ref()
        .expect("lease should decode");
    assert_eq!(lease.expires_at_ms, 1_735_689_600_000);
}

#[test]
fn deserialize_acquire_response_given_too_many_results_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "results": (0..101)
            .map(|index| serde_json::json!({"key": format!("route:{index}")}))
            .collect::<Vec<_>>()
    });

    assert!(serde_json::from_value::<RateLimitAcquireLeaseResponse>(value).is_err());
}

#[test]
fn validate_acquire_response_given_surplus_grant_then_rejects() {
    let request = RateLimitAcquireLeaseRequest {
        params: params(),
        leases: vec![RateLimitAcquireLeaseRequestItem {
            key: "route:user".to_string(),
            requested_tokens: 2,
            min_grant_tokens: 1,
        }],
    };
    let response = RateLimitAcquireLeaseResponse {
        results: vec![RateLimitAcquireLeaseResult {
            key: "route:user".to_string(),
            lease: Some(RateLimitLease {
                key: "route:user".to_string(),
                lease_id: "lease_fixture".to_string(),
                granted_tokens: 3,
                expires_at_ms: 4_102_444_800_000,
            }),
            retry_after_ms: None,
        }],
    };

    assert!(response.validate_for_request(&request).is_err());
}

#[test]
fn validate_giveback_response_given_surplus_return_then_rejects() {
    let request = RateLimitGiveBackLeaseRequest {
        params: params(),
        leases: vec![RateLimitGiveBackLeaseRequestItem {
            key: "route:user".to_string(),
            lease_id: "lease_fixture".to_string(),
            return_tokens: 2,
        }],
    };
    let response = RateLimitGiveBackLeaseResponse {
        results: vec![RateLimitGiveBackLeaseResult {
            key: "route:user".to_string(),
            lease_id: "lease_fixture".to_string(),
            returned_tokens: 3,
        }],
    };

    assert!(response.validate_for_request(&request).is_err());
}

#[test]
fn runtime_config_given_auxfn_public_shape_then_converts_periods_and_groups() {
    let response: RateLimitConfigResponse = serde_json::from_value(serde_json::json!({
        "config": {
            "defaults": {
                "routes": {
                    "POST /canary": {"limit": 120, "period": "minute", "burst": 20}
                },
                "route_groups": {
                    "reads": {
                        "limit": 3600,
                        "period": "hour",
                        "routes": ["GET /one", "GET /two"]
                    }
                }
            },
            "named": {},
            "entitlement_overrides": {},
            "org_overrides": {}
        },
        "resolved": null
    }))
    .expect("decode AuxFn public rate-limit config");

    let config = response.into_rate_limit_config();

    assert_eq!(config.defaults["POST /canary"].rps, 2.0);
    assert_eq!(config.defaults["POST /canary"].burst, Some(20));
    assert_eq!(config.defaults["GET /one"].rps, 1.0);
    assert_eq!(config.defaults["GET /two"].rps, 1.0);
}

#[test]
fn network_identity_given_ipv4_then_uses_exact_address() {
    let identity =
        RateLimitNetworkIdentity::from_client_ip("203.0.113.9").expect("valid network identity");

    assert_eq!(identity.as_str(), "203.0.113.9");
}

#[test]
fn network_identity_given_ipv6_privacy_addresses_then_uses_same_64_bucket() {
    let first = RateLimitNetworkIdentity::from_client_ip("2001:db8:1234:5678:1111::1")
        .expect("first network identity");
    let second = RateLimitNetworkIdentity::from_client_ip("2001:db8:1234:5678:ffff::abcd")
        .expect("second network identity");

    assert_eq!(first, second);
    assert_eq!(first.as_str(), "2001:db8:1234:5678::/64");
}

#[test]
fn registry_rate_limit_request_given_complete_pull_context_then_validates() {
    let request = registry_rate_limit_request(RegistryRateLimitAction::Pull);

    request
        .validate()
        .expect("registry rate-limit request should validate");
    assert_eq!(request.hourly_limit(), 1_000);
    assert_eq!(request.window_seconds(), 3_600);
}

#[test]
fn registry_rate_limit_request_given_push_context_then_uses_push_default() {
    let request = registry_rate_limit_request(RegistryRateLimitAction::Push);

    assert_eq!(request.hourly_limit(), 100);
}

#[test]
fn registry_rate_limit_request_given_malformed_client_ip_then_rejects() {
    let mut request = registry_rate_limit_request(RegistryRateLimitAction::Pull);
    request.client_ip = "not an ip".to_string();

    assert!(request.validate().is_err());
}

fn registry_rate_limit_request(action: RegistryRateLimitAction) -> RegistryRateLimitRequest {
    RegistryRateLimitRequest {
        repository: "team/service-api".to_string(),
        user_id: "user_123".to_string(),
        organization_id: "org_acme".to_string(),
        client_ip: "2001:db8:1234:5678:abcd::1".to_string(),
        action,
        cost: 1,
        defaults: RegistryRateLimitDefaults {
            pull_limit_per_hour: 1_000,
            push_limit_per_hour: 100,
        },
    }
}
