use std::{hint::black_box, time::Instant};

use serde_json::{Value, json};

use super::{ClaimPredicate, CompiledRoutePolicy, JsonPath};
use crate::{RevocationLookup, RevocationSnapshot};

#[test]
#[ignore = "performance receipt; run in isolation with --ignored --nocapture"]
fn compiled_route_policy_avoids_per_request_document_parsing() {
    let source = json!({
        "paths": {
            "/documents/{document_id}": {
                "parameters": [{
                    "in": "path",
                    "name": "document_id",
                    "required": true,
                    "schema": {"type": "string", "format": "uuid"}
                }],
                "get": {
                    "operationId": "getDocument",
                    "x-aux-authn": {"mode": "bearer", "audiences": ["api"]},
                    "x-aux-authz": {
                        "required_scopes": ["documents.read"],
                        "claims": {"all": [{"path": "$.tenant_tier", "equals": "enterprise"}]}
                    }
                }
            },
            "/health": {"get": {"x-aux-authn": {"mode": "public"}}}
        },
        "x-aux-fallback": {"x-aux-authn": {"mode": "public"}}
    });
    let compiled = CompiledRoutePolicy::compile_value(source.clone()).expect("compile policy");
    let path = "/documents/550e8400-e29b-41d4-a716-446655440000";
    let claims = json!({"tenant_tier": "enterprise"});
    let iterations = 500;

    let parse_each_request = Instant::now();
    for _ in 0..iterations {
        let policy = CompiledRoutePolicy::compile_value(source.clone()).expect("compile policy");
        for (request_path, expected_template) in [
            (path, "/documents/{document_id}"),
            ("/health", "/health"),
            ("/unmatched", "*"),
        ] {
            let route = policy
                .match_route("GET", request_path)
                .expect("route match");
            assert_eq!(route.operation.template, expected_template);
            let allowed = route
                .operation
                .authz
                .as_ref()
                .and_then(|authz| authz.claims.as_ref())
                .is_none_or(|predicate| predicate.evaluate(&claims));
            black_box(allowed);
        }
    }
    let parse_each_request_ns = parse_each_request.elapsed().as_nanos();

    let compiled_lookup = Instant::now();
    for _ in 0..iterations {
        for (request_path, expected_template) in [
            (path, "/documents/{document_id}"),
            ("/health", "/health"),
            ("/unmatched", "*"),
        ] {
            let route = compiled
                .match_route("GET", request_path)
                .expect("route match");
            assert_eq!(route.operation.template, expected_template);
            let allowed = route
                .operation
                .authz
                .as_ref()
                .and_then(|authz| authz.claims.as_ref())
                .is_none_or(|predicate| predicate.evaluate(&claims));
            black_box(allowed);
        }
    }
    let compiled_lookup_ns = compiled_lookup.elapsed().as_nanos();

    println!(
        "route_policy_perf iterations={iterations} parse_each_request_ns={parse_each_request_ns} \
         compiled_lookup_ns={compiled_lookup_ns}"
    );
    assert!(parse_each_request_ns > compiled_lookup_ns);

    let maximum_predicate = ClaimPredicate::All(
        (0..128)
            .map(|_| ClaimPredicate::Equals {
                path: JsonPath::parse("$.tenant_tier").expect("claim path"),
                value: json!("enterprise"),
            })
            .collect(),
    );
    let predicate_started = Instant::now();
    for _ in 0..iterations {
        assert!(maximum_predicate.evaluate(&claims));
    }
    let predicate_ns = predicate_started.elapsed().as_nanos();

    let revocations = RevocationSnapshot::new(
        ["api".to_string()],
        (0..10_000).map(|index| (format!("jti-{index}"), 2_000)),
        0,
        10_000,
        60_000,
    );
    let revocation_audiences = ["api".to_string()];
    let revocation_started = Instant::now();
    for index in 0..iterations {
        let lookup = revocations.lookup_for_audiences(
            &revocation_audiences,
            &format!("jti-{}", index % 10_000),
            1_000,
        );
        assert_eq!(lookup, RevocationLookup::Revoked);
        black_box(lookup);
    }
    let revocation_ns = revocation_started.elapsed().as_nanos();
    println!(
        "route_policy_perf predicate_128_ns={predicate_ns} revocation_lookup_ns={revocation_ns}"
    );
    let _: Value = source;
}
