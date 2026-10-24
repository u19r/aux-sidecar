use super::*;

fn policy() -> Value {
    serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "test", "version": "1"},
        "paths": {
            "/documents/{document_id}": {
                "get": {
                    "operationId": "getDocument",
                    "parameters": [{"in": "path", "name": "document_id", "required": true, "schema": {"type": "string", "format": "uuid"}}],
                    "x-aux-authn": {"mode": "bearer", "audiences": ["https://api.example.test"]},
                    "x-aux-authz": {
                        "required_scopes": ["documents.read"],
                        "claims": {"all": [{"path": "$.tenant_tier", "equals": "enterprise"}]},
                        "decision": {"action": "document.read", "resource": "document:{document_id}"}
                    }
                }
            },
            "/health": {
                "get": {"x-aux-authn": {"mode": "public"}}
            }
        }
    })
}

#[test]
fn compiles_full_document_and_matches_exact_before_template() {
    let compiled = CompiledRoutePolicy::compile_value(policy()).expect("policy compiles");
    let exact = compiled.match_route("GET", "/health").expect("exact route");
    assert_eq!(exact.operation.authn.mode, RouteAuthnMode::Public);
    let route = compiled
        .match_route("GET", "/documents/550e8400-e29b-41d4-a716-446655440000")
        .expect("template route");
    assert_eq!(
        route.captures["document_id"],
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert!(
        route
            .operation
            .authz
            .as_ref()
            .expect("authz")
            .claims
            .as_ref()
            .expect("claims")
            .evaluate(&serde_json::json!({"tenant_tier":"enterprise"}))
    );
}

#[test]
fn rejects_missing_authn_and_external_refs() {
    let missing = serde_json::json!({"openapi":"3.1.0","paths":{"/missing":{"get":{}}}});
    assert!(matches!(
        CompiledRoutePolicy::compile_value(missing),
        Err(RoutePolicyError::AuthnMissing(_))
    ));
    let external = serde_json::json!({"openapi":"3.1.0","paths":{"/x":{"get":{"$ref":"https://example.test/op"}}}});
    assert_eq!(
        CompiledRoutePolicy::compile_value(external),
        Err(RoutePolicyError::ExternalReference)
    );
}

#[test]
fn accepts_yaml_and_rejects_invalid_uuid_capture() {
    let yaml = br#"openapi: 3.1.0
paths:
  /items/{id}:
    get:
      parameters:
        - in: path
          name: id
          required: true
          schema: {type: string, format: uuid}
      x-aux-authn:
        mode: bearer
        audiences: [api]
"#;
    let compiled = CompiledRoutePolicy::compile(yaml).expect("yaml compiles");
    assert!(compiled.match_route("GET", "/items/not-a-uuid").is_none());
}

#[test]
fn rejects_missing_audience_for_bearer() {
    let value = serde_json::json!({
        "openapi": "3.1.0",
        "paths": {"/x": {"get": {"x-aux-authn": {"mode": "bearer"}}}}
    });
    assert!(matches!(
        CompiledRoutePolicy::compile_value(value),
        Err(RoutePolicyError::AuthnInvalid(_))
    ));
}

#[test]
fn compact_paths_document_may_omit_descriptive_openapi_fields() {
    let value = serde_json::json!({
        "paths": {"/x": {"get": {"x-aux-authn": {"mode": "public"}}}}
    });
    assert!(CompiledRoutePolicy::compile_value(value).is_ok());

    let invalid_version = serde_json::json!({
        "openapi": "3.0.3",
        "paths": {"/x": {"get": {"x-aux-authn": {"mode": "public"}}}}
    });
    assert_eq!(
        CompiledRoutePolicy::compile_value(invalid_version),
        Err(RoutePolicyError::OpenApiVersionInvalid)
    );
}

#[test]
fn matches_compiled_fallback_after_concrete_routes() {
    let value = serde_json::json!({
        "openapi": "3.1.0",
        "paths": {"/health": {"get": {"x-aux-authn": {"mode": "public"}}}},
        "x-aux-fallback": {"x-aux-authn": {"mode": "bearer", "audiences": ["api"]}}
    });
    let compiled = CompiledRoutePolicy::compile_value(value).expect("fallback compiles");
    let fallback = compiled
        .match_route("POST", "/not-described")
        .expect("fallback route");
    assert_eq!(fallback.operation.authn.mode, RouteAuthnMode::Bearer);
    assert!(compiled.fallback_match().is_some());
}

#[test]
fn rejects_false_exists_predicate_instead_of_treating_it_as_presence() {
    let value = serde_json::json!({
        "paths": {
            "/x": {
                "get": {
                    "x-aux-authn": {"mode": "public"},
                    "x-aux-authz": {"claims": {"path": "$.tenant", "exists": false}}
                }
            }
        }
    });
    assert!(matches!(
        CompiledRoutePolicy::compile_value(value),
        Err(RoutePolicyError::AuthzInvalid(_))
    ));
}
