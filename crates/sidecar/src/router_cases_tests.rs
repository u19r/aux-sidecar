use std::io::Write;

use axum::body::to_bytes;
use tower::ServiceExt;

use super::*;
use crate::{
    constants::{MAX_REQUEST_BODY_BYTES, MAX_UPSTREAM_RESPONSE_BYTES, TEST_BODY_LIMIT_BYTES},
    transport_helpers::{valid_traceparent, valid_tracestate},
};
#[tokio::test]
async fn health_surfaces_given_missing_state_then_live_is_ok_and_ready_is_unavailable() {
    let upstream_addr = spawn_upstream_server().await;
    for path in ["/sidecar/live", "/sidecar/health"] {
        let response = sidecar_router(upstream_addr)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), TEST_BODY_LIMIT_BYTES)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "live");
    }

    let response = sidecar_router(upstream_addr)
        .oneshot(
            Request::builder()
                .uri("/sidecar/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), TEST_BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["ready"], false);
    assert_eq!(value["reason_codes"][0], "required_state_missing");
}

#[tokio::test]
async fn status_given_secret_configuration_then_excludes_secrets_and_customer_data() {
    let upstream_addr = spawn_upstream_server().await;
    let response = sidecar_router(upstream_addr)
        .oneshot(
            Request::builder()
                .uri("/sidecar/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), TEST_BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("route-test-redacted"));
    assert!(!text.contains("tenant.example"));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["preset"], "kubernetes");
    assert!(value["capabilities"].is_array());
}

#[tokio::test]
async fn proxy_route_given_proxy_preset_and_missing_authorization_then_returns_challenge() {
    let upstream_addr = spawn_upstream_server().await;
    let mut policy = tempfile::NamedTempFile::new().unwrap();
    write!(
        policy,
        "{}",
        serde_json::json!({
            "tenant_id": "tenant-1",
            "organization_id": "org-1",
            "policy_generation": "proxy-v1",
            "pull_limit_per_hour": 100,
            "push_limit_per_hour": 10,
            "blocklist_policies": [],
            "trusted_context_headers": ["x-aux-subject-id"]
        })
    )
    .unwrap();
    let mut config = sidecar_config(upstream_addr);
    config.preset = sidecar_core::DeploymentPreset::Proxy;
    config.proxy_policy_path = Some(policy.path().to_path_buf());
    let app = build_router(build_state(config).unwrap());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/sidecar/proxy/check")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["www-authenticate"],
        "DPoP algs=\"ES256\", Bearer"
    );
}

#[tokio::test]
async fn authz_shadow_metrics_route_given_no_shadow_requests_then_returns_zero_counters() {
    let upstream_addr = spawn_upstream_server().await;
    let app = sidecar_router(upstream_addr);
    let request = Request::builder()
        .method("GET")
        .uri("/sidecar/authz/shadow_metrics")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["attempts"], 0);
    assert_eq!(value["matches"], 0);
    assert_eq!(value["mismatches"], 0);
    assert_eq!(value["errors"], 0);
}

#[tokio::test]
async fn authz_route_given_upstream_internal_diagnostics_then_public_json_excludes_them() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = Router::new().route(
        "/authz/runtime/evaluation",
        post(|| async {
            Json(json!({
                "decision": false,
                "context": {"reason_admin": "stable public reason", "policy_version": 7},
                "diagnostics": {
                    "determining_policy_ids": ["internal_policy_123"],
                    "cedar_errors": ["sensitive_entity_attribute"]
                }
            }))
        }),
    );
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/authz/evaluate")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "subject": {"type": "user", "id": "user_123"},
                "resource": {"type": "repository", "id": "repo_123"},
                "action": {"name": "read"}
            })
            .to_string(),
        ))
        .unwrap();

    let response = sidecar_router(addr).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), TEST_BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("stable public reason"));
    for internal in [
        "diagnostics",
        "determining_policy_ids",
        "internal_policy_123",
        "cedar_errors",
        "sensitive_entity_attribute",
    ] {
        assert!(
            !text.contains(internal),
            "leaked internal diagnostic {internal}"
        );
    }
}

#[tokio::test]
async fn authz_route_given_oversized_upstream_response_then_rejects_before_json_decode() {
    let large_body = format!(
        r#"{{"decision":false,"padding":"{}"}}"#,
        "x".repeat(MAX_UPSTREAM_RESPONSE_BYTES + 1)
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = Router::new().route(
        "/authz/runtime/evaluation",
        post(move || {
            let large_body = large_body.clone();
            async move { (StatusCode::OK, large_body) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/authz/evaluate")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "subject": {"type": "user", "id": "user_123"},
                "resource": {"type": "repository", "id": "repo_123"},
                "action": {"name": "read"}
            })
            .to_string(),
        ))
        .unwrap();

    let response = sidecar_router(addr).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn json_route_given_oversized_request_then_rejects_before_handler() {
    let upstream_addr = spawn_upstream_server().await;
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/authz/evaluate")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(format!(
            r#"{{"subject":{{"type":"user","id":"user"}},"resource":{{"type":"repo","id":"repo"}},"action":{{"name":"read"}},"padding":"{}"}}"#,
            "x".repeat(MAX_REQUEST_BODY_BYTES)
        )))
        .unwrap();

    let response = sidecar_router(upstream_addr)
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn rate_limit_config_route_given_upstream_secret_error_then_redacts_local_error_body() {
    let upstream_addr = spawn_sensitive_error_server().await;
    let app = sidecar_router(upstream_addr);
    let request = Request::builder()
        .method("GET")
        .uri("/sidecar/rate_limit/config")
        .header("x-forwarded-for", "127.0.0.1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = to_bytes(response.into_body(), TEST_BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["code"], "rate_limit_upstream_failure");
    assert!(!value["message"].as_str().unwrap().contains("sensitive"));
}

#[test]
fn traceparent_given_valid_w3c_shape_then_accepts() {
    assert!(valid_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    ));
}

#[test]
fn trace_headers_given_invalid_values_then_rejects() {
    assert!(!valid_traceparent(
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    ));
    assert!(!valid_traceparent(
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
    ));
    assert!(!valid_tracestate("tenant=value\nnext=value"));
}

#[tokio::test]
async fn validate_authn_jwt_route_given_valid_token_then_returns_claims() {
    let jwks_addr = spawn_jwks_server().await;
    let app = sidecar_router(jwks_addr);
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/authn/validate_jwt")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "token": sidecar_fixtures::jwt::authn_token_with_issuer(&issuer(jwks_addr)) })
                .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["claims"]["iss"], issuer(jwks_addr));
    assert_eq!(value["cache_status"], "miss");
}

#[tokio::test]
async fn validate_oauth_access_token_route_given_valid_token_then_returns_claims() {
    let jwks_addr = spawn_jwks_server().await;
    let app = sidecar_router(jwks_addr);
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/oauth/validate_access_token")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "token": sidecar_fixtures::jwt::oauth_token_with_issuer(&issuer(jwks_addr)), "scheme":"Bearer", "method":"GET", "target_uri":"https://resource.example/a" })
                .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["claims"]["aud"], sidecar_fixtures::jwt::audience());
}

#[tokio::test]
async fn begin_hosted_login_route_given_valid_request_then_returns_login_url_with_state() {
    let upstream_addr = spawn_upstream_server().await;
    let app = sidecar_router(upstream_addr);
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/hosted_login/begin")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "client_id": sidecar_fixtures::jwt::audience(),
                "redirect_uri": "http://127.0.0.1:8787/callback",
                "scopes": ["openid"]
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let login_url = value["login_url"].as_str().unwrap();
    assert!(login_url.contains("/oauth2/authorize"));
    assert!(login_url.contains("code_challenge_method=S256"));
}

#[tokio::test]
async fn complete_hosted_login_route_given_original_state_then_returns_tokens() {
    let upstream_addr = spawn_upstream_server().await;
    let app = sidecar_router(upstream_addr);
    let begin_response = app
        .clone()
        .oneshot(begin_hosted_login_request())
        .await
        .unwrap();
    let begin_body = to_bytes(begin_response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let begin_value: serde_json::Value = serde_json::from_slice(&begin_body).unwrap();
    let state = login_url_param(begin_value["login_url"].as_str().unwrap(), "state");
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/hosted_login/complete")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "state": state,
                "code": "code_fixture"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["tokens"]["token_type"], "Bearer");
    assert_eq!(
        value["access_token_claims"]["aud"],
        sidecar_fixtures::jwt::audience()
    );
}

#[tokio::test]
async fn given_unavailable_runtime_authority_when_validating_or_proxying_then_service_is_unavailable()
 {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    for upstream_status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let forwarded = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&forwarded);
        let upstream = Router::new()
            .route(
                "/runtime/local/sync",
                post(move || async move { upstream_status }),
            )
            .route(
                "/documents/one",
                get(move || {
                    let observed = Arc::clone(&observed);
                    async move {
                        observed.fetch_add(1, Ordering::Relaxed);
                        "document"
                    }
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let mut config = sidecar_config(address);
        config.upstream_url = Some(format!("http://{address}"));
        config.external_base_url = Some("https://resource.example".to_owned());
        let app = build_router(build_state(config).unwrap());
        let token = sidecar_fixtures::jwt::oauth_token_with_issuer(&issuer(address));
        let validation = Request::builder().method("POST")
            .uri("/sidecar/oauth/validate_access_token").header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"token":token,"scheme":"Bearer","method":"GET","target_uri":"https://resource.example/documents/one"}).to_string())).unwrap();
        let protected = Request::builder()
            .uri("/documents/one")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        for request in [validation, protected] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream runtime status {upstream_status} is not caller authentication"
            );
            assert!(!response.headers().contains_key("www-authenticate"));
        }
        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/documents/one")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert!(missing.headers().contains_key("www-authenticate"));
        let explicit = Request::builder().method("POST").uri("/sidecar/sync")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"protocol_version":1,"known":{},"want":["jwks"],"authz":null,"entitlements":[],"blocklist_policy_refs":[],"revocation_audiences":[]}).to_string())).unwrap();
        assert_eq!(
            app.oneshot(explicit).await.unwrap().status(),
            StatusCode::BAD_GATEWAY,
            "explicit operator sync retains its transport error"
        );
        assert_eq!(forwarded.load(Ordering::Relaxed), 0);
        server.abort();
    }
}
