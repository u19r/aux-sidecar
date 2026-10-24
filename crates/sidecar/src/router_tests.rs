use std::{net::SocketAddr, time::Duration};

use axum::{
    Json, Router,
    body::Body,
    extract::OriginalUri,
    http::{HeaderMap, Request, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use serde_json::json;
use sidecar_core::{LocalAuthzMode, LocalAuthzRemoteFallback};
use tower::ServiceExt;

use crate::{config::SidecarConfig, router::build_router, state::build_state};

#[path = "router_cases_tests.rs"]
mod router_cases;

fn begin_hosted_login_request() -> Request<Body> {
    Request::builder()
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
        .unwrap()
}

pub(crate) fn sidecar_router(jwks_addr: SocketAddr) -> Router {
    build_router(build_state(sidecar_config(jwks_addr)).unwrap())
}

fn sidecar_config(jwks_addr: SocketAddr) -> SidecarConfig {
    SidecarConfig {
        external_base_url: None,
        preset: sidecar_core::DeploymentPreset::Kubernetes,
        bind_addr: "127.0.0.1:0".to_string(),
        unix_socket_path: None,
        proxy_policy_path: None,
        route_policy_path: None,
        upstream_url: None,
        base_url: issuer(jwks_addr),
        issuer: issuer(jwks_addr),
        api_key: "route-test-redacted".to_string(),
        tenant_domain: None,
        login_redirect_url: Some("http://127.0.0.1:3000/login".to_string()),
        resource_audiences: vec![sidecar_fixtures::jwt::audience().to_string()],
        audience_check_disabled: false,
        jwt_clock_skew_seconds: 0,
        config_path: None,
        cache_ttl_seconds: 60,
        stale_cache_ttl_seconds: 300,
        authz_local_mode: LocalAuthzMode::RemoteOnly,
        authz_cache_ttl_seconds: 10,
        authz_stale_cache_ttl_seconds: 30,
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::CacheMiss,
        unsafe_bind_non_loopback: false,
    }
}

fn issuer(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

async fn spawn_jwks_server() -> SocketAddr {
    spawn_upstream_server().await
}

pub(crate) async fn spawn_upstream_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let token_issuer = issuer(addr);
    let app = Router::new()
        .route(
            "/.well-known/jwks.json",
            get(|| async { Json(sidecar_fixtures::jwt::jwks()) }),
        )
        .route(
            "/oauth2/token",
            post(move || {
                let token_issuer = token_issuer.clone();
                async move {
                    Json(json!({
                        "access_token": sidecar_fixtures::jwt::oauth_token_with_issuer(&token_issuer),
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "refresh_token": "refresh_456",
                        "scope": "openid profile"
                    }))
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

async fn spawn_sensitive_error_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/rate-limit/runtime/config",
        get(|| async {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "sensitive upstream detail",
            )
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn route_proxy_validates_and_forwards_original_bearer() {
    let jwks_addr = spawn_jwks_server().await;
    let upstream_addr = spawn_capture_server().await;
    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("routes.json");
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "openapi": "3.1.0",
            "paths": {
                "/documents/{document_id}": {
                    "get": {
                        "operationId": "get_document",
                        "parameters": [{
                            "in": "path", "name": "document_id", "required": true,
                            "schema": {"type": "string", "format": "uuid"}
                        }],
                        "x-aux-authn": {
                            "mode": "bearer",
                            "audiences": [sidecar_fixtures::jwt::audience()]
                        },
                        "x-aux-authz": {"required_scopes": []}
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let mut config = sidecar_config(jwks_addr);
    config.route_policy_path = Some(policy_path);
    config.upstream_url = Some(issuer(upstream_addr));
    config.external_base_url = Some("https://resource.example".into());
    let state = build_state(config).unwrap();
    state
        .engine
        .state()
        .store_revocation_snapshot(sidecar_core::RevocationSnapshot::new(
            [sidecar_fixtures::jwt::audience().to_string()],
            std::iter::empty::<(String, i64)>(),
            sidecar_core::current_time_millis(),
            60_000,
            60_000,
        ));
    let app = build_router(state);
    let token = sidecar_fixtures::jwt::oauth_token_with_issuer(&issuer(jwks_addr));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/documents/550e8400-e29b-41d4-a716-446655440000?include=owner")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["path"],
        "/documents/550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(value["authorization"], format!("Bearer {token}"));
}

#[tokio::test]
async fn route_proxy_rejects_invalid_bearer_before_upstream() {
    let jwks_addr = spawn_jwks_server().await;
    let upstream_addr = spawn_capture_server().await;
    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("routes.json");
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "paths": {
                "/private": {
                    "get": {
                        "x-aux-authn": {
                            "mode": "bearer",
                            "audiences": [sidecar_fixtures::jwt::audience()]
                        }
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let mut config = sidecar_config(jwks_addr);
    config.route_policy_path = Some(policy_path);
    config.upstream_url = Some(issuer(upstream_addr));
    config.external_base_url = Some("https://resource.example".into());
    let app = build_router(build_state(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/private")
                .header("authorization", "Bearer not-a-jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));
}

async fn spawn_capture_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(
        |OriginalUri(uri): OriginalUri, headers: HeaderMap| async move {
            Json(json!({
                "path": uri.path(),
                "authorization": headers.get("authorization").and_then(|value| value.to_str().ok())
            }))
        },
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

fn login_url_param(login_url: &str, name: &str) -> String {
    url::Url::parse(login_url)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
        .unwrap()
}

#[tokio::test]
async fn given_bound_resource_token_when_native_proxy_receives_valid_or_stolen_presenters_then_only_valid_requests_reach_upstream()
 {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let jwks_addr = spawn_jwks_server().await;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let observed = effects.clone();
    let upstream = Router::new().fallback(move || {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            "protected"
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let mut config = sidecar_config(jwks_addr);
    config.upstream_url = Some(issuer(upstream_addr));
    config.external_base_url = Some("https://resource.example/prefix".into());
    let state = build_state(config).unwrap();
    state
        .engine
        .state()
        .store_revocation_snapshot(sidecar_core::RevocationSnapshot::new(
            [sidecar_fixtures::jwt::audience().to_owned()],
            std::iter::empty::<(String, i64)>(),
            sidecar_core::current_time_millis(),
            60_000,
            60_000,
        ));
    let app = build_router(state);
    let key = oauth_dpop::test_support::ProofKey::from_seed(1);
    let token = sidecar_fixtures::jwt::oauth_token_with_confirmation_for_issuer(
        &issuer(jwks_addr),
        json!({"jkt":key.thumbprint().as_str()}),
    );
    let claims = json!({"jti":"native-request","htm":"GET","htu":"https://resource.example/prefix/private","iat":sidecar_core::current_time_millis()/1000,
        "ath":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))});
    let proof = key.sign(&claims);
    let valid = Request::builder()
        .uri("/private?include=one")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof)
        .header("x-forwarded-host", "attacker.example")
        .header("x-forwarded-proto", "http")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(valid).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    for scheme in ["Bearer", "DPoP"] {
        let request = Request::builder()
            .uri("/private")
            .header("authorization", format!("{scheme} {token}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));
    }
    let duplicate = Request::builder()
        .uri("/private")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof)
        .header("dpop", &proof)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let wrong_method = Request::builder()
        .method("POST")
        .uri("/private")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(wrong_method).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let missing = app
        .oneshot(
            Request::builder()
                .uri("/private")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert!(
        !missing.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("error=")
    );
    server.abort();
}

#[tokio::test]
async fn given_private_backend_and_public_issuer_when_verifying_tokens_then_only_the_configured_issuer_is_accepted()
 {
    let address = spawn_jwks_server().await;
    let mut config = sidecar_config(address);
    let public_issuer = "https://account.example.test";
    config.issuer = public_issuer.to_owned();
    assert!(config.validate().is_ok());
    assert_eq!(
        config
            .engine_config()
            .jwt_validation
            .as_ref()
            .unwrap()
            .issuer,
        public_issuer
    );
    let app = build_router(build_state(config).unwrap());
    let begin = app
        .clone()
        .oneshot(begin_hosted_login_request())
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let body = axum::body::to_bytes(begin.into_body(), 65536)
        .await
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let login = url::Url::parse(document["login_url"].as_str().unwrap()).unwrap();
    assert_eq!(login.origin().ascii_serialization(), public_issuer);
    assert_eq!(login.path(), "/oauth2/authorize");
    for (token_issuer, expected) in [
        (public_issuer.to_owned(), StatusCode::OK),
        (issuer(address), StatusCode::UNAUTHORIZED),
        (
            "https://other.example.test".to_owned(),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/sidecar/oauth/validate_access_token")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "token": sidecar_fixtures::jwt::oauth_token_with_issuer(&token_issuer),
                    "scheme": "Bearer", "method": "GET", "target_uri": "https://resource.example/a"
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
}
