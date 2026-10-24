use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use serde_json::json;
use tower::ServiceExt;

use crate::{
    constants::TEST_BODY_LIMIT_BYTES,
    router_tests::{sidecar_router, spawn_upstream_server},
};

#[tokio::test]
async fn refresh_hosted_login_route_given_refresh_token_then_returns_rotated_tokens() {
    let upstream_addr = spawn_upstream_server().await;
    let app = sidecar_router(upstream_addr);
    let request = Request::builder()
        .method("POST")
        .uri("/sidecar/hosted_login/refresh")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "client_id": sidecar_fixtures::jwt::audience(),
                "refresh_token": "refresh_123",
                "scope": "openid profile"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), TEST_BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["tokens"]["token_type"], "Bearer");
    assert_eq!(value["tokens"]["refresh_token"], "refresh_456");
    assert_eq!(
        value["access_token_claims"]["aud"],
        sidecar_fixtures::jwt::audience()
    );
}
