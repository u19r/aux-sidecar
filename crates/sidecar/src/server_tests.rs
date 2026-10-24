use std::time::Duration;

use sidecar_core::{DeploymentPreset, LocalAuthzMode, LocalAuthzRemoteFallback};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{config::SidecarConfig, server};

#[test]
fn sidecar_config_given_remote_plaintext_base_url_then_rejects_it() {
    let config = SidecarConfig {
        external_base_url: None,
        preset: DeploymentPreset::Kubernetes,
        bind_addr: "127.0.0.1:9001".to_string(),
        unix_socket_path: None,
        proxy_policy_path: None,
        route_policy_path: None,
        upstream_url: None,
        base_url: "http://tenant.example.test".to_string(),
        issuer: "https://tenant.example.test".to_string(),
        api_key: "fixture-secret".to_string(),
        tenant_domain: None,
        login_redirect_url: None,
        resource_audiences: Vec::new(),
        audience_check_disabled: true,
        jwt_clock_skew_seconds: 0,
        config_path: None,
        cache_ttl_seconds: 60,
        stale_cache_ttl_seconds: 300,
        authz_local_mode: LocalAuthzMode::Enforced,
        authz_cache_ttl_seconds: 10,
        authz_stale_cache_ttl_seconds: 30,
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::Never,
        unsafe_bind_non_loopback: false,
    };
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn unix_listener_given_private_socket_then_serves_liveness_without_tcp() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("sidecar.sock");
    let config = SidecarConfig {
        external_base_url: None,
        preset: DeploymentPreset::Kubernetes,
        bind_addr: "127.0.0.1:0".to_string(),
        unix_socket_path: Some(socket.clone()),
        proxy_policy_path: None,
        route_policy_path: None,
        upstream_url: None,
        base_url: "https://tenant.example.test".to_string(),
        issuer: "https://tenant.example.test".to_string(),
        api_key: "fixture-secret".to_string(),
        tenant_domain: None,
        login_redirect_url: None,
        resource_audiences: Vec::new(),
        audience_check_disabled: true,
        jwt_clock_skew_seconds: 0,
        config_path: None,
        cache_ttl_seconds: 60,
        stale_cache_ttl_seconds: 300,
        authz_local_mode: LocalAuthzMode::Enforced,
        authz_cache_ttl_seconds: 10,
        authz_stale_cache_ttl_seconds: 30,
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::Never,
        unsafe_bind_non_loopback: false,
    };
    let task = tokio::spawn(async move {
        server::serve(config)
            .await
            .map_err(|error| error.to_string())
    });
    let mut stream = connect_with_retry(&socket).await;
    stream
        .write_all(b"GET /sidecar/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    task.abort();

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("\"status\":\"live\""));
}

async fn connect_with_retry(path: &std::path::Path) -> tokio::net::UnixStream {
    for _ in 0..50 {
        if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("sidecar Unix socket did not become ready");
}
