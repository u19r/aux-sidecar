use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::json;
use sidecar_contract::{
    RateLimitConfig, RequestContext, TokenResponse, ValidateAuthnJwtRequest,
    ValidateOAuthAccessTokenRequest,
};

use crate::{
    JwtValidationConfig, LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngine,
    SidecarEngineConfig, SidecarFuture, SidecarTransport,
};

#[derive(Debug)]
pub(crate) struct TestTransport {
    jwks: serde_json::Value,
    jwks_fetch_count: Arc<AtomicUsize>,
}

impl TestTransport {
    pub(crate) fn new() -> Self {
        Self {
            jwks: test_jwks(),
            jwks_fetch_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn with_jwks(jwks: serde_json::Value) -> Self {
        Self {
            jwks,
            jwks_fetch_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn with_jwks_fetch_count(jwks_fetch_count: Arc<AtomicUsize>) -> Self {
        Self {
            jwks: test_jwks(),
            jwks_fetch_count,
        }
    }
}

impl SidecarTransport for TestTransport {
    fn acquire_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitAcquireLeaseResponse> {
        unimplemented_future()
    }

    fn give_back_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitGiveBackLeaseResponse> {
        unimplemented_future()
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, RateLimitConfig> {
        Box::pin(async { Ok(RateLimitConfig::default()) })
    }

    fn decide_blocklist<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimeBlocklistDecisionResponse> {
        unimplemented_future()
    }

    fn decide_policy<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimePolicyDecisionResponse> {
        unimplemented_future()
    }

    fn evaluate_authz<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::ApiEvaluationRequest,
    ) -> SidecarFuture<'a, sidecar_contract::UpstreamAuthzResponse> {
        unimplemented_future()
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, sidecar_contract::EntitlementEvaluateResponse> {
        unimplemented_future()
    }

    fn fetch_jwks<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        self.jwks_fetch_count.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(self.jwks.clone()) })
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        Box::pin(async move {
            Ok(TokenResponse {
                access_token: test_token(Some("sidecar-resource")),
                token_type: "Bearer".to_string(),
                expires_in: 300,
                refresh_token: None,
                scope: None,
                id_token: None,
            })
        })
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        Box::pin(async move {
            assert!(form_fields.contains(&("grant_type", "refresh_token".to_string())));
            assert!(form_fields.contains(&("client_id", "sidecar-hosted-login".to_string())));
            assert!(
                form_fields
                    .iter()
                    .any(|(name, value)| *name == "refresh_token" && value == "refresh_123")
            );
            Ok(TokenResponse {
                access_token: test_token(Some("sidecar-resource")),
                token_type: "Bearer".to_string(),
                expires_in: 300,
                refresh_token: Some("refresh_456".to_string()),
                scope: Some("openid profile".to_string()),
                id_token: None,
            })
        })
    }
}

#[tokio::test]
async fn get_rate_limit_config_given_empty_cache_then_fetches_and_caches() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let first = engine
        .get_rate_limit_config(&RequestContext::default())
        .await
        .unwrap();
    let second = engine
        .get_rate_limit_config(&RequestContext::default())
        .await
        .unwrap();

    assert_eq!(first.cache_status, sidecar_contract::CacheStatus::Miss);
    assert_eq!(second.cache_status, sidecar_contract::CacheStatus::Fresh);
}

#[tokio::test]
async fn validate_authn_jwt_given_valid_token_then_returns_claims() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let result = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(test_token(None)),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.claims["iss"], sidecar_fixtures::jwt::issuer());
    assert_eq!(result.claims["sub"], "user_fixture");
    assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Miss);
}

#[tokio::test]
async fn validate_authn_jwt_given_cached_jwks_then_reuses_cached_keys() {
    let fetch_count = Arc::new(AtomicUsize::new(0));
    let engine = SidecarEngine::new(
        config(),
        TestTransport::with_jwks_fetch_count(Arc::clone(&fetch_count)),
    );

    let first = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(test_token(None)),
            },
        )
        .await
        .unwrap();
    let second = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(test_token(None)),
            },
        )
        .await
        .unwrap();

    assert_eq!(first.cache_status, sidecar_contract::CacheStatus::Miss);
    assert_eq!(second.cache_status, sidecar_contract::CacheStatus::Fresh);
    assert_eq!(fetch_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn validate_authn_jwt_given_shared_state_and_different_issuer_then_rejects_other_tenant_token()
 {
    let state = Arc::new(crate::SidecarState::new());
    let issuer_a = "https://tenant-a.example.test";
    let issuer_b = "https://tenant-b.example.test";
    let engine_a = SidecarEngine::with_state(
        config_with_issuer(issuer_a),
        Arc::clone(&state),
        TestTransport::new(),
    );
    let engine_b =
        SidecarEngine::with_state(config_with_issuer(issuer_b), state, TestTransport::new());
    let tenant_a_token = sidecar_fixtures::jwt::authn_token_with_issuer(issuer_a);

    engine_a
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(tenant_a_token.clone()),
            },
        )
        .await
        .unwrap();
    let error = engine_b
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(tenant_a_token),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwt_invalid");
}

#[tokio::test]
async fn validate_authn_jwt_given_invalid_jwks_then_returns_parse_error() {
    let engine = SidecarEngine::new(
        config(),
        TestTransport::with_jwks(json!({ "keys": "not-a-key-list" })),
    );

    let error = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(test_token(None)),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwks_parse_failed");
}

#[tokio::test]
async fn validate_oauth_access_token_given_conflicting_library_audience_config_then_rejects_config()
{
    let mut config = config();
    if let Some(validation) = config.jwt_validation.as_mut() {
        validation.audience_check_disabled = true;
    }
    let engine = SidecarEngine::new(config, TestTransport::new());

    let error = engine
        .validate_oauth_access_token(
            &RequestContext::default(),
            &ValidateOAuthAccessTokenRequest {
                scheme: "Bearer".into(),
                method: "GET".into(),
                target_uri: "https://sidecar-resource.test/a".into(),
                proof: None,
                token: Some(sidecar_fixtures::jwt::oauth_token()),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "resource_audience_conflict");
}

pub(crate) fn config() -> SidecarEngineConfig {
    config_with_issuer(sidecar_fixtures::jwt::issuer())
}

pub(crate) fn config_with_issuer(issuer: &str) -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: crate::DeploymentPreset::Embedded,
        base_url: issuer.to_string(),
        api_key: "key".to_string(),
        tenant_domain: None,
        cache_ttl: Duration::from_secs(60),
        stale_cache_ttl: Duration::from_secs(300),
        authz_local_mode: LocalAuthzMode::RemoteOnly,
        authz_cache_ttl: Duration::from_secs(10),
        authz_stale_cache_ttl: Duration::from_secs(30),
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::CacheMiss,
        jwt_validation: Some(JwtValidationConfig {
            issuer: issuer.to_string(),
            login_redirect_url: Some("http://127.0.0.1:3000/login".to_string()),
            resource_audiences: Some(vec!["sidecar-resource".to_string()]),
            audience_check_disabled: false,
            clock_skew_seconds: 0,
        }),
    }
}

pub(crate) fn test_jwks() -> serde_json::Value {
    sidecar_fixtures::jwt::jwks()
}

pub(crate) fn test_token(audience: Option<&str>) -> String {
    match audience {
        Some(audience) => sidecar_fixtures::jwt::token(Some(audience)),
        None => sidecar_fixtures::jwt::authn_token(),
    }
}

pub(crate) fn login_url_param(login_url: &str, name: &str) -> String {
    url::Url::parse(login_url)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
        .unwrap()
}

fn unimplemented_future<'a, T>() -> SidecarFuture<'a, T> {
    Box::pin(async {
        Err(crate::SidecarError::internal(
            "not_implemented",
            "test stub",
        ))
    })
}
