#![allow(unused_imports)]
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::json;
use sidecar_contract::{
    BeginHostedLoginRequest, CompleteHostedLoginRequest, RateLimitConfig,
    RefreshHostedLoginRequest, RequestContext, TokenResponse, ValidateAuthnJwtRequest,
    ValidateOAuthAccessTokenRequest,
};

use crate::{
    JwtValidationConfig, LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngine,
    SidecarEngineConfig, SidecarFuture, SidecarTransport,
    engine_tests::{TestTransport, config, config_with_issuer, login_url_param, test_token},
};

#[tokio::test]
async fn validate_authn_jwt_given_missing_token_then_returns_login_redirect() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest::default(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwt_missing");
    assert_eq!(
        error.redirect_url,
        Some("http://127.0.0.1:3000/login".to_string())
    );
    assert_eq!(error.redirect_reason, Some("login_required"));
}

#[tokio::test]
async fn validate_oauth_access_token_given_audience_match_then_returns_claims() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let result = engine
        .validate_oauth_access_token(
            &RequestContext::default(),
            &ValidateOAuthAccessTokenRequest {
                scheme: "Bearer".into(),
                method: "GET".into(),
                target_uri: "https://sidecar-resource.test/a".into(),
                proof: None,
                token: Some(test_token(Some("sidecar-resource"))),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.claims["aud"], "sidecar-resource");
}

#[tokio::test]
async fn validate_oauth_access_token_given_audience_mismatch_then_rejects() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .validate_oauth_access_token(
            &RequestContext::default(),
            &ValidateOAuthAccessTokenRequest {
                scheme: "Bearer".into(),
                method: "GET".into(),
                target_uri: "https://sidecar-resource.test/a".into(),
                proof: None,
                token: Some(test_token(Some("other-client"))),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwt_invalid");
}

#[tokio::test]
async fn validate_oauth_access_token_given_audience_check_disabled_then_accepts_missing_audience() {
    let mut config = config();
    if let Some(validation) = config.jwt_validation.as_mut() {
        validation.resource_audiences = None;
        validation.audience_check_disabled = true;
    }
    let engine = SidecarEngine::new(config, TestTransport::new());

    let result = engine
        .validate_oauth_access_token(
            &RequestContext::default(),
            &ValidateOAuthAccessTokenRequest {
                scheme: "Bearer".into(),
                method: "GET".into(),
                target_uri: "https://sidecar-resource.test/a".into(),
                proof: None,
                token: Some(sidecar_fixtures::jwt::oauth_token_without_audience()),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.claims["iss"], sidecar_fixtures::jwt::issuer());
}

#[tokio::test]
async fn validate_oauth_access_token_given_authn_token_then_rejects_token_type() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .validate_oauth_access_token(
            &RequestContext::default(),
            &ValidateOAuthAccessTokenRequest {
                scheme: "Bearer".into(),
                method: "GET".into(),
                target_uri: "https://sidecar-resource.test/a".into(),
                proof: None,
                token: Some(sidecar_fixtures::jwt::authn_token()),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwt_invalid");
}

#[tokio::test]
async fn validate_authn_jwt_given_oauth_access_token_then_rejects_token_type() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some(sidecar_fixtures::jwt::oauth_token()),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwt_invalid");
}

#[tokio::test]
async fn validate_authn_jwt_given_malformed_token_then_rejects_header_before_claims() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .validate_authn_jwt(
            &RequestContext::default(),
            &ValidateAuthnJwtRequest {
                token: Some("not-a-jwt".to_string()),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "jwt_header_invalid");
}

#[tokio::test]
async fn hosted_login_given_begin_and_complete_then_exchanges_code_and_validates_token() {
    let engine = SidecarEngine::new(config(), TestTransport::new());
    let begin = engine
        .begin_hosted_login(&BeginHostedLoginRequest {
            client_id: "sidecar-hosted-login".to_string(),
            redirect_uri: "http://127.0.0.1:8787/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            login_hint: Some("user@example.test".to_string()),
        })
        .unwrap();
    let state = login_url_param(&begin.login_url, "state");

    let completed = engine
        .complete_hosted_login(
            &RequestContext::default(),
            &CompleteHostedLoginRequest {
                state,
                code: Some("code_123".to_string()),
                error: None,
                error_description: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(completed.tokens.token_type, "Bearer");
    assert_eq!(completed.access_token_claims["aud"], "sidecar-resource");
}

#[tokio::test]
async fn hosted_login_given_remote_redirect_uri_then_rejects_begin_request() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .begin_hosted_login(&BeginHostedLoginRequest {
            client_id: "sidecar-hosted-login".to_string(),
            redirect_uri: "https://attacker.example.test/callback".to_string(),
            scopes: Vec::new(),
            login_hint: None,
        })
        .unwrap_err();

    assert_eq!(error.code, "hosted_login_redirect_uri_untrusted");
}

#[tokio::test]
async fn hosted_login_given_oversized_direct_input_then_rejects_before_url_construction() {
    let engine = SidecarEngine::new(config(), TestTransport::new());
    let error = engine
        .begin_hosted_login(&BeginHostedLoginRequest {
            client_id: "client".to_string(),
            redirect_uri: format!("http://127.0.0.1/{}", "x".repeat(2_048)),
            scopes: Vec::new(),
            login_hint: None,
        })
        .expect_err("oversized direct hosted-login input should fail");

    assert_eq!(error.code, "hosted_login_input_too_large");
}

#[tokio::test]
async fn hosted_login_given_reused_state_then_rejects_second_completion() {
    let engine = SidecarEngine::new(config(), TestTransport::new());
    let begin = engine
        .begin_hosted_login(&BeginHostedLoginRequest {
            client_id: "sidecar-hosted-login".to_string(),
            redirect_uri: "http://127.0.0.1:8787/callback".to_string(),
            scopes: Vec::new(),
            login_hint: None,
        })
        .unwrap();
    let state = login_url_param(&begin.login_url, "state");
    let request = CompleteHostedLoginRequest {
        state,
        code: Some("code_123".to_string()),
        error: None,
        error_description: None,
    };

    engine
        .complete_hosted_login(&RequestContext::default(), &request)
        .await
        .unwrap();
    let error = engine
        .complete_hosted_login(&RequestContext::default(), &request)
        .await
        .unwrap_err();

    assert_eq!(error.code, "hosted_login_state_invalid");
}

#[tokio::test]
async fn hosted_login_given_refresh_token_then_exchanges_refresh_and_validates_access_token() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let refreshed = engine
        .refresh_hosted_login(
            &RequestContext::default(),
            &RefreshHostedLoginRequest {
                client_id: "sidecar-hosted-login".to_string(),
                refresh_token: "refresh_123".to_string(),
                scope: Some("openid profile".to_string()),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        refreshed.tokens.refresh_token.as_deref(),
        Some("refresh_456")
    );
    assert_eq!(refreshed.access_token_claims["aud"], "sidecar-resource");
}

#[tokio::test]
async fn hosted_login_given_empty_refresh_token_then_rejects_without_exchange() {
    let engine = SidecarEngine::new(config(), TestTransport::new());

    let error = engine
        .refresh_hosted_login(
            &RequestContext::default(),
            &RefreshHostedLoginRequest {
                client_id: "sidecar-hosted-login".to_string(),
                refresh_token: " ".to_string(),
                scope: None,
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "hosted_login_refresh_token_missing");
}

#[test]
fn given_no_configured_jwt_identity_when_beginning_hosted_login_then_missing_validation_is_rejected_before_handoff()
 {
    let mut settings = config();
    settings.jwt_validation = None;
    let engine = SidecarEngine::new(settings, TestTransport::new());
    let error = engine
        .begin_hosted_login(&BeginHostedLoginRequest {
            client_id: "sidecar-hosted-login".into(),
            redirect_uri: "http://127.0.0.1:8787/callback".into(),
            scopes: vec!["openid".into()],
            login_hint: None,
        })
        .unwrap_err();
    assert_eq!(error.code, "jwt_validation_missing");
}

#[test]
fn given_invalid_issuer_when_embedded_engine_begins_hosted_login_then_handoff_is_rejected() {
    for issuer in [
        "https://account.example.test/.",
        "https://account.example.test/a/..",
        "https://account.example.test/%2e",
        "https://user@account.example.test",
        "http://remote.example.test",
        "https://account.example.test/path",
        "https://account.example.test?query=value",
        "https://account.example.test#fragment",
    ] {
        let engine = SidecarEngine::new(config_with_issuer(issuer), TestTransport::new());
        let error = engine
            .begin_hosted_login(&BeginHostedLoginRequest {
                client_id: "sidecar-hosted-login".into(),
                redirect_uri: "http://127.0.0.1:8787/callback".into(),
                scopes: vec!["openid".into()],
                login_hint: None,
            })
            .unwrap_err();
        assert_eq!(error.code, "jwt_issuer_invalid");
    }
}
