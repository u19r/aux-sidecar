use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use oauth_dpop::test_support::ProofKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use sidecar_contract::{RequestContext, ValidateOAuthAccessTokenRequest};

use crate::{
    DeploymentPreset, SidecarEngine,
    engine_tests::{TestTransport, config},
};

fn request(key: &ProofKey, token: &str) -> ValidateOAuthAccessTokenRequest {
    let proof=key.sign(&json!({"jti":"request","htm":"GET","htu":"https://resource.example/a","iat":crate::state::current_time_millis()/1000,
        "ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}));
    ValidateOAuthAccessTokenRequest {
        scheme: "DPoP".into(),
        method: "GET".into(),
        target_uri: "https://resource.example/a".into(),
        proof: Some(proof),
        token: Some(token.into()),
    }
}

#[tokio::test]
async fn given_each_preset_and_cached_bound_token_when_proof_changes_then_every_request_checks_presenter_without_jwks_or_policy_roundtrips()
 {
    for preset in [
        DeploymentPreset::Embedded,
        DeploymentPreset::Proxy,
        DeploymentPreset::Worker,
        DeploymentPreset::Lambda,
        DeploymentPreset::Kubernetes,
    ] {
        let count = Arc::new(AtomicUsize::new(0));
        let mut configured = config();
        configured.preset = preset;
        configured
            .jwt_validation
            .as_mut()
            .unwrap()
            .resource_audiences = Some(vec![sidecar_fixtures::jwt::audience().into()]);
        let engine = SidecarEngine::new(
            configured,
            TestTransport::with_jwks_fetch_count(count.clone()),
        );
        let key = ProofKey::from_seed(1);
        let other = ProofKey::from_seed(2);
        let token = sidecar_fixtures::jwt::oauth_token_with_confirmation(
            json!({"jkt":key.thumbprint().as_str(),"extension":true}),
        );
        let valid = request(&key, &token);
        assert!(
            engine
                .validate_oauth_access_token(&RequestContext::default(), &valid)
                .await
                .is_ok()
        );
        assert!(
            engine
                .validate_oauth_access_token(&RequestContext::default(), &valid)
                .await
                .is_ok()
        );
        let mut attacks = Vec::new();
        let mut missing = valid.clone();
        missing.proof = None;
        attacks.push(missing);
        let mut bearer = valid.clone();
        bearer.scheme = "Bearer".into();
        attacks.push(bearer);
        let mut method = valid.clone();
        method.method = "POST".into();
        attacks.push(method);
        let mut uri = valid.clone();
        uri.target_uri = "https://resource.example/b".into();
        attacks.push(uri);
        attacks.push(request(&other, &token));
        let mut coalesced = valid.clone();
        coalesced.proof = Some(format!(
            "{},{}",
            valid.proof.as_ref().unwrap(),
            valid.proof.as_ref().unwrap()
        ));
        attacks.push(coalesced);
        let mut wrong_hash = request(&key, "another-token");
        wrong_hash.token = Some(token.clone());
        attacks.push(wrong_hash);
        let stale=key.sign(&json!({"jti":"stale","htm":"GET","htu":"https://resource.example/a","iat":0,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}));
        let mut expired = valid.clone();
        expired.proof = Some(stale);
        attacks.push(expired);
        for invalid in attacks {
            let error = engine
                .validate_oauth_access_token(&RequestContext::default(), &invalid)
                .await
                .unwrap_err();
            assert_eq!(error.status_code, 401);
            assert!(!error.to_string().contains(&token));
            assert!(error.oauth_challenge().unwrap().starts_with("DPoP "));
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(
            engine
                .validate_oauth_access_token(&RequestContext::default(), &valid)
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn given_unbound_or_unsupported_confirmation_when_presented_then_rejects_dpop_or_unsupported_authority_and_preserves_bearer()
 {
    let mut configured = config();
    configured
        .jwt_validation
        .as_mut()
        .unwrap()
        .resource_audiences = Some(vec![sidecar_fixtures::jwt::audience().into()]);
    let engine = SidecarEngine::new(configured, TestTransport::new());
    let key = ProofKey::from_seed(1);
    let token = sidecar_fixtures::jwt::oauth_token();
    let mut presented = request(&key, &token);
    assert_eq!(
        engine
            .validate_oauth_access_token(&RequestContext::default(), &presented)
            .await
            .unwrap_err()
            .status_code,
        401
    );
    presented.scheme = "Bearer".into();
    presented.proof = None;
    assert!(
        engine
            .validate_oauth_access_token(&RequestContext::default(), &presented)
            .await
            .is_ok()
    );
    for confirmation in [
        json!({"future":"unsupported"}),
        json!({"jkt":"invalid"}),
        json!(null),
    ] {
        presented.token = Some(sidecar_fixtures::jwt::oauth_token_with_confirmation(
            confirmation,
        ));
        assert_eq!(
            engine
                .validate_oauth_access_token(&RequestContext::default(), &presented)
                .await
                .unwrap_err()
                .status_code,
            401
        );
    }
}

#[test]
fn given_excessive_expiry_leeway_when_constructing_verification_policy_then_rejects_transition_unsafe_config()
 {
    let mut configured = config();
    let validation = configured.jwt_validation.as_mut().unwrap();
    validation.clock_skew_seconds = oauth_dpop::MAX_ACCESS_TOKEN_EXPIRY_LEEWAY_SECONDS;
    assert!(validation.validate().is_ok());
    validation.clock_skew_seconds += 1;
    assert!(validation.validate().is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn given_independent_openssl_corpus_when_all_presets_validate_cold_and_warm_authority_then_agree_with_the_wasm_contract()
 {
    let producer = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/dpop-adapter-corpus.mjs");
    let output = std::process::Command::new("node")
        .arg(&producer)
        .arg("--emit")
        .output()
        .unwrap();
    assert!(output.status.success());
    let corpus: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let _clock =
        crate::state::test_support::FixedClock::new(corpus["now_seconds"].as_i64().unwrap() * 1000);
    let cases = corpus["cases"].as_array().unwrap();
    let mut decisions = 0;
    for preset in [
        DeploymentPreset::Embedded,
        DeploymentPreset::Proxy,
        DeploymentPreset::Worker,
        DeploymentPreset::Lambda,
        DeploymentPreset::Kubernetes,
    ] {
        let mut configured = config();
        configured.preset = preset;
        let policy = configured.jwt_validation.as_mut().unwrap();
        policy.issuer = corpus["issuer"].as_str().unwrap().into();
        policy.resource_audiences = Some(vec![corpus["audience"].as_str().unwrap().into()]);
        let engine =
            SidecarEngine::new(configured, TestTransport::with_jwks(corpus["jwks"].clone()));
        for entry in cases {
            for _ in 0..2 {
                let request = ValidateOAuthAccessTokenRequest {
                    scheme: "DPoP".into(),
                    token: Some(corpus["access_token"].as_str().unwrap().into()),
                    proof: Some(entry["proof"].as_str().unwrap().into()),
                    method: entry["request_method"].as_str().unwrap_or("GET").into(),
                    target_uri: corpus["target_uri"].as_str().unwrap().into(),
                };
                let result = engine
                    .validate_oauth_access_token(&RequestContext::default(), &request)
                    .await;
                let name = entry["name"].as_str().unwrap();
                assert_eq!(
                    result.is_ok(),
                    entry["accepted"].as_bool().unwrap(),
                    "{name}"
                );
                if let Err(error) = result {
                    assert_eq!(error.status_code, 401, "{name}");
                    assert_eq!(error.code, "invalid_dpop_proof", "{name}");
                }
                decisions += 1;
            }
        }
    }
    assert_eq!(decisions, cases.len() * 10);
}
