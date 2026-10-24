use serde_json::json;

use crate::api::SidecarClient;

#[test]
fn begin_hosted_login_given_missing_trusted_config_then_rejects_request() {
    let client = SidecarClient::new();

    let response = client.begin_hosted_login(
        &json!({
            "client_id": "sidecar-wasm",
            "redirect_uri": "http://127.0.0.1:8787/callback",
            "scopes": ["openid"]
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["code"], "jwt_validation_missing");
}

#[test]
fn begin_hosted_login_given_private_backend_then_uses_configured_public_issuer() {
    let mut client = SidecarClient::new();
    configure_trusted_jwt_with_base_url(&mut client, "http://127.0.0.1:39080");

    let response = client.begin_hosted_login(
        &json!({
            "client_id": "sidecar-wasm",
            "redirect_uri": "http://127.0.0.1:8787/callback",
            "scopes": ["openid"]
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert!(value["login_url"].as_str().unwrap().starts_with(&format!(
        "{}/oauth2/authorize?",
        sidecar_fixtures::jwt::issuer()
    )));
}

#[test]
fn validate_authn_jwt_given_host_jwks_then_returns_claims() {
    let mut client = SidecarClient::new();
    configure_trusted_jwt(&mut client);

    let response = client.validate_authn_jwt(
        &json!({
            "request": {"token": sidecar_fixtures::jwt::authn_token()}
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["claims"]["sub"], "user_fixture");
}

#[test]
fn validate_oauth_access_token_given_host_jwks_then_returns_claims() {
    let mut client = SidecarClient::new();
    configure_trusted_jwt(&mut client);

    let response = client.validate_oauth_access_token(
        &json!({
            "request": {"token": sidecar_fixtures::jwt::oauth_token(), "scheme":"Bearer", "method":"GET", "target_uri":"https://resource.example/a"}
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["claims"]["aud"], sidecar_fixtures::jwt::audience());
}

#[test]
fn validate_authn_jwt_given_missing_trusted_config_then_rejects_request() {
    let client = SidecarClient::new();

    let response = client.validate_authn_jwt(
        &json!({
            "request": {"token": sidecar_fixtures::jwt::authn_token()}
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["code"], "wasm_trusted_jwt_missing");
}

#[test]
fn configure_trusted_jwt_given_relative_base_url_then_rejects_request() {
    let mut client = SidecarClient::new();

    let response = client.configure_trusted_jwt(
        &json!({
            "jwks": sidecar_fixtures::jwt::jwks(),
            "issuer": sidecar_fixtures::jwt::issuer(),
            "base_url": "/tenant",
            "resource_audiences": [sidecar_fixtures::jwt::audience()]
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["code"], "wasm_base_url_invalid");
}

#[test]
fn configure_trusted_jwt_given_embedded_credentials_then_rejects_them() {
    let mut client = SidecarClient::new();

    let response = client.configure_trusted_jwt(
        &json!({
            "jwks": {},
            "issuer": sidecar_fixtures::jwt::issuer(),
            "base_url": "https://user:password@example.com",
            "resource_audiences": [sidecar_fixtures::jwt::audience()]
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["code"], "wasm_base_url_credentials");
}

#[test]
fn configure_trusted_jwt_given_remote_plaintext_base_url_then_rejects_it() {
    let mut client = SidecarClient::new();

    let response = client.configure_trusted_jwt(
        &json!({
            "jwks": {},
            "issuer": sidecar_fixtures::jwt::issuer(),
            "base_url": "http://tenant.example.test",
            "resource_audiences": [sidecar_fixtures::jwt::audience()]
        })
        .to_string(),
    );

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["code"], "wasm_base_url_insecure");
}

#[test]
fn configure_trusted_jwt_given_oversized_json_then_rejects_before_parse() {
    let mut client = SidecarClient::new();
    let issuer = "i".repeat(crate::host::MAX_WASM_REQUEST_BYTES);
    let config = json!({
        "jwks": {},
        "issuer": issuer,
        "base_url": "http://127.0.0.1:8080",
        "resource_audiences": [sidecar_fixtures::jwt::audience()]
    })
    .to_string();
    assert!(config.len() > crate::host::MAX_WASM_REQUEST_BYTES);

    let response = client.configure_trusted_jwt(&config);

    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["code"], "wasm_request_too_large");
}

fn configure_trusted_jwt(client: &mut SidecarClient) {
    configure_trusted_jwt_with_base_url(client, "http://127.0.0.1:8080");
}

fn configure_trusted_jwt_with_base_url(client: &mut SidecarClient, base_url: &str) {
    let response = client.configure_trusted_jwt(
        &json!({
            "jwks": sidecar_fixtures::jwt::jwks(),
            "issuer": sidecar_fixtures::jwt::issuer(),
            "base_url": base_url,
            "resource_audiences": [sidecar_fixtures::jwt::audience()]
        })
        .to_string(),
    );
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["configured"], true);
}

#[test]
fn given_bound_token_when_wasm_export_validates_presenter_then_matches_native_challenge_and_rejects_stolen_token()
 {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let mut client = SidecarClient::new();
    configure_trusted_jwt(&mut client);
    let key = oauth_dpop::test_support::ProofKey::from_seed(1);
    let token = sidecar_fixtures::jwt::oauth_token_with_confirmation(
        json!({"jkt":key.thumbprint().as_str()}),
    );
    let proof=key.sign(&json!({"jti":"wasm-request","htm":"GET","htu":"https://resource.example/a","iat":chrono::Utc::now().timestamp(),
        "ath":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}));
    let mut request = json!({"request":{"token":token,"scheme":"DPoP","proof":proof,"method":"GET","target_uri":"https://resource.example/a"}});
    let accepted: serde_json::Value =
        serde_json::from_str(&client.validate_oauth_access_token(&request.to_string())).unwrap();
    assert!(accepted.get("claims").is_some());
    request["request"]["proof"] = serde_json::Value::Null;
    let denied: serde_json::Value =
        serde_json::from_str(&client.validate_oauth_access_token(&request.to_string())).unwrap();
    assert_eq!(denied["status_code"], 401);
    assert_eq!(denied["code"], "invalid_dpop_proof");
    assert!(
        denied["www_authenticate"]
            .as_str()
            .unwrap()
            .contains("DPoP")
    );
}

#[test]
fn configure_trusted_jwt_given_invalid_issuer_then_rejects_configuration() {
    for issuer in [
        "https://account.example.test/.",
        "https://account.example.test/a/..",
        "https://account.example.test/%2e",
        "",
        "/relative",
        "http://remote.example.test",
        "https://user@account.example.test",
        "https://account.example.test/path",
        "https://account.example.test/",
        "https://account.example.test?query=value",
        "https://account.example.test#fragment",
        " https://account.example.test",
        "https://account.example.test\\path",
    ] {
        let mut client = SidecarClient::new();
        let response = client.configure_trusted_jwt(
            &json!({
                "jwks": sidecar_fixtures::jwt::jwks(), "issuer": issuer,
                "resource_audiences": [sidecar_fixtures::jwt::audience()]
            })
            .to_string(),
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["code"], "jwt_issuer_invalid");
    }
}
