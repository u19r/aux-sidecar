use std::collections::HashMap;

use sidecar_core::DeploymentPreset;

use crate::config::LambdaExtensionConfig;

#[test]
fn configuration_given_required_environment_then_uses_lambda_safe_defaults() {
    let values = HashMap::from([
        ("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001"),
        ("AUX_BASE_URL", "https://tenant.example.test"),
        ("AUX_API_KEY", "fixture-secret"),
        ("AUX_NO_AUDIENCE_CHECK", "true"),
    ]);

    let config =
        LambdaExtensionConfig::from_source(|name| values.get(name).map(ToString::to_string))
            .unwrap();

    assert_eq!(config.sidecar.preset, DeploymentPreset::Lambda);
    assert_eq!(config.sidecar.bind_addr, "127.0.0.1:2773");
}

#[test]
fn configuration_given_non_loopback_bind_then_rejects_it() {
    let values = HashMap::from([
        ("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001"),
        ("AUX_BASE_URL", "https://tenant.example.test"),
        ("AUX_API_KEY", "fixture-secret"),
        ("AUX_NO_AUDIENCE_CHECK", "true"),
        ("AUX_BIND_ADDR", "0.0.0.0:2773"),
    ]);

    let result =
        LambdaExtensionConfig::from_source(|name| values.get(name).map(ToString::to_string));

    assert!(result.is_err());
}

#[test]
fn configuration_given_plaintext_remote_base_url_then_rejects_it() {
    let values = HashMap::from([
        ("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001"),
        ("AUX_BASE_URL", "http://tenant.example.test"),
        ("AUX_API_KEY", "fixture-secret"),
        ("AUX_NO_AUDIENCE_CHECK", "true"),
    ]);

    let result =
        LambdaExtensionConfig::from_source(|name| values.get(name).map(ToString::to_string));

    assert!(result.is_err());
}

#[test]
fn configuration_given_runtime_api_path_then_rejects_it() {
    let values = HashMap::from([
        ("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001/runtime"),
        ("AUX_BASE_URL", "https://tenant.example.test"),
        ("AUX_API_KEY", "fixture-secret"),
        ("AUX_NO_AUDIENCE_CHECK", "true"),
    ]);

    let result =
        LambdaExtensionConfig::from_source(|name| values.get(name).map(ToString::to_string));

    assert!(result.is_err());
}

#[test]
fn given_private_backend_and_explicit_public_issuer_when_loading_extension_then_shared_verifier_uses_public_identity()
 {
    let values = HashMap::from([
        ("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001"),
        ("AUX_BASE_URL", "http://127.0.0.1:8080"),
        ("AUX_ISSUER", "https://account.example.test"),
        ("AUX_API_KEY", "fixture-secret"),
        ("AUX_NO_AUDIENCE_CHECK", "true"),
    ]);
    let config =
        LambdaExtensionConfig::from_source(|name| values.get(name).map(ToString::to_string))
            .unwrap();
    assert_eq!(config.sidecar.base_url, "http://127.0.0.1:8080");
    assert_eq!(config.sidecar.issuer, "https://account.example.test");
    assert_eq!(
        config
            .sidecar
            .engine_config()
            .jwt_validation
            .as_ref()
            .unwrap()
            .issuer,
        "https://account.example.test"
    );
    let invalid = LambdaExtensionConfig::from_source(|name| {
        if name == "AUX_ISSUER" {
            Some("https://user@account.example.test".into())
        } else {
            values.get(name).map(ToString::to_string)
        }
    });
    assert!(invalid.is_err());
}
