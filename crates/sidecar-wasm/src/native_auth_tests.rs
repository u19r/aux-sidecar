#[test]
fn given_hostless_wasm_bridge_when_status_is_read_then_local_advanced_fraud_and_recovery_are_not_claimed()
 {
    let client = crate::api::SidecarClient::new();
    let status: serde_json::Value = serde_json::from_str(&client.status()).unwrap();
    let capabilities = status["capabilities"].as_array().unwrap();
    assert!(
        capabilities
            .iter()
            .any(|cap| cap["name"] == "advanced_fraud" && cap["state"] == "remote_only")
    );
    assert!(
        capabilities
            .iter()
            .any(|cap| cap["name"] == "hosted_recovery" && cap["state"] == "unsupported")
    );
    assert!(
        capabilities
            .iter()
            .any(|cap| cap["name"] == "native_auth_end_user_context" && cap["state"] == "unknown")
    );
}
