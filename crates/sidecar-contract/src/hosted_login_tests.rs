use crate::{BeginHostedLoginRequest, RefreshHostedLoginRequest};

#[test]
fn hosted_login_begin_given_oversized_redirect_then_rejects_before_materialization() {
    let payload = serde_json::json!({
        "client_id": "client",
        "redirect_uri": format!("http://127.0.0.1/{}", "x".repeat(2_048)),
    });

    assert!(serde_json::from_value::<BeginHostedLoginRequest>(payload).is_err());
}

#[test]
fn hosted_login_begin_given_too_many_scopes_then_rejects_before_materialization() {
    let payload = serde_json::json!({
        "client_id": "client",
        "redirect_uri": "http://127.0.0.1:3000/callback",
        "scopes": (0..33).map(|index| format!("scope-{index}")).collect::<Vec<_>>(),
    });

    assert!(serde_json::from_value::<BeginHostedLoginRequest>(payload).is_err());
}

#[test]
fn hosted_login_refresh_given_oversized_token_then_rejects_before_materialization() {
    let payload = serde_json::json!({
        "client_id": "client",
        "refresh_token": "x".repeat(513),
    });

    assert!(serde_json::from_value::<RefreshHostedLoginRequest>(payload).is_err());
}
