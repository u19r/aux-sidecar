fn main() {
    let issuer = std::env::args()
        .nth(1)
        .unwrap_or_else(|| sidecar_fixtures::jwt::issuer().to_string());
    let output = serde_json::json!({
        "jwks": sidecar_fixtures::jwt::jwks(),
        "token": sidecar_fixtures::jwt::authn_token_with_issuer(&issuer),
        "oauth_token": sidecar_fixtures::jwt::oauth_token_with_issuer(&issuer),
        "audience": sidecar_fixtures::jwt::audience(),
    });
    println!("{output}");
}
