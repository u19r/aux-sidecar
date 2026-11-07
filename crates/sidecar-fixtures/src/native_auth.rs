use serde_json::Value;

/// Public synthetic wire material shared by native, library and WASM adapters.
pub fn cases() -> Vec<Value> {
    serde_json::from_str(include_str!("../assets/native-auth.v1.json"))
        .expect("maintained native authentication fixture")
}

pub fn response_for_token(token: &str) -> Option<Value> {
    let name = token.strip_prefix("fixture-native-auth-")?;
    cases().into_iter().find(|case| case["name"] == name)
}

pub fn token_response(case: &Value) -> Value {
    let mut body = case["body"].clone();
    if case["status"] == 200 {
        body["access_token"] = super::jwt::oauth_token().into();
    }
    body
}
