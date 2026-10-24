#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedLoginSession {
    pub state: String,
    pub code_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub expires_at_ms: i64,
}
