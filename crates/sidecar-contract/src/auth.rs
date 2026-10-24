use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CacheStatus;

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidateAuthnJwtRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl fmt::Debug for ValidateAuthnJwtRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidateAuthnJwtRequest")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidateOAuthAccessTokenRequest {
    pub scheme: String,
    pub method: String,
    pub target_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl fmt::Debug for ValidateOAuthAccessTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidateOAuthAccessTokenRequest")
            .field("proof", &self.proof.as_ref().map(|_| "<redacted>"))
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtValidationResult {
    pub claims: serde_json::Value,
    pub cache_status: CacheStatus,
}
