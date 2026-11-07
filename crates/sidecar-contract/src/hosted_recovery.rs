use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    BeginHostedLoginRequest, RefreshHostedLoginRequest, native_auth::NativeAuthenticationRecovery,
};

/// Original credentials remain on this back-channel request. A continuation
/// alone can never stage or complete native authentication.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostedRecoveryGrant {
    AuthorizationCode {
        #[serde(deserialize_with = "crate::serde_bounds::deserialize_non_empty_bounded_string")]
        state: String,
        #[serde(deserialize_with = "crate::serde_bounds::deserialize_non_empty_bounded_string")]
        code: String,
        recovery: NativeAuthenticationRecovery,
    },
    RefreshToken {
        request: RefreshHostedLoginRequest,
        recovery: NativeAuthenticationRecovery,
    },
}

impl std::fmt::Debug for HostedRecoveryGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostedRecoveryGrant([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginHostedRecoveryRequest {
    pub grant: HostedRecoveryGrant,
    pub authorization: BeginHostedLoginRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginHostedRecoveryResult {
    pub stage: NativeRecoveryStage,
    /// Correlates the native issuer's eventual callback with local PKCE.
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeRecoveryStage {
    #[serde(deserialize_with = "deserialize_stage_handle")]
    pub stage_handle: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum NativeRecoveryGrant {
    AuthorizationCode {
        client_id: String,
        code: String,
        redirect_uri: String,
        code_verifier: String,
        continuation_id: String,
        resource: Option<String>,
    },
    RefreshToken {
        client_id: String,
        refresh_token: String,
        scope: Option<String>,
        continuation_id: String,
        resource: Option<String>,
    },
}

impl std::fmt::Debug for NativeRecoveryGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeRecoveryGrant([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeRecoveryAuthorization {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub resource: Vec<String>,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeRecoveryStageRequest {
    pub grant: NativeRecoveryGrant,
    pub authorization: NativeRecoveryAuthorization,
}

impl NativeRecoveryGrant {
    pub fn resource(&self) -> Option<&str> {
        match self {
            Self::AuthorizationCode { resource, .. } | Self::RefreshToken { resource, .. } => {
                resource.as_deref()
            }
        }
    }
}

fn deserialize_stage_handle<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: serde::Deserializer<'de> {
    let value = crate::serde_bounds::deserialize_non_empty_string_with_limit(
        deserializer,
        crate::constants::NATIVE_RECOVERY_STAGE_HANDLE_BYTES,
    )?;
    if value.len() != crate::constants::NATIVE_RECOVERY_STAGE_HANDLE_BYTES {
        return Err(serde::de::Error::custom(
            "invalid native recovery stage handle",
        ));
    }
    Ok(value)
}
