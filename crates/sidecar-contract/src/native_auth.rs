use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::serde_bounds;

/// Native recovery locators carry no proof or credential authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeAuthenticationRecovery {
    pub code: NativeRecoveryCode,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub continuation_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeRecoveryCode {
    FraudBlocked,
    ReauthenticationRequired,
    StepUpRequired,
}

impl NativeRecoveryCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FraudBlocked => "fraud_blocked",
            Self::ReauthenticationRequired => "reauthentication_required",
            Self::StepUpRequired => "step_up_required",
        }
    }
}

/// These coarse warnings never assert that incomplete evidence was clean.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeAuthenticationWarnings {
    #[serde(deserialize_with = "deserialize_warning_codes")]
    pub codes: Vec<NativeAuthenticationWarningCode>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub decision_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeAuthenticationWarningCode {
    EvaluationWarning,
    EvaluationDegraded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeOAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    InvalidTarget,
    InvalidDpopProof,
    UseDpopNonce,
    ServerError,
    TemporarilyUnavailable,
    #[serde(other)]
    Unknown,
}

/// Only safe typed protocol material crosses the sidecar error boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NativeAuthenticationFailure {
    RecoveryRequired {
        recovery: NativeAuthenticationRecovery,
    },
    Denied {
        error: NativeOAuthErrorCode,
    },
    Retry {
        retry_after_seconds: Option<u32>,
    },
}

/// Native wire format. Provider descriptions and arbitrary extension fields
/// are intentionally not retained or copied into sidecar errors.
#[derive(Debug, Clone, Deserialize)]
pub struct NativeOAuthTokenFailure {
    pub error: NativeOAuthErrorCode,
    #[serde(default)]
    pub aux_recovery: Option<NativeAuthenticationRecovery>,
    #[serde(
        default,
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub request_id: Option<String>,
}

fn deserialize_warning_codes<'de, D>(
    deserializer: D,
) -> Result<Vec<NativeAuthenticationWarningCode>, D::Error>
where D: serde::Deserializer<'de> {
    let codes = serde_bounds::deserialize_bounded_vec(
        deserializer,
        crate::constants::NATIVE_AUTH_MAX_WARNING_CODES,
    )?;
    if codes.is_empty() {
        return Err(serde::de::Error::custom(
            "native warning codes must be nonempty",
        ));
    }
    Ok(codes)
}
