use thiserror::Error;

pub type SidecarResult<T> = Result<T, SidecarError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAuthzFallbackReason {
    CacheMiss,
    RefreshError,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct SidecarError {
    pub code: &'static str,
    pub message: String,
    pub status_code: u16,
    pub redirect_url: Option<String>,
    pub redirect_reason: Option<&'static str>,
    pub local_authz_fallback_reason: Option<LocalAuthzFallbackReason>,
}

impl SidecarError {
    pub fn oauth_challenge(&self) -> Option<String> {
        if self.status_code != 401 {
            return None;
        }
        let challenge = match self.code {
            "oauth_token_missing" => oauth_dpop::ResourceChallenge::MissingCredentials,
            "invalid_dpop_proof" => oauth_dpop::ResourceChallenge::InvalidDpopProof,
            _ => oauth_dpop::ResourceChallenge::InvalidToken,
        };
        Some(challenge.render())
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::with_status(code, message, 400)
    }

    pub fn bad_gateway(code: &'static str, message: impl Into<String>) -> Self {
        Self::with_status(code, message, 502)
    }

    pub fn service_unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::with_status(code, message, 503)
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::with_status(code, message, 401)
    }

    pub fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self::with_status(code, message, 500)
    }

    pub fn with_status(code: &'static str, message: impl Into<String>, status_code: u16) -> Self {
        Self {
            code,
            message: message.into(),
            status_code,
            redirect_url: None,
            redirect_reason: None,
            local_authz_fallback_reason: None,
        }
    }

    pub fn with_local_authz_fallback_reason(mut self, reason: LocalAuthzFallbackReason) -> Self {
        self.local_authz_fallback_reason = Some(reason);
        self
    }
}

impl From<sidecar_contract::ContractError> for SidecarError {
    fn from(value: sidecar_contract::ContractError) -> Self {
        match value {
            sidecar_contract::ContractError::Invalid { code, message } => {
                Self::bad_request(code, message)
            }
        }
    }
}
