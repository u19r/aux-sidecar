use std::{fmt, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{SidecarError, SidecarResult};

pub const MAX_RESOURCE_AUDIENCES: usize = 32;
pub const MAX_RESOURCE_AUDIENCE_BYTES: usize = 1024;
// Retained export for existing embedded callers; the protocol owns the bound.
pub use oauth_dpop::MAX_ACCESS_TOKEN_BYTES as MAX_JWT_TOKEN_BYTES;
pub const MAX_JWT_CLAIMS_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtValidationConfig {
    pub issuer: String,
    pub login_redirect_url: Option<String>,
    pub resource_audiences: Option<Vec<String>>,
    pub audience_check_disabled: bool,
    pub clock_skew_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAuthzMode {
    RemoteOnly,
    Shadow,
    Enforced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAuthzRemoteFallback {
    CacheMiss,
    RefreshError,
    Never,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPreset {
    Worker,
    Lambda,
    Kubernetes,
    Proxy,
    Embedded,
}

impl DeploymentPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Lambda => "lambda",
            Self::Kubernetes => "kubernetes",
            Self::Proxy => "proxy",
            Self::Embedded => "embedded",
        }
    }
}

impl FromStr for DeploymentPreset {
    type Err = SidecarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "worker" => Ok(Self::Worker),
            "lambda" => Ok(Self::Lambda),
            "kubernetes" => Ok(Self::Kubernetes),
            "proxy" => Ok(Self::Proxy),
            "embedded" => Ok(Self::Embedded),
            _ => Err(SidecarError::bad_request(
                "deployment_preset_invalid",
                "deployment preset must be worker, lambda, kubernetes, proxy, or embedded",
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SidecarEngineConfig {
    pub preset: DeploymentPreset,
    pub base_url: String,
    pub api_key: String,
    pub tenant_domain: Option<String>,
    pub cache_ttl: Duration,
    pub stale_cache_ttl: Duration,
    pub authz_local_mode: LocalAuthzMode,
    pub authz_cache_ttl: Duration,
    pub authz_stale_cache_ttl: Duration,
    pub authz_refresh_after_percent: u8,
    pub authz_remote_fallback: LocalAuthzRemoteFallback,
    pub jwt_validation: Option<JwtValidationConfig>,
}

impl fmt::Debug for SidecarEngineConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SidecarEngineConfig")
            .field("preset", &self.preset)
            .field("base_url", &"<redacted>")
            .field("api_key", &"<redacted>")
            .field(
                "tenant_domain",
                &self.tenant_domain.as_ref().map(|_| "<redacted>"),
            )
            .field("cache_ttl", &self.cache_ttl)
            .field("stale_cache_ttl", &self.stale_cache_ttl)
            .field("authz_local_mode", &self.authz_local_mode)
            .field("authz_cache_ttl", &self.authz_cache_ttl)
            .field("authz_stale_cache_ttl", &self.authz_stale_cache_ttl)
            .field(
                "authz_refresh_after_percent",
                &self.authz_refresh_after_percent,
            )
            .field("authz_remote_fallback", &self.authz_remote_fallback)
            .field("jwt_validation_configured", &self.jwt_validation.is_some())
            .finish()
    }
}

impl JwtValidationConfig {
    pub fn validate(&self) -> SidecarResult<()> {
        if self.clock_skew_seconds > oauth_dpop::MAX_ACCESS_TOKEN_EXPIRY_LEEWAY_SECONDS {
            return Err(SidecarError::bad_request(
                "jwt_leeway_invalid",
                "JWT expiry leeway exceeds the access-token bound",
            ));
        }
        parse_issuer_url(&self.issuer)?;

        let has_audiences = self
            .resource_audiences
            .as_ref()
            .is_some_and(|audiences| !audiences.is_empty());
        if self.audience_check_disabled {
            if has_audiences {
                return Err(SidecarError::bad_request(
                    "resource_audience_conflict",
                    "configure resource audiences or disabled audience checks, not both",
                ));
            }
            return Ok(());
        }

        let Some(audiences) = self.resource_audiences.as_ref() else {
            return Err(SidecarError::bad_request(
                "resource_audience_missing",
                "at least one resource audience must be configured",
            ));
        };
        if audiences.is_empty() {
            return Err(SidecarError::bad_request(
                "resource_audience_missing",
                "at least one resource audience must be configured",
            ));
        }
        if audiences.len() > MAX_RESOURCE_AUDIENCES {
            return Err(SidecarError::bad_request(
                "resource_audience_too_many",
                "resource audiences exceed the configured limit",
            ));
        }
        if audiences.iter().any(|audience| {
            audience.trim().is_empty()
                || audience.len() > MAX_RESOURCE_AUDIENCE_BYTES
                || audience.chars().any(char::is_control)
        }) {
            return Err(SidecarError::bad_request(
                "resource_audience_invalid",
                "resource audiences must be non-empty, bounded, and free of control characters",
            ));
        }
        Ok(())
    }
}

/// Validate the canonical AuxFn protocol origin independently of backend
/// routing.
pub fn parse_issuer_url(issuer: &str) -> SidecarResult<url::Url> {
    let invalid = || {
        SidecarError::bad_request(
            "jwt_issuer_invalid",
            "JWT issuer must be an HTTPS origin without credentials, path, query or fragment; \
             HTTP is allowed only for loopback development",
        )
    };
    let parsed = url::Url::parse(issuer).map_err(|_| invalid())?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !(parsed.scheme() == "https" || parsed.scheme() == "http" && is_loopback)
        || issuer != parsed.origin().ascii_serialization()
    {
        return Err(invalid());
    }
    Ok(parsed)
}
