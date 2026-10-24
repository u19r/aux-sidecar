use std::{fmt, net::SocketAddr, path::PathBuf, time::Duration};

use sidecar_core::{
    DeploymentPreset, JwtValidationConfig, LocalAuthzMode, LocalAuthzRemoteFallback,
    SidecarEngineConfig,
};
use url::{Host, Url};

#[derive(Clone)]
pub struct SidecarConfig {
    pub preset: DeploymentPreset,
    pub bind_addr: String,
    pub unix_socket_path: Option<PathBuf>,
    pub proxy_policy_path: Option<PathBuf>,
    pub route_policy_path: Option<PathBuf>,
    pub upstream_url: Option<String>,
    pub external_base_url: Option<String>,
    pub base_url: String,
    pub issuer: String,
    pub api_key: String,
    pub tenant_domain: Option<String>,
    pub login_redirect_url: Option<String>,
    pub resource_audiences: Vec<String>,
    pub audience_check_disabled: bool,
    pub jwt_clock_skew_seconds: u64,
    pub config_path: Option<PathBuf>,
    pub cache_ttl_seconds: u64,
    pub stale_cache_ttl_seconds: u64,
    pub authz_local_mode: LocalAuthzMode,
    pub authz_cache_ttl_seconds: u64,
    pub authz_stale_cache_ttl_seconds: u64,
    pub authz_refresh_after_percent: u8,
    pub authz_remote_fallback: LocalAuthzRemoteFallback,
    pub unsafe_bind_non_loopback: bool,
}

impl fmt::Debug for SidecarConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SidecarConfig")
            .field("preset", &self.preset)
            .field("bind_addr", &self.bind_addr)
            .field("unix_socket_path", &self.unix_socket_path)
            .field("proxy_policy_path", &self.proxy_policy_path)
            .field("route_policy_path", &self.route_policy_path)
            .field(
                "upstream_url",
                &self.upstream_url.as_ref().map(|_| "<redacted>"),
            )
            .field("base_url", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("api_key", &"<redacted>")
            .field(
                "tenant_domain",
                &self.tenant_domain.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "login_redirect_url",
                &self.login_redirect_url.as_ref().map(|_| "<redacted>"),
            )
            .field("resource_audiences", &self.resource_audiences.len())
            .field("audience_check_disabled", &self.audience_check_disabled)
            .field("unsafe_bind_non_loopback", &self.unsafe_bind_non_loopback)
            .finish_non_exhaustive()
    }
}

impl SidecarConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_base_url(&self.base_url)?;
        sidecar_core::config::parse_issuer_url(&self.issuer).map_err(|error| error.to_string())?;
        if let Some(base) = self.external_base_url.as_deref() {
            let external = Url::parse(base).map_err(|_| "invalid external base URL".to_owned())?;
            for audience in &self.resource_audiences {
                if let Ok(resource) = Url::parse(audience)
                    && resource.has_host()
                    && (resource.scheme() != external.scheme()
                        || resource.host_str() != external.host_str()
                        || resource.port_or_known_default() != external.port_or_known_default())
                {
                    return Err("URI audience must match external base scheme, host, and \
                                effective port"
                        .to_owned());
                }
            }
            oauth_dpop::DpopTargetUri::parse_base(base).map_err(|_| {
                "external base must be absolute HTTPS without query or fragment".to_owned()
            })?;
        }
        if self.upstream_url.is_some() && self.external_base_url.is_none() {
            return Err(
                "plaintext proxy listener requires an explicit HTTPS external base URL".to_owned(),
            );
        }
        validate_bind_addr(&self.bind_addr, self.unsafe_bind_non_loopback)?;
        if self.route_policy_path.is_some() && self.upstream_url.is_none() {
            return Err("route-aware HTTP proxying requires an upstream URL".to_string());
        }
        if self.upstream_url.is_some() && self.audience_check_disabled {
            return Err("HTTP proxying requires OAuth audience validation".to_string());
        }
        if self.upstream_url.is_some() && self.resource_audiences.is_empty() {
            return Err(
                "HTTP proxying requires at least one configured resource audience".to_string(),
            );
        }
        if self.resource_audiences.len() > 32 {
            return Err("resource audience configuration exceeds 32 entries".to_string());
        }
        let mut unique_audiences = std::collections::BTreeSet::new();
        if self
            .resource_audiences
            .iter()
            .any(|audience| audience.trim().is_empty() || !unique_audiences.insert(audience))
        {
            return Err("resource audiences must be non-empty and unique".to_string());
        }
        if let Some(upstream_url) = self.upstream_url.as_deref() {
            validate_upstream_url(upstream_url)?;
        }
        Ok(())
    }

    pub fn engine_config(&self) -> SidecarEngineConfig {
        SidecarEngineConfig {
            preset: self.preset,
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
            tenant_domain: self.tenant_domain.clone(),
            cache_ttl: Duration::from_secs(self.cache_ttl_seconds),
            stale_cache_ttl: Duration::from_secs(self.stale_cache_ttl_seconds),
            authz_local_mode: self.authz_local_mode,
            authz_cache_ttl: Duration::from_secs(self.authz_cache_ttl_seconds),
            authz_stale_cache_ttl: Duration::from_secs(self.authz_stale_cache_ttl_seconds),
            authz_refresh_after_percent: self.authz_refresh_after_percent,
            authz_remote_fallback: self.authz_remote_fallback,
            jwt_validation: Some(JwtValidationConfig {
                issuer: self.issuer.clone(),
                login_redirect_url: self.login_redirect_url.clone(),
                resource_audiences: (!self.resource_audiences.is_empty())
                    .then(|| self.resource_audiences.clone()),
                audience_check_disabled: self.audience_check_disabled,
                clock_skew_seconds: self.jwt_clock_skew_seconds,
            }),
        }
    }
}

pub fn validate_upstream_url(upstream_url: &str) -> Result<(), String> {
    let parsed =
        Url::parse(upstream_url).map_err(|error| format!("upstream URL is invalid: {error}"))?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "upstream URL must be an HTTP URL without credentials, query, or fragment".to_string(),
        );
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("upstream URL must use HTTP or HTTPS".to_string());
    }
    Ok(())
}

pub fn validate_base_url(base_url: &str) -> Result<(), String> {
    let parsed = Url::parse(base_url).map_err(|error| format!("base URL is invalid: {error}"))?;
    if parsed.host_str().is_none() {
        return Err("base URL must include a host".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("base URL must not include URL credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("base URL must not include a query or fragment".to_string());
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if url_host_is_loopback(&parsed) => Ok(()),
        "http" => {
            Err("base URL must use https unless it targets localhost or loopback".to_string())
        }
        _ => Err("base URL must use http or https".to_string()),
    }
}

pub fn validate_bind_addr(bind_addr: &str, allow_non_loopback: bool) -> Result<(), String> {
    let parsed = bind_addr
        .parse::<SocketAddr>()
        .map_err(|error| format!("bind address must be a socket address: {error}"))?;
    if parsed.ip().is_loopback() || allow_non_loopback {
        return Ok(());
    }
    Err("bind address must be loopback unless explicitly unsafe".to_string())
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Resolve protocol identity independently from the backend connection address.
pub fn resolve_issuer(base_url: &str, explicit: Option<String>) -> Result<String, String> {
    let issuer = explicit.unwrap_or_else(|| base_url.trim_end_matches('/').to_owned());
    sidecar_core::config::parse_issuer_url(&issuer).map_err(|error| error.to_string())?;
    Ok(issuer)
}
