use sidecar_core::{
    DeploymentPreset, LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngineConfig, SidecarError,
};
use url::{Host, Url};

use crate::constants;

pub(crate) const MAX_TRUSTED_CONFIG_STRING_BYTES: usize = 8 * 1024;
pub(crate) const MAX_TRUSTED_RESOURCE_AUDIENCES: usize = 32;

pub(crate) fn default_config() -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: DeploymentPreset::Worker,
        base_url: constants::DEFAULT_RUNTIME_BASE_URL.to_string(),
        api_key: String::new(),
        tenant_domain: None,
        cache_ttl: constants::DEFAULT_CACHE_TTL,
        stale_cache_ttl: constants::DEFAULT_STALE_CACHE_TTL,
        authz_local_mode: LocalAuthzMode::RemoteOnly,
        authz_cache_ttl: constants::DEFAULT_AUTHZ_CACHE_TTL,
        authz_stale_cache_ttl: constants::DEFAULT_AUTHZ_STALE_CACHE_TTL,
        authz_refresh_after_percent: constants::DEFAULT_AUTHZ_REFRESH_AFTER_PERCENT,
        authz_remote_fallback: LocalAuthzRemoteFallback::CacheMiss,
        jwt_validation: None,
    }
}

pub(crate) fn validate_base_url(value: Option<String>) -> sidecar_core::SidecarResult<String> {
    let raw = value.unwrap_or_else(|| constants::DEFAULT_RUNTIME_BASE_URL.to_string());
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SidecarError::bad_request(
            "wasm_base_url_missing",
            "trusted wasm base_url must not be empty",
        ));
    }
    if trimmed.len() > MAX_TRUSTED_CONFIG_STRING_BYTES {
        return Err(SidecarError::bad_request(
            "wasm_base_url_invalid",
            "trusted wasm base_url exceeds the configured length limit",
        ));
    }
    let parsed = Url::parse(trimmed).map_err(|_| {
        SidecarError::bad_request(
            "wasm_base_url_invalid",
            "trusted wasm base_url must be an absolute HTTP(S) URL",
        )
    })?;
    if parsed.host().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.scheme(), "http" | "https")
    {
        return Err(SidecarError::bad_request(
            "wasm_base_url_invalid",
            "trusted wasm base_url must be an absolute HTTP(S) URL",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SidecarError::bad_request(
            "wasm_base_url_credentials",
            "trusted wasm base_url must not include URL credentials",
        ));
    }
    if parsed.scheme() == "http" && !url_host_is_loopback(&parsed) {
        return Err(SidecarError::bad_request(
            "wasm_base_url_insecure",
            "trusted wasm base_url must use https unless it targets localhost or loopback",
        ));
    }
    Ok(trimmed.to_string())
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub(crate) fn validate_non_empty(
    value: String,
    code: &'static str,
) -> sidecar_core::SidecarResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_TRUSTED_CONFIG_STRING_BYTES {
        return Err(SidecarError::bad_request(
            code,
            "trusted wasm JWT configuration is incomplete",
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn validate_optional_config_string(
    value: Option<String>,
    code: &'static str,
) -> sidecar_core::SidecarResult<Option<String>> {
    value
        .map(|value| validate_non_empty(value, code))
        .transpose()
}

pub(crate) fn validate_resource_audiences(
    values: Vec<String>,
) -> sidecar_core::SidecarResult<Vec<String>> {
    if values.len() > MAX_TRUSTED_RESOURCE_AUDIENCES {
        return Err(SidecarError::bad_request(
            "wasm_resource_audiences_too_many",
            "trusted wasm resource audiences exceed the configured limit",
        ));
    }
    values
        .into_iter()
        .map(|value| validate_non_empty(value, "wasm_resource_audience_invalid"))
        .collect()
}

pub(crate) fn parse_authz_local_mode(
    value: Option<&str>,
) -> sidecar_core::SidecarResult<LocalAuthzMode> {
    match value.unwrap_or("remote_only") {
        "remote_only" => Ok(LocalAuthzMode::RemoteOnly),
        "shadow" => Ok(LocalAuthzMode::Shadow),
        "enforced" => Ok(LocalAuthzMode::Enforced),
        _ => Err(SidecarError::bad_request(
            "wasm_authz_local_mode_invalid",
            "authz_local_mode must be remote_only, shadow, or enforced",
        )),
    }
}

pub(crate) fn parse_authz_remote_fallback(
    value: Option<&str>,
) -> sidecar_core::SidecarResult<LocalAuthzRemoteFallback> {
    match value.unwrap_or("cache_miss") {
        "cache_miss" => Ok(LocalAuthzRemoteFallback::CacheMiss),
        "refresh_error" => Ok(LocalAuthzRemoteFallback::RefreshError),
        "never" => Ok(LocalAuthzRemoteFallback::Never),
        _ => Err(SidecarError::bad_request(
            "wasm_authz_remote_fallback_invalid",
            "authz_remote_fallback must be cache_miss, refresh_error, or never",
        )),
    }
}
