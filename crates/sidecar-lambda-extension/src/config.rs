use sidecar::config::SidecarConfig;
use sidecar_core::{DeploymentPreset, LocalAuthzMode, LocalAuthzRemoteFallback};
use url::Url;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:2773";
const MAX_CONFIG_VALUE_BYTES: usize = 8 * 1024;
const MAX_RUNTIME_API_BYTES: usize = 256;
const MAX_RESOURCE_AUDIENCES: usize = 32;
const MAX_RESOURCE_AUDIENCE_BYTES: usize = 1024;

#[derive(Debug, Clone)]
pub(crate) struct LambdaExtensionConfig {
    pub(crate) runtime_api: String,
    pub(crate) sidecar: SidecarConfig,
}

impl LambdaExtensionConfig {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|name| std::env::var(name).ok())
    }

    pub(crate) fn from_source<F>(source: F) -> Result<Self, ConfigError>
    where F: Fn(&str) -> Option<String> {
        let runtime_api = required_value(&source, "AWS_LAMBDA_RUNTIME_API")?;
        validate_runtime_api(&runtime_api)?;
        let base_url = required_value(&source, "AUX_BASE_URL")?;
        sidecar::config::validate_base_url(&base_url).map_err(|_| ConfigError("AUX_BASE_URL"))?;
        let issuer =
            sidecar::config::resolve_issuer(&base_url, optional_value(&source, "AUX_ISSUER")?)
                .map_err(|_| ConfigError("AUX_ISSUER"))?;
        let api_key = required_value(&source, "AUX_API_KEY")?;
        validate_header_value(&api_key, "AUX_API_KEY")?;
        let bind_addr = optional_value(&source, "AUX_BIND_ADDR")?
            .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());
        sidecar::config::validate_bind_addr(&bind_addr, false)
            .map_err(|_| ConfigError("AUX_BIND_ADDR"))?;
        let resource_audiences = resource_audiences(&source)?;
        let audience_check_disabled = parse_bool(&source, "AUX_NO_AUDIENCE_CHECK", false)?;
        validate_audience_config(&resource_audiences, audience_check_disabled)?;
        let tenant_domain = optional_value(&source, "AUX_TENANT_DOMAIN")?;
        if let Some(value) = tenant_domain.as_deref() {
            validate_header_value(value, "AUX_TENANT_DOMAIN")?;
        }
        Ok(Self {
            runtime_api,
            sidecar: SidecarConfig {
                preset: DeploymentPreset::Lambda,
                bind_addr,
                unix_socket_path: None,
                proxy_policy_path: None,
                route_policy_path: None,
                upstream_url: None,
                external_base_url: optional_value(&source, "AUX_EXTERNAL_BASE_URL")?,
                base_url,
                issuer,
                api_key,
                tenant_domain,
                login_redirect_url: optional_value(&source, "AUX_LOGIN_REDIRECT_URL")?,
                resource_audiences,
                audience_check_disabled,
                jwt_clock_skew_seconds: parse_u64(&source, "AUX_JWT_CLOCK_SKEW_SECONDS", 0)?,
                config_path: optional_value(&source, "AUX_CONFIG_PATH")?.map(Into::into),
                cache_ttl_seconds: parse_u64(&source, "AUX_CACHE_TTL_SECONDS", 60)?,
                stale_cache_ttl_seconds: parse_u64(&source, "AUX_STALE_CACHE_TTL_SECONDS", 300)?,
                authz_local_mode: LocalAuthzMode::Enforced,
                authz_cache_ttl_seconds: parse_u64(&source, "AUX_AUTHZ_CACHE_TTL_SECONDS", 10)?,
                authz_stale_cache_ttl_seconds: parse_u64(
                    &source,
                    "AUX_AUTHZ_STALE_CACHE_TTL_SECONDS",
                    30,
                )?,
                authz_refresh_after_percent: 50,
                authz_remote_fallback: LocalAuthzRemoteFallback::Never,
                unsafe_bind_non_loopback: false,
            },
        })
    }
}

fn required_value<F>(source: &F, name: &'static str) -> Result<String, ConfigError>
where F: Fn(&str) -> Option<String> {
    optional_value(source, name)?.ok_or(ConfigError(name))
}

fn optional_value<F>(source: &F, name: &'static str) -> Result<Option<String>, ConfigError>
where F: Fn(&str) -> Option<String> {
    source(name)
        .map(|value| validate_text(value, name))
        .transpose()
}

fn validate_text(value: String, name: &'static str) -> Result<String, ConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_CONFIG_VALUE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConfigError(name));
    }
    Ok(value)
}

fn validate_header_value(value: &str, name: &'static str) -> Result<(), ConfigError> {
    if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(ConfigError(name));
    }
    Ok(())
}

fn validate_runtime_api(runtime_api: &str) -> Result<(), ConfigError> {
    runtime_api_url(runtime_api, "/")
        .map(|_| ())
        .map_err(|_| ConfigError("AWS_LAMBDA_RUNTIME_API"))
}

pub(crate) fn runtime_api_url(runtime_api: &str, path: &str) -> Result<Url, ()> {
    if runtime_api.is_empty()
        || runtime_api.len() > MAX_RUNTIME_API_BYTES
        || runtime_api.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(());
    }
    let mut url = Url::parse(&format!("http://{runtime_api}")).map_err(|_| ())?;
    if url.scheme() != "http"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    url.set_path(path);
    Ok(url)
}

fn resource_audiences<F>(source: &F) -> Result<Vec<String>, ConfigError>
where F: Fn(&str) -> Option<String> {
    let Some(raw) = optional_value(source, "AUX_RESOURCE_AUDIENCES")? else {
        return Ok(Vec::new());
    };
    let mut audiences = Vec::new();
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if value.len() > MAX_RESOURCE_AUDIENCE_BYTES
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ConfigError("AUX_RESOURCE_AUDIENCES"));
        }
        audiences.push(value.to_string());
        if audiences.len() > MAX_RESOURCE_AUDIENCES {
            return Err(ConfigError("AUX_RESOURCE_AUDIENCES"));
        }
    }
    Ok(audiences)
}

fn validate_audience_config(
    resource_audiences: &[String],
    audience_check_disabled: bool,
) -> Result<(), ConfigError> {
    match (resource_audiences.is_empty(), audience_check_disabled) {
        (false, false) | (true, true) => Ok(()),
        _ => Err(ConfigError("AUX_RESOURCE_AUDIENCES")),
    }
}

fn parse_bool<F>(source: &F, name: &'static str, default: bool) -> Result<bool, ConfigError>
where F: Fn(&str) -> Option<String> {
    let Some(value) = optional_value(source, name)? else {
        return Ok(default);
    };
    match value.as_str() {
        "1" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(ConfigError(name)),
    }
}

fn parse_u64<F>(source: &F, name: &'static str, default: u64) -> Result<u64, ConfigError>
where F: Fn(&str) -> Option<String> {
    optional_value(source, name)?.map_or(Ok(default), |value| {
        value.parse().map_err(|_| ConfigError(name))
    })
}

#[derive(Debug)]
pub(crate) struct ConfigError(&'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "missing or invalid required configuration {}",
            self.0
        )
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
