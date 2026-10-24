use sidecar_core::{
    LocalAuthzMode, LocalAuthzRemoteFallback, MAX_RESOURCE_AUDIENCE_BYTES, MAX_RESOURCE_AUDIENCES,
};

use crate::{cli::CliError, config};

pub(crate) fn authz_local_mode<F>(
    explicit: Option<String>,
    default: LocalAuthzMode,
    env: &F,
) -> Result<LocalAuthzMode, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    let Some(raw) = optional_value(explicit, "AUX_AUTHZ_LOCAL_MODE", env)? else {
        return Ok(default);
    };
    match raw.as_str() {
        "remote-only" => Ok(LocalAuthzMode::RemoteOnly),
        "shadow" => Ok(LocalAuthzMode::Shadow),
        "enforced" => Ok(LocalAuthzMode::Enforced),
        _ => Err(CliError::new(
            "AUX_AUTHZ_LOCAL_MODE must be remote-only, shadow, or enforced",
        )),
    }
}

pub(crate) fn authz_remote_fallback<F>(
    explicit: Option<String>,
    env: &F,
) -> Result<LocalAuthzRemoteFallback, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    let Some(raw) = optional_value(explicit, "AUX_AUTHZ_REMOTE_FALLBACK", env)? else {
        return Ok(LocalAuthzRemoteFallback::CacheMiss);
    };
    match raw.as_str() {
        "cache-miss" => Ok(LocalAuthzRemoteFallback::CacheMiss),
        "refresh-error" => Ok(LocalAuthzRemoteFallback::RefreshError),
        "never" => Ok(LocalAuthzRemoteFallback::Never),
        _ => Err(CliError::new(
            "AUX_AUTHZ_REMOTE_FALLBACK must be cache-miss, refresh-error, or never",
        )),
    }
}

pub(crate) fn resource_audiences<F>(
    explicit: Vec<String>,
    env: &F,
) -> Result<Vec<String>, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    if !explicit.is_empty() {
        let values = explicit
            .into_iter()
            .map(|value| non_empty(value, "--resource-audience"))
            .collect::<Result<Vec<_>, _>>()?;
        return validate_resource_audiences(values);
    }
    let Some(raw) = optional_value(None, "AUX_RESOURCE_AUDIENCES", env)? else {
        return Ok(Vec::new());
    };
    let values = raw
        .split(',')
        .map(|value| non_empty(value.to_string(), "AUX_RESOURCE_AUDIENCES"))
        .collect::<Result<Vec<_>, _>>()?;
    validate_resource_audiences(values)
}

fn validate_resource_audiences(values: Vec<String>) -> Result<Vec<String>, CliError> {
    if values.len() > MAX_RESOURCE_AUDIENCES {
        return Err(CliError::new(format!(
            "resource audiences exceed the configured limit of {MAX_RESOURCE_AUDIENCES}"
        )));
    }
    if values.iter().any(|value| {
        value.len() > MAX_RESOURCE_AUDIENCE_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(CliError::new(format!(
            "resource audiences must be at most {MAX_RESOURCE_AUDIENCE_BYTES} bytes and contain \
             no control characters"
        )));
    }
    Ok(values)
}

pub(crate) fn audience_check_disabled<F>(explicit: bool, env: &F) -> Result<bool, CliError>
where F: Fn(&str) -> Result<String, std::env::VarError> {
    if explicit {
        return Ok(true);
    }
    let Some(raw) = optional_value(None, "AUX_NO_AUDIENCE_CHECK", env)? else {
        return Ok(false);
    };
    bool_value(&raw, "AUX_NO_AUDIENCE_CHECK")
}

pub(crate) fn unsafe_bind_non_loopback<F>(explicit: bool, env: &F) -> Result<bool, CliError>
where F: Fn(&str) -> Result<String, std::env::VarError> {
    if explicit {
        return Ok(true);
    }
    let Some(raw) = optional_value(None, "AUX_UNSAFE_BIND_NON_LOOPBACK", env)? else {
        return Ok(false);
    };
    bool_value(&raw, "AUX_UNSAFE_BIND_NON_LOOPBACK")
}

fn bool_value(raw: &str, name: &str) -> Result<bool, CliError> {
    match raw {
        "1" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(CliError::new(format!("{name} must be true or false"))),
    }
}

pub(crate) fn validate_audience_config(
    resource_audiences: &[String],
    disabled: bool,
) -> Result<(), CliError> {
    match (resource_audiences.is_empty(), disabled) {
        (false, false) | (true, true) => Ok(()),
        (false, true) => Err(CliError::new(
            "configure either --resource-audience or --no-audience-check, not both",
        )),
        (true, false) => Err(CliError::new(
            "missing required --resource-audience, AUX_RESOURCE_AUDIENCES, or --no-audience-check",
        )),
    }
}

pub(crate) fn validate_base_url(base_url: &str) -> Result<(), CliError> {
    config::validate_base_url(base_url).map_err(|error| {
        CliError::new(format!(
            "AUX_BASE_URL must be valid and use an allowed scheme: {error}"
        ))
    })
}

pub(crate) fn validate_bind_addr(
    bind_addr: &str,
    unsafe_non_loopback: bool,
) -> Result<(), CliError> {
    config::validate_bind_addr(bind_addr, unsafe_non_loopback).map_err(|error| {
        CliError::new(format!(
            "AUX_BIND_ADDR must be loopback unless --unsafe-bind-non-loopback is set: {error}"
        ))
    })
}

pub(crate) fn optional_value<F>(
    explicit: Option<String>,
    env_name: &str,
    env: &F,
) -> Result<Option<String>, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    if let Some(value) = explicit {
        return non_empty(value, env_name).map(Some);
    }
    match env(env_name) {
        Ok(value) => non_empty(value, env_name).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::new(format!(
            "{env_name} must contain valid Unicode"
        ))),
    }
}

pub(crate) fn non_empty(value: String, name: &str) -> Result<String, CliError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CliError::new(format!("{name} must not be empty")));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn seconds_value<F>(
    explicit: Option<String>,
    env_name: &str,
    default: u64,
    env: &F,
) -> Result<u64, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    let Some(raw) = optional_value(explicit, env_name, env)? else {
        return Ok(default);
    };
    raw.parse::<u64>()
        .map_err(|err| CliError::new(format!("{env_name} must be a non-negative integer: {err}")))
}

pub(crate) fn percent_value<F>(
    explicit: Option<String>,
    env_name: &str,
    default: u8,
    env: &F,
) -> Result<u8, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    let Some(raw) = optional_value(explicit, env_name, env)? else {
        return Ok(default);
    };
    let value = raw
        .parse::<u8>()
        .map_err(|err| CliError::new(format!("{env_name} must be an integer: {err}")))?;
    if !(1..=100).contains(&value) {
        return Err(CliError::new(format!(
            "{env_name} must be between 1 and 100"
        )));
    }
    Ok(value)
}
