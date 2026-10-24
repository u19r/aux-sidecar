use std::net::Ipv6Addr;

use chrono::DateTime;
use serde::{
    Deserialize,
    de::{self, Deserializer},
};

use crate::{ContractError, ContractResult, rate_limit::MAX_EVENTS_PER_BATCH};

pub(crate) const RATE_LIMIT_KEY_MAX_LEN: usize = 256;

pub(crate) fn validate_lease_batch_len(len: usize) -> ContractResult<()> {
    if len == 0 {
        return Err(rate_limit_invalid("leases must not be empty"));
    }
    if len > MAX_EVENTS_PER_BATCH {
        return Err(rate_limit_invalid("leases exceed batch limit"));
    }
    Ok(())
}

pub(crate) fn validate_rate_limit_key(key: &str) -> ContractResult<()> {
    if key.is_empty() || key.len() > RATE_LIMIT_KEY_MAX_LEN {
        return Err(rate_limit_invalid(format!("invalid rate limit key: {key}")));
    }
    Ok(())
}

pub(crate) fn validate_non_empty(value: &str, field: &str) -> ContractResult<()> {
    if value.trim().is_empty() {
        return Err(rate_limit_invalid(format!("{field} must not be empty")));
    }
    Ok(())
}

pub(crate) fn validate_positive(value: u32, field: &str) -> ContractResult<()> {
    if value == 0 {
        return Err(rate_limit_invalid(format!("{field} must be positive")));
    }
    Ok(())
}

pub(crate) fn ipv6_64_identity(ipv6: Ipv6Addr) -> String {
    let segments = ipv6.segments();
    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        0,
        0,
        0,
        0,
    )
    .to_string()
        + "/64"
}

pub(crate) fn rate_limit_invalid(message: impl Into<String>) -> ContractError {
    ContractError::invalid("rate_limit_request_invalid", message)
}

pub(crate) fn deserialize_expires_at_ms<'de, D>(deserializer: D) -> Result<i64, D::Error>
where D: Deserializer<'de> {
    let value = serde_json::Value::deserialize(deserializer)?;
    if let Some(millis) = value.as_i64() {
        return Ok(millis);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| de::Error::custom("expires_at must be an integer or RFC3339 string"))?;
    DateTime::parse_from_rfc3339(raw)
        .map(|datetime| datetime.timestamp_millis())
        .map_err(de::Error::custom)
}
