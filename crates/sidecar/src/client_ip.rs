use std::net::IpAddr;

use axum::http::{HeaderMap, header::FORWARDED};

use crate::constants::{X_FORWARDED_FOR, X_REAL_IP};

pub fn extract_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    forwarded_for(headers)
        .or_else(|| real_ip(headers))
        .or_else(|| forwarded(headers))
}

fn forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_FORWARDED_FOR)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_ip)
}

fn real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_REAL_IP)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_ip)
}

fn forwarded(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get(FORWARDED)?.to_str().ok()?;
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("for="))
        .and_then(parse_ip)
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    value.trim().trim_matches('"').parse().ok()
}
