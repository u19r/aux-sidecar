use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::{ContractError, ContractResult};

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestContext")
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("client_ip", &self.client_ip)
            .field(
                "tenant_domain",
                &self.tenant_domain.as_ref().map(|_| "<redacted>"),
            )
            .field("traceparent", &self.traceparent)
            .field(
                "tracestate",
                &self.tracestate.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl RequestContext {
    pub fn require_client_ip(&self) -> ContractResult<IpAddr> {
        let Some(client_ip) = self.client_ip.as_deref() else {
            return Err(ContractError::invalid(
                "client_ip_missing",
                "client ip is required for this call",
            ));
        };

        client_ip.parse().map_err(|_| {
            ContractError::invalid(
                "client_ip_invalid",
                format!("invalid client ip: {client_ip}"),
            )
        })
    }

    pub fn bearer_token(&self) -> ContractResult<Option<&str>> {
        let Some(authorization) = self.authorization.as_deref() else {
            return Ok(None);
        };
        let trimmed = authorization.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let Some(token) = trimmed.strip_prefix("Bearer ") else {
            return Err(ContractError::invalid(
                "authorization_header_invalid",
                "authorization must use Bearer scheme",
            ));
        };
        let token = token.trim();
        if token.is_empty() {
            return Err(ContractError::invalid(
                "authorization_header_invalid",
                "authorization bearer token must not be empty",
            ));
        }

        Ok(Some(token))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    Miss,
    Fresh,
    Stale,
}
