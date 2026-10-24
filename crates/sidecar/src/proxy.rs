use std::{collections::HashSet, path::Path};

use axum::http::HeaderMap;
use serde::Deserialize;
use sidecar_contract::{
    RegistryMetricDimensions, RegistryRateLimitAction, RegistryRateLimitDefaults,
    RegistryRateLimitRequest, RuntimeBlocklistPolicyRef, RuntimePolicyDecisionRequest,
};

const COUNTRY_HEADER: &str = "x-aux-country";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyPolicyConfig {
    pub tenant_id: String,
    pub organization_id: String,
    pub policy_generation: String,
    pub pull_limit_per_hour: u32,
    pub push_limit_per_hour: u32,
    #[serde(default)]
    pub blocklist_policies: Vec<RuntimeBlocklistPolicyRef>,
    #[serde(default)]
    pub entitlement_keys: Vec<String>,
    pub trusted_context_headers: Vec<String>,
}

impl ProxyPolicyConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|_| "proxy policy file could not be read".to_string())?;
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| "proxy policy file is invalid".to_string())?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.tenant_id.trim().is_empty()
            || self.organization_id.trim().is_empty()
            || self.policy_generation.trim().is_empty()
            || self.pull_limit_per_hour == 0
            || self.push_limit_per_hour == 0
            || self
                .entitlement_keys
                .iter()
                .any(|key| key.trim().is_empty())
        {
            return Err("proxy policy has missing or invalid required values".to_string());
        }
        let _ = self.allowlist()?;
        Ok(())
    }

    pub fn request(
        &self,
        headers: &HeaderMap,
        authenticated_subject: &str,
    ) -> Result<RuntimePolicyDecisionRequest, String> {
        self.reject_untrusted_context_headers(headers)?;
        let method = required_header(headers, "x-original-method")?;
        let uri = required_header(headers, "x-original-uri")?;
        let _host = required_header(headers, "x-original-host")?;
        let client_ip = required_header(headers, "x-original-client-ip")?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid original client IP".to_string())?;
        if authenticated_subject.trim().is_empty() {
            return Err("authenticated subject is missing".to_string());
        }
        let action = action(method)?;
        let rate_limit = RegistryRateLimitRequest {
            repository: uri.to_string(),
            user_id: authenticated_subject.to_string(),
            organization_id: self.organization_id.clone(),
            client_ip: client_ip.to_string(),
            action,
            cost: 1,
            defaults: RegistryRateLimitDefaults {
                pull_limit_per_hour: self.pull_limit_per_hour,
                push_limit_per_hour: self.push_limit_per_hour,
            },
        };
        let metrics = RegistryMetricDimensions {
            repository: uri.to_string(),
            user_id: authenticated_subject.to_string(),
            organization_id: self.organization_id.clone(),
            action,
            status_class: "2xx".to_string(),
            bytes: None,
        };
        let mut request = RuntimePolicyDecisionRequest::from_registry_context(
            self.tenant_id.clone(),
            rate_limit,
            self.blocklist_policies.clone(),
            metrics,
        )
        .map_err(|_| "proxy request mapping failed".to_string())?;
        request
            .policy_generation
            .clone_from(&self.policy_generation);
        request.network.country = optional_header(headers, COUNTRY_HEADER).map(str::to_string);
        Ok(request)
    }

    fn reject_untrusted_context_headers(&self, headers: &HeaderMap) -> Result<(), String> {
        let allowlist = self.allowlist()?;
        if headers
            .keys()
            .any(|name| name.as_str().starts_with("x-aux-") && !allowlist.contains(name.as_str()))
        {
            return Err("untrusted proxy context header".to_string());
        }
        Ok(())
    }

    fn allowlist(&self) -> Result<HashSet<&str>, String> {
        let allowlist = self
            .trusted_context_headers
            .iter()
            .map(|value| value.as_str())
            .collect::<HashSet<_>>();
        if allowlist.len() != self.trusted_context_headers.len()
            || allowlist.iter().any(|value| {
                !value.starts_with("x-aux-")
                    || value
                        .bytes()
                        .any(|byte| !byte.is_ascii_lowercase() && byte != b'-')
            })
        {
            return Err("proxy trusted context header allowlist is invalid".to_string());
        }
        Ok(allowlist)
    }
}

fn action(method: &str) -> Result<RegistryRateLimitAction, String> {
    match method {
        "GET" | "HEAD" => Ok(RegistryRateLimitAction::Pull),
        "POST" | "PUT" | "PATCH" | "DELETE" => Ok(RegistryRateLimitAction::Push),
        _ => Err("unsupported original request method".to_string()),
    }
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, String> {
    optional_header(headers, name).ok_or_else(|| format!("missing required proxy header {name}"))
}

fn optional_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}
