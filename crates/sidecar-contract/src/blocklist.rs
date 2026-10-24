use serde::{Deserialize, Serialize};

use crate::{
    ContractError, ContractResult, RateLimitNetworkIdentity,
    constants::{CONTRACT_MAX_STRING_BYTES, MAX_BLOCKLIST_MATCHES, MAX_BLOCKLIST_POLICY_REFS},
    rate_limit::RegistryRateLimitAction,
    serde_bounds,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeBlocklistPolicyRef {
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub reason: Option<String>,
}

impl RuntimeBlocklistPolicyRef {
    pub fn validate(&self) -> ContractResult<()> {
        validate_text(&self.name, "policy name", "blocklist_request_invalid")?;
        if let Some(reason) = &self.reason {
            validate_text(reason, "policy reason", "blocklist_request_invalid")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeBlocklistDecisionRequest {
    pub tenant_id: String,
    pub org_id: String,
    #[serde(default = "default_product_domain")]
    pub product_domain: String,
    pub resource: String,
    pub action: RegistryRateLimitAction,
    pub client_ip: String,
    pub network_identity: RateLimitNetworkIdentity,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub country: Option<String>,
    #[serde(default, deserialize_with = "deserialize_policy_refs")]
    pub policy_refs: Vec<RuntimeBlocklistPolicyRef>,
}

impl RuntimeBlocklistDecisionRequest {
    pub fn validate(&self) -> ContractResult<()> {
        validate_non_empty(&self.tenant_id, "tenant_id")?;
        validate_non_empty(&self.org_id, "org_id")?;
        validate_non_empty(&self.product_domain, "product_domain")?;
        validate_non_empty(&self.resource, "resource")?;
        let expected = RateLimitNetworkIdentity::from_client_ip(&self.client_ip)?;
        if expected != self.network_identity {
            return Err(blocklist_invalid(
                "blocklist_request_invalid",
                "network_identity must match canonical client_ip identity",
            ));
        }
        if self.policy_refs.len() > MAX_BLOCKLIST_POLICY_REFS {
            return Err(blocklist_invalid(
                "blocklist_request_invalid",
                "policy_refs exceed the blocklist bound",
            ));
        }
        for policy in &self.policy_refs {
            policy.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeBlocklistMatch {
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub kind: String,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub value: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub policy: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeBlocklistDecisionResponse {
    pub blocked: bool,
    #[serde(default, deserialize_with = "deserialize_matches")]
    pub matches: Vec<RuntimeBlocklistMatch>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub audit_subject: Option<String>,
}

impl RuntimeBlocklistDecisionResponse {
    pub fn validate(&self) -> ContractResult<()> {
        if self.matches.len() > MAX_BLOCKLIST_MATCHES {
            return Err(blocklist_invalid(
                "blocklist_response_invalid",
                "matches exceed the blocklist bound",
            ));
        }
        for matched in &self.matches {
            validate_text(&matched.kind, "match kind", "blocklist_response_invalid")?;
            validate_text(&matched.value, "match value", "blocklist_response_invalid")?;
            if let Some(policy) = &matched.policy {
                validate_text(policy, "match policy", "blocklist_response_invalid")?;
            }
            if let Some(reason) = &matched.reason {
                validate_text(reason, "match reason", "blocklist_response_invalid")?;
            }
        }
        if let Some(audit_subject) = &self.audit_subject {
            validate_text(audit_subject, "audit subject", "blocklist_response_invalid")?;
        }
        Ok(())
    }
}

fn deserialize_policy_refs<'de, D>(
    deserializer: D,
) -> Result<Vec<RuntimeBlocklistPolicyRef>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_BLOCKLIST_POLICY_REFS)
}

fn deserialize_matches<'de, D>(deserializer: D) -> Result<Vec<RuntimeBlocklistMatch>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_BLOCKLIST_MATCHES)
}

fn default_product_domain() -> String {
    "registry".to_string()
}

fn validate_non_empty(value: &str, field: &str) -> ContractResult<()> {
    validate_text(value, field, "blocklist_request_invalid")
}

fn validate_text(value: &str, field: &str, code: &'static str) -> ContractResult<()> {
    if value.trim().is_empty() || value.len() > CONTRACT_MAX_STRING_BYTES {
        return Err(blocklist_invalid(
            code,
            format!("{field} must contain between 1 and {CONTRACT_MAX_STRING_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn blocklist_invalid(code: &'static str, message: impl Into<String>) -> ContractError {
    ContractError::invalid(code, message)
}
