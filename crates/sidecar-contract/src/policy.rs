use serde::{Deserialize, Serialize};

use crate::{
    ContractError, ContractResult, RegistryMetricDimensions, RegistryRateLimitRequest,
    RuntimeBlocklistPolicyRef,
    constants::{CONTRACT_MAX_STRING_BYTES, MAX_BLOCKLIST_POLICY_REFS, MAX_POLICY_RATE_LIMITS},
    rate_limit::RateLimitNetworkIdentity,
    serde_bounds,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyDecisionRequest {
    pub tenant_id: String,
    pub org_id: String,
    pub subject: RuntimePolicySubject,
    pub resource: RuntimePolicyResource,
    pub action: RuntimePolicyAction,
    pub network: RuntimePolicyNetwork,
    pub rate_limit: RuntimePolicyRateLimitContext,
    pub blocklist: RuntimePolicyBlocklistContext,
    pub metrics: RuntimePolicyMetricAttribution,
    pub policy_generation: String,
}

impl RuntimePolicyDecisionRequest {
    pub fn validate(&self) -> ContractResult<()> {
        validate_text(&self.tenant_id, "tenant_id")?;
        validate_text(&self.org_id, "org_id")?;
        validate_text(&self.subject.kind, "subject kind")?;
        validate_text(&self.subject.id, "subject id")?;
        validate_text(&self.resource.kind, "resource kind")?;
        validate_text(&self.resource.id, "resource id")?;
        validate_text(&self.action.name, "action name")?;
        if self.action.cost == 0 {
            return Err(policy_invalid("action cost must be positive"));
        }
        let expected = RateLimitNetworkIdentity::from_client_ip(&self.network.client_ip)?;
        if expected != self.network.identity {
            return Err(policy_invalid(
                "network_identity must match canonical client_ip identity",
            ));
        }
        if let Some(country) = &self.network.country {
            validate_text(country, "country")?;
        }
        if self.rate_limit.limits.len() > MAX_POLICY_RATE_LIMITS {
            return Err(policy_invalid("rate-limit limits exceed the policy bound"));
        }
        for limit in &self.rate_limit.limits {
            limit.validate()?;
        }
        if self.blocklist.policies.len() > MAX_BLOCKLIST_POLICY_REFS {
            return Err(policy_invalid("blocklist policies exceed the policy bound"));
        }
        for policy in &self.blocklist.policies {
            policy.validate()?;
        }
        validate_text(&self.metrics.domain, "metrics domain")?;
        if let Some(environment) = &self.metrics.environment {
            validate_text(environment, "metrics environment")?;
        }
        validate_text(&self.policy_generation, "policy_generation")
    }

    pub fn from_registry_context(
        tenant_id: String,
        rate_limit: RegistryRateLimitRequest,
        blocklist_policies: Vec<RuntimeBlocklistPolicyRef>,
        metric_dimensions: RegistryMetricDimensions,
    ) -> crate::ContractResult<Self> {
        rate_limit.validate()?;
        metric_dimensions.validate()?;
        if blocklist_policies.len() > MAX_BLOCKLIST_POLICY_REFS {
            return Err(policy_invalid("blocklist policies exceed the policy bound"));
        }
        let network_identity = rate_limit.network_identity()?;
        let hourly_limit = rate_limit.hourly_limit();
        let window_seconds = rate_limit.window_seconds();
        let organization_descriptor = RuntimePolicyRateLimitDescriptor {
            domain: "registry".to_string(),
            tenant_id: tenant_id.clone(),
            org_id: rate_limit.organization_id.clone(),
            action: rate_limit.action.as_str().to_string(),
            resource: rate_limit.repository.clone(),
            scope: "organization".to_string(),
            repository: rate_limit.repository.clone(),
            user_id: rate_limit.user_id.clone(),
            network_identity: network_identity.clone(),
        };
        let network_descriptor = RuntimePolicyRateLimitDescriptor {
            domain: "registry".to_string(),
            tenant_id: tenant_id.clone(),
            org_id: rate_limit.organization_id.clone(),
            action: rate_limit.action.as_str().to_string(),
            resource: rate_limit.repository.clone(),
            scope: "network".to_string(),
            repository: rate_limit.repository.clone(),
            user_id: rate_limit.user_id.clone(),
            network_identity: network_identity.clone(),
        };
        let request = Self {
            tenant_id: tenant_id.clone(),
            org_id: rate_limit.organization_id.clone(),
            subject: RuntimePolicySubject {
                kind: "user".to_string(),
                id: rate_limit.user_id.clone(),
            },
            resource: RuntimePolicyResource {
                kind: "repository".to_string(),
                id: rate_limit.repository.clone(),
            },
            action: RuntimePolicyAction {
                name: rate_limit.action.as_str().to_string(),
                cost: rate_limit.cost,
            },
            network: RuntimePolicyNetwork {
                client_ip: rate_limit.client_ip.clone(),
                identity: network_identity.clone(),
                country: None,
            },
            rate_limit: RuntimePolicyRateLimitContext {
                enabled: true,
                defaults: RuntimePolicyRateLimitDefaults {
                    pull_limit_per_hour: rate_limit.defaults.pull_limit_per_hour,
                    push_limit_per_hour: rate_limit.defaults.push_limit_per_hour,
                },
                limits: vec![
                    RuntimePolicyWindowedLimit {
                        descriptor: organization_descriptor,
                        limit: hourly_limit,
                        window_seconds,
                        cost: rate_limit.cost,
                        control_class: "quota".to_string(),
                    },
                    RuntimePolicyWindowedLimit {
                        descriptor: network_descriptor,
                        limit: hourly_limit,
                        window_seconds,
                        cost: rate_limit.cost,
                        control_class: "quota".to_string(),
                    },
                ],
            },
            blocklist: RuntimePolicyBlocklistContext {
                enabled: !blocklist_policies.is_empty(),
                policies: blocklist_policies,
            },
            metrics: RuntimePolicyMetricAttribution {
                enabled: true,
                domain: "registry".to_string(),
                environment: None,
                dimensions: metric_dimensions,
            },
            policy_generation: "direct".to_string(),
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicySubject {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyResource {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyAction {
    pub name: String,
    pub cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyNetwork {
    pub client_ip: String,
    pub identity: RateLimitNetworkIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyRateLimitDefaults {
    pub pull_limit_per_hour: u32,
    pub push_limit_per_hour: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyRateLimitContext {
    pub enabled: bool,
    pub defaults: RuntimePolicyRateLimitDefaults,
    #[serde(deserialize_with = "deserialize_limits")]
    pub limits: Vec<RuntimePolicyWindowedLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyWindowedLimit {
    pub descriptor: RuntimePolicyRateLimitDescriptor,
    pub limit: u32,
    pub window_seconds: u32,
    pub cost: u32,
    pub control_class: String,
}

impl RuntimePolicyWindowedLimit {
    fn validate(&self) -> ContractResult<()> {
        if self.limit == 0 || self.window_seconds == 0 || self.cost == 0 {
            return Err(policy_invalid(
                "windowed rate-limit values must be positive",
            ));
        }
        if self.cost > self.limit {
            return Err(policy_invalid("rate-limit cost exceeds the limit"));
        }
        validate_text(&self.control_class, "control_class")?;
        self.descriptor.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyRateLimitDescriptor {
    pub domain: String,
    pub tenant_id: String,
    pub org_id: String,
    pub action: String,
    pub resource: String,
    pub scope: String,
    pub repository: String,
    pub user_id: String,
    pub network_identity: RateLimitNetworkIdentity,
}

impl RuntimePolicyRateLimitDescriptor {
    fn validate(&self) -> ContractResult<()> {
        for (value, field) in [
            (&self.domain, "descriptor domain"),
            (&self.tenant_id, "descriptor tenant_id"),
            (&self.org_id, "descriptor org_id"),
            (&self.action, "descriptor action"),
            (&self.resource, "descriptor resource"),
            (&self.scope, "descriptor scope"),
            (&self.repository, "descriptor repository"),
            (&self.user_id, "descriptor user_id"),
        ] {
            validate_text(value, field)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyBlocklistContext {
    pub enabled: bool,
    #[serde(deserialize_with = "deserialize_policies")]
    pub policies: Vec<RuntimeBlocklistPolicyRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyMetricAttribution {
    pub enabled: bool,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub dimensions: RegistryMetricDimensions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyDecisionResponse {
    pub allowed: bool,
    pub status: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_policy: Option<String>,
    pub policy_generation: String,
    pub controls: serde_json::Value,
}

fn deserialize_limits<'de, D>(
    deserializer: D,
) -> Result<Vec<RuntimePolicyWindowedLimit>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_POLICY_RATE_LIMITS)
}

fn deserialize_policies<'de, D>(
    deserializer: D,
) -> Result<Vec<RuntimeBlocklistPolicyRef>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_BLOCKLIST_POLICY_REFS)
}

fn validate_text(value: &str, field: &str) -> ContractResult<()> {
    if value.trim().is_empty() || value.len() > CONTRACT_MAX_STRING_BYTES {
        return Err(policy_invalid(format!(
            "{field} must contain between 1 and {CONTRACT_MAX_STRING_BYTES} bytes"
        )));
    }
    Ok(())
}

fn policy_invalid(message: impl Into<String>) -> ContractError {
    ContractError::invalid("runtime_policy_request_invalid", message)
}
