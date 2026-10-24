use serde::{Deserialize, Serialize};

use crate::{ContractError, ContractResult, rate_limit::RegistryRateLimitAction};

pub const REGISTRY_PULL_TOTAL: &str = "aux_registry_pull_total";
pub const REGISTRY_PUSH_TOTAL: &str = "aux_registry_push_total";
pub const REGISTRY_STORAGE_BYTES_TOTAL: &str = "aux_registry_storage_bytes_total";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryMetricDimensions {
    pub repository: String,
    pub user_id: String,
    pub organization_id: String,
    pub action: RegistryRateLimitAction,
    pub status_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

impl RegistryMetricDimensions {
    pub fn validate(&self) -> ContractResult<()> {
        validate_non_empty(&self.repository, "repository")?;
        validate_non_empty(&self.user_id, "user_id")?;
        validate_non_empty(&self.organization_id, "organization_id")?;
        validate_status_class(&self.status_class)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryMetricIngestRequest {
    pub metric_name: String,
    pub value: u64,
    pub dimensions: RegistryMetricDimensions,
}

impl RegistryMetricIngestRequest {
    pub fn validate(&self) -> ContractResult<()> {
        validate_registry_metric_name(&self.metric_name)?;
        self.dimensions.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryPrometheusRollupLabels {
    pub environment: String,
    pub action: RegistryRateLimitAction,
    pub status_class: String,
}

impl RegistryPrometheusRollupLabels {
    pub fn validate(&self) -> ContractResult<()> {
        validate_non_empty(&self.environment, "environment")?;
        validate_status_class(&self.status_class)
    }
}

fn validate_registry_metric_name(metric_name: &str) -> ContractResult<()> {
    match metric_name {
        REGISTRY_PULL_TOTAL | REGISTRY_PUSH_TOTAL | REGISTRY_STORAGE_BYTES_TOTAL => Ok(()),
        _ => Err(metrics_invalid(format!(
            "unsupported registry metric name: {metric_name}"
        ))),
    }
}

fn validate_status_class(status_class: &str) -> ContractResult<()> {
    let valid = matches!(status_class, "2xx" | "3xx" | "4xx" | "5xx");
    if valid {
        Ok(())
    } else {
        Err(metrics_invalid(format!(
            "unsupported status_class: {status_class}"
        )))
    }
}

fn validate_non_empty(value: &str, field: &str) -> ContractResult<()> {
    if value.trim().is_empty() {
        return Err(metrics_invalid(format!("{field} must not be empty")));
    }
    Ok(())
}

fn metrics_invalid(message: impl Into<String>) -> ContractError {
    ContractError::invalid("metrics_request_invalid", message)
}
