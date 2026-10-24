use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    CacheStatus, ContractError, ContractResult,
    constants::{
        CONTRACT_MAX_STRING_BYTES, MAX_ENTITLEMENT_KEYS, MAX_ENTITLEMENT_RESPONSE_ITEMS,
        MAX_ENTITLEMENT_USED_ENTITLEMENTS,
    },
    serde_bounds,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementEvaluateRequest {
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub org_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub at_time: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_entitlement_keys"
    )]
    pub keys: Option<Vec<String>>,
}

impl EntitlementEvaluateRequest {
    pub fn validate(&self) -> ContractResult<()> {
        validate_text(&self.org_id, "org_id")?;
        if let Some(at_time) = &self.at_time {
            validate_text(at_time, "at_time")?;
        }
        if let Some(keys) = &self.keys {
            if keys.len() > MAX_ENTITLEMENT_KEYS {
                return Err(entitlement_invalid(
                    "entitlement_request_invalid",
                    "keys exceed the entitlement bound",
                ));
            }
            let mut unique_keys = HashSet::with_capacity(keys.len());
            for key in keys {
                validate_entitlement_key(key, "entitlement_request_invalid")?;
                if !unique_keys.insert(key.as_str()) {
                    return Err(entitlement_invalid(
                        "entitlement_request_invalid",
                        "keys contain a duplicate entitlement key",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntitlementEvaluateResponse {
    #[serde(deserialize_with = "deserialize_entitlement_items")]
    pub items: Vec<EntitlementEvaluationResult>,
}

impl EntitlementEvaluateResponse {
    pub fn validate(&self) -> ContractResult<()> {
        if self.items.len() > MAX_ENTITLEMENT_RESPONSE_ITEMS {
            return Err(entitlement_invalid(
                "entitlement_response_invalid",
                "items exceed the entitlement bound",
            ));
        }
        let mut keys = HashSet::with_capacity(self.items.len());
        for item in &self.items {
            item.validate()?;
            if !keys.insert(item.key.as_str()) {
                return Err(entitlement_invalid(
                    "entitlement_response_invalid",
                    "items contain a duplicate key",
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &EntitlementEvaluateRequest) -> ContractResult<()> {
        request.validate()?;
        self.validate()?;
        let Some(keys) = &request.keys else {
            return Ok(());
        };
        if self.items.len() != keys.len() {
            return Err(entitlement_invalid(
                "entitlement_response_invalid",
                "response item count does not match requested keys",
            ));
        }
        let response_keys = self
            .items
            .iter()
            .map(|item| item.key.as_str())
            .collect::<HashSet<_>>();
        for key in keys {
            if !response_keys.contains(key.as_str()) {
                return Err(entitlement_invalid(
                    "entitlement_response_invalid",
                    "response is missing a requested key",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntitlementEvaluationResult {
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub key: String,
    pub decision: EntitlementDecision,
    #[serde(deserialize_with = "deserialize_used_entitlements")]
    pub used_entitlements: Vec<EntitlementUsedEntitlement>,
}

impl EntitlementEvaluationResult {
    fn validate(&self) -> ContractResult<()> {
        validate_entitlement_key(&self.key, "entitlement_response_invalid")?;
        for used in &self.used_entitlements {
            used.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum EntitlementDecision {
    NotEntitled,
    Denied,
    Granted { value: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntitlementUsedEntitlement {
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub entitlement_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_non_empty_bounded_string"
    )]
    pub name: Option<String>,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub operator: String,
    pub value: serde_json::Value,
}

impl EntitlementUsedEntitlement {
    fn validate(&self) -> ContractResult<()> {
        validate_text(&self.entitlement_id, "entitlement_id")?;
        if let Some(name) = &self.name {
            validate_text(name, "entitlement name")?;
        }
        validate_text(&self.operator, "operator")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntitlementsEvaluationResult {
    pub response: EntitlementEvaluateResponse,
    pub cache_status: CacheStatus,
}

impl EntitlementsEvaluationResult {
    pub fn validate(&self) -> ContractResult<()> {
        self.response.validate()
    }

    pub fn validate_for_request(&self, request: &EntitlementEvaluateRequest) -> ContractResult<()> {
        self.response.validate_for_request(request)
    }
}

fn deserialize_entitlement_keys<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_optional_bounded_string_vec(deserializer, MAX_ENTITLEMENT_KEYS)
}

fn deserialize_entitlement_items<'de, D>(
    deserializer: D,
) -> Result<Vec<EntitlementEvaluationResult>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_ENTITLEMENT_RESPONSE_ITEMS)
}

fn deserialize_used_entitlements<'de, D>(
    deserializer: D,
) -> Result<Vec<EntitlementUsedEntitlement>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_ENTITLEMENT_USED_ENTITLEMENTS)
}

fn validate_text(value: &str, field: &str) -> ContractResult<()> {
    if value.trim().is_empty() || value.len() > CONTRACT_MAX_STRING_BYTES {
        return Err(entitlement_invalid(
            "entitlement_request_invalid",
            format!("{field} must contain between 1 and {CONTRACT_MAX_STRING_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_entitlement_key(value: &str, code: &'static str) -> ContractResult<()> {
    if value.trim().is_empty()
        || value.len() > crate::constants::MAX_ENTITLEMENT_KEY_LENGTH
        || value.contains('#')
    {
        return Err(entitlement_invalid(
            code,
            format!(
                "entitlement key must contain between 1 and {} bytes and no '#'",
                crate::constants::MAX_ENTITLEMENT_KEY_LENGTH
            ),
        ));
    }
    Ok(())
}

fn entitlement_invalid(code: &'static str, message: impl Into<String>) -> ContractError {
    ContractError::invalid(code, message)
}
