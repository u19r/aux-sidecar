use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    ContractResult,
    rate_limit::{MAX_EVENTS_PER_BATCH, RateLimitParameters},
    rate_limit_helpers::{
        RATE_LIMIT_KEY_MAX_LEN, deserialize_expires_at_ms, rate_limit_invalid,
        validate_lease_batch_len, validate_non_empty, validate_positive, validate_rate_limit_key,
    },
    serde_bounds,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitAcquireLeaseRequestItem {
    #[serde(deserialize_with = "deserialize_rate_limit_key")]
    pub key: String,
    pub requested_tokens: u32,
    pub min_grant_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitAcquireLeaseRequest {
    pub params: RateLimitParameters,
    pub leases: Vec<RateLimitAcquireLeaseRequestItem>,
}

impl RateLimitAcquireLeaseRequest {
    pub fn validate(&self) -> ContractResult<()> {
        self.params.validate()?;
        validate_lease_batch_len(self.leases.len())?;
        let max_burst_tokens = self.params.max_burst_tokens();
        let mut keys = HashSet::with_capacity(self.leases.len());

        for lease in &self.leases {
            validate_rate_limit_key(&lease.key)?;
            if !keys.insert(lease.key.as_str()) {
                return Err(rate_limit_invalid(
                    "acquire lease request contains a duplicate key",
                ));
            }
            validate_positive(lease.requested_tokens, "requested_tokens")?;
            validate_positive(lease.min_grant_tokens, "min_grant_tokens")?;
            if lease.requested_tokens < lease.min_grant_tokens {
                return Err(rate_limit_invalid(
                    "requested_tokens must be greater than or equal to min_grant_tokens",
                ));
            }
            if u64::from(lease.min_grant_tokens) > max_burst_tokens {
                return Err(rate_limit_invalid(
                    "min_grant_tokens exceeds bucket capacity",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitLease {
    #[serde(deserialize_with = "deserialize_rate_limit_key")]
    pub key: String,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub lease_id: String,
    pub granted_tokens: u32,
    #[serde(alias = "expires_at", deserialize_with = "deserialize_expires_at_ms")]
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitAcquireLeaseResult {
    #[serde(deserialize_with = "deserialize_rate_limit_key")]
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<RateLimitLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitAcquireLeaseResponse {
    #[serde(deserialize_with = "deserialize_acquire_results")]
    pub results: Vec<RateLimitAcquireLeaseResult>,
}

impl RateLimitAcquireLeaseResponse {
    pub fn validate_for_request(
        &self,
        request: &RateLimitAcquireLeaseRequest,
    ) -> ContractResult<()> {
        request.validate()?;
        if self.results.len() > request.leases.len() {
            return Err(rate_limit_invalid(
                "lease response contains more results than requested leases",
            ));
        }

        let requested = request
            .leases
            .iter()
            .map(|lease| (lease.key.as_str(), lease))
            .collect::<HashMap<_, _>>();
        let mut returned = HashSet::with_capacity(self.results.len());
        for result in &self.results {
            validate_rate_limit_key(&result.key)?;
            let request_item = requested
                .get(result.key.as_str())
                .ok_or_else(|| rate_limit_invalid("lease response contains an unsolicited key"))?;
            if !returned.insert(result.key.as_str()) {
                return Err(rate_limit_invalid(
                    "lease response contains a duplicate key",
                ));
            }
            if let Some(lease) = &result.lease {
                validate_lease(lease)?;
                if lease.key != result.key {
                    return Err(rate_limit_invalid(
                        "lease response key does not match the result key",
                    ));
                }
                if lease.granted_tokens > request_item.requested_tokens {
                    return Err(rate_limit_invalid(
                        "lease response grants more tokens than requested",
                    ));
                }
                if lease.granted_tokens < request_item.min_grant_tokens {
                    return Err(rate_limit_invalid(
                        "lease response grants fewer tokens than the requested minimum",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitGiveBackLeaseRequestItem {
    #[serde(deserialize_with = "deserialize_rate_limit_key")]
    pub key: String,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub lease_id: String,
    pub return_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitGiveBackLeaseRequest {
    pub params: RateLimitParameters,
    pub leases: Vec<RateLimitGiveBackLeaseRequestItem>,
}

impl RateLimitGiveBackLeaseRequest {
    pub fn validate(&self) -> ContractResult<()> {
        self.params.validate()?;
        validate_lease_batch_len(self.leases.len())?;
        let mut lease_ids = HashSet::with_capacity(self.leases.len());

        for lease in &self.leases {
            validate_rate_limit_key(&lease.key)?;
            if lease.lease_id.trim().is_empty() {
                return Err(rate_limit_invalid("lease_id must not be empty"));
            }
            validate_positive(lease.return_tokens, "return_tokens")?;
            if !lease_ids.insert((lease.key.as_str(), lease.lease_id.as_str())) {
                return Err(rate_limit_invalid(
                    "give-back request contains a duplicate lease",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitGiveBackLeaseResult {
    #[serde(deserialize_with = "deserialize_rate_limit_key")]
    pub key: String,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub lease_id: String,
    pub returned_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitGiveBackLeaseResponse {
    #[serde(deserialize_with = "deserialize_giveback_results")]
    pub results: Vec<RateLimitGiveBackLeaseResult>,
}

impl RateLimitGiveBackLeaseResponse {
    pub fn validate_for_request(
        &self,
        request: &RateLimitGiveBackLeaseRequest,
    ) -> ContractResult<()> {
        request.validate()?;
        if self.results.len() > request.leases.len() {
            return Err(rate_limit_invalid(
                "give-back response contains more results than requested leases",
            ));
        }

        let requested = request
            .leases
            .iter()
            .map(|lease| {
                (
                    (lease.key.as_str(), lease.lease_id.as_str()),
                    lease.return_tokens,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut returned = HashSet::with_capacity(self.results.len());
        for result in &self.results {
            validate_rate_limit_key(&result.key)?;
            validate_non_empty(&result.lease_id, "lease_id")?;
            let maximum = requested
                .get(&(result.key.as_str(), result.lease_id.as_str()))
                .ok_or_else(|| {
                    rate_limit_invalid("give-back response contains an unsolicited lease")
                })?;
            if !returned.insert((result.key.as_str(), result.lease_id.as_str())) {
                return Err(rate_limit_invalid(
                    "give-back response contains a duplicate lease",
                ));
            }
            if result.returned_tokens > *maximum {
                return Err(rate_limit_invalid(
                    "give-back response returns more tokens than requested",
                ));
            }
        }
        Ok(())
    }
}

fn validate_lease(lease: &RateLimitLease) -> ContractResult<()> {
    validate_rate_limit_key(&lease.key)?;
    validate_non_empty(&lease.lease_id, "lease_id")?;
    validate_positive(lease.granted_tokens, "granted_tokens")
}

fn deserialize_rate_limit_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_non_empty_string_with_limit(deserializer, RATE_LIMIT_KEY_MAX_LEN)
}

fn deserialize_acquire_results<'de, D>(
    deserializer: D,
) -> Result<Vec<RateLimitAcquireLeaseResult>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_EVENTS_PER_BATCH)
}

fn deserialize_giveback_results<'de, D>(
    deserializer: D,
) -> Result<Vec<RateLimitGiveBackLeaseResult>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_EVENTS_PER_BATCH)
}
