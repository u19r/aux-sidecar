use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use sidecar_contract::{
    EntitlementDecision, EntitlementEvaluateRequest, EntitlementEvaluateResponse,
    EntitlementEvaluationResult,
};

use crate::{SidecarError, SidecarResult};

#[derive(Debug, Clone, PartialEq)]
pub struct LocalEntitlementSnapshot {
    response: EntitlementEvaluateResponse,
    item_indices: HashMap<String, usize>,
    valid_until_ms: i64,
    requested_keys: Option<Vec<String>>,
}

impl LocalEntitlementSnapshot {
    pub fn compile(payload: serde_json::Value) -> SidecarResult<Self> {
        let payload: EntitlementSyncPayload =
            serde_json::from_value(payload).map_err(|_| invalid())?;
        Self::from_payload(payload)
    }

    pub(crate) fn compile_borrowed(payload: &serde_json::Value) -> SidecarResult<Self> {
        let payload = EntitlementSyncPayload::deserialize(payload).map_err(|_| invalid())?;
        Self::from_payload(payload)
    }

    fn from_payload(payload: EntitlementSyncPayload) -> SidecarResult<Self> {
        if payload.valid_until_ms <= 0 {
            return Err(invalid());
        }
        let requested_keys = payload
            .requested_keys
            .map(|mut keys| {
                let request = EntitlementEvaluateRequest {
                    org_id: "runtime".to_string(),
                    at_time: None,
                    keys: Some(keys.clone()),
                };
                request.validate().map_err(|_| invalid())?;
                keys.sort_unstable();
                Ok::<_, SidecarError>(keys)
            })
            .transpose()?;
        let response = payload.response;
        response.validate().map_err(|_| invalid())?;
        let mut unique_keys = HashSet::with_capacity(response.items.len());
        if response
            .items
            .iter()
            .any(|item| !unique_keys.insert(item.key.as_str()))
        {
            return Err(invalid());
        }
        let item_indices = response
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| (item.key.clone(), index))
            .collect();
        Ok(Self {
            response,
            item_indices,
            valid_until_ms: payload.valid_until_ms,
            requested_keys,
        })
    }

    pub fn is_valid(&self, now_ms: i64) -> bool {
        now_ms <= self.valid_until_ms
    }

    pub fn covers(&self, request: &EntitlementEvaluateRequest) -> bool {
        match (&self.requested_keys, &request.keys) {
            (None, _) | (Some(_), None) => self.requested_keys.is_none(),
            (Some(cached), Some(requested)) => requested
                .iter()
                .all(|key| cached.binary_search(key).is_ok()),
        }
    }

    pub(crate) fn evaluate(
        &self,
        request: &EntitlementEvaluateRequest,
    ) -> EntitlementEvaluateResponse {
        let Some(keys) = request.keys.as_ref() else {
            return self.response.clone();
        };
        EntitlementEvaluateResponse {
            items: keys
                .iter()
                .map(|key| {
                    self.item_indices
                        .get(key)
                        .and_then(|index| self.response.items.get(*index))
                        .cloned()
                        .unwrap_or_else(|| EntitlementEvaluationResult {
                            key: key.clone(),
                            decision: EntitlementDecision::NotEntitled,
                            used_entitlements: Vec::new(),
                        })
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct EntitlementSyncPayload {
    response: EntitlementEvaluateResponse,
    valid_until_ms: i64,
    #[serde(default)]
    requested_keys: Option<Vec<String>>,
}

fn invalid() -> SidecarError {
    SidecarError::bad_gateway(
        "runtime_sync_entitlements_invalid",
        "synchronized entitlement artifact is invalid",
    )
}
