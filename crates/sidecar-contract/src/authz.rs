use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    CacheStatus,
    constants::{MAX_SYNC_AUTHZ_RESOURCES, MAX_SYNC_AUTHZ_SUBJECTS},
    serde_bounds,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiSubject {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiAction {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiEvaluationRequest {
    pub subject: ApiSubject,
    pub resource: ApiResource,
    pub action: ApiAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_context: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_context: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Remote evaluation accepts application attributes, while credential-derived
/// context stays local or is derived by AuxFn from authenticated headers.
#[derive(Serialize)]
pub struct RuntimeEvaluationRequest<'a> {
    subject: &'a ApiSubject,
    resource: &'a ApiResource,
    action: &'a ApiAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

impl<'a> From<&'a ApiEvaluationRequest> for RuntimeEvaluationRequest<'a> {
    fn from(request: &'a ApiEvaluationRequest) -> Self {
        Self {
            subject: &request.subject,
            resource: &request.resource,
            action: &request.action,
            context: request.context.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiResponseContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiEvaluationResponse {
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ApiResponseContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamAuthzResponse {
    pub status_code: u16,
    pub response: ApiEvaluationResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub www_authenticate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzEvaluationResult {
    pub response: ApiEvaluationResponse,
    pub cache_status: CacheStatus,
    pub status_code: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub www_authenticate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzPolicyVersionSnapshot {
    pub tenant_id: String,
    pub current_policy_version: u64,
    pub generated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzPolicySnapshot {
    pub tenant_id: String,
    pub policy_version: u64,
    pub config_hash: String,
    pub config: serde_json::Value,
    pub compiled_bundle: serde_json::Value,
    pub generated_at_ms: i64,
    /// Upstream cache guidance retained for wire compatibility.
    /// Version-addressed policy snapshots are immutable, so sidecar storage
    /// intentionally ignores this value and evicts only by its bounded LRU
    /// capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzEvaluationDataSnapshotRequest {
    pub policy_version: u64,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_subject_requests"
    )]
    pub subjects: Vec<AuthzSubjectAccessSnapshotRequest>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_resource_requests"
    )]
    pub resources: Vec<AuthzResourceAccessSnapshotRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AuthzSubjectAccessSnapshotRequest {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
    #[serde(default)]
    pub include_principal_id: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AuthzResourceAccessSnapshotRequest {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

fn deserialize_subject_requests<'de, D>(
    deserializer: D,
) -> Result<Vec<AuthzSubjectAccessSnapshotRequest>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_SYNC_AUTHZ_SUBJECTS)
}

fn deserialize_resource_requests<'de, D>(
    deserializer: D,
) -> Result<Vec<AuthzResourceAccessSnapshotRequest>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_SYNC_AUTHZ_RESOURCES)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzEvaluationDataSnapshot {
    pub tenant_id: String,
    pub policy_version: u64,
    pub generated_at_ms: i64,
    #[serde(default)]
    pub subjects: Vec<AuthzSubjectAccessSnapshot>,
    #[serde(default)]
    pub resources: Vec<AuthzResourceAccessSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzSubjectAccessSnapshot {
    /// Tenant that owns this subject and every access relationship in the
    /// snapshot.
    pub tenant_id: String,
    pub subject: ApiSubject,
    #[serde(default)]
    pub assignments: Vec<serde_json::Value>,
    #[serde(default)]
    pub subject_parents: Vec<AuthzParentRef>,
    #[serde(default)]
    pub resource_scopes: HashMap<String, Vec<String>>,
    pub fetched_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzResourceAccessSnapshot {
    /// Tenant that owns this resource and its relationship snapshot.
    pub tenant_id: String,
    pub resource_type: String,
    pub resource_id: String,
    /// Trusted resource attributes used by the local evaluator.
    pub properties: serde_json::Value,
    #[serde(default)]
    pub resource_parents: Vec<AuthzParentRef>,
    pub fetched_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzParentRef {
    pub ref_type: String,
    pub id: String,
}
