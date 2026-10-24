use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    AuthzEvaluationDataSnapshotRequest, ContractError, ContractResult, EntitlementEvaluateRequest,
    RuntimeBlocklistPolicyRef,
    constants::{
        MAX_BLOCKLIST_POLICY_REFS, MAX_SYNC_AUTHZ_RESOURCES, MAX_SYNC_AUTHZ_SUBJECTS,
        SYNC_MAX_ARTIFACTS, SYNC_MAX_ENTITLEMENT_ORGS, SYNC_MAX_KEY_LENGTH, SYNC_MAX_KIND_LENGTH,
        SYNC_MAX_MUTABLE_AGE_MS, SYNC_MAX_REFRESH_AFTER_MS, SYNC_MAX_RESPONSE_BYTES, SYNC_MAX_WANT,
        SYNC_PROTOCOL_VERSION,
    },
    serde_bounds,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyncArtifactKind {
    Jwks,
    AuthzPolicy,
    AuthzEvaluationData,
    RateLimitConfig,
    Blocklist,
    Entitlements,
    Revocations,
    Unknown(String),
}

impl SyncArtifactKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Jwks => "jwks",
            Self::AuthzPolicy => "authz_policy",
            Self::AuthzEvaluationData => "authz_evaluation_data",
            Self::RateLimitConfig => "rate_limit_config",
            Self::Blocklist => "blocklist",
            Self::Entitlements => "entitlements",
            Self::Revocations => "revocations",
            Self::Unknown(value) => value,
        }
    }

    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for SyncArtifactKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<String> for SyncArtifactKind {
    fn from(value: String) -> Self {
        match value.as_str() {
            "jwks" => Self::Jwks,
            "authz_policy" => Self::AuthzPolicy,
            "authz_evaluation_data" => Self::AuthzEvaluationData,
            "rate_limit_config" => Self::RateLimitConfig,
            "blocklist" => Self::Blocklist,
            "entitlements" => Self::Entitlements,
            "revocations" => Self::Revocations,
            _ => Self::Unknown(value),
        }
    }
}

impl Serialize for SyncArtifactKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SyncArtifactKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        serde_bounds::deserialize_bounded_string(deserializer).map(Self::from)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSyncKnownVersions {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub jwks: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub authz_policy: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub rate_limit_config: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub blocklist: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_bounds::deserialize_optional_bounded_string"
    )]
    pub revocations: Option<String>,
    #[serde(default, deserialize_with = "deserialize_known_entitlements")]
    pub entitlements: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSyncRequest {
    pub protocol_version: u16,
    #[serde(default)]
    pub known: RuntimeSyncKnownVersions,
    #[serde(deserialize_with = "deserialize_want")]
    pub want: Vec<SyncArtifactKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authz: Option<AuthzEvaluationDataSnapshotRequest>,
    #[serde(default, deserialize_with = "deserialize_entitlement_requests")]
    pub entitlements: Vec<EntitlementEvaluateRequest>,
    #[serde(default, deserialize_with = "deserialize_blocklist_policy_refs")]
    pub blocklist_policy_refs: Vec<RuntimeBlocklistPolicyRef>,
    /// Resource audiences whose revocation state the runtime is authorized to
    /// cache.  The server returns only this bounded audience set.
    #[serde(default, deserialize_with = "deserialize_revocation_audiences")]
    pub revocation_audiences: Vec<String>,
}

impl RuntimeSyncRequest {
    pub fn validate(&self) -> ContractResult<()> {
        validate_protocol(self.protocol_version)?;
        if self.want.is_empty() || self.want.len() > SYNC_MAX_WANT {
            return Err(sync_invalid(
                "want must contain between 1 and 32 artifact kinds",
            ));
        }
        if self.want.iter().any(|kind| !kind.is_known()) {
            return Err(sync_invalid(
                "want contains an unsupported required artifact kind",
            ));
        }
        if self
            .want
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.want.len()
        {
            return Err(sync_invalid("want contains duplicate artifact kinds"));
        }
        if self.known.entitlements.len() > SYNC_MAX_ENTITLEMENT_ORGS
            || self.entitlements.len() > SYNC_MAX_ENTITLEMENT_ORGS
        {
            return Err(sync_invalid(
                "entitlement organization count exceeds the sync bound",
            ));
        }
        validate_known_versions(&self.known)?;
        if self.revocation_audiences.len() > crate::constants::SYNC_MAX_REVOCATION_AUDIENCES {
            return Err(sync_invalid(
                "revocation audience count exceeds the sync bound",
            ));
        }
        for audience in &self.revocation_audiences {
            validate_bounded(audience, "revocation audience")?;
        }
        if self.want.contains(&SyncArtifactKind::Revocations)
            && self.revocation_audiences.is_empty()
        {
            return Err(sync_invalid(
                "revocation_audiences are required when revocations are requested",
            ));
        }
        if let Some(authz) = &self.authz {
            if authz.subjects.len() > MAX_SYNC_AUTHZ_SUBJECTS {
                return Err(sync_invalid("authz subject count exceeds the sync bound"));
            }
            if authz.resources.len() > MAX_SYNC_AUTHZ_RESOURCES {
                return Err(sync_invalid("authz resource count exceeds the sync bound"));
            }
            for subject in &authz.subjects {
                validate_bounded(&subject.subject_type, "authz subject type")?;
                validate_bounded(&subject.id, "authz subject id")?;
            }
            for resource in &authz.resources {
                validate_bounded(&resource.resource_type, "authz resource type")?;
                validate_bounded(&resource.id, "authz resource id")?;
            }
        }
        for entitlement in &self.entitlements {
            entitlement.validate().map_err(|error| {
                sync_invalid(format!("invalid entitlement sync request: {error}"))
            })?;
        }
        if self.blocklist_policy_refs.len() > MAX_BLOCKLIST_POLICY_REFS {
            return Err(sync_invalid(
                "blocklist policy count exceeds the sync bound",
            ));
        }
        for policy in &self.blocklist_policy_refs {
            policy.validate().map_err(|error| {
                sync_invalid(format!("invalid blocklist sync request: {error}"))
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSyncArtifact {
    pub kind: SyncArtifactKind,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub key: String,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub version: String,
    #[serde(deserialize_with = "serde_bounds::deserialize_non_empty_bounded_string")]
    pub etag: String,
    pub immutable: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_max_age"
    )]
    pub max_age_ms: Option<u64>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSyncCapabilities {
    pub authz: u16,
    pub rate_limit: u16,
    pub entitlements: u16,
    pub blocklist: u16,
    pub combined_policy: u16,
    #[serde(default)]
    pub revocations: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSyncResponse {
    pub protocol_version: u16,
    pub server_time: String,
    pub refresh_after_ms: u64,
    #[serde(deserialize_with = "deserialize_artifacts")]
    pub artifacts: Vec<RuntimeSyncArtifact>,
    #[serde(default, deserialize_with = "deserialize_unchanged")]
    pub unchanged: Vec<SyncArtifactKind>,
    pub capabilities: RuntimeSyncCapabilities,
}

impl RuntimeSyncResponse {
    pub fn validate(&self) -> ContractResult<()> {
        validate_protocol(self.protocol_version)?;
        if self.server_time.trim().is_empty() {
            return Err(sync_invalid("server_time must not be empty"));
        }
        if chrono::DateTime::parse_from_rfc3339(&self.server_time).is_err() {
            return Err(sync_invalid(
                "server_time must be a valid RFC3339 timestamp",
            ));
        }
        if self.refresh_after_ms > SYNC_MAX_REFRESH_AFTER_MS {
            return Err(sync_invalid("refresh_after_ms exceeds the sync bound"));
        }
        if self.artifacts.len() > SYNC_MAX_ARTIFACTS {
            return Err(sync_invalid("artifact count exceeds the sync bound"));
        }
        let mut identities = std::collections::BTreeSet::new();
        for artifact in &self.artifacts {
            validate_artifact(artifact)?;
            if !identities.insert((artifact.kind.clone(), artifact.key.clone())) {
                return Err(sync_invalid("sync response contains a duplicate artifact"));
            }
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|_| sync_invalid("sync response could not be size checked"))?;
        if encoded.len() > SYNC_MAX_RESPONSE_BYTES {
            return Err(sync_invalid("sync response exceeds the byte bound"));
        }
        Ok(())
    }
}

fn validate_protocol(protocol_version: u16) -> ContractResult<()> {
    if protocol_version != SYNC_PROTOCOL_VERSION {
        return Err(sync_invalid(format!(
            "unsupported sync protocol version {protocol_version}"
        )));
    }
    Ok(())
}

fn validate_known_versions(known: &RuntimeSyncKnownVersions) -> ContractResult<()> {
    for value in [
        known.jwks.as_deref(),
        known.authz_policy.as_deref(),
        known.rate_limit_config.as_deref(),
        known.blocklist.as_deref(),
        known.revocations.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_bounded(value, "known version")?;
    }
    for (key, version) in &known.entitlements {
        validate_bounded(key, "entitlement organization key")?;
        validate_bounded(version, "entitlement version")?;
    }
    Ok(())
}

fn validate_artifact(artifact: &RuntimeSyncArtifact) -> ContractResult<()> {
    if artifact.kind.as_str().len() > SYNC_MAX_KIND_LENGTH {
        return Err(sync_invalid("artifact kind exceeds the sync bound"));
    }
    validate_bounded(&artifact.key, "artifact key")?;
    validate_bounded(&artifact.version, "artifact version")?;
    validate_bounded(&artifact.etag, "artifact etag")?;
    if !artifact.immutable && artifact.max_age_ms.is_none() {
        return Err(sync_invalid("mutable artifacts require max_age_ms"));
    }
    if artifact
        .max_age_ms
        .is_some_and(|max_age_ms| max_age_ms > SYNC_MAX_MUTABLE_AGE_MS)
    {
        return Err(sync_invalid("artifact max_age_ms exceeds the sync bound"));
    }
    Ok(())
}

fn deserialize_want<'de, D>(deserializer: D) -> Result<Vec<SyncArtifactKind>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, SYNC_MAX_WANT)
}

fn deserialize_entitlement_requests<'de, D>(
    deserializer: D,
) -> Result<Vec<EntitlementEvaluateRequest>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, SYNC_MAX_ENTITLEMENT_ORGS)
}

fn deserialize_blocklist_policy_refs<'de, D>(
    deserializer: D,
) -> Result<Vec<RuntimeBlocklistPolicyRef>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, MAX_BLOCKLIST_POLICY_REFS)
}

fn deserialize_revocation_audiences<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(
        deserializer,
        crate::constants::SYNC_MAX_REVOCATION_AUDIENCES,
    )
}

fn deserialize_artifacts<'de, D>(deserializer: D) -> Result<Vec<RuntimeSyncArtifact>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, SYNC_MAX_ARTIFACTS)
}

fn deserialize_unchanged<'de, D>(deserializer: D) -> Result<Vec<SyncArtifactKind>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_vec(deserializer, SYNC_MAX_WANT)
}

fn deserialize_max_age<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_optional_bounded_u64(deserializer, SYNC_MAX_MUTABLE_AGE_MS)
}

fn deserialize_known_entitlements<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_string_map(deserializer, SYNC_MAX_ENTITLEMENT_ORGS)
}

fn validate_bounded(value: &str, field: &str) -> ContractResult<()> {
    if value.trim().is_empty() || value.len() > SYNC_MAX_KEY_LENGTH {
        return Err(sync_invalid(format!(
            "{field} must contain between 1 and {SYNC_MAX_KEY_LENGTH} bytes"
        )));
    }
    Ok(())
}

fn sync_invalid(message: impl Into<String>) -> ContractError {
    ContractError::invalid("runtime_sync_invalid", message)
}
