use serde::Serialize;
use sidecar_contract::SyncArtifactKind;

use crate::{
    DeploymentPreset, SidecarEngine, SidecarEngineConfig, SidecarState, SidecarTransport,
    state::current_time_millis,
};

impl<T> SidecarEngine<T>
where T: SidecarTransport
{
    pub fn live(&self) -> LiveStatus {
        live(&self.state)
    }

    pub fn ready(&self) -> ReadyStatus {
        ready(&self.config, &self.state, self.transport.host_available())
    }

    pub fn status(&self) -> OperationalStatus {
        status(&self.config, &self.state, self.transport.host_available())
    }

    pub fn capabilities(&self) -> Vec<CapabilityStatus> {
        capabilities()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveStatus {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityStatus {
    pub name: &'static str,
    pub version: u16,
    pub state: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadyStatus {
    pub ready: bool,
    pub reason_codes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OperationalStatus {
    pub version: &'static str,
    pub preset: &'static str,
    pub uptime_ms: u64,
    pub ready: bool,
    pub reason_codes: Vec<&'static str>,
    pub sync_generation: u64,
    pub next_refresh_ms: u64,
    pub artifact_count: usize,
    pub ignored_optional_artifacts: u64,
    pub lease_pool_count: usize,
    pub lease_item_count: usize,
    pub lease_granted_tokens: u64,
    pub lease_consumed_tokens: u64,
    pub lease_duplicate_responses: u64,
    pub host_transport: &'static str,
    pub capabilities: Vec<CapabilityStatus>,
}

pub(crate) fn live(state: &SidecarState) -> LiveStatus {
    LiveStatus {
        status: "live",
        version: env!("CARGO_PKG_VERSION"),
        uptime_ms: state.uptime_ms(),
    }
}

pub(crate) fn ready(
    config: &SidecarEngineConfig,
    state: &SidecarState,
    host_available: bool,
) -> ReadyStatus {
    let snapshot = state.runtime_sync_snapshot();
    let now_ms = now_ms();
    let stale_ms = i64::try_from(config.stale_cache_ttl.as_millis()).unwrap_or(i64::MAX);
    let states = required_artifacts(config)
        .iter()
        .map(|kind| snapshot.kind_state(kind, now_ms, stale_ms))
        .collect::<Vec<_>>();
    let mut reason_codes = Vec::new();
    if states.contains(&"missing") {
        reason_codes.push("required_state_missing");
    }
    if states.contains(&"expired") {
        reason_codes.push("required_state_expired");
    }
    if !host_available {
        reason_codes.push("host_transport_unavailable");
    }
    let capabilities = &snapshot.capabilities;
    if [
        capabilities.authz,
        capabilities.rate_limit,
        capabilities.entitlements,
        capabilities.blocklist,
        capabilities.combined_policy,
        capabilities.revocations,
    ]
    .into_iter()
    .any(|version| version > 1)
    {
        reason_codes.push("capability_version_incompatible");
    }
    ReadyStatus {
        ready: reason_codes.is_empty(),
        reason_codes,
    }
}

pub(crate) fn status(
    config: &SidecarEngineConfig,
    state: &SidecarState,
    host_available: bool,
) -> OperationalStatus {
    let ready = ready(config, state, host_available);
    let snapshot = state.runtime_sync_snapshot();
    let lease_metrics = state.lease_pool_metrics();
    OperationalStatus {
        version: env!("CARGO_PKG_VERSION"),
        preset: config.preset.as_str(),
        uptime_ms: state.uptime_ms(),
        ready: ready.ready,
        reason_codes: ready.reason_codes,
        sync_generation: snapshot.generation,
        next_refresh_ms: snapshot.refresh_after_ms,
        artifact_count: snapshot.artifact_count(),
        ignored_optional_artifacts: snapshot.ignored_optional_artifacts,
        lease_pool_count: lease_metrics.pool_count,
        lease_item_count: lease_metrics.item_count,
        lease_granted_tokens: lease_metrics.granted_tokens,
        lease_consumed_tokens: lease_metrics.consumed_tokens,
        lease_duplicate_responses: lease_metrics.duplicate_responses,
        host_transport: if host_available {
            "available"
        } else {
            "unavailable"
        },
        capabilities: capabilities(),
    }
}

pub(crate) fn capabilities() -> Vec<CapabilityStatus> {
    [
        "authz",
        "rate_limit",
        "entitlements",
        "blocklist",
        "combined_policy",
        "jwt",
        "hosted_login",
        "runtime_sync",
        "revocations",
    ]
    .into_iter()
    .map(|name| CapabilityStatus {
        name,
        version: 1,
        state: "supported",
    })
    .collect()
}

fn required_artifacts(config: &SidecarEngineConfig) -> Vec<SyncArtifactKind> {
    if matches!(config.preset, DeploymentPreset::Embedded) {
        return Vec::new();
    }
    let mut required = vec![
        SyncArtifactKind::AuthzPolicy,
        SyncArtifactKind::AuthzEvaluationData,
        SyncArtifactKind::RateLimitConfig,
        SyncArtifactKind::Blocklist,
    ];
    if config.jwt_validation.is_some() {
        required.push(SyncArtifactKind::Jwks);
    }
    required
}

pub(crate) fn now_ms() -> i64 {
    current_time_millis()
}
