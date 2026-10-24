use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use futures::future::Shared;
use sidecar_contract::{
    RuntimeSyncArtifact, RuntimeSyncCapabilities, RuntimeSyncKnownVersions, RuntimeSyncResponse,
    SyncArtifactKind,
};

use super::authorization_sync::AuthorizationInvalidations;
use crate::{
    SidecarError, SidecarResult, SidecarState,
    constants::{
        MAX_ACTIVE_SYNC_FLIGHTS, MAX_RUNTIME_SYNC_ARTIFACT_BYTES, MAX_RUNTIME_SYNC_ARTIFACTS,
    },
};

#[cfg(not(target_arch = "wasm32"))]
pub type SyncFlightFuture = Shared<
    Pin<Box<dyn Future<Output = SidecarResult<Option<RuntimeSyncResponse>>> + Send + 'static>>,
>;

#[cfg(target_arch = "wasm32")]
pub type SyncFlightFuture =
    Shared<Pin<Box<dyn Future<Output = SidecarResult<Option<RuntimeSyncResponse>>> + 'static>>>;

pub type SyncFlightKey = (Arc<sidecar_contract::RuntimeSyncRequest>, bool);
pub type ActiveSyncFlights = Vec<(SyncFlightKey, u64, SyncFlightFuture)>;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuntimeSyncSnapshot {
    pub generation: u64,
    pub server_time: String,
    pub refresh_after_ms: u64,
    artifacts: BTreeMap<SyncArtifactKind, Arc<BTreeMap<String, StoredRuntimeSyncArtifact>>>,
    refreshed_at_ms: BTreeMap<SyncArtifactKind, i64>,
    pub ignored_optional_artifacts: u64,
    pub capabilities: RuntimeSyncCapabilities,
}

#[derive(Debug, Clone, PartialEq)]
struct StoredRuntimeSyncArtifact {
    artifact: Arc<RuntimeSyncArtifact>,
    received_at_ms: i64,
    payload_bytes: usize,
}

#[derive(Debug, Clone)]
pub(super) struct CachedBlocklistRuntime {
    pub(super) etag: String,
    pub(super) runtime: std::sync::Arc<crate::local_blocklist::LocalBlocklistRuntime>,
    pub(super) received_at_ms: i64,
    pub(super) max_age_ms: u64,
}

#[derive(Debug, Clone)]
pub(super) struct CachedEntitlementSnapshot {
    pub(super) etag: String,
    pub(super) snapshot: std::sync::Arc<crate::local_entitlements::LocalEntitlementSnapshot>,
}

impl RuntimeSyncSnapshot {
    pub(crate) fn artifact_count(&self) -> usize {
        self.artifacts
            .values()
            .map(|artifacts| artifacts.len())
            .sum()
    }

    pub(crate) fn kind_state(
        &self,
        kind: &SyncArtifactKind,
        now_ms: i64,
        stale_ms: i64,
    ) -> &'static str {
        let mut found = false;
        let mut stale = false;
        let Some(artifacts) = self.artifacts.get(kind) else {
            return "missing";
        };
        for stored in artifacts.values() {
            found = true;
            if stored.artifact.immutable {
                return "fresh";
            }
            let max_age_ms = stored.artifact.max_age_ms.unwrap_or_default();
            let received_at_ms = self.effective_received_at(kind, stored.received_at_ms);
            let fresh_until =
                received_at_ms.saturating_add(i64::try_from(max_age_ms).unwrap_or(i64::MAX));
            if now_ms <= fresh_until {
                return "fresh";
            }
            if now_ms <= fresh_until.saturating_add(stale_ms) {
                stale = true;
            }
        }
        if stale {
            "stale"
        } else if found {
            "expired"
        } else {
            "missing"
        }
    }

    pub fn from_response(
        current: Option<&Self>,
        response: RuntimeSyncResponse,
    ) -> SidecarResult<Self> {
        if let Some(current) = current
            && !current.server_time.is_empty()
            && server_time(&response.server_time)? < server_time(&current.server_time)?
        {
            return Err(SidecarError::bad_gateway(
                "runtime_sync_out_of_order",
                "runtime sync response predates visible state",
            ));
        }
        let mut artifacts = current
            .map(|snapshot| snapshot.artifacts.clone())
            .unwrap_or_default();
        let mut ignored_optional_artifacts = current
            .map(|snapshot| snapshot.ignored_optional_artifacts)
            .unwrap_or_default();
        let mut refreshed_at_ms = current
            .map(|snapshot| snapshot.refreshed_at_ms.clone())
            .unwrap_or_default();
        let received_at_ms = crate::state::current_time_millis();
        for kind in &response.unchanged {
            if artifacts.contains_key(kind) {
                refreshed_at_ms.insert(kind.clone(), received_at_ms);
            }
        }
        let capabilities = response.capabilities;
        for artifact in response.artifacts {
            if !artifact.kind.is_known() {
                ignored_optional_artifacts = ignored_optional_artifacts.saturating_add(1);
                continue;
            }
            let kind = artifact.kind.clone();
            let key = artifact.key.clone();
            if artifact.immutable
                && artifacts
                    .get(&kind)
                    .and_then(|stored_artifacts| stored_artifacts.get(&key))
                    .is_some_and(|existing| existing.artifact.etag != artifact.etag)
            {
                return Err(SidecarError::bad_gateway(
                    "runtime_sync_immutable_conflict",
                    "an immutable runtime artifact changed under the same identity",
                ));
            }
            Arc::make_mut(artifacts.entry(kind).or_default()).insert(
                key,
                StoredRuntimeSyncArtifact {
                    payload_bytes: serde_json::to_vec(&artifact.payload)
                        .map_err(|_| {
                            SidecarError::bad_gateway(
                                "runtime_sync_artifact_invalid",
                                "runtime sync artifact payload could not be measured",
                            )
                        })?
                        .len(),
                    artifact: Arc::new(artifact),
                    received_at_ms,
                },
            );
        }
        prune_artifacts(&mut artifacts);
        Ok(Self {
            generation: current
                .map(|snapshot| snapshot.generation)
                .unwrap_or_default()
                .saturating_add(1),
            server_time: response.server_time,
            refresh_after_ms: response.refresh_after_ms,
            artifacts,
            refreshed_at_ms,
            ignored_optional_artifacts,
            capabilities,
        })
    }

    pub fn known_versions(&self) -> RuntimeSyncKnownVersions {
        let mut known = RuntimeSyncKnownVersions::default();
        for (kind, stored_artifacts) in &self.artifacts {
            for (key, stored) in stored_artifacts.iter() {
                let artifact = &stored.artifact;
                match kind {
                    SyncArtifactKind::Jwks => known.jwks = Some(artifact.version.clone()),
                    SyncArtifactKind::AuthzPolicy => {
                        known.authz_policy = Some(artifact.version.clone());
                    }
                    SyncArtifactKind::RateLimitConfig => {
                        known.rate_limit_config = Some(artifact.version.clone());
                    }
                    SyncArtifactKind::Blocklist => {
                        known.blocklist = Some(artifact.version.clone());
                    }
                    SyncArtifactKind::Revocations => {
                        known.revocations = Some(artifact.version.clone());
                    }
                    SyncArtifactKind::Entitlements => {
                        known
                            .entitlements
                            .insert(key.clone(), artifact.version.clone());
                    }
                    SyncArtifactKind::AuthzEvaluationData | SyncArtifactKind::Unknown(_) => {}
                }
            }
        }
        known
    }

    pub(crate) fn known_versions_for(
        &self,
        request: &sidecar_contract::RuntimeSyncRequest,
    ) -> RuntimeSyncKnownVersions {
        let mut known = RuntimeSyncKnownVersions::default();
        let wants = |kind: &SyncArtifactKind| request.want.contains(kind);
        if wants(&SyncArtifactKind::Jwks) {
            known.jwks = self.version(&SyncArtifactKind::Jwks, "tenant");
        }
        if wants(&SyncArtifactKind::AuthzPolicy) {
            known.authz_policy = self.version(&SyncArtifactKind::AuthzPolicy, "tenant");
        }
        if wants(&SyncArtifactKind::RateLimitConfig) {
            known.rate_limit_config = self.version(&SyncArtifactKind::RateLimitConfig, "tenant");
        }
        if wants(&SyncArtifactKind::Blocklist) {
            known.blocklist = self.version(&SyncArtifactKind::Blocklist, "tenant");
        }
        if wants(&SyncArtifactKind::Revocations) {
            known.revocations = self.version(&SyncArtifactKind::Revocations, "tenant");
        }
        if wants(&SyncArtifactKind::Entitlements)
            && let Some(artifacts) = self.artifacts.get(&SyncArtifactKind::Entitlements)
        {
            for entitlement in &request.entitlements {
                if let Some(stored) = artifacts.get(&entitlement.org_id) {
                    known
                        .entitlements
                        .insert(entitlement.org_id.clone(), stored.artifact.version.clone());
                }
            }
        }
        known
    }

    fn version(&self, kind: &SyncArtifactKind, key: &str) -> Option<String> {
        self.artifacts
            .get(kind)
            .and_then(|artifacts| artifacts.get(key))
            .map(|stored| stored.artifact.version.clone())
    }

    fn effective_received_at(&self, kind: &SyncArtifactKind, stored_at_ms: i64) -> i64 {
        self.refreshed_at_ms
            .get(kind)
            .copied()
            .unwrap_or_default()
            .max(stored_at_ms)
    }

    pub(super) fn artifact(
        &self,
        kind: &SyncArtifactKind,
        key: &str,
    ) -> Option<(RuntimeSyncArtifact, i64)> {
        self.artifacts
            .get(kind)
            .and_then(|stored_artifacts| stored_artifacts.get(key))
            .map(|stored| {
                (
                    (*stored.artifact).clone(),
                    self.effective_received_at(kind, stored.received_at_ms),
                )
            })
    }

    pub(super) fn shared_artifact(
        &self,
        kind: &SyncArtifactKind,
        key: &str,
    ) -> Option<(Arc<RuntimeSyncArtifact>, i64)> {
        self.artifacts
            .get(kind)
            .and_then(|stored_artifacts| stored_artifacts.get(key))
            .map(|stored| {
                (
                    Arc::clone(&stored.artifact),
                    self.effective_received_at(kind, stored.received_at_ms),
                )
            })
    }
}

fn prune_artifacts(
    artifacts: &mut BTreeMap<SyncArtifactKind, Arc<BTreeMap<String, StoredRuntimeSyncArtifact>>>,
) {
    while !artifacts.is_empty()
        && (artifact_count(artifacts) > MAX_RUNTIME_SYNC_ARTIFACTS
            || artifact_bytes(artifacts) > MAX_RUNTIME_SYNC_ARTIFACT_BYTES)
    {
        let Some((kind, key)) = artifacts
            .iter()
            .flat_map(|(kind, stored_artifacts)| {
                stored_artifacts
                    .iter()
                    .map(move |(key, stored)| (kind, key, stored))
            })
            .min_by_key(|(_, _, stored)| stored.received_at_ms)
            .map(|(kind, key, _)| (kind.clone(), key.clone()))
        else {
            break;
        };
        if let Some(stored_artifacts) = artifacts.get_mut(&kind) {
            Arc::make_mut(stored_artifacts).remove(&key);
            if stored_artifacts.is_empty() {
                artifacts.remove(&kind);
            }
        }
    }
}

fn artifact_count(
    artifacts: &BTreeMap<SyncArtifactKind, Arc<BTreeMap<String, StoredRuntimeSyncArtifact>>>,
) -> usize {
    artifacts.values().map(|stored| stored.len()).sum()
}

fn artifact_bytes(
    artifacts: &BTreeMap<SyncArtifactKind, Arc<BTreeMap<String, StoredRuntimeSyncArtifact>>>,
) -> usize {
    artifacts
        .values()
        .flat_map(|stored| stored.values())
        .map(|stored| stored.payload_bytes)
        .sum()
}

impl SidecarState {
    pub fn apply_runtime_sync(&self, response: RuntimeSyncResponse) -> SidecarResult<()> {
        response.validate()?;
        let invalidations = AuthorizationInvalidations::prepare(&response)?;
        let mut guard = self.runtime_sync.write().map_err(|_| {
            SidecarError::internal(
                "runtime_sync_state_unavailable",
                "runtime sync state lock is unavailable",
            )
        })?;
        let next = RuntimeSyncSnapshot::from_response(Some(&guard), response)?;
        if let Some((artifact, _)) = next.artifact(&SyncArtifactKind::Revocations, "tenant") {
            self.store_revocation_snapshot_from_payload(
                &artifact.payload,
                crate::state::current_time_millis(),
            )?;
        }
        *guard = next;
        invalidations.apply(self);
        Ok(())
    }

    pub fn runtime_sync_snapshot(&self) -> RuntimeSyncSnapshot {
        self.runtime_sync
            .read()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub fn runtime_sync_known_versions(&self) -> RuntimeSyncKnownVersions {
        self.runtime_sync
            .read()
            .map(|snapshot| snapshot.known_versions())
            .unwrap_or_default()
    }

    pub(crate) fn runtime_sync_known_versions_for(
        &self,
        request: &sidecar_contract::RuntimeSyncRequest,
    ) -> RuntimeSyncKnownVersions {
        self.runtime_sync
            .read()
            .map(|snapshot| snapshot.known_versions_for(request))
            .unwrap_or_default()
    }

    pub fn runtime_sync_artifact(
        &self,
        kind: SyncArtifactKind,
        key: &str,
    ) -> Option<RuntimeSyncArtifact> {
        self.runtime_sync
            .read()
            .ok()?
            .artifact(&kind, key)
            .map(|(artifact, _)| artifact)
    }

    pub fn runtime_sync_artifact_with_age(
        &self,
        kind: SyncArtifactKind,
        key: &str,
    ) -> Option<(RuntimeSyncArtifact, i64)> {
        self.runtime_sync.read().ok()?.artifact(&kind, key)
    }

    pub(crate) fn shared_runtime_sync_artifact(
        &self,
        kind: SyncArtifactKind,
        key: &str,
    ) -> Option<Arc<RuntimeSyncArtifact>> {
        self.runtime_sync
            .read()
            .ok()?
            .shared_artifact(&kind, key)
            .map(|(artifact, _)| artifact)
    }

    pub(crate) fn shared_runtime_sync_artifact_with_age(
        &self,
        kind: SyncArtifactKind,
        key: &str,
    ) -> Option<(Arc<RuntimeSyncArtifact>, i64)> {
        self.runtime_sync.read().ok()?.shared_artifact(&kind, key)
    }

    pub fn sync_flight(
        &self,
        key: SyncFlightKey,
        create: impl FnOnce() -> SyncFlightFuture,
    ) -> (u64, SyncFlightFuture) {
        if let Ok(mut guard) = self.sync_flight.lock() {
            if let Some((_, id, future)) =
                guard.iter().find(|(active_key, _, _)| active_key == &key)
            {
                return (*id, future.clone());
            }
            let id = self
                .next_sync_flight_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let future = create();
            if guard.len() < MAX_ACTIVE_SYNC_FLIGHTS {
                guard.push((key, id, future.clone()));
            } else {
                return (0, future);
            }
            return (id, future);
        }
        (0, create())
    }

    pub fn finish_sync_flight(&self, id: u64) {
        if let Ok(mut guard) = self.sync_flight.lock() {
            guard.retain(|(_, active_id, _)| *active_id != id);
        }
    }

    #[cfg(test)]
    pub(crate) fn active_sync_flight_count(&self) -> usize {
        self.sync_flight
            .lock()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }
}

fn server_time(value: &str) -> SidecarResult<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
        SidecarError::bad_gateway(
            "runtime_sync_response_invalid",
            "runtime sync server time is invalid",
        )
    })
}
