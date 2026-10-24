use sidecar_contract::{
    RequestContext, RuntimeSyncKnownVersions, RuntimeSyncRequest, SyncArtifactKind,
};

use super::{SidecarEngine, current_time_millis};
use crate::{SidecarResult, SidecarTransport};

impl<T> SidecarEngine<T>
where T: SidecarTransport + 'static
{
    /// Ensure the local revocation snapshot is available before protected
    /// bearer traffic. Refreshes are coalesced and bounded; a stale snapshot
    /// remains usable only through its hard ceiling, while an initial or
    /// expired snapshot fails closed.
    pub async fn ensure_revocation_snapshot(&self, context: &RequestContext) -> SidecarResult<()> {
        let audiences = self
            .config
            .jwt_validation
            .as_ref()
            .and_then(|validation| validation.resource_audiences.clone())
            .filter(|audiences| !audiences.is_empty())
            .ok_or_else(|| {
                crate::SidecarError::service_unavailable(
                    "revocation_audiences_missing",
                    "protected bearer traffic requires configured revocation audiences",
                )
            })?;
        let now_ms = current_time_millis();
        let state = self.state.revocation_snapshot_state(&audiences, now_ms);
        if matches!(state, crate::RevocationSnapshotState::Fresh) {
            return Ok(());
        }
        if self.state.claim_revocation_refresh_attempt(now_ms, 10_000) {
            let request = RuntimeSyncRequest {
                protocol_version: 1,
                known: RuntimeSyncKnownVersions::default(),
                want: vec![SyncArtifactKind::Revocations],
                authz: None,
                entitlements: Vec::new(),
                blocklist_policy_refs: Vec::new(),
                revocation_audiences: audiences.clone(),
            };
            match self.try_sync_runtime(context, request).await {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        state,
                        crate::RevocationSnapshotState::Stale
                            | crate::RevocationSnapshotState::Expired
                    ) && error.code == "runtime_sync_unavailable" =>
                {
                    // A bounded stale snapshot remains usable during a
                    // transient sync outage; the lookup below enforces its
                    // hard maximum.
                }
                Err(error) => return Err(error),
            }
        }
        match self
            .state
            .revocation_snapshot_state(&audiences, current_time_millis())
        {
            crate::RevocationSnapshotState::Fresh | crate::RevocationSnapshotState::Stale => Ok(()),
            crate::RevocationSnapshotState::Expired
            | crate::RevocationSnapshotState::Missing
            | crate::RevocationSnapshotState::Uncovered => {
                Err(crate::SidecarError::service_unavailable(
                    "revocation_snapshot_unavailable",
                    "protected bearer traffic requires a current revocation snapshot",
                ))
            }
        }
    }
}
