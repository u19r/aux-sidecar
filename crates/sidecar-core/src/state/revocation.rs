use std::sync::{Arc, atomic::Ordering};

use super::SidecarState;
use crate::revocation::{RevocationLookup, RevocationSnapshot, RevocationSnapshotState};

impl SidecarState {
    pub fn revocation_lookup_for_audiences(
        &self,
        audiences: &[String],
        jti: &str,
        now_ms: i64,
    ) -> RevocationLookup {
        self.revocation_snapshot
            .read()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .map(|snapshot| snapshot.lookup_for_audiences(audiences, jti, now_ms))
            })
            .unwrap_or(RevocationLookup::Unavailable)
    }

    pub fn revocation_snapshot_state(
        &self,
        audiences: &[String],
        now_ms: i64,
    ) -> RevocationSnapshotState {
        self.revocation_snapshot
            .read()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .map(|snapshot| snapshot.state(audiences, now_ms))
            })
            .unwrap_or(RevocationSnapshotState::Missing)
    }

    pub fn mark_revocation_required(&self, audiences: Vec<String>) {
        if let Ok(mut guard) = self.revocation_required_audiences.write() {
            *guard = Some(audiences);
        }
    }

    pub fn revocation_required_audiences(&self) -> Option<Vec<String>> {
        self.revocation_required_audiences
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Limit refresh attempts to one per interval so stale traffic does not
    /// turn an upstream outage into a per-request feed storm.
    pub fn claim_revocation_refresh_attempt(&self, now_ms: i64, interval_ms: i64) -> bool {
        let previous = self
            .revocation_last_refresh_attempt_ms
            .load(Ordering::Relaxed);
        if now_ms.saturating_sub(previous) < interval_ms {
            return false;
        }
        self.revocation_last_refresh_attempt_ms
            .compare_exchange(previous, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    pub fn store_revocation_snapshot(&self, snapshot: RevocationSnapshot) {
        if let Ok(mut guard) = self.revocation_snapshot.write() {
            *guard = Some(Arc::new(snapshot));
        }
    }

    pub fn store_revocation_snapshot_from_payload(
        &self,
        payload: &serde_json::Value,
        received_at_ms: i64,
    ) -> Result<(), crate::SidecarError> {
        let snapshot =
            RevocationSnapshot::from_payload(payload, received_at_ms).map_err(|message| {
                crate::SidecarError::bad_gateway("runtime_sync_revocations_invalid", message)
            })?;
        if let Some(audiences) = self.revocation_required_audiences()
            && !snapshot.covers(&audiences)
        {
            return Err(crate::SidecarError::bad_gateway(
                "runtime_sync_revocations_incomplete",
                "runtime revocation snapshot does not cover configured audiences",
            ));
        }
        self.store_revocation_snapshot(snapshot);
        Ok(())
    }
}
