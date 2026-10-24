//! Bounded tenant/audience JWT revocation snapshots.
//!
//! Receivers replace a complete snapshot atomically. A stale snapshot can be
//! used only through its configured hard ceiling; an absent or over-ceiling
//! snapshot is deliberately distinguishable so callers can return `503`.

use std::collections::{BTreeSet, HashMap};

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationLookup {
    NotRevoked,
    /// The snapshot is past its refresh interval but still inside the
    /// explicitly bounded stale window. Callers may continue using it while
    /// a refresh is attempted out of band.
    Stale,
    Revoked,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSnapshotState {
    Fresh,
    Stale,
    Expired,
    Missing,
    Uncovered,
}

#[derive(Debug, Clone)]
pub struct RevocationSnapshot {
    audiences: BTreeSet<String>,
    revoked: HashMap<String, i64>,
    fresh_until_ms: i64,
    stale_until_ms: i64,
}

impl RevocationSnapshot {
    pub fn new(
        audiences: impl IntoIterator<Item = String>,
        entries: impl IntoIterator<Item = (String, i64)>,
        received_at_ms: i64,
        fresh_ttl_ms: i64,
        stale_ttl_ms: i64,
    ) -> Self {
        let fresh_ttl_ms = fresh_ttl_ms.max(0);
        let stale_ttl_ms = stale_ttl_ms.max(fresh_ttl_ms);
        Self {
            audiences: audiences.into_iter().collect(),
            revoked: entries.into_iter().collect(),
            fresh_until_ms: received_at_ms.saturating_add(fresh_ttl_ms),
            stale_until_ms: received_at_ms.saturating_add(stale_ttl_ms),
        }
    }

    #[must_use]
    pub fn covers(&self, audiences: &[String]) -> bool {
        !audiences.is_empty()
            && audiences
                .iter()
                .all(|audience| self.audiences.contains(audience))
    }

    #[must_use]
    pub fn state(&self, audiences: &[String], now_ms: i64) -> RevocationSnapshotState {
        if !self.covers(audiences) {
            return RevocationSnapshotState::Uncovered;
        }
        if now_ms <= self.fresh_until_ms {
            RevocationSnapshotState::Fresh
        } else if now_ms <= self.stale_until_ms {
            RevocationSnapshotState::Stale
        } else {
            RevocationSnapshotState::Expired
        }
    }

    /// Decode the strictly bounded runtime-sync representation. The caller
    /// supplies the receipt time so an unchanged artifact can extend its
    /// refresh window without trusting a client-controlled timestamp.
    pub fn from_payload(payload: &Value, received_at_ms: i64) -> Result<Self, &'static str> {
        let payload: RevocationPayload =
            serde_json::from_value(payload.clone()).map_err(|_| "revocation payload invalid")?;
        if payload.audiences.is_empty() || payload.audiences.len() > 32 {
            return Err("revocation audience set is invalid");
        }
        let audience_count = payload.audiences.len();
        let unique_audiences = payload.audiences.iter().collect::<BTreeSet<_>>();
        if unique_audiences.len() != audience_count {
            return Err("revocation audience set contains duplicates");
        }
        if payload.audiences.iter().any(|audience| {
            audience.trim().is_empty()
                || audience.len() > 1_024
                || audience.chars().any(char::is_control)
        }) {
            return Err("revocation audience is invalid");
        }
        if payload.items.len() > 100_000 {
            return Err("revocation item count exceeds the bound");
        }
        let mut entries = HashMap::with_capacity(payload.items.len());
        for item in payload.items {
            if item.jti.trim().is_empty() || item.jti.len() > 512 || item.exp <= 0 {
                return Err("revocation item is invalid");
            }
            entries.insert(item.jti, item.exp);
        }
        let fresh_ttl_ms = payload.fresh_ttl_ms.unwrap_or(10_000).min(60_000);
        let stale_ttl_ms = payload.stale_ttl_ms.unwrap_or(60_000).min(60_000);
        if stale_ttl_ms < fresh_ttl_ms {
            return Err("revocation stale ttl precedes fresh ttl");
        }
        Ok(Self::new(
            payload.audiences,
            entries,
            received_at_ms,
            fresh_ttl_ms as i64,
            stale_ttl_ms as i64,
        ))
    }

    #[must_use]
    pub fn lookup_for_audiences(
        &self,
        audiences: &[String],
        jti: &str,
        now_ms: i64,
    ) -> RevocationLookup {
        let state = self.state(audiences, now_ms);
        if matches!(
            state,
            RevocationSnapshotState::Expired | RevocationSnapshotState::Uncovered
        ) {
            return RevocationLookup::Unavailable;
        }
        if self.revoked.contains_key(jti) {
            return RevocationLookup::Revoked;
        }
        if matches!(state, RevocationSnapshotState::Stale) {
            RevocationLookup::Stale
        } else {
            RevocationLookup::NotRevoked
        }
    }
}

#[derive(Debug, Deserialize)]
struct RevocationPayload {
    audiences: Vec<String>,
    #[serde(default)]
    items: Vec<RevocationItem>,
    #[serde(default)]
    fresh_ttl_ms: Option<u64>,
    #[serde(default)]
    stale_ttl_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RevocationItem {
    jti: String,
    exp: i64,
}

#[cfg(test)]
#[path = "revocation_tests.rs"]
mod revocation_tests;
