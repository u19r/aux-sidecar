use std::sync::Arc;

use sidecar_contract::RateLimitParameters;

use super::{LeasePoolKey, SharedLeasePoolState};
use crate::constants::MAX_LEASE_POOL_KEYS;

fn key_named(key: String) -> LeasePoolKey {
    LeasePoolKey {
        params: RateLimitParameters {
            limit_per_second: 10,
            burst: 10,
            lease_duration_ms: 1_000,
            estimated_nodes: 1,
            giveback_grace_ms: 100,
        },
        key,
    }
}

#[test]
fn key_lock_registry_falls_back_when_all_key_locks_are_active() {
    let state = SharedLeasePoolState::default();
    let active_locks = (0..MAX_LEASE_POOL_KEYS)
        .map(|index| state.key_lock(&key_named(format!("active-{index}"))))
        .collect::<Vec<_>>();

    let overflow_lock = state.key_lock(&key_named("overflow".to_string()));

    assert!(Arc::ptr_eq(&overflow_lock, &state.global_key_lock));
    assert_eq!(
        state
            .key_locks
            .lock()
            .expect("lock registry is not poisoned")
            .len(),
        MAX_LEASE_POOL_KEYS
    );
    drop(active_locks);
}
