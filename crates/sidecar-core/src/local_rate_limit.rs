use std::{
    collections::HashMap,
    sync::{Arc, Mutex as SyncMutex, Weak},
};

use futures::lock::Mutex;
use sidecar_contract::{
    RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseRequestItem, RateLimitCheckRequest,
    RateLimitCheckResponse, RateLimitParameters, RequestContext,
};

use crate::{
    SidecarEngineConfig, SidecarError, SidecarResult, SidecarTransport,
    constants::{LOCAL_LEASE_REFILL_MAX_TOKENS, MAX_LEASE_ITEMS_PER_KEY, MAX_LEASE_POOL_KEYS},
    state::current_time_millis,
};

pub(crate) type SharedLeasePool = Arc<SharedLeasePoolState>;

#[derive(Debug, Default)]
pub(crate) struct SharedLeasePoolState {
    pool: Mutex<LeasePool>,
    key_locks: SyncMutex<HashMap<LeasePoolKey, Weak<Mutex<()>>>>,
    global_key_lock: Arc<Mutex<()>>,
}

pub(crate) fn new_pool() -> SharedLeasePool {
    Arc::new(SharedLeasePoolState::default())
}

pub(crate) async fn check<T>(
    pool: SharedLeasePool,
    config: &SidecarEngineConfig,
    transport: &Arc<T>,
    context: &RequestContext,
    request: &RateLimitCheckRequest,
) -> SidecarResult<RateLimitCheckResponse>
where
    T: SidecarTransport + 'static,
{
    request.validate()?;
    let pool_key = LeasePoolKey {
        params: request.params.clone(),
        key: request.key.clone(),
    };
    let now_ms = current_time_millis();
    if let Some(remaining_tokens) = pool
        .pool
        .lock()
        .await
        .consume(&pool_key, request.cost, now_ms)
    {
        return Ok(allowed(remaining_tokens));
    }

    let key_lock = pool.key_lock(&pool_key);
    let _key_guard = key_lock.lock().await;
    let now_ms = current_time_millis();
    if let Some(remaining_tokens) = pool
        .pool
        .lock()
        .await
        .consume(&pool_key, request.cost, now_ms)
    {
        return Ok(allowed(remaining_tokens));
    }

    let requested_tokens = request
        .params
        .max_burst_tokens()
        .min(LOCAL_LEASE_REFILL_MAX_TOKENS)
        .max(u64::from(request.cost));
    let requested_tokens = u32::try_from(requested_tokens).map_err(|_| {
        SidecarError::bad_request(
            "rate_limit_request_invalid",
            "local lease refill exceeds the supported token count",
        )
    })?;
    let acquire_request = RateLimitAcquireLeaseRequest {
        params: request.params.clone(),
        leases: vec![RateLimitAcquireLeaseRequestItem {
            key: request.key.clone(),
            requested_tokens,
            min_grant_tokens: request.cost,
        }],
    };
    let response = transport
        .acquire_leases(config, context, &acquire_request)
        .await?;
    response.validate_for_request(&acquire_request)?;
    let result = response
        .results
        .into_iter()
        .find(|result| result.key == request.key)
        .ok_or_else(|| {
            SidecarError::bad_gateway(
                "rate_limit_lease_response_invalid",
                "lease response omitted the requested key",
            )
        })?;
    let retry_after_ms = result.retry_after_ms;
    let mut leases = pool.pool.lock().await;
    if let Some(lease) = result.lease {
        if lease.key != request.key || lease.expires_at_ms <= now_ms {
            return Err(SidecarError::bad_gateway(
                "rate_limit_lease_response_invalid",
                "lease response contained an invalid lease",
            ));
        }
        if lease.granted_tokens > requested_tokens {
            return Err(SidecarError::bad_gateway(
                "rate_limit_lease_response_invalid",
                "lease response granted more tokens than requested",
            ));
        }
        let expires_at_ms = bounded_lease_expiry(
            lease.expires_at_ms,
            now_ms,
            request.params.lease_duration_ms,
        );
        leases.insert(
            &pool_key,
            lease.lease_id,
            lease.granted_tokens,
            expires_at_ms,
        );
        if let Some(remaining_tokens) = leases.consume(&pool_key, request.cost, now_ms) {
            return Ok(allowed(remaining_tokens));
        }
    }
    Ok(RateLimitCheckResponse {
        allowed: false,
        remaining_tokens: leases.remaining(&pool_key, now_ms),
        retry_after_ms,
    })
}

impl SharedLeasePoolState {
    fn key_lock(&self, key: &LeasePoolKey) -> Arc<Mutex<()>> {
        let mut locks = match self.key_locks.lock() {
            Ok(locks) => locks,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        if locks.len() >= MAX_LEASE_POOL_KEYS {
            locks.retain(|_, lock| lock.strong_count() > 0);
            if locks.len() >= MAX_LEASE_POOL_KEYS {
                return Arc::clone(&self.global_key_lock);
            }
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    pub(crate) fn metrics(&self) -> LeasePoolMetrics {
        self.pool
            .try_lock()
            .map(|pool| pool.metrics())
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[path = "local_rate_limit_internal_tests.rs"]
mod local_rate_limit_internal_tests;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LeasePoolKey {
    pub(crate) params: RateLimitParameters,
    pub(crate) key: String,
}

#[derive(Debug, Clone)]
struct LeaseItem {
    lease_id: String,
    remaining_tokens: u64,
    expires_at_ms: i64,
}

#[derive(Debug, Default)]
pub(crate) struct LeasePool {
    items: HashMap<LeasePoolKey, LeasePoolEntry>,
    access_clock: u64,
    granted_tokens: u64,
    consumed_tokens: u64,
    duplicate_responses: u64,
}

#[derive(Debug, Default)]
struct LeasePoolEntry {
    items: Vec<LeaseItem>,
    last_used: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LeasePoolMetrics {
    pub(crate) pool_count: usize,
    pub(crate) item_count: usize,
    pub(crate) granted_tokens: u64,
    pub(crate) consumed_tokens: u64,
    pub(crate) duplicate_responses: u64,
}

impl LeasePool {
    pub(crate) fn consume(&mut self, key: &LeasePoolKey, cost: u32, now_ms: i64) -> Option<u64> {
        self.access_clock = self.access_clock.saturating_add(1);
        let entry = self.items.get_mut(key)?;
        entry
            .items
            .retain(|item| item.expires_at_ms > now_ms && item.remaining_tokens > 0);
        entry.last_used = self.access_clock;
        let available = entry
            .items
            .iter()
            .fold(0_u64, |sum, item| sum.saturating_add(item.remaining_tokens));
        if available < u64::from(cost) {
            return None;
        }
        let mut needed = u64::from(cost);
        for item in &mut entry.items {
            let consumed = needed.min(item.remaining_tokens);
            item.remaining_tokens -= consumed;
            needed -= consumed;
            if needed == 0 {
                break;
            }
        }
        self.consumed_tokens = self.consumed_tokens.saturating_add(u64::from(cost));
        Some(available - u64::from(cost))
    }

    pub(crate) fn insert(
        &mut self,
        key: &LeasePoolKey,
        lease_id: String,
        granted_tokens: u32,
        expires_at_ms: i64,
    ) {
        if self.items.len() >= MAX_LEASE_POOL_KEYS
            && !self.items.contains_key(key)
            && let Some(expired_key) = self.least_recently_used_key()
        {
            self.items.remove(&expired_key);
        }
        self.access_clock = self.access_clock.saturating_add(1);
        let entry = self.items.entry(key.clone()).or_default();
        entry.last_used = self.access_clock;
        let items = &mut entry.items;
        if items.iter().any(|item| item.lease_id == lease_id) {
            self.duplicate_responses = self.duplicate_responses.saturating_add(1);
            return;
        }
        if items.len() >= MAX_LEASE_ITEMS_PER_KEY
            && let Some((index, _)) = items
                .iter()
                .enumerate()
                .min_by_key(|(_, item)| item.expires_at_ms)
        {
            items.remove(index);
        }
        items.push(LeaseItem {
            lease_id,
            remaining_tokens: u64::from(granted_tokens),
            expires_at_ms,
        });
        self.granted_tokens = self
            .granted_tokens
            .saturating_add(u64::from(granted_tokens));
    }

    pub(crate) fn remaining(&mut self, key: &LeasePoolKey, now_ms: i64) -> u64 {
        self.access_clock = self.access_clock.saturating_add(1);
        self.items.get_mut(key).map_or(0, |entry| {
            entry
                .items
                .retain(|item| item.expires_at_ms > now_ms && item.remaining_tokens > 0);
            entry.last_used = self.access_clock;
            entry
                .items
                .iter()
                .fold(0_u64, |sum, item| sum.saturating_add(item.remaining_tokens))
        })
    }

    fn least_recently_used_key(&self) -> Option<LeasePoolKey> {
        self.items
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
    }

    pub(crate) fn metrics(&self) -> LeasePoolMetrics {
        LeasePoolMetrics {
            pool_count: self.items.len(),
            item_count: self.items.values().map(|entry| entry.items.len()).sum(),
            granted_tokens: self.granted_tokens,
            consumed_tokens: self.consumed_tokens,
            duplicate_responses: self.duplicate_responses,
        }
    }
}

fn allowed(remaining_tokens: u64) -> RateLimitCheckResponse {
    RateLimitCheckResponse {
        allowed: true,
        remaining_tokens,
        retry_after_ms: None,
    }
}

pub(crate) fn bounded_lease_expiry(
    server_expiry_ms: i64,
    acquired_at_ms: i64,
    lease_duration_ms: u32,
) -> i64 {
    server_expiry_ms.min(acquired_at_ms.saturating_add(i64::from(lease_duration_ms)))
}
