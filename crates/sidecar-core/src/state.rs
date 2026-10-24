use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock, atomic::AtomicI64},
    time::Duration,
};

use authz_runtime::EvaluationRuntime;
use jwt_decode::JwtVerifier;
use sidecar_contract::{
    AuthzPolicySnapshot, AuthzPolicyVersionSnapshot, AuthzResourceAccessSnapshot,
    AuthzSubjectAccessSnapshot, RateLimitConfig,
};

use crate::{
    auth::{JwtValidationCacheKey, JwtValidationPolicies, JwtValidationResultCacheKey},
    constants::{MAX_AUTHZ_CACHE_ENTRIES, MAX_AUTHZ_REFRESHES, MAX_ENTITLEMENT_SNAPSHOTS},
    local_blocklist::LocalBlocklistRuntime,
    local_entitlements::LocalEntitlementSnapshot,
    local_rate_limit::SharedLeasePool,
    revocation::RevocationSnapshot,
    windowed_rate_limit::{WindowedRateLimitPool, WindowedRateLimitRequest},
};

mod authorization_sync;
mod authz;
mod cache;
mod hosted_login;
mod immutable_cache;
#[path = "state/revocation.rs"]
mod revocation_state;
mod runtime_caches;
mod sync;
#[cfg(test)]
pub(crate) mod test_support;

use authz::AuthzCacheKind;
pub(crate) use authz::jittered_policy_pointer_refresh_percent;
pub use authz::{
    AuthzCacheMetricCounters, AuthzCacheMetrics, AuthzRefreshKey, AuthzResourceCacheKey,
    AuthzSubjectCacheKey, LocalAuthzShadowMetrics,
};
pub use cache::{AuthzCachedValueState, CachedValue, CachedValueState, current_time_millis};
pub use hosted_login::HostedLoginSession;
use immutable_cache::BoundedLruCache;
use runtime_caches::prune_expired_and_bound_cache;
use sync::{ActiveSyncFlights, CachedBlocklistRuntime, CachedEntitlementSnapshot};
pub use sync::{RuntimeSyncSnapshot, SyncFlightFuture};

pub struct SidecarState {
    started_at_ms: i64,
    rate_limit_config: RwLock<Option<CachedValue<RateLimitConfig>>>,
    authz_policy_version: RwLock<Option<CachedValue<AuthzPolicyVersionSnapshot>>>,
    authz_policy_snapshots: RwLock<BoundedLruCache<u64, Arc<AuthzPolicySnapshot>>>,
    authz_evaluation_runtimes: RwLock<BoundedLruCache<u64, Arc<EvaluationRuntime>>>,
    authz_subject_access:
        RwLock<HashMap<AuthzSubjectCacheKey, CachedValue<Arc<AuthzSubjectAccessSnapshot>>>>,
    authz_resource_access:
        RwLock<HashMap<AuthzResourceCacheKey, CachedValue<Arc<AuthzResourceAccessSnapshot>>>>,
    authz_refreshes: RwLock<HashSet<AuthzRefreshKey>>,
    authz_shadow_metrics: RwLock<LocalAuthzShadowMetrics>,
    authz_cache_metrics: RwLock<AuthzCacheMetrics>,
    jwt_verifiers: RwLock<HashMap<JwtVerifierCacheKey, CachedValue<Arc<JwtVerifier>>>>,
    jwt_validation_policies: RwLock<HashMap<JwtValidationCacheKey, Arc<JwtValidationPolicies>>>,
    jwt_validation_results:
        RwLock<HashMap<JwtValidationResultCacheKey, runtime_caches::CachedJwtValidationResult>>,
    revocation_snapshot: RwLock<Option<Arc<RevocationSnapshot>>>,
    revocation_required_audiences: RwLock<Option<Vec<String>>>,
    revocation_last_refresh_attempt_ms: AtomicI64,
    hosted_login_sessions: RwLock<HashMap<String, HostedLoginSession>>,
    runtime_sync: RwLock<RuntimeSyncSnapshot>,
    sync_flight: std::sync::Mutex<ActiveSyncFlights>,
    next_sync_flight_id: std::sync::atomic::AtomicU64,
    blocklist_runtime: RwLock<Option<CachedBlocklistRuntime>>,
    entitlement_snapshots: RwLock<HashMap<String, CachedEntitlementSnapshot>>,
    windowed_rate_limits: RwLock<WindowedRateLimitPool>,
    lease_pool: SharedLeasePool,
}

impl std::fmt::Debug for SidecarState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarState").finish_non_exhaustive()
    }
}

impl SidecarState {
    pub fn new() -> Self {
        Self {
            started_at_ms: crate::status::now_ms(),
            rate_limit_config: RwLock::new(None),
            authz_policy_version: RwLock::new(None),
            authz_policy_snapshots: RwLock::new(BoundedLruCache::new(
                crate::constants::MAX_AUTHZ_POLICY_SNAPSHOTS,
            )),
            authz_evaluation_runtimes: RwLock::new(BoundedLruCache::new(
                crate::constants::MAX_AUTHZ_EVALUATION_RUNTIMES,
            )),
            authz_subject_access: RwLock::new(HashMap::new()),
            authz_resource_access: RwLock::new(HashMap::new()),
            authz_refreshes: RwLock::new(HashSet::new()),
            authz_shadow_metrics: RwLock::new(LocalAuthzShadowMetrics::default()),
            authz_cache_metrics: RwLock::new(AuthzCacheMetrics::default()),
            jwt_verifiers: RwLock::new(HashMap::new()),
            jwt_validation_policies: RwLock::new(HashMap::new()),
            jwt_validation_results: RwLock::new(HashMap::new()),
            revocation_snapshot: RwLock::new(None),
            revocation_required_audiences: RwLock::new(None),
            revocation_last_refresh_attempt_ms: AtomicI64::new(i64::MIN),
            hosted_login_sessions: RwLock::new(HashMap::new()),
            runtime_sync: RwLock::new(RuntimeSyncSnapshot::default()),
            sync_flight: std::sync::Mutex::new(Vec::new()),
            next_sync_flight_id: std::sync::atomic::AtomicU64::new(1),
            blocklist_runtime: RwLock::new(None),
            entitlement_snapshots: RwLock::new(HashMap::new()),
            windowed_rate_limits: RwLock::new(WindowedRateLimitPool::default()),
            lease_pool: crate::local_rate_limit::new_pool(),
        }
    }

    pub(crate) fn uptime_ms(&self) -> u64 {
        crate::status::now_ms()
            .saturating_sub(self.started_at_ms)
            .try_into()
            .unwrap_or_default()
    }

    pub(crate) fn lease_pool_metrics(&self) -> crate::local_rate_limit::LeasePoolMetrics {
        self.lease_pool.metrics()
    }

    pub fn local_blocklist_runtime(
        &self,
        etag: &str,
        now_ms: i64,
        stale_ttl: Duration,
    ) -> Option<(Arc<LocalBlocklistRuntime>, CachedValueState)> {
        self.blocklist_runtime.read().ok().and_then(|guard| {
            let cached = guard.as_ref()?;
            if cached.etag != etag {
                return None;
            }
            let fresh_until = cached
                .received_at_ms
                .saturating_add(i64::try_from(cached.max_age_ms).unwrap_or(i64::MAX));
            if now_ms <= fresh_until {
                return Some((Arc::clone(&cached.runtime), CachedValueState::Fresh));
            }
            let stale_ms = i64::try_from(stale_ttl.as_millis()).unwrap_or(i64::MAX);
            (now_ms <= fresh_until.saturating_add(stale_ms))
                .then(|| (Arc::clone(&cached.runtime), CachedValueState::Stale))
        })
    }

    pub fn store_local_blocklist_runtime(
        &self,
        etag: String,
        runtime: Arc<LocalBlocklistRuntime>,
        received_at_ms: i64,
        max_age_ms: u64,
    ) {
        if let Ok(mut guard) = self.blocklist_runtime.write() {
            *guard = Some(CachedBlocklistRuntime {
                etag,
                runtime,
                received_at_ms,
                max_age_ms,
            });
        }
    }

    pub fn local_entitlement_snapshot(
        &self,
        org_id: &str,
        etag: &str,
        now_ms: i64,
    ) -> Option<Arc<LocalEntitlementSnapshot>> {
        self.entitlement_snapshots.read().ok().and_then(|guard| {
            let cached = guard.get(org_id)?;
            (cached.etag == etag && cached.snapshot.is_valid(now_ms))
                .then(|| Arc::clone(&cached.snapshot))
        })
    }

    pub fn store_local_entitlement_snapshot(
        &self,
        org_id: String,
        etag: String,
        snapshot: Arc<LocalEntitlementSnapshot>,
    ) {
        if let Ok(mut guard) = self.entitlement_snapshots.write() {
            if guard.len() >= MAX_ENTITLEMENT_SNAPSHOTS
                && let Some(key) = guard.keys().next().cloned()
            {
                guard.remove(&key);
            }
            guard.insert(org_id, CachedEntitlementSnapshot { etag, snapshot });
        }
    }

    pub(crate) fn lease_pool(&self) -> SharedLeasePool {
        Arc::clone(&self.lease_pool)
    }

    pub(crate) fn check_windowed_rate_limits(
        &self,
        requests: &[WindowedRateLimitRequest],
    ) -> Vec<sidecar_contract::RateLimitCheckResponse> {
        self.windowed_rate_limits
            .write()
            .map(|mut pool| pool.check_many(requests, current_time_millis()))
            .unwrap_or_else(|_| {
                requests
                    .iter()
                    .map(|_| sidecar_contract::RateLimitCheckResponse {
                        allowed: false,
                        remaining_tokens: 0,
                        retry_after_ms: Some(1_000),
                    })
                    .collect()
            })
    }

    pub fn rate_limit_config(&self, now_ms: i64) -> Option<(RateLimitConfig, CachedValueState)> {
        self.rate_limit_config
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|cached| cached.value(now_ms)))
    }

    pub fn store_rate_limit_config(
        &self,
        value: RateLimitConfig,
        fresh_ttl: Duration,
        stale_ttl: Duration,
    ) {
        let now_ms = current_time_millis();
        if let Ok(mut guard) = self.rate_limit_config.write() {
            *guard = Some(CachedValue::new(value, fresh_ttl, stale_ttl, now_ms));
        }
    }

    pub fn authz_policy_version(
        &self,
        now_ms: i64,
    ) -> Option<(AuthzPolicyVersionSnapshot, AuthzCachedValueState)> {
        let result = self
            .authz_policy_version
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|cached| cached.authz_value(now_ms)));
        self.record_authz_cache_lookup(AuthzCacheKind::Pointer, result.is_some());
        result
    }

    pub fn store_authz_policy_version(
        &self,
        value: AuthzPolicyVersionSnapshot,
        fresh_ttl: Duration,
        stale_ttl: Duration,
        refresh_after_percent: u8,
    ) {
        let now_ms = current_time_millis();
        let refresh_after_percent = jittered_policy_pointer_refresh_percent(refresh_after_percent);
        if let Ok(mut guard) = self.authz_policy_version.write() {
            *guard = Some(CachedValue::new_with_refresh_after(
                value,
                fresh_ttl,
                stale_ttl,
                refresh_after_percent,
                now_ms,
            ));
        }
    }

    pub fn authz_policy_snapshot(
        &self,
        version: u64,
        _now_ms: i64,
    ) -> Option<(Arc<AuthzPolicySnapshot>, AuthzCachedValueState)> {
        let result = self
            .authz_policy_snapshots
            .write()
            .ok()
            .and_then(|mut guard| guard.get(&version))
            .map(|snapshot| (snapshot, AuthzCachedValueState::Fresh));
        self.record_authz_cache_lookup(AuthzCacheKind::Policy, result.is_some());
        result
    }

    pub fn store_authz_policy_snapshot(&self, value: impl Into<Arc<AuthzPolicySnapshot>>) {
        let value = value.into();
        if let Ok(mut guard) = self.authz_policy_snapshots.write()
            && guard.insert(value.policy_version, value)
        {
            self.record_authz_cache_evictions(AuthzCacheKind::Policy, 1);
        }
    }

    pub fn authz_evaluation_runtime(
        &self,
        version: u64,
        _now_ms: i64,
    ) -> Option<(Arc<EvaluationRuntime>, AuthzCachedValueState)> {
        let result = self
            .authz_evaluation_runtimes
            .write()
            .ok()
            .and_then(|mut guard| guard.get(&version))
            .map(|runtime| (runtime, AuthzCachedValueState::Fresh));
        self.record_authz_cache_lookup(AuthzCacheKind::Runtime, result.is_some());
        result
    }

    pub fn store_authz_evaluation_runtime(&self, version: u64, value: Arc<EvaluationRuntime>) {
        if let Ok(mut guard) = self.authz_evaluation_runtimes.write()
            && guard.insert(version, value)
        {
            self.record_authz_cache_evictions(AuthzCacheKind::Runtime, 1);
        }
    }

    pub fn authz_subject_access(
        &self,
        key: &AuthzSubjectCacheKey,
        now_ms: i64,
    ) -> Option<(Arc<AuthzSubjectAccessSnapshot>, AuthzCachedValueState)> {
        let result = self
            .authz_subject_access
            .read()
            .ok()
            .and_then(|guard| guard.get(key).and_then(|cached| cached.authz_value(now_ms)));
        self.record_authz_cache_lookup(AuthzCacheKind::Subject, result.is_some());
        result
    }

    pub fn store_authz_subject_access(
        &self,
        key: AuthzSubjectCacheKey,
        value: impl Into<Arc<AuthzSubjectAccessSnapshot>>,
        fresh_ttl: Duration,
        stale_ttl: Duration,
        refresh_after_percent: u8,
    ) {
        let now_ms = current_time_millis();
        let value = value.into();
        if let Ok(mut guard) = self.authz_subject_access.write() {
            let before = guard.len();
            prune_expired_and_bound_cache(&mut guard, now_ms, MAX_AUTHZ_CACHE_ENTRIES);
            self.record_authz_cache_evictions(
                AuthzCacheKind::Subject,
                before.saturating_sub(guard.len()) as u64,
            );
            guard.insert(
                key,
                CachedValue::new_with_refresh_after(
                    value,
                    fresh_ttl,
                    stale_ttl,
                    refresh_after_percent,
                    now_ms,
                ),
            );
        }
    }

    pub fn authz_resource_access(
        &self,
        key: &AuthzResourceCacheKey,
        now_ms: i64,
    ) -> Option<(Arc<AuthzResourceAccessSnapshot>, AuthzCachedValueState)> {
        let result = self
            .authz_resource_access
            .read()
            .ok()
            .and_then(|guard| guard.get(key).and_then(|cached| cached.authz_value(now_ms)));
        self.record_authz_cache_lookup(AuthzCacheKind::Resource, result.is_some());
        result
    }

    pub fn store_authz_resource_access(
        &self,
        key: AuthzResourceCacheKey,
        value: impl Into<Arc<AuthzResourceAccessSnapshot>>,
        fresh_ttl: Duration,
        stale_ttl: Duration,
        refresh_after_percent: u8,
    ) {
        let now_ms = current_time_millis();
        let value = value.into();
        if let Ok(mut guard) = self.authz_resource_access.write() {
            let before = guard.len();
            prune_expired_and_bound_cache(&mut guard, now_ms, MAX_AUTHZ_CACHE_ENTRIES);
            self.record_authz_cache_evictions(
                AuthzCacheKind::Resource,
                before.saturating_sub(guard.len()) as u64,
            );
            guard.insert(
                key,
                CachedValue::new_with_refresh_after(
                    value,
                    fresh_ttl,
                    stale_ttl,
                    refresh_after_percent,
                    now_ms,
                ),
            );
        }
    }

    pub fn try_begin_authz_refresh(&self, key: AuthzRefreshKey) -> bool {
        self.authz_refreshes
            .write()
            .map(|mut guard| {
                if guard.contains(&key) {
                    return false;
                }
                if guard.len() >= MAX_AUTHZ_REFRESHES {
                    return false;
                }
                guard.insert(key)
            })
            .unwrap_or(false)
    }

    pub fn finish_authz_refresh(&self, key: &AuthzRefreshKey) {
        if let Ok(mut guard) = self.authz_refreshes.write() {
            guard.remove(key);
        }
    }

    pub fn authz_cache_metrics(&self) -> AuthzCacheMetrics {
        self.authz_cache_metrics
            .read()
            .map(|metrics| *metrics)
            .unwrap_or_default()
    }

    fn record_authz_cache_lookup(&self, kind: AuthzCacheKind, hit: bool) {
        let Ok(mut metrics) = self.authz_cache_metrics.write() else {
            return;
        };
        let counters = kind.counters(&mut metrics);
        if hit {
            counters.hits = counters.hits.saturating_add(1);
        } else {
            counters.misses = counters.misses.saturating_add(1);
        }
    }

    fn record_authz_cache_evictions(&self, kind: AuthzCacheKind, count: u64) {
        if count == 0 {
            return;
        }
        if let Ok(mut metrics) = self.authz_cache_metrics.write() {
            let counters = kind.counters(&mut metrics);
            counters.evictions = counters.evictions.saturating_add(count);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JwtVerifierCacheKey {
    base_url: String,
    tenant_domain: Option<String>,
}
