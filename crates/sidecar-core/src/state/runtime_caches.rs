use std::{collections::HashMap, hash::Hash, sync::Arc, time::Duration};

use jwt_decode::JwtVerifier;

use crate::{
    auth::{JwtValidationCacheKey, JwtValidationPolicies, JwtValidationResultCacheKey},
    constants::{
        MAX_HOSTED_LOGIN_SESSIONS, MAX_JWT_POLICY_CACHE_ENTRIES,
        MAX_JWT_VALIDATION_RESULT_CACHE_BYTES, MAX_JWT_VALIDATION_RESULT_CACHE_ENTRIES,
        MAX_JWT_VERIFIER_CACHE_ENTRIES,
    },
    state::{
        CachedValue, CachedValueState, HostedLoginSession, JwtVerifierCacheKey, SidecarState,
        current_time_millis,
    },
};

#[derive(Debug, Clone)]
pub(super) struct CachedJwtValidationResult {
    claims: Arc<serde_json::Value>,
    claims_bytes: usize,
    expires_at_ms: i64,
}

impl JwtVerifierCacheKey {
    pub fn from_config(config: &crate::SidecarEngineConfig) -> Self {
        Self {
            base_url: config.base_url.trim_end_matches('/').to_string(),
            tenant_domain: config.tenant_domain.clone(),
        }
    }
}

impl SidecarState {
    pub(crate) fn jwt_validation_result(
        &self,
        key: &JwtValidationResultCacheKey,
        now_ms: i64,
    ) -> Option<serde_json::Value> {
        let claims = self
            .jwt_validation_results
            .read()
            .ok()?
            .get(key)
            .filter(|cached| cached.expires_at_ms > now_ms)
            .map(|cached| Arc::clone(&cached.claims))?;
        Some((*claims).clone())
    }

    pub(crate) fn store_jwt_validation_result(
        &self,
        key: JwtValidationResultCacheKey,
        claims: serde_json::Value,
        cache_ttl: Duration,
    ) {
        let Ok(claims_bytes) = serde_json::to_vec(&claims).map(|encoded| encoded.len()) else {
            return;
        };
        if claims_bytes > MAX_JWT_VALIDATION_RESULT_CACHE_BYTES {
            return;
        }
        let now_ms = current_time_millis();
        let Some(token_expiry_ms) = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .and_then(|seconds| seconds.checked_mul(1_000))
        else {
            return;
        };
        let ttl_ms = i64::try_from(cache_ttl.as_millis()).unwrap_or(i64::MAX);
        let expires_at_ms = token_expiry_ms.min(now_ms.saturating_add(ttl_ms));
        if expires_at_ms <= now_ms {
            return;
        }
        if let Ok(mut guard) = self.jwt_validation_results.write() {
            guard.retain(|_, cached| cached.expires_at_ms > now_ms);
            guard.remove(&key);
            while guard.len() >= MAX_JWT_VALIDATION_RESULT_CACHE_ENTRIES
                || guard
                    .values()
                    .map(|cached| cached.claims_bytes)
                    .sum::<usize>()
                    .saturating_add(claims_bytes)
                    > MAX_JWT_VALIDATION_RESULT_CACHE_BYTES
            {
                let Some(oldest_key) = guard.keys().next().cloned() else {
                    break;
                };
                guard.remove(&oldest_key);
            }
            guard.insert(
                key,
                CachedJwtValidationResult {
                    claims: Arc::new(claims),
                    claims_bytes,
                    expires_at_ms,
                },
            );
        }
    }

    pub fn jwt_verifier(
        &self,
        key: &JwtVerifierCacheKey,
        now_ms: i64,
    ) -> Option<(Arc<JwtVerifier>, CachedValueState)> {
        self.jwt_verifiers
            .read()
            .ok()
            .and_then(|guard| guard.get(key).and_then(|cached| cached.value(now_ms)))
    }

    pub fn store_jwt_verifier(
        &self,
        key: JwtVerifierCacheKey,
        value: Arc<JwtVerifier>,
        fresh_ttl: Duration,
        stale_ttl: Duration,
    ) {
        let now_ms = current_time_millis();
        if let Ok(mut guard) = self.jwt_verifiers.write() {
            prune_expired_and_bound_cache(&mut guard, now_ms, MAX_JWT_VERIFIER_CACHE_ENTRIES);
            guard.insert(key, CachedValue::new(value, fresh_ttl, stale_ttl, now_ms));
        }
    }

    pub fn jwt_validation_policies(
        &self,
        key: &JwtValidationCacheKey,
    ) -> Option<Arc<JwtValidationPolicies>> {
        self.jwt_validation_policies
            .read()
            .ok()
            .and_then(|guard| guard.get(key).map(Arc::clone))
    }

    pub fn store_jwt_validation_policies(
        &self,
        key: JwtValidationCacheKey,
        value: Arc<JwtValidationPolicies>,
    ) {
        if let Ok(mut guard) = self.jwt_validation_policies.write() {
            bound_map(&mut guard, MAX_JWT_POLICY_CACHE_ENTRIES);
            guard.insert(key, value);
        }
    }

    pub fn store_hosted_login_session(&self, session: HostedLoginSession) {
        let now_ms = current_time_millis();
        if let Ok(mut guard) = self.hosted_login_sessions.write() {
            guard.retain(|_, session| session.expires_at_ms >= now_ms);
            bound_map(&mut guard, MAX_HOSTED_LOGIN_SESSIONS);
            guard.insert(session.state.clone(), session);
        }
    }

    pub fn take_hosted_login_session(
        &self,
        state: &str,
        now_ms: i64,
    ) -> Option<HostedLoginSession> {
        let mut guard = self.hosted_login_sessions.write().ok()?;
        guard.retain(|_, session| session.expires_at_ms >= now_ms);
        let session = guard.remove(state)?;
        (session.expires_at_ms >= now_ms).then_some(session)
    }
}

pub(super) fn prune_expired_and_bound_cache<K, V>(
    cache: &mut HashMap<K, CachedValue<V>>,
    now_ms: i64,
    max_entries: usize,
) where
    K: Clone + Eq + Hash,
    V: Clone,
{
    cache.retain(|_, value| !value.is_expired(now_ms));
    bound_map(cache, max_entries);
}

fn bound_map<K, V>(cache: &mut HashMap<K, V>, max_entries: usize)
where K: Clone + Eq + Hash {
    while cache.len() >= max_entries {
        let Some(key) = cache.keys().next().cloned() else {
            return;
        };
        cache.remove(&key);
    }
}
