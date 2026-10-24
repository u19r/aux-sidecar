use std::time::Duration;

use crate::constants::{
    MAX_AUTHZ_REFRESH_AFTER_PERCENT, MIN_AUTHZ_REFRESH_AFTER_PERCENT, PERCENT_SCALE,
};

#[derive(Debug, Clone)]
pub struct CachedValue<T> {
    value: T,
    refresh_after_ms: i64,
    fresh_until_ms: i64,
    stale_until_ms: i64,
}

impl<T> CachedValue<T>
where T: Clone
{
    pub fn new(value: T, fresh_ttl: Duration, stale_ttl: Duration, now_ms: i64) -> Self {
        let fresh_until_ms = now_ms.saturating_add(duration_millis(fresh_ttl));
        let stale_until_ms = fresh_until_ms.saturating_add(duration_millis(stale_ttl));
        Self {
            value,
            refresh_after_ms: fresh_until_ms,
            fresh_until_ms,
            stale_until_ms,
        }
    }

    pub fn new_with_refresh_after(
        value: T,
        fresh_ttl: Duration,
        stale_ttl: Duration,
        refresh_after_percent: u8,
        now_ms: i64,
    ) -> Self {
        let fresh_ms = duration_millis(fresh_ttl);
        let refresh_after_ms = now_ms.saturating_add(percent_millis(
            fresh_ms,
            refresh_after_percent.clamp(
                MIN_AUTHZ_REFRESH_AFTER_PERCENT,
                MAX_AUTHZ_REFRESH_AFTER_PERCENT,
            ),
        ));
        let fresh_until_ms = now_ms.saturating_add(fresh_ms);
        let stale_until_ms = fresh_until_ms.saturating_add(duration_millis(stale_ttl));
        Self {
            value,
            refresh_after_ms,
            fresh_until_ms,
            stale_until_ms,
        }
    }

    pub fn value(&self, now_ms: i64) -> Option<(T, CachedValueState)> {
        if now_ms <= self.fresh_until_ms {
            return Some((self.value.clone(), CachedValueState::Fresh));
        }
        if now_ms <= self.stale_until_ms {
            return Some((self.value.clone(), CachedValueState::Stale));
        }
        None
    }

    pub fn authz_value(&self, now_ms: i64) -> Option<(T, AuthzCachedValueState)> {
        if now_ms <= self.refresh_after_ms {
            return Some((self.value.clone(), AuthzCachedValueState::Fresh));
        }
        if now_ms <= self.fresh_until_ms {
            return Some((self.value.clone(), AuthzCachedValueState::RefreshDue));
        }
        if now_ms <= self.stale_until_ms {
            return Some((self.value.clone(), AuthzCachedValueState::Stale));
        }
        None
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms > self.stale_until_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedValueState {
    Fresh,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzCachedValueState {
    Fresh,
    RefreshDue,
    Stale,
}

pub fn current_time_millis() -> i64 {
    #[cfg(test)]
    if let Some(now) = super::test_support::find_fixed_time() {
        return now;
    }
    current_time_millis_impl()
}

#[cfg(target_arch = "wasm32")]
fn current_time_millis_impl() -> i64 {
    js_sys::Date::now() as i64
}

#[cfg(not(target_arch = "wasm32"))]
fn current_time_millis_impl() -> i64 {
    use std::{sync::OnceLock, time::Instant};

    static BASE_TIME: OnceLock<(Instant, i64)> = OnceLock::new();
    let (base_instant, base_ms) = BASE_TIME.get_or_init(|| (Instant::now(), system_time_millis()));
    base_ms.saturating_add(duration_millis(base_instant.elapsed()))
}

#[cfg(not(target_arch = "wasm32"))]
fn system_time_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration_millis(duration),
        Err(_) => 0,
    }
}

fn duration_millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn percent_millis(duration_ms: i64, percent: u8) -> i64 {
    duration_ms.saturating_mul(i64::from(percent)) / PERCENT_SCALE
}
