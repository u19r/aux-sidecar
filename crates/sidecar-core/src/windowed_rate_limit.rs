use std::collections::HashMap;

use sidecar_contract::RateLimitCheckResponse;

pub(crate) const MAX_WINDOWED_RATE_LIMIT_KEYS: usize = 4_096;

#[derive(Debug, Clone)]
pub(crate) struct WindowedRateLimitRequest {
    pub(crate) key: String,
    pub(crate) limit: u32,
    pub(crate) window_seconds: u32,
    pub(crate) cost: u32,
}

#[derive(Debug, Default)]
pub(crate) struct WindowedRateLimitPool {
    entries: HashMap<String, WindowedRateLimitEntry>,
    access_clock: u64,
}

#[derive(Debug)]
struct WindowedRateLimitEntry {
    limit: u32,
    window_seconds: u32,
    window_started_at_ms: i64,
    consumed: u32,
    last_used: u64,
}

impl WindowedRateLimitPool {
    pub(crate) fn check_many(
        &mut self,
        requests: &[WindowedRateLimitRequest],
        now_ms: i64,
    ) -> Vec<RateLimitCheckResponse> {
        requests
            .iter()
            .map(|request| self.check(request, now_ms))
            .collect()
    }

    fn check(&mut self, request: &WindowedRateLimitRequest, now_ms: i64) -> RateLimitCheckResponse {
        self.access_clock = self.access_clock.saturating_add(1);
        let now_ms = now_ms.max(0);
        let window_ms = i64::from(request.window_seconds).saturating_mul(1_000);
        let window_started_at_ms = now_ms / window_ms * window_ms;
        if !self.entries.contains_key(&request.key)
            && self.entries.len() >= MAX_WINDOWED_RATE_LIMIT_KEYS
            && let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&key);
        }

        let entry =
            self.entries
                .entry(request.key.clone())
                .or_insert_with(|| WindowedRateLimitEntry {
                    limit: request.limit,
                    window_seconds: request.window_seconds,
                    window_started_at_ms,
                    consumed: 0,
                    last_used: self.access_clock,
                });
        if entry.limit != request.limit
            || entry.window_seconds != request.window_seconds
            || entry.window_started_at_ms != window_started_at_ms
        {
            entry.limit = request.limit;
            entry.window_seconds = request.window_seconds;
            entry.window_started_at_ms = window_started_at_ms;
            entry.consumed = 0;
        }
        entry.last_used = self.access_clock;

        let remaining = request.limit.saturating_sub(entry.consumed);
        if request.cost <= remaining {
            entry.consumed = entry.consumed.saturating_add(request.cost);
            return RateLimitCheckResponse {
                allowed: true,
                remaining_tokens: u64::from(remaining.saturating_sub(request.cost)),
                retry_after_ms: None,
            };
        }

        let next_window_ms = window_started_at_ms.saturating_add(window_ms);
        RateLimitCheckResponse {
            allowed: false,
            remaining_tokens: u64::from(remaining),
            retry_after_ms: Some(next_window_ms.saturating_sub(now_ms) as u64),
        }
    }
}
