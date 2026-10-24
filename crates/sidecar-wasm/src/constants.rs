use std::time::Duration;

pub(crate) const DEFAULT_RUNTIME_BASE_URL: &str = "http://127.0.0.1:8080";
pub(crate) const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
pub(crate) const DEFAULT_STALE_CACHE_TTL: Duration = Duration::from_secs(300);
pub(crate) const DEFAULT_AUTHZ_CACHE_TTL: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_AUTHZ_STALE_CACHE_TTL: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_AUTHZ_REFRESH_AFTER_PERCENT: u8 = 50;
pub(crate) const DEFAULT_JWT_CLOCK_SKEW_SECONDS: u64 = 0;
#[cfg(target_arch = "wasm32")]
pub(crate) const WASM_REQUEST_TIMEOUT_MILLIS: f64 = 30_000.0;
