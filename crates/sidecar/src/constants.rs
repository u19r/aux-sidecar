pub(crate) const TRACEPARENT: &str = "traceparent";
pub(crate) const TRACESTATE: &str = "tracestate";
pub(crate) const X_FORWARDED_FOR: &str = "x-forwarded-for";
pub(crate) const X_REAL_IP: &str = "x-real-ip";
pub(crate) const X_PROXY_ADAPTER: &str = "x-proxy-adapter";
pub(crate) const X_AUX_PROXY_STATUS: &str = "x-aux-proxy-status";

pub(crate) const TRACEPARENT_PARTS: usize = 4;
pub(crate) const TRACEPARENT_VERSION_LEN: usize = 2;
pub(crate) const TRACEPARENT_TRACE_ID_LEN: usize = 32;
pub(crate) const TRACEPARENT_PARENT_ID_LEN: usize = 16;
pub(crate) const TRACEPARENT_FLAGS_LEN: usize = 2;
pub(crate) const TRACEPARENT_FORBIDDEN_VERSION: &str = "ff";
pub(crate) const TRACEPARENT_ZERO_PARENT_ID: &str = "0000000000000000";
pub(crate) const TRACEPARENT_ZERO_TRACE_ID: &str = "00000000000000000000000000000000";
pub(crate) const TRACESTATE_MAX_LEN: usize = 512;
pub(crate) const MAX_UPSTREAM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const UPSTREAM_REQUEST_TIMEOUT_SECONDS: u64 = 30;

#[cfg(test)]
pub(crate) const TEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;
