//! Shared sidecar runtime crate.

pub mod auth;
pub mod config;
mod constants;
pub mod engine;
mod engine_hosted_login;
mod engine_jwt;
pub mod error;
pub mod hosted_login;
pub mod local_authz;
pub mod local_blocklist;
pub mod local_entitlements;
mod local_policy;
mod local_rate_limit;
pub mod revocation;
pub mod route_policy;
mod runtime_sync;
pub mod state;
mod status;
pub mod transport;
mod windowed_rate_limit;

#[cfg(test)]
mod artifact_compile_performance_tests;
#[cfg(test)]
mod authorization_sync_tests;
#[cfg(test)]
mod engine_additional_tests;
#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod local_authz_cache_performance_tests;
#[cfg(test)]
mod local_authz_conversion_performance_tests;
#[cfg(test)]
mod local_authz_performance_tests;
#[cfg(test)]
mod local_authz_tests;
#[cfg(test)]
mod local_blocklist_tests;
#[cfg(test)]
mod local_entitlements_tests;
#[cfg(test)]
mod local_rate_limit_tests;
#[cfg(test)]
mod performance_candidate_tests;
#[cfg(test)]
mod performance_support_tests;
#[cfg(test)]
mod performance_tests;
#[cfg(test)]
mod revocation_performance_tests;
#[cfg(test)]
mod runtime_sync_performance_tests;
#[cfg(test)]
mod runtime_sync_state_performance_tests;
#[cfg(test)]
mod runtime_sync_test_support;
#[cfg(test)]
mod runtime_sync_tests;
#[cfg(test)]
mod runtime_sync_transport_tests;
#[cfg(test)]
mod state_additional_tests;
#[cfg(test)]
mod state_cache_performance_tests;
#[cfg(test)]
mod state_jwt_tests;
#[cfg(test)]
mod state_sync_tests;
#[cfg(test)]
pub(crate) mod state_tests;
#[cfg(test)]
mod status_tests;
#[cfg(test)]
mod windowed_rate_limit_tests;

pub use config::{
    DeploymentPreset, JwtValidationConfig, LocalAuthzMode, LocalAuthzRemoteFallback,
    MAX_JWT_CLAIMS_BYTES, MAX_JWT_TOKEN_BYTES, MAX_RESOURCE_AUDIENCE_BYTES, MAX_RESOURCE_AUDIENCES,
    SidecarEngineConfig,
};
pub use engine::SidecarEngine;
pub use error::{LocalAuthzFallbackReason, SidecarError, SidecarResult};
pub use revocation::{RevocationLookup, RevocationSnapshot, RevocationSnapshotState};
pub use route_policy::{CompiledRoutePolicy, RouteMatch, RoutePolicyError};
pub use state::{
    AuthzCacheMetricCounters, AuthzCacheMetrics, AuthzCachedValueState, AuthzRefreshKey,
    AuthzResourceCacheKey, AuthzSubjectCacheKey, CachedValue, CachedValueState, HostedLoginSession,
    LocalAuthzShadowMetrics, SidecarState, current_time_millis,
};
pub use status::{CapabilityStatus, LiveStatus, OperationalStatus, ReadyStatus};
pub use transport::{SidecarFuture, SidecarTransport};

#[cfg(test)]
mod dpop_tests;
