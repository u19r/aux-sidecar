//! Sidecar-owned AuxFn contract types.

pub mod auth;
pub mod authz;
pub mod blocklist;
mod constants;
pub mod context;
pub mod entitlements;
pub mod error;
pub mod hosted_login;
pub mod metrics;
pub mod policy;
pub mod rate_limit;
mod rate_limit_helpers;
mod rate_limit_lease;
mod serde_bounds;
pub mod sync;

#[cfg(test)]
mod authz_tests;
#[cfg(test)]
mod blocklist_tests;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod entitlements_tests;
#[cfg(test)]
mod hosted_login_tests;
#[cfg(test)]
mod metrics_tests;
#[cfg(test)]
mod performance_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod rate_limit_tests;
#[cfg(test)]
mod sync_tests;

pub use auth::{JwtValidationResult, ValidateAuthnJwtRequest, ValidateOAuthAccessTokenRequest};
pub use authz::{
    ApiAction, ApiEvaluationRequest, ApiEvaluationResponse, ApiResource, ApiResponseContext,
    ApiSubject, AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest,
    AuthzEvaluationResult, AuthzParentRef, AuthzPolicySnapshot, AuthzPolicyVersionSnapshot,
    AuthzResourceAccessSnapshot, AuthzResourceAccessSnapshotRequest, AuthzSubjectAccessSnapshot,
    AuthzSubjectAccessSnapshotRequest, UpstreamAuthzResponse,
};
pub use blocklist::{
    RuntimeBlocklistDecisionRequest, RuntimeBlocklistDecisionResponse, RuntimeBlocklistMatch,
    RuntimeBlocklistPolicyRef,
};
pub use context::{CacheStatus, RequestContext};
pub use entitlements::{
    EntitlementDecision, EntitlementEvaluateRequest, EntitlementEvaluateResponse,
    EntitlementEvaluationResult, EntitlementUsedEntitlement, EntitlementsEvaluationResult,
};
pub use error::{ContractError, ContractResult};
pub use hosted_login::{
    BeginHostedLoginRequest, BeginHostedLoginResult, CompleteHostedLoginRequest,
    CompleteHostedLoginResult, HostedLoginTokenSet, RefreshHostedLoginRequest,
    RefreshHostedLoginResult, TokenResponse,
};
pub use metrics::{
    REGISTRY_PULL_TOTAL, REGISTRY_PUSH_TOTAL, REGISTRY_STORAGE_BYTES_TOTAL,
    RegistryMetricDimensions, RegistryMetricIngestRequest, RegistryPrometheusRollupLabels,
};
pub use policy::{
    RuntimePolicyAction, RuntimePolicyBlocklistContext, RuntimePolicyDecisionRequest,
    RuntimePolicyDecisionResponse, RuntimePolicyMetricAttribution, RuntimePolicyNetwork,
    RuntimePolicyRateLimitContext, RuntimePolicyRateLimitDefaults,
    RuntimePolicyRateLimitDescriptor, RuntimePolicyResource, RuntimePolicySubject,
    RuntimePolicyWindowedLimit,
};
pub use rate_limit::{
    ConfigResult, RateLimitCheckRequest, RateLimitCheckResponse, RateLimitConfig,
    RateLimitConfigResponse, RateLimitNetworkIdentity, RateLimitParameters, RateLimitRoute,
    RateLimitRouteConfig, RegistryRateLimitAction, RegistryRateLimitDefaults,
    RegistryRateLimitRequest,
};
pub use rate_limit_lease::{
    RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseRequestItem, RateLimitAcquireLeaseResponse,
    RateLimitAcquireLeaseResult, RateLimitGiveBackLeaseRequest, RateLimitGiveBackLeaseRequestItem,
    RateLimitGiveBackLeaseResponse, RateLimitGiveBackLeaseResult, RateLimitLease,
};
pub use sync::{
    RuntimeSyncArtifact, RuntimeSyncCapabilities, RuntimeSyncKnownVersions, RuntimeSyncRequest,
    RuntimeSyncResponse, SyncArtifactKind,
};
