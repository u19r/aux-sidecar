use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use sidecar_contract::{
    ApiAction, ApiEvaluationRequest, ApiEvaluationResponse, ApiResource, ApiSubject,
    AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest, AuthzPolicySnapshot,
    AuthzPolicyVersionSnapshot, AuthzResourceAccessSnapshot, AuthzSubjectAccessSnapshot,
    RequestContext, UpstreamAuthzResponse,
};

mod fixture;

use fixture::AuthzFixture;

use crate::{
    JwtValidationConfig, LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngineConfig,
    SidecarFuture, SidecarTransport,
};

pub(super) const TENANT_ID: &str = "tenant_123";
pub(super) const POLICY_VERSION: u64 = 42;
const SUBJECT_ID: &str = "user_123";
const RESOURCE_TYPE: &str = "document";
const RESOURCE_ID: &str = "doc_123";
const ROLE_ID: &str = "viewer";

#[derive(Debug, Clone)]
pub(crate) struct SnapshotTransport {
    fixture: Arc<AuthzFixture>,
    counts: Arc<SnapshotCounts>,
    revoked: Arc<AtomicBool>,
    fault: SnapshotFault,
    evaluation_requests: Arc<Mutex<Vec<AuthzEvaluationDataSnapshotRequest>>>,
}

impl SnapshotTransport {
    pub(crate) fn new() -> Self {
        Self {
            fixture: Arc::new(AuthzFixture::new()),
            counts: Arc::new(SnapshotCounts::default()),
            revoked: Arc::new(AtomicBool::new(false)),
            fault: SnapshotFault::None,
            evaluation_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(super) fn failing_policy_snapshot() -> Self {
        Self::with_fault(SnapshotFault::PolicySnapshotUnavailable)
    }

    pub(super) fn with_fault(fault: SnapshotFault) -> Self {
        Self {
            fault,
            ..Self::new()
        }
    }

    pub(super) fn revoke_subject_access(&self) {
        self.revoked.store(true, Ordering::Relaxed);
    }

    pub(super) fn remote_count(&self) -> usize {
        self.counts.remote.load(Ordering::Relaxed)
    }

    pub(super) fn policy_version_count(&self) -> usize {
        self.counts.policy_version.load(Ordering::Relaxed)
    }

    pub(super) fn policy_snapshot_count(&self) -> usize {
        self.counts.policy_snapshot.load(Ordering::Relaxed)
    }

    pub(crate) fn evaluation_data_count(&self) -> usize {
        self.counts.evaluation_data.load(Ordering::Relaxed)
    }

    pub(super) fn evaluation_requests(&self) -> Vec<AuthzEvaluationDataSnapshotRequest> {
        self.evaluation_requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }

    pub(crate) fn subject_snapshot(&self) -> AuthzSubjectAccessSnapshot {
        self.fixture.evaluation_data.subjects[0].clone()
    }

    pub(crate) fn resource_snapshot(&self) -> AuthzResourceAccessSnapshot {
        self.fixture.evaluation_data.resources[0].clone()
    }
}

#[derive(Debug, Default)]
struct SnapshotCounts {
    remote: AtomicUsize,
    policy_version: AtomicUsize,
    policy_snapshot: AtomicUsize,
    evaluation_data: AtomicUsize,
}

impl SidecarTransport for SnapshotTransport {
    fn acquire_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitAcquireLeaseResponse> {
        unimplemented_future()
    }

    fn give_back_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitGiveBackLeaseResponse> {
        unimplemented_future()
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitConfig> {
        unimplemented_future()
    }

    fn decide_blocklist<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimeBlocklistDecisionResponse> {
        unimplemented_future()
    }

    fn decide_policy<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimePolicyDecisionResponse> {
        unimplemented_future()
    }

    fn evaluate_authz<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a ApiEvaluationRequest,
    ) -> SidecarFuture<'a, UpstreamAuthzResponse> {
        self.counts.remote.fetch_add(1, Ordering::Relaxed);
        let response = ApiEvaluationResponse {
            decision: false,
            challenge: None,
            context: None,
        };
        Box::pin(async move {
            Ok(UpstreamAuthzResponse {
                status_code: 200,
                response,
                www_authenticate: None,
            })
        })
    }

    fn load_authz_policy_version<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, AuthzPolicyVersionSnapshot> {
        self.counts.policy_version.fetch_add(1, Ordering::Relaxed);
        let snapshot = self.fixture.policy_version.clone();
        Box::pin(async move { Ok(snapshot) })
    }

    fn load_authz_policy_snapshot<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        version: Option<u64>,
    ) -> SidecarFuture<'a, AuthzPolicySnapshot> {
        self.counts.policy_snapshot.fetch_add(1, Ordering::Relaxed);
        assert_eq!(version, Some(POLICY_VERSION));
        if self.fault == SnapshotFault::PolicySnapshotUnavailable {
            return Box::pin(async {
                Err(crate::SidecarError::bad_gateway(
                    "authz_policy_snapshot_unavailable",
                    "policy snapshot unavailable",
                ))
            });
        }
        let mut snapshot = self.fixture.policy_snapshot.clone();
        if self.fault == SnapshotFault::PolicySnapshotVersionMismatch {
            snapshot.policy_version = snapshot.policy_version.saturating_add(1);
        }
        Box::pin(async move { Ok(snapshot) })
    }

    fn load_authz_evaluation_data<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        request: &'a AuthzEvaluationDataSnapshotRequest,
    ) -> SidecarFuture<'a, AuthzEvaluationDataSnapshot> {
        self.counts.evaluation_data.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request.policy_version, POLICY_VERSION);
        assert!(request.subjects.len() <= 1);
        assert!(request.resources.len() <= 1);
        assert!(!request.subjects.is_empty() || !request.resources.is_empty());
        if let Ok(mut requests) = self.evaluation_requests.lock() {
            requests.push(request.clone());
        }
        let mut snapshot = if self.revoked.load(Ordering::Relaxed) {
            self.fixture.revoked_evaluation_data.clone()
        } else {
            self.fixture.evaluation_data.clone()
        };
        match self.fault {
            SnapshotFault::SubjectMissing => snapshot.subjects.clear(),
            SnapshotFault::ResourceMissing => snapshot.resources.clear(),
            SnapshotFault::InvalidSubjectAssignment => {
                if let Some(subject) = snapshot.subjects.first_mut() {
                    subject.assignments = vec![serde_json::json!({
                        "role_id": 42,
                    })];
                }
            }
            SnapshotFault::EvaluationDataTenantMismatch => {
                snapshot.tenant_id = "tenant_other".to_string();
            }
            SnapshotFault::EvaluationDataChildTenantMismatch => {
                if let Some(subject) = snapshot.subjects.first_mut() {
                    subject.tenant_id = "tenant_other".to_string();
                }
            }
            SnapshotFault::None
            | SnapshotFault::PolicySnapshotUnavailable
            | SnapshotFault::PolicySnapshotVersionMismatch => {}
        }
        if request.subjects.is_empty() {
            snapshot.subjects.clear();
        }
        if request.resources.is_empty() {
            snapshot.resources.clear();
        }
        Box::pin(async move { Ok(snapshot) })
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, sidecar_contract::EntitlementEvaluateResponse> {
        unimplemented_future()
    }

    fn fetch_jwks<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        unimplemented_future()
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unimplemented_future()
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unimplemented_future()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnapshotFault {
    None,
    PolicySnapshotUnavailable,
    PolicySnapshotVersionMismatch,
    SubjectMissing,
    ResourceMissing,
    InvalidSubjectAssignment,
    EvaluationDataTenantMismatch,
    EvaluationDataChildTenantMismatch,
}

pub(crate) fn evaluation_request() -> ApiEvaluationRequest {
    ApiEvaluationRequest {
        subject: ApiSubject {
            subject_type: "user".to_string(),
            id: SUBJECT_ID.to_string(),
            properties: None,
        },
        resource: ApiResource {
            resource_type: RESOURCE_TYPE.to_string(),
            id: RESOURCE_ID.to_string(),
            properties: None,
        },
        action: ApiAction {
            name: "read".to_string(),
            properties: None,
        },
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    }
}

pub(crate) fn config(mode: LocalAuthzMode) -> SidecarEngineConfig {
    config_with_fallback(mode, LocalAuthzRemoteFallback::CacheMiss)
}

pub(super) fn config_with_fallback(
    mode: LocalAuthzMode,
    fallback: LocalAuthzRemoteFallback,
) -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: crate::DeploymentPreset::Embedded,
        base_url: "http://127.0.0.1:3000".to_string(),
        api_key: "key".to_string(),
        tenant_domain: None,
        cache_ttl: Duration::from_secs(60),
        stale_cache_ttl: Duration::from_secs(300),
        authz_local_mode: mode,
        authz_cache_ttl: Duration::from_secs(10),
        authz_stale_cache_ttl: Duration::from_secs(30),
        authz_refresh_after_percent: 50,
        authz_remote_fallback: fallback,
        jwt_validation: Some(JwtValidationConfig {
            issuer: sidecar_fixtures::jwt::issuer().to_string(),
            login_redirect_url: None,
            resource_audiences: Some(vec![sidecar_fixtures::jwt::audience().to_string()]),
            audience_check_disabled: false,
            clock_skew_seconds: 0,
        }),
    }
}

fn unimplemented_future<'a, T>() -> SidecarFuture<'a, T> {
    Box::pin(async {
        Err(crate::SidecarError::internal(
            "not_implemented",
            "test stub",
        ))
    })
}
