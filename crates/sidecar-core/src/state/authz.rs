use sidecar_contract::{AuthzResourceAccessSnapshotRequest, AuthzSubjectAccessSnapshotRequest};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthzSubjectCacheKey {
    tenant_id: String,
    policy_version: u64,
    subject_type: String,
    id: String,
    include_principal_id: bool,
}

impl AuthzSubjectCacheKey {
    pub fn new(
        tenant_id: String,
        policy_version: u64,
        subject_type: String,
        id: String,
        include_principal_id: bool,
    ) -> Self {
        Self {
            tenant_id,
            policy_version,
            subject_type,
            id,
            include_principal_id,
        }
    }

    pub fn from_request(
        tenant_id: String,
        version: u64,
        value: &AuthzSubjectAccessSnapshotRequest,
    ) -> Self {
        Self::new(
            tenant_id,
            version,
            value.subject_type.clone(),
            value.id.clone(),
            value.include_principal_id,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthzResourceCacheKey {
    tenant_id: String,
    policy_version: u64,
    resource_type: String,
    id: String,
}

impl AuthzResourceCacheKey {
    pub fn new(tenant_id: String, policy_version: u64, resource_type: String, id: String) -> Self {
        Self {
            tenant_id,
            policy_version,
            resource_type,
            id,
        }
    }

    pub fn from_request(
        tenant_id: String,
        version: u64,
        value: &AuthzResourceAccessSnapshotRequest,
    ) -> Self {
        Self::new(
            tenant_id,
            version,
            value.resource_type.clone(),
            value.id.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthzRefreshKey {
    PolicyVersion,
    Subject(AuthzSubjectCacheKey),
    Resource(AuthzResourceCacheKey),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalAuthzShadowMetrics {
    pub attempts: u64,
    pub matches: u64,
    pub mismatches: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthzCacheMetricCounters {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthzCacheMetrics {
    pub pointer: AuthzCacheMetricCounters,
    pub policy: AuthzCacheMetricCounters,
    pub runtime: AuthzCacheMetricCounters,
    pub subject: AuthzCacheMetricCounters,
    pub resource: AuthzCacheMetricCounters,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AuthzCacheKind {
    Pointer,
    Policy,
    Runtime,
    Subject,
    Resource,
}

impl AuthzCacheKind {
    pub(crate) fn counters(self, metrics: &mut AuthzCacheMetrics) -> &mut AuthzCacheMetricCounters {
        match self {
            Self::Pointer => &mut metrics.pointer,
            Self::Policy => &mut metrics.policy,
            Self::Runtime => &mut metrics.runtime,
            Self::Subject => &mut metrics.subject,
            Self::Resource => &mut metrics.resource,
        }
    }
}

pub(crate) fn jittered_policy_pointer_refresh_percent(configured: u8) -> u8 {
    const MAX_JITTER_PERCENTAGE_POINTS: i16 = 10;
    let jitter = rand::random_range(-MAX_JITTER_PERCENTAGE_POINTS..=MAX_JITTER_PERCENTAGE_POINTS);
    i16::from(configured).saturating_add(jitter).clamp(
        i16::from(crate::constants::MIN_AUTHZ_REFRESH_AFTER_PERCENT),
        i16::from(crate::constants::MAX_AUTHZ_REFRESH_AFTER_PERCENT),
    ) as u8
}

impl Default for crate::SidecarState {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::SidecarState {
    pub fn authz_shadow_metrics(&self) -> LocalAuthzShadowMetrics {
        self.authz_shadow_metrics
            .read()
            .map(|guard| *guard)
            .unwrap_or_default()
    }

    pub fn record_authz_shadow_match(&self) {
        if let Ok(mut guard) = self.authz_shadow_metrics.write() {
            guard.attempts = guard.attempts.saturating_add(1);
            guard.matches = guard.matches.saturating_add(1);
        }
    }

    pub fn record_authz_shadow_mismatch(&self) {
        if let Ok(mut guard) = self.authz_shadow_metrics.write() {
            guard.attempts = guard.attempts.saturating_add(1);
            guard.mismatches = guard.mismatches.saturating_add(1);
        }
    }

    pub fn record_authz_shadow_error(&self) {
        if let Ok(mut guard) = self.authz_shadow_metrics.write() {
            guard.attempts = guard.attempts.saturating_add(1);
            guard.errors = guard.errors.saturating_add(1);
        }
    }
}
