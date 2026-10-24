use std::sync::Arc;

use sidecar_contract::{
    AuthzResourceAccessSnapshot, AuthzResourceAccessSnapshotRequest, AuthzSubjectAccessSnapshot,
    AuthzSubjectAccessSnapshotRequest,
};

#[derive(Clone, Copy)]
pub(super) struct EvaluationDataRequest<'a> {
    pub(super) tenant_id: &'a str,
    pub(super) policy_version: u64,
    pub(super) subject: &'a AuthzSubjectAccessSnapshotRequest,
    pub(super) resource: &'a AuthzResourceAccessSnapshotRequest,
}

pub(super) struct OwnedEvaluationDataRequest {
    pub(super) tenant_id: String,
    pub(super) policy_version: u64,
    pub(super) subject: AuthzSubjectAccessSnapshotRequest,
    pub(super) resource: AuthzResourceAccessSnapshotRequest,
}

impl OwnedEvaluationDataRequest {
    pub(super) fn as_borrowed(&self) -> EvaluationDataRequest<'_> {
        EvaluationDataRequest {
            tenant_id: &self.tenant_id,
            policy_version: self.policy_version,
            subject: &self.subject,
            resource: &self.resource,
        }
    }
}

impl From<EvaluationDataRequest<'_>> for OwnedEvaluationDataRequest {
    fn from(request: EvaluationDataRequest<'_>) -> Self {
        Self {
            tenant_id: request.tenant_id.to_string(),
            policy_version: request.policy_version,
            subject: request.subject.clone(),
            resource: request.resource.clone(),
        }
    }
}

pub(super) struct CachedEvaluationData {
    pub(super) subject: Option<Arc<AuthzSubjectAccessSnapshot>>,
    pub(super) resource: Option<Arc<AuthzResourceAccessSnapshot>>,
}
