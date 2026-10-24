use serde::de::DeserializeOwned;
use sidecar_contract::{
    AuthzEvaluationDataSnapshot, AuthzPolicySnapshot, RuntimeSyncArtifact, RuntimeSyncResponse,
    SyncArtifactKind,
};

use super::{AuthzResourceCacheKey, AuthzSubjectCacheKey, SidecarState};
use crate::{SidecarError, SidecarResult};

/// The wire-artifact cache and the local evaluator's derived views must agree.
pub(super) struct AuthorizationInvalidations {
    policy: bool,
    subjects: Vec<AuthzSubjectCacheKey>,
    resources: Vec<AuthzResourceCacheKey>,
}

impl AuthorizationInvalidations {
    pub(super) fn prepare(response: &RuntimeSyncResponse) -> SidecarResult<Self> {
        let mut invalidations = Self {
            policy: false,
            subjects: Vec::new(),
            resources: Vec::new(),
        };
        for artifact in &response.artifacts {
            match artifact.kind {
                SyncArtifactKind::AuthzPolicy => {
                    let _: AuthzPolicySnapshot = decode_artifact(artifact)?;
                    invalidations.policy = true;
                }
                SyncArtifactKind::AuthzEvaluationData => {
                    invalidations.include_data(decode_artifact(artifact)?)?
                }
                _ => {}
            }
        }
        Ok(invalidations)
    }

    fn include_data(&mut self, data: AuthzEvaluationDataSnapshot) -> SidecarResult<()> {
        if data
            .subjects
            .iter()
            .any(|subject| subject.tenant_id != data.tenant_id)
            || data
                .resources
                .iter()
                .any(|resource| resource.tenant_id != data.tenant_id)
        {
            return Err(SidecarError::bad_gateway(
                "runtime_sync_artifact_invalid",
                "authorization snapshots do not belong to the artifact account",
            ));
        }
        for subject in data.subjects {
            // Responses do not retain include_principal_id; retire both derived
            // projections.
            for include_principal_id in [false, true] {
                self.subjects.push(AuthzSubjectCacheKey::new(
                    data.tenant_id.clone(),
                    data.policy_version,
                    subject.subject.subject_type.clone(),
                    subject.subject.id.clone(),
                    include_principal_id,
                ));
            }
        }
        for resource in data.resources {
            self.resources.push(AuthzResourceCacheKey::new(
                data.tenant_id.clone(),
                data.policy_version,
                resource.resource_type,
                resource.resource_id,
            ));
        }
        Ok(())
    }

    pub(super) fn apply(self, state: &SidecarState) {
        if self.policy
            && let Ok(mut policy) = state.authz_policy_version.write()
        {
            *policy = None;
        }
        if let Ok(mut subjects) = state.authz_subject_access.write() {
            for key in self.subjects {
                subjects.remove(&key);
            }
        }
        if let Ok(mut resources) = state.authz_resource_access.write() {
            for key in self.resources {
                resources.remove(&key);
            }
        }
    }
}

fn decode_artifact<T: DeserializeOwned>(artifact: &RuntimeSyncArtifact) -> SidecarResult<T> {
    T::deserialize(&artifact.payload).map_err(|_| {
        SidecarError::bad_gateway(
            "runtime_sync_artifact_invalid",
            "runtime sync authorization artifact has an invalid payload",
        )
    })
}
