use std::sync::Arc;

use sidecar_contract::{
    AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest, AuthzPolicySnapshot,
    AuthzPolicyVersionSnapshot, RequestContext, RuntimeSyncKnownVersions, RuntimeSyncRequest,
    SyncArtifactKind,
};

use crate::{SidecarEngineConfig, SidecarError, SidecarResult, SidecarState, SidecarTransport};

pub(super) async fn sync_authz_policy<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
) -> SidecarResult<Option<(AuthzPolicyVersionSnapshot, AuthzPolicySnapshot)>>
where
    T: SidecarTransport + 'static,
{
    let request = sync_request(SyncArtifactKind::AuthzPolicy, None);
    match crate::runtime_sync::synchronize(config, state, transport, context, request, false).await
    {
        Ok(_) => {
            let artifact = state
                .shared_runtime_sync_artifact(SyncArtifactKind::AuthzPolicy, "tenant")
                .ok_or_else(|| {
                    SidecarError::bad_gateway(
                        "runtime_sync_artifact_missing",
                        "runtime sync omitted the required authorization policy",
                    )
                })?;
            let policy: AuthzPolicySnapshot = serde::Deserialize::deserialize(&artifact.payload)
                .map_err(|_| {
                    SidecarError::bad_gateway(
                        "runtime_sync_artifact_invalid",
                        "runtime sync authorization policy could not be decoded",
                    )
                })?;
            let version = AuthzPolicyVersionSnapshot {
                tenant_id: policy.tenant_id.clone(),
                current_policy_version: policy.policy_version,
                generated_at_ms: policy.generated_at_ms,
            };
            Ok(Some((version, policy)))
        }
        Err(error) if error.code == "runtime_sync_unavailable" => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) async fn sync_authz_evaluation_data<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    authz: AuthzEvaluationDataSnapshotRequest,
) -> SidecarResult<Option<AuthzEvaluationDataSnapshot>>
where
    T: SidecarTransport + 'static,
{
    let request = sync_request(SyncArtifactKind::AuthzEvaluationData, Some(authz));
    match crate::runtime_sync::synchronize(config, state, transport, context, request, true).await {
        Ok(Some(response)) => {
            let artifact = response
                .artifacts
                .into_iter()
                .find(|artifact| artifact.kind == SyncArtifactKind::AuthzEvaluationData)
                .ok_or_else(|| {
                    SidecarError::bad_gateway(
                        "runtime_sync_artifact_missing",
                        "runtime sync omitted required authorization evaluation data",
                    )
                })?;
            serde_json::from_value(artifact.payload)
                .map(Some)
                .map_err(|_| {
                    SidecarError::bad_gateway(
                        "runtime_sync_artifact_invalid",
                        "runtime sync authorization evaluation data could not be decoded",
                    )
                })
        }
        Ok(None) => Err(SidecarError::internal(
            "runtime_sync_response_missing",
            "runtime sync authorization evaluation response is unavailable",
        )),
        Err(error) if error.code == "runtime_sync_unavailable" => Ok(None),
        Err(error) => Err(error),
    }
}

fn sync_request(
    kind: SyncArtifactKind,
    authz: Option<AuthzEvaluationDataSnapshotRequest>,
) -> RuntimeSyncRequest {
    RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![kind],
        authz,
        entitlements: Vec::new(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    }
}
