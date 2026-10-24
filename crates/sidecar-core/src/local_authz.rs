use std::sync::Arc;

use authz_runtime::{
    EvaluationRuntime, LocalAuthzEvaluator, LocalEvaluationInput, TrustedAuthorizationContext,
};
use sidecar_contract::{
    ApiEvaluationRequest, AuthzEvaluationResult, AuthzPolicySnapshot, RequestContext,
};

use crate::{SidecarEngineConfig, SidecarError, SidecarResult, SidecarState, SidecarTransport};

mod cache;
mod cache_models;
mod cache_refresh;
mod conversion;
mod refresh;
mod sync;

use cache::{
    LocalAuthzCacheSummary, load_evaluation_data, load_policy_snapshot, load_policy_version,
};
use cache_models::EvaluationDataRequest;
#[cfg(test)]
pub(crate) use conversion::subject_type_from_str;
use conversion::{
    evaluation_request_from_api, resource_access_snapshot_from_api, resource_snapshot_request,
    result_from_local_response, runtime_from_policy_snapshot, subject_access_snapshot_from_api,
    subject_snapshot_request,
};

pub async fn evaluate<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: &ApiEvaluationRequest,
) -> SidecarResult<AuthzEvaluationResult>
where
    T: SidecarTransport + 'static,
{
    reject_unsupported_context(context, request)?;
    let evaluation_request = evaluation_request_from_api(request)?;
    let mut cache_summary = LocalAuthzCacheSummary::default();
    let policy_version =
        load_policy_version(config, state, transport, context, &mut cache_summary).await?;
    let policy_snapshot = load_policy_snapshot(
        config,
        state,
        transport,
        context,
        policy_version.current_policy_version,
        &mut cache_summary,
    )
    .await?;
    let subject_request = subject_snapshot_request(request)?;
    let resource_request = resource_snapshot_request(request);
    let data_request = EvaluationDataRequest {
        tenant_id: &policy_snapshot.tenant_id,
        policy_version: policy_snapshot.policy_version,
        subject: &subject_request,
        resource: &resource_request,
    };
    let (subject_access, resource_access) = load_evaluation_data(
        config,
        state,
        transport,
        context,
        data_request,
        &mut cache_summary,
    )
    .await?;

    let runtime = load_evaluation_runtime(state, &policy_snapshot)?;
    let response = LocalAuthzEvaluator::from_arc(runtime)
        .evaluate(LocalEvaluationInput {
            tenant_id: policy_snapshot.tenant_id.clone(),
            request: evaluation_request,
            trusted_context: TrustedAuthorizationContext::default(),
            subject_access: subject_access_snapshot_from_api(&subject_access)?,
            resource_access: resource_access_snapshot_from_api(&resource_access),
        })
        .map_err(|err| SidecarError::internal("authz_local_evaluation_failed", err.to_string()))?;
    Ok(result_from_local_response(
        response,
        cache_summary.cache_status(),
    ))
}

fn load_evaluation_runtime(
    state: &SidecarState,
    policy_snapshot: &AuthzPolicySnapshot,
) -> SidecarResult<Arc<EvaluationRuntime>> {
    let now_ms = crate::state::current_time_millis();
    if let Some((runtime, _cache_state)) =
        state.authz_evaluation_runtime(policy_snapshot.policy_version, now_ms)
    {
        return Ok(runtime);
    }

    let runtime = runtime_from_policy_snapshot(policy_snapshot)?;
    let runtime = Arc::new(runtime);
    state.store_authz_evaluation_runtime(policy_snapshot.policy_version, Arc::clone(&runtime));
    Ok(runtime)
}

fn reject_unsupported_context(
    context: &RequestContext,
    request: &ApiEvaluationRequest,
) -> SidecarResult<()> {
    if request.jwt_context.is_some()
        || request.session_context.is_some()
        || request.token_context.is_some()
    {
        return Err(SidecarError::bad_request(
            "authz_local_credential_context_untrusted",
            "local AuthZ does not accept caller-supplied credential context; use remote AuthZ for \
             validated authentication context",
        ));
    }

    let Some(authorization) = context.authorization.as_deref().map(str::trim) else {
        return Ok(());
    };
    if authorization.is_empty() {
        return Ok(());
    }

    if authorization
        .get(.."Bearer ".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Bearer "))
    {
        return Err(SidecarError::bad_request(
            "authz_local_bearer_context_unsupported",
            "local AuthZ cannot evaluate bearer authorization context",
        ));
    }

    if authorization
        .get(.."ApiKey ".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ApiKey "))
    {
        return Err(SidecarError::bad_request(
            "authz_local_api_key_context_unsupported",
            "local AuthZ cannot evaluate API-key authorization context",
        ));
    }

    Err(SidecarError::bad_request(
        "authz_local_authorization_context_unsupported",
        "local AuthZ supports only Bearer or ApiKey authorization context",
    ))
}
