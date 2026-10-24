use std::collections::HashSet;

use authz_cedar::CompiledBundle;
use authz_runtime::{
    EffectiveRoleAssignment, EvaluationRuntime, ParentRef, ResourceAccessSnapshot,
    SubjectAccessSnapshot,
};
use authz_types::{
    Action, ConfigurationModel, Context, EvaluationRequest, Resource, Subject, SubjectType,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sidecar_contract::{
    ApiEvaluationRequest, ApiEvaluationResponse, ApiResponseContext, AuthzEvaluationResult,
    AuthzParentRef, AuthzPolicySnapshot, AuthzResourceAccessSnapshot,
    AuthzResourceAccessSnapshotRequest, AuthzSubjectAccessSnapshot,
    AuthzSubjectAccessSnapshotRequest, CacheStatus,
};

use crate::{SidecarError, SidecarResult};

pub(super) fn runtime_from_policy_snapshot(
    snapshot: &AuthzPolicySnapshot,
) -> SidecarResult<EvaluationRuntime> {
    let config = from_value_ref::<ConfigurationModel>(
        &snapshot.config,
        "authz_policy_config_invalid",
        "policy snapshot config is not a valid configuration model",
    )?
    .into_validated()
    .map_err(|errors| {
        SidecarError::bad_gateway(
            "authz_policy_config_invalid",
            format!("policy snapshot config failed validation: {errors:?}"),
        )
    })?;
    let bundle = from_value_ref::<CompiledBundle>(
        &snapshot.compiled_bundle,
        "authz_compiled_bundle_invalid",
        "policy snapshot compiled bundle is not a valid Cedar bundle",
    )?;
    EvaluationRuntime::build(config, &bundle)
        .map_err(|err| SidecarError::bad_gateway("authz_runtime_build_failed", err.to_string()))
}

pub(super) fn evaluation_request_from_api(
    request: &ApiEvaluationRequest,
) -> SidecarResult<EvaluationRequest> {
    Ok(EvaluationRequest {
        subject: subject_from_api(&request.subject)?,
        resource: Resource {
            resource_type: request.resource.resource_type.clone(),
            id: request.resource.id.clone(),
            properties: optional_map_value(request.resource.properties.clone()),
        },
        action: Action {
            name: request.action.name.clone(),
            properties: optional_map_value(request.action.properties.clone()),
        },
        context: request
            .context
            .clone()
            .map(|context| Context::new(Value::Object(context))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    })
}

fn subject_from_api(subject: &sidecar_contract::ApiSubject) -> SidecarResult<Subject> {
    Ok(Subject {
        subject_type: subject_type_from_str(&subject.subject_type)?,
        id: subject.id.clone(),
        properties: optional_map_value(subject.properties.clone()),
    })
}

pub(crate) fn subject_type_from_str(subject_type: &str) -> SidecarResult<SubjectType> {
    match subject_type {
        "user" => Ok(SubjectType::User),
        "group" => Ok(SubjectType::Group),
        "role" => Ok(SubjectType::Role),
        "api_key" => Ok(SubjectType::ApiKey),
        "machine" | "service_account" => Ok(SubjectType::Machine),
        "protocol" => Ok(SubjectType::Protocol),
        _ => Err(SidecarError::bad_request(
            "authz_subject_type_invalid",
            format!("unsupported subject type '{subject_type}'"),
        )),
    }
}

pub(super) fn subject_access_snapshot_from_api(
    snapshot: &AuthzSubjectAccessSnapshot,
) -> SidecarResult<SubjectAccessSnapshot> {
    let assignments = snapshot
        .assignments
        .iter()
        .map(|assignment| {
            from_value_ref::<EffectiveRoleAssignment>(
                assignment,
                "authz_subject_assignment_invalid",
                "subject assignment snapshot is not valid",
            )
        })
        .collect::<SidecarResult<Vec<_>>>()?;
    let resource_scopes = snapshot
        .resource_scopes
        .iter()
        .map(|(resource_type, resource_ids)| {
            (
                resource_type.clone(),
                resource_ids.iter().cloned().collect::<HashSet<_>>(),
            )
        })
        .collect();
    Ok(SubjectAccessSnapshot {
        tenant_id: snapshot.tenant_id.clone(),
        subject: subject_from_api(&snapshot.subject)?,
        assignments,
        subject_parents: parent_refs_from_api(&snapshot.subject_parents),
        resource_scopes,
        fetched_at_ms: snapshot.fetched_at_ms,
    })
}

pub(super) fn resource_access_snapshot_from_api(
    snapshot: &AuthzResourceAccessSnapshot,
) -> ResourceAccessSnapshot {
    ResourceAccessSnapshot {
        tenant_id: snapshot.tenant_id.clone(),
        resource_type: snapshot.resource_type.clone(),
        resource_id: snapshot.resource_id.clone(),
        properties: snapshot.properties.clone(),
        resource_parents: parent_refs_from_api(&snapshot.resource_parents),
        fetched_at_ms: snapshot.fetched_at_ms,
    }
}

fn parent_refs_from_api(parents: &[AuthzParentRef]) -> Vec<ParentRef> {
    parents
        .iter()
        .map(|parent| ParentRef {
            ref_type: parent.ref_type.clone(),
            id: parent.id.clone(),
        })
        .collect()
}

fn from_value_ref<T>(
    value: &Value,
    code: &'static str,
    description: &'static str,
) -> SidecarResult<T>
where
    T: DeserializeOwned,
{
    T::deserialize(value)
        .map_err(|err| SidecarError::bad_gateway(code, format!("{description}: {err}")))
}

fn optional_map_value(value: Option<Map<String, Value>>) -> Option<Value> {
    value.map(Value::Object)
}

pub(super) fn subject_snapshot_request(
    request: &ApiEvaluationRequest,
) -> SidecarResult<AuthzSubjectAccessSnapshotRequest> {
    Ok(AuthzSubjectAccessSnapshotRequest {
        subject_type: request.subject.subject_type.clone(),
        id: request.subject.id.clone(),
        include_principal_id: false,
    })
}

pub(super) fn resource_snapshot_request(
    request: &ApiEvaluationRequest,
) -> AuthzResourceAccessSnapshotRequest {
    AuthzResourceAccessSnapshotRequest {
        resource_type: request.resource.resource_type.clone(),
        id: request.resource.id.clone(),
    }
}

pub(super) fn result_from_local_response(
    response: authz_types::EvaluationResponse,
    cache_status: CacheStatus,
) -> AuthzEvaluationResult {
    let www_authenticate = response
        .challenge
        .as_ref()
        .and_then(|challenge| challenge.www_authenticate.clone());
    let status_code = if response.challenge.is_some() {
        401
    } else {
        200
    };
    AuthzEvaluationResult {
        response: ApiEvaluationResponse {
            decision: response.decision,
            challenge: response.challenge.and_then(|challenge| {
                serde_json::to_value(challenge)
                    .ok()
                    .and_then(|value| match value {
                        Value::Object(map) => Some(map),
                        _ => None,
                    })
            }),
            context: response.context.map(|context| ApiResponseContext {
                reason_admin: context.reason,
                effective_permission: context.effective_permission,
                policy_version: context.policy_version,
            }),
        },
        cache_status,
        status_code,
        www_authenticate,
    }
}
