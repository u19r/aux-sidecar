use std::{sync::Arc, time::Duration};

use sidecar_contract::{
    AuthzResourceAccessSnapshotRequest, AuthzSubjectAccessSnapshotRequest, CacheStatus,
    RequestContext,
};

use super::support::{
    POLICY_VERSION, SnapshotFault, SnapshotTransport, TENANT_ID, config, config_with_fallback,
    evaluation_request,
};
use crate::{LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngine, local_authz};

#[tokio::test]
async fn local_authz_given_empty_cache_then_fetches_snapshots_and_evaluates() {
    let transport = SnapshotTransport::new();
    let state = Arc::new(crate::SidecarState::new());
    let result = local_authz::evaluate(
        &config(LocalAuthzMode::RemoteOnly),
        &state,
        &Arc::new(transport.clone()),
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect("local authz evaluation");

    assert!(result.response.decision);
    assert_eq!(result.status_code, 200);
    assert_eq!(result.cache_status, CacheStatus::Miss);
    assert_eq!(transport.policy_version_count(), 1);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 1);
    assert!(
        state
            .authz_evaluation_runtime(POLICY_VERSION, crate::state::current_time_millis())
            .is_some(),
        "local authz should cache the built evaluation runtime",
    );

    let cached = local_authz::evaluate(
        &config(LocalAuthzMode::RemoteOnly),
        &state,
        &Arc::new(transport.clone()),
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect("cached local authz evaluation");

    assert!(cached.response.decision);
    assert_eq!(cached.cache_status, CacheStatus::Fresh);
    assert_eq!(transport.policy_version_count(), 1);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 1);
}

#[tokio::test]
async fn cold_policy_version_given_concurrent_requests_then_fetches_snapshot_once() {
    let transport = Arc::new(SnapshotTransport::new());
    let state = Arc::new(crate::SidecarState::new());
    let config = Arc::new(config(LocalAuthzMode::Enforced));
    let evaluations = (0..20).map(|_| {
        let transport = Arc::clone(&transport);
        let state = Arc::clone(&state);
        let config = Arc::clone(&config);
        async move {
            local_authz::evaluate(
                &config,
                &state,
                &transport,
                &RequestContext::default(),
                &evaluation_request(),
            )
            .await
        }
    });

    let results = futures::future::join_all(evaluations).await;

    assert!(results.iter().all(Result::is_ok));
    assert_eq!(transport.policy_snapshot_count(), 1);
}

#[tokio::test]
async fn evaluation_data_given_only_subject_expired_then_requests_no_resource_snapshot() {
    let transport = SnapshotTransport::new();
    let state = Arc::new(crate::SidecarState::new());
    let config = config(LocalAuthzMode::Enforced);
    let transport = Arc::new(transport);
    local_authz::evaluate(
        &config,
        &state,
        &transport,
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect("prime caches");
    let subject_request = AuthzSubjectAccessSnapshotRequest {
        subject_type: "user".to_string(),
        id: "user_123".to_string(),
        include_principal_id: false,
    };
    state.store_authz_subject_access(
        crate::AuthzSubjectCacheKey::from_request(
            TENANT_ID.to_string(),
            POLICY_VERSION,
            &subject_request,
        ),
        transport.subject_snapshot(),
        Duration::ZERO,
        Duration::ZERO,
        100,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;

    local_authz::evaluate(
        &config,
        &state,
        &transport,
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect("refresh subject only");

    let requests = transport.evaluation_requests();
    let request = requests.last().expect("refresh request");
    assert_eq!(request.subjects, vec![subject_request]);
    assert!(request.resources.is_empty());
}

#[tokio::test]
async fn evaluation_data_given_only_resource_expired_then_requests_no_subject_snapshot() {
    let transport = SnapshotTransport::new();
    let state = Arc::new(crate::SidecarState::new());
    let config = config(LocalAuthzMode::Enforced);
    let transport = Arc::new(transport);
    local_authz::evaluate(
        &config,
        &state,
        &transport,
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect("prime caches");
    let resource_request = AuthzResourceAccessSnapshotRequest {
        resource_type: "document".to_string(),
        id: "doc_123".to_string(),
    };
    state.store_authz_resource_access(
        crate::AuthzResourceCacheKey::from_request(
            TENANT_ID.to_string(),
            POLICY_VERSION,
            &resource_request,
        ),
        transport.resource_snapshot(),
        Duration::ZERO,
        Duration::ZERO,
        100,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;

    local_authz::evaluate(
        &config,
        &state,
        &transport,
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect("refresh resource only");

    let requests = transport.evaluation_requests();
    let request = requests.last().expect("refresh request");
    assert!(request.subjects.is_empty());
    assert_eq!(request.resources, vec![resource_request]);
}

#[tokio::test]
async fn local_authz_given_invalid_subject_type_then_rejects_before_fetch() {
    let transport = SnapshotTransport::new();
    let state = Arc::new(crate::SidecarState::new());
    let mut request = evaluation_request();
    request.subject.subject_type = "custom_user".to_string();

    let error = local_authz::evaluate(
        &config(LocalAuthzMode::RemoteOnly),
        &state,
        &Arc::new(transport.clone()),
        &RequestContext::default(),
        &request,
    )
    .await
    .expect_err("invalid subject type should fail");

    assert_eq!(error.code, "authz_subject_type_invalid");
    assert_eq!(transport.policy_version_count(), 0);
}

#[tokio::test]
async fn local_authz_given_cross_tenant_evaluation_data_then_rejects_before_cache() {
    let transport = SnapshotTransport::with_fault(SnapshotFault::EvaluationDataTenantMismatch);
    let state = Arc::new(crate::SidecarState::new());

    let error = local_authz::evaluate(
        &config(LocalAuthzMode::Enforced),
        &state,
        &Arc::new(transport),
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect_err("cross-tenant evaluation data must fail closed");

    assert_eq!(error.code, "authz_evaluation_data_tenant_mismatch");
}

#[tokio::test]
async fn local_authz_given_cross_tenant_child_snapshot_then_rejects_before_cache() {
    let transport = SnapshotTransport::with_fault(SnapshotFault::EvaluationDataChildTenantMismatch);
    let state = Arc::new(crate::SidecarState::new());

    let error = local_authz::evaluate(
        &config(LocalAuthzMode::Enforced),
        &state,
        &Arc::new(transport),
        &RequestContext::default(),
        &evaluation_request(),
    )
    .await
    .expect_err("cross-tenant child snapshot must fail closed");

    assert_eq!(error.code, "authz_evaluation_data_tenant_mismatch");
}

#[tokio::test]
async fn local_authz_given_bearer_without_jwt_context_then_reports_unsupported_context() {
    let transport = SnapshotTransport::new();
    let state = Arc::new(crate::SidecarState::new());
    let context = RequestContext {
        authorization: Some("Bearer redacted".to_string()),
        ..RequestContext::default()
    };

    let error = local_authz::evaluate(
        &config(LocalAuthzMode::RemoteOnly),
        &state,
        &Arc::new(transport.clone()),
        &context,
        &evaluation_request(),
    )
    .await
    .expect_err("unsupported bearer context should fail");

    assert_eq!(error.code, "authz_local_bearer_context_unsupported");
    assert_eq!(transport.policy_version_count(), 0);
}

#[tokio::test]
async fn local_authz_given_caller_credential_context_then_fails_closed_before_fetch() {
    for context_name in ["jwt_context", "session_context", "token_context"] {
        let transport = SnapshotTransport::new();
        let state = Arc::new(crate::SidecarState::new());
        let mut request = evaluation_request();
        let context = serde_json::Map::new();
        match context_name {
            "jwt_context" => request.jwt_context = Some(context),
            "session_context" => request.session_context = Some(context),
            "token_context" => request.token_context = Some(context),
            _ => unreachable!(),
        }

        let error = local_authz::evaluate(
            &config(LocalAuthzMode::RemoteOnly),
            &state,
            &Arc::new(transport.clone()),
            &RequestContext::default(),
            &request,
        )
        .await
        .expect_err("caller credential context must not enter local AuthZ");

        assert_eq!(error.code, "authz_local_credential_context_untrusted");
        assert_eq!(transport.policy_version_count(), 0);
    }
}

#[tokio::test]
async fn engine_shadow_mode_returns_remote_response_and_runs_local_evaluation() {
    let transport = SnapshotTransport::new();
    let engine = SidecarEngine::new(config(LocalAuthzMode::Shadow), transport.clone());

    let result = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect("shadow evaluation");

    assert!(!result.response.decision);
    assert_eq!(result.cache_status, CacheStatus::Miss);
    let metrics = engine.state().authz_shadow_metrics();
    assert_eq!(metrics.attempts, 1);
    assert_eq!(metrics.matches, 0);
    assert_eq!(metrics.mismatches, 1);
    assert_eq!(metrics.errors, 0);
    assert_eq!(transport.remote_count(), 1);
    assert_eq!(transport.policy_version_count(), 1);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 1);
}

#[tokio::test]
async fn engine_enforced_mode_returns_local_response_without_remote_call() {
    let transport = SnapshotTransport::new();
    let engine = SidecarEngine::new(
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never),
        transport.clone(),
    );

    let result = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect("enforced evaluation");

    assert!(result.response.decision);
    assert_eq!(result.status_code, 200);
    assert_eq!(result.cache_status, CacheStatus::Miss);
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.policy_version_count(), 1);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 1);
}

#[tokio::test]
async fn engine_enforced_mode_given_snapshot_failure_and_fallback_allowed_then_calls_remote() {
    let transport = SnapshotTransport::failing_policy_snapshot();
    let engine = SidecarEngine::new(
        config_with_fallback(
            LocalAuthzMode::Enforced,
            LocalAuthzRemoteFallback::CacheMiss,
        ),
        transport.clone(),
    );

    let result = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect("enforced fallback evaluation");

    assert!(!result.response.decision);
    assert_eq!(result.cache_status, CacheStatus::Miss);
    assert_eq!(transport.remote_count(), 1);
    assert_eq!(transport.policy_version_count(), 1);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 0);
}

#[tokio::test]
async fn engine_enforced_mode_given_snapshot_failure_and_fallback_never_then_fails_closed() {
    let transport = SnapshotTransport::failing_policy_snapshot();
    let engine = SidecarEngine::new(
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never),
        transport.clone(),
    );

    let error = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect_err("enforced mode should fail closed");

    assert_eq!(error.code, "authz_policy_snapshot_unavailable");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.policy_version_count(), 1);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 0);
}

#[tokio::test]
async fn engine_enforced_mode_given_missing_subject_snapshot_and_fallback_never_then_fails_closed()
{
    let transport = SnapshotTransport::with_fault(SnapshotFault::SubjectMissing);
    let engine = SidecarEngine::new(
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never),
        transport.clone(),
    );

    let error = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect_err("missing subject snapshot should fail closed");

    assert_eq!(error.code, "authz_subject_snapshot_missing");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.evaluation_data_count(), 1);
}
#[tokio::test]
async fn engine_enforced_mode_given_missing_resource_snapshot_and_fallback_never_then_fails_closed()
{
    let transport = SnapshotTransport::with_fault(SnapshotFault::ResourceMissing);
    let engine = SidecarEngine::new(
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never),
        transport.clone(),
    );

    let error = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect_err("missing resource snapshot should fail closed");

    assert_eq!(error.code, "authz_resource_snapshot_missing");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.evaluation_data_count(), 1);
}

#[tokio::test]
async fn engine_enforced_mode_given_policy_version_mismatch_and_fallback_never_then_fails_closed() {
    let transport = SnapshotTransport::with_fault(SnapshotFault::PolicySnapshotVersionMismatch);
    let engine = SidecarEngine::new(
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never),
        transport.clone(),
    );

    let error = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect_err("policy version mismatch should fail closed");

    assert_eq!(error.code, "authz_policy_snapshot_version_mismatch");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.policy_snapshot_count(), 1);
    assert_eq!(transport.evaluation_data_count(), 0);
}

#[tokio::test]
async fn engine_enforced_mode_given_invalid_subject_snapshot_and_fallback_never_then_fails_closed()
{
    let transport = SnapshotTransport::with_fault(SnapshotFault::InvalidSubjectAssignment);
    let engine = SidecarEngine::new(
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never),
        transport.clone(),
    );

    let error = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect_err("invalid subject snapshot should fail closed");

    assert_eq!(error.code, "authz_subject_assignment_invalid");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.evaluation_data_count(), 1);
}

#[tokio::test]
async fn engine_enforced_mode_given_invalid_subject_snapshot_and_cache_miss_fallback_then_fails_closed()
 {
    let transport = SnapshotTransport::with_fault(SnapshotFault::InvalidSubjectAssignment);
    let engine = SidecarEngine::new(
        config_with_fallback(
            LocalAuthzMode::Enforced,
            LocalAuthzRemoteFallback::CacheMiss,
        ),
        transport.clone(),
    );

    let error = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect_err("invalid subject snapshot should not fall back remotely");

    assert_eq!(error.code, "authz_subject_assignment_invalid");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.evaluation_data_count(), 1);
}
