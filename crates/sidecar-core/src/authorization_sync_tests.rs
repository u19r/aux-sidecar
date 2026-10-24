use std::{collections::HashMap, sync::Arc, time::Duration};

use serde_json::json;
use sidecar_contract::{
    ApiSubject, AuthzEvaluationDataSnapshot, AuthzPolicyVersionSnapshot,
    AuthzResourceAccessSnapshot, AuthzSubjectAccessSnapshot, RuntimeSyncArtifact,
    RuntimeSyncCapabilities, RuntimeSyncResponse, SyncArtifactKind,
};

use crate::{AuthzResourceCacheKey, AuthzSubjectCacheKey, SidecarState, current_time_millis};

#[test]
fn given_warm_authorization_snapshots_when_synchronized_then_the_old_data_cannot_be_reused() {
    let state = SidecarState::new();
    let mut subject = subject_snapshot();
    let mut resource = resource_snapshot();
    let subject_key =
        AuthzSubjectCacheKey::new("account".into(), 7, "user".into(), "person".into(), false);
    let resource_key =
        AuthzResourceCacheKey::new("account".into(), 7, "document".into(), "doc_1".into());
    state.store_authz_subject_access(
        subject_key.clone(),
        Arc::new(subject.clone()),
        Duration::from_secs(3600),
        Duration::ZERO,
        100,
    );
    let unrelated_key = AuthzSubjectCacheKey::new(
        "other-account".into(),
        7,
        "user".into(),
        "person".into(),
        false,
    );
    state.store_authz_subject_access(
        unrelated_key.clone(),
        Arc::new(subject.clone()),
        Duration::from_secs(3600),
        Duration::ZERO,
        100,
    );
    state.store_authz_resource_access(
        resource_key.clone(),
        Arc::new(resource.clone()),
        Duration::from_secs(3600),
        Duration::ZERO,
        100,
    );
    subject.subject.properties = Some(serde_json::from_value(json!({"version":2})).unwrap());
    subject.fetched_at_ms = 2;
    resource.properties = json!({"org_id":"organization_2"});
    resource.fetched_at_ms = 2;
    let data = AuthzEvaluationDataSnapshot {
        tenant_id: "account".into(),
        policy_version: 7,
        generated_at_ms: 2,
        subjects: vec![subject.clone()],
        resources: vec![resource.clone()],
    };
    state
        .apply_runtime_sync(sync_response(serde_json::to_value(data).unwrap()))
        .unwrap();
    let updated_subject = state.authz_subject_access(&subject_key, current_time_millis());
    let updated_resource = state.authz_resource_access(&resource_key, current_time_millis());
    assert!(
        updated_subject
            .is_none_or(|(value, _)| value.subject.properties == subject.subject.properties)
    );
    assert!(updated_resource.is_none_or(|(value, _)| value.properties == resource.properties));
    assert_eq!(
        state
            .authz_subject_access(&unrelated_key, current_time_millis())
            .unwrap()
            .0
            .subject
            .properties,
        subject_snapshot().subject.properties
    );
}

#[test]
fn given_warm_authorization_snapshots_when_the_sync_payload_is_invalid_then_no_sync_state_is_committed()
 {
    let state = SidecarState::new();
    let key = AuthzSubjectCacheKey::new("account".into(), 7, "user".into(), "person".into(), false);
    state.store_authz_subject_access(
        key.clone(),
        Arc::new(subject_snapshot()),
        Duration::from_secs(3600),
        Duration::ZERO,
        100,
    );
    let mut foreign_subject = subject_snapshot();
    foreign_subject.tenant_id = "other-account".into();
    let foreign_data = AuthzEvaluationDataSnapshot {
        tenant_id: "account".into(),
        policy_version: 7,
        generated_at_ms: 2,
        subjects: vec![foreign_subject],
        resources: vec![],
    };
    for payload in [json!({}), serde_json::to_value(foreign_data).unwrap()] {
        assert!(state.apply_runtime_sync(sync_response(payload)).is_err());
    }
    assert!(
        state
            .runtime_sync_artifact(SyncArtifactKind::AuthzEvaluationData, "evaluation")
            .is_none()
    );
    assert_eq!(
        state
            .authz_subject_access(&key, current_time_millis())
            .unwrap()
            .0
            .subject
            .properties,
        subject_snapshot().subject.properties
    );
}

#[test]
fn given_a_cached_policy_pointer_when_a_policy_is_synchronized_then_the_old_pointer_is_not_served()
{
    let state = SidecarState::new();
    state.store_authz_policy_version(
        AuthzPolicyVersionSnapshot {
            tenant_id: "account".into(),
            current_policy_version: 7,
            generated_at_ms: 1,
        },
        Duration::from_secs(3600),
        Duration::ZERO,
        100,
    );
    let mut response = sync_response(
        json!({"tenant_id":"account","policy_version":8,"config_hash":"new",
        "config":{},"compiled_bundle":{},"generated_at_ms":2}),
    );
    response.artifacts[0].kind = SyncArtifactKind::AuthzPolicy;
    response.artifacts[0].key = "tenant".into();
    response.artifacts[0].immutable = true;
    state.apply_runtime_sync(response).unwrap();
    assert!(
        state
            .authz_policy_version(current_time_millis())
            .is_none_or(|(value, _)| value.current_policy_version == 8)
    );
}

fn subject_snapshot() -> AuthzSubjectAccessSnapshot {
    AuthzSubjectAccessSnapshot {
        tenant_id: "account".into(),
        subject: ApiSubject {
            subject_type: "user".into(),
            id: "person".into(),
            properties: Some(serde_json::from_value(json!({"version":1})).unwrap()),
        },
        assignments: vec![],
        subject_parents: vec![],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    }
}

fn resource_snapshot() -> AuthzResourceAccessSnapshot {
    AuthzResourceAccessSnapshot {
        tenant_id: "account".into(),
        resource_type: "document".into(),
        resource_id: "doc_1".into(),
        properties: json!({"org_id":"organization_1"}),
        resource_parents: vec![],
        fetched_at_ms: 1,
    }
}

fn sync_response(payload: serde_json::Value) -> RuntimeSyncResponse {
    RuntimeSyncResponse {
        protocol_version: 1,
        server_time: "2026-10-14T20:00:00Z".into(),
        refresh_after_ms: 1000,
        artifacts: vec![RuntimeSyncArtifact {
            kind: SyncArtifactKind::AuthzEvaluationData,
            key: "evaluation".into(),
            version: "2".into(),
            etag: "2".into(),
            immutable: false,
            max_age_ms: Some(1000),
            payload,
        }],
        unchanged: vec![],
        capabilities: RuntimeSyncCapabilities::default(),
    }
}
