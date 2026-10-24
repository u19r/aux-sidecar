use serde_json::json;

use crate::{
    AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest, AuthzPolicySnapshot,
    AuthzPolicyVersionSnapshot,
};

#[test]
fn authz_local_snapshot_payloads_match_auxfn_public_contract_shape() {
    let version: AuthzPolicyVersionSnapshot = serde_json::from_value(json!({
        "tenant_id": "t_123",
        "current_policy_version": 7,
        "generated_at_ms": 123456789
    }))
    .expect("policy version snapshot");
    assert_eq!(version.current_policy_version, 7);

    let policy: AuthzPolicySnapshot = serde_json::from_value(json!({
        "tenant_id": "t_123",
        "policy_version": 7,
        "config_hash": "hash",
        "config": { "version": 1, "resource_types": [], "permissions": [], "roles": [] },
        "compiled_bundle": { "version": 7 },
        "generated_at_ms": 123456789,
        "max_age_seconds": 10
    }))
    .expect("policy snapshot");
    assert_eq!(policy.max_age_seconds, Some(10));

    let request = AuthzEvaluationDataSnapshotRequest {
        policy_version: 7,
        subjects: vec![crate::AuthzSubjectAccessSnapshotRequest {
            subject_type: "user".to_string(),
            id: "u_123".to_string(),
            include_principal_id: true,
        }],
        resources: vec![crate::AuthzResourceAccessSnapshotRequest {
            resource_type: "document".to_string(),
            id: "doc_123".to_string(),
        }],
    };
    let request_json = serde_json::to_value(request).expect("snapshot request");
    assert_eq!(request_json["subjects"][0]["type"], "user");
    assert!(request_json["subjects"][0].get("token_cache_key").is_none());
    assert_eq!(request_json["resources"][0]["type"], "document");

    let data: AuthzEvaluationDataSnapshot = serde_json::from_value(json!({
        "tenant_id": "t_123",
        "policy_version": 7,
        "generated_at_ms": 123456790,
        "subjects": [{
            "tenant_id": "t_123",
            "subject": { "type": "user", "id": "u_123" },
            "assignments": [],
            "subject_parents": [{ "ref_type": "tenant", "id": "t_123" }],
            "resource_scopes": {},
            "fetched_at_ms": 123456790
        }],
        "resources": [{
            "tenant_id": "t_123",
            "resource_type": "document",
            "resource_id": "doc_123",
            "properties": {},
            "resource_parents": [],
            "fetched_at_ms": 123456790
        }]
    }))
    .expect("evaluation data snapshot");
    assert_eq!(data.subjects[0].subject.subject_type, "user");
    assert_eq!(data.resources[0].resource_type, "document");
}

#[test]
fn authz_public_response_excludes_internal_cedar_diagnostics() {
    let response = crate::ApiEvaluationResponse {
        decision: false,
        challenge: None,
        context: Some(crate::ApiResponseContext {
            reason_admin: Some("stable public reason".to_string()),
            effective_permission: None,
            policy_version: Some(7),
        }),
    };

    let json = serde_json::to_value(response).expect("response JSON");
    let text = json.to_string();

    for internal_key in [
        "diagnostics",
        "determining_policy",
        "policy_ids",
        "cedar_errors",
        "entity_attributes",
        "_authz",
    ] {
        assert!(
            !text.contains(internal_key),
            "leaked internal key {internal_key}"
        );
    }
}
