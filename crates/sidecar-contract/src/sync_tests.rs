use crate::{
    AuthzEvaluationDataSnapshotRequest, AuthzResourceAccessSnapshotRequest,
    AuthzSubjectAccessSnapshotRequest, EntitlementEvaluateRequest, RuntimeSyncArtifact,
    RuntimeSyncCapabilities, RuntimeSyncKnownVersions, RuntimeSyncRequest, RuntimeSyncResponse,
    SyncArtifactKind,
};

#[test]
fn sync_response_given_all_artifacts_valid_then_accepts_atomic_envelope() {
    let response = RuntimeSyncResponse {
        protocol_version: 1,
        server_time: "2026-07-11T12:00:00Z".to_string(),
        refresh_after_ms: 5_000,
        artifacts: vec![RuntimeSyncArtifact {
            kind: SyncArtifactKind::AuthzPolicy,
            key: "tenant".to_string(),
            version: "42".to_string(),
            etag: "sha256:fixture".to_string(),
            immutable: true,
            max_age_ms: None,
            payload: serde_json::json!({"policy_version": 42}),
        }],
        unchanged: vec![SyncArtifactKind::Jwks],
        capabilities: RuntimeSyncCapabilities::default(),
    };

    response.validate().unwrap();
}

#[test]
fn sync_response_given_duplicate_identity_then_rejects_before_apply() {
    let artifact = RuntimeSyncArtifact {
        kind: SyncArtifactKind::Blocklist,
        key: "tenant".to_string(),
        version: "7".to_string(),
        etag: "sha256:fixture".to_string(),
        immutable: false,
        max_age_ms: Some(5_000),
        payload: serde_json::json!({}),
    };
    let response = RuntimeSyncResponse {
        protocol_version: 1,
        server_time: "2026-07-11T12:00:00Z".to_string(),
        refresh_after_ms: 5_000,
        artifacts: vec![artifact.clone(), artifact],
        unchanged: Vec::new(),
        capabilities: RuntimeSyncCapabilities::default(),
    };

    assert!(matches!(
        response.validate().unwrap_err(),
        crate::ContractError::Invalid {
            code: "runtime_sync_invalid",
            ..
        }
    ));
}

#[test]
fn sync_request_given_unknown_required_kind_then_rejects() {
    let request = RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::Unknown("future_required".to_string())],
        authz: None,
        entitlements: Vec::new(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    };

    assert!(matches!(
        request.validate().unwrap_err(),
        crate::ContractError::Invalid {
            code: "runtime_sync_invalid",
            ..
        }
    ));
}

#[test]
fn sync_artifact_kind_given_unknown_optional_response_kind_then_preserves_name() {
    let kind: SyncArtifactKind = serde_json::from_str(r#""future_optional""#).unwrap();
    assert_eq!(kind.as_str(), "future_optional");
    assert!(!kind.is_known());
}

#[test]
fn sync_protocol_version_property_accepts_only_version_one() {
    for protocol_version in 0..=u16::MAX {
        let request = RuntimeSyncRequest {
            protocol_version,
            known: RuntimeSyncKnownVersions::default(),
            want: vec![SyncArtifactKind::Jwks],
            authz: None,
            entitlements: Vec::new(),
            blocklist_policy_refs: Vec::new(),
            revocation_audiences: Vec::new(),
        };
        assert_eq!(request.validate().is_ok(), protocol_version == 1);
    }
}

#[test]
fn sync_artifact_kind_property_round_trips_known_and_unknown_values() {
    for kind in [
        SyncArtifactKind::Jwks,
        SyncArtifactKind::AuthzPolicy,
        SyncArtifactKind::AuthzEvaluationData,
        SyncArtifactKind::RateLimitConfig,
        SyncArtifactKind::Blocklist,
        SyncArtifactKind::Entitlements,
        SyncArtifactKind::Unknown("future_optional".to_string()),
    ] {
        let encoded = serde_json::to_string(&kind).unwrap();
        let decoded: SyncArtifactKind = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, kind);
    }
}

#[test]
fn sync_request_given_too_many_authz_subjects_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "protocol_version": 1,
        "want": ["authz_evaluation_data"],
        "authz": {
            "policy_version": 1,
            "subjects": (0..101)
                .map(|index| serde_json::json!({"type": "user", "id": format!("user-{index}")}))
                .collect::<Vec<_>>()
        }
    });

    assert!(serde_json::from_value::<RuntimeSyncRequest>(value).is_err());
}

#[test]
fn sync_request_given_too_many_entitlement_organizations_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "protocol_version": 1,
        "want": ["entitlements"],
        "entitlements": (0..129)
            .map(|index| serde_json::json!({"org_id": format!("org-{index}")}))
            .collect::<Vec<_>>()
    });

    assert!(serde_json::from_value::<RuntimeSyncRequest>(value).is_err());
}

#[test]
fn sync_request_given_directly_oversized_nested_state_then_rejects() {
    let request = RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::AuthzEvaluationData],
        authz: Some(AuthzEvaluationDataSnapshotRequest {
            policy_version: 1,
            subjects: (0..101)
                .map(|index| AuthzSubjectAccessSnapshotRequest {
                    subject_type: "user".to_string(),
                    id: format!("user-{index}"),
                    include_principal_id: false,
                })
                .collect(),
            resources: Vec::<AuthzResourceAccessSnapshotRequest>::new(),
        }),
        entitlements: Vec::<EntitlementEvaluateRequest>::new(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn sync_response_given_unbounded_mutable_age_then_rejects() {
    let mut response = valid_mutable_response();
    response.artifacts[0].max_age_ms = Some(u64::MAX);

    assert!(response.validate().is_err());
}

#[test]
fn sync_response_given_unbounded_refresh_after_then_rejects() {
    let mut response = valid_mutable_response();
    response.refresh_after_ms = u64::MAX;

    assert!(response.validate().is_err());
}

fn valid_mutable_response() -> RuntimeSyncResponse {
    RuntimeSyncResponse {
        protocol_version: 1,
        server_time: "2026-07-11T12:00:00Z".to_string(),
        refresh_after_ms: 5_000,
        artifacts: vec![RuntimeSyncArtifact {
            kind: SyncArtifactKind::Blocklist,
            key: "tenant".to_string(),
            version: "1".to_string(),
            etag: "etag".to_string(),
            immutable: false,
            max_age_ms: Some(5_000),
            payload: serde_json::json!({}),
        }],
        unchanged: Vec::new(),
        capabilities: RuntimeSyncCapabilities::default(),
    }
}
