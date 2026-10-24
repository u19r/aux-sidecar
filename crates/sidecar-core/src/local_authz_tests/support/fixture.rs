use std::collections::HashMap;

use authz_cedar::compile_policy_bundle;
use authz_runtime::{
    EffectiveRoleAssignment, SubjectParentTemplate, build_subject_parent_template,
};
use authz_types::{
    ActionDefinition, ConfigurationModel, Permission, PermissionActionRef, PermissionId, Role,
    RolePermission, Scope,
};
use sidecar_contract::{
    ApiSubject, AuthzEvaluationDataSnapshot, AuthzParentRef, AuthzPolicySnapshot,
    AuthzPolicyVersionSnapshot, AuthzResourceAccessSnapshot, AuthzSubjectAccessSnapshot,
};

use super::{POLICY_VERSION, RESOURCE_ID, RESOURCE_TYPE, ROLE_ID, SUBJECT_ID, TENANT_ID};

#[derive(Debug)]
pub(super) struct AuthzFixture {
    pub(super) policy_version: AuthzPolicyVersionSnapshot,
    pub(super) policy_snapshot: AuthzPolicySnapshot,
    pub(super) evaluation_data: AuthzEvaluationDataSnapshot,
    pub(super) revoked_evaluation_data: AuthzEvaluationDataSnapshot,
}

impl AuthzFixture {
    pub(super) fn new() -> Self {
        let now_ms = crate::state::current_time_millis();
        let config = configuration_model();
        let validated = config.clone().into_validated().expect("valid config");
        let bundle =
            compile_policy_bundle(&validated, POLICY_VERSION).expect("compiled exact bundle");
        let assignment = EffectiveRoleAssignment {
            principal_id: None,
            role_id: ROLE_ID.to_string(),
            scope_type: Some("tenant".to_string()),
            scope_id: None,
            expires_at: None,
        };
        let template =
            build_subject_parent_template(std::slice::from_ref(&assignment), &[], TENANT_ID);
        let resource_scopes = template
            .resource_scopes
            .iter()
            .map(|(key, values)| (key.clone(), values.iter().cloned().collect::<Vec<_>>()))
            .collect::<HashMap<_, _>>();

        Self {
            policy_version: AuthzPolicyVersionSnapshot {
                tenant_id: TENANT_ID.to_string(),
                current_policy_version: POLICY_VERSION,
                generated_at_ms: now_ms,
            },
            policy_snapshot: AuthzPolicySnapshot {
                tenant_id: TENANT_ID.to_string(),
                policy_version: POLICY_VERSION,
                config_hash: "hash_123".to_string(),
                config: serde_json::to_value(config).expect("config json"),
                compiled_bundle: serde_json::to_value(bundle).expect("bundle json"),
                generated_at_ms: now_ms,
                max_age_seconds: None,
            },
            evaluation_data: evaluation_data(assignment, template, resource_scopes, now_ms),
            revoked_evaluation_data: revoked_evaluation_data(now_ms),
        }
    }
}

fn evaluation_data(
    assignment: EffectiveRoleAssignment,
    template: SubjectParentTemplate,
    resource_scopes: HashMap<String, Vec<String>>,
    now_ms: i64,
) -> AuthzEvaluationDataSnapshot {
    AuthzEvaluationDataSnapshot {
        tenant_id: TENANT_ID.to_string(),
        policy_version: POLICY_VERSION,
        generated_at_ms: now_ms,
        subjects: vec![AuthzSubjectAccessSnapshot {
            tenant_id: TENANT_ID.to_string(),
            subject: test_subject(),
            assignments: vec![serde_json::to_value(assignment).expect("assignment json")],
            subject_parents: template
                .parents
                .into_iter()
                .map(|parent| AuthzParentRef {
                    ref_type: parent.ref_type,
                    id: parent.id,
                })
                .collect(),
            resource_scopes,
            fetched_at_ms: now_ms,
        }],
        resources: vec![test_resource(now_ms)],
    }
}

fn revoked_evaluation_data(now_ms: i64) -> AuthzEvaluationDataSnapshot {
    AuthzEvaluationDataSnapshot {
        tenant_id: TENANT_ID.to_string(),
        policy_version: POLICY_VERSION,
        generated_at_ms: now_ms,
        subjects: vec![AuthzSubjectAccessSnapshot {
            tenant_id: TENANT_ID.to_string(),
            subject: test_subject(),
            assignments: Vec::new(),
            subject_parents: Vec::new(),
            resource_scopes: HashMap::new(),
            fetched_at_ms: now_ms,
        }],
        resources: vec![test_resource(now_ms)],
    }
}

fn test_subject() -> ApiSubject {
    ApiSubject {
        subject_type: "user".to_string(),
        id: SUBJECT_ID.to_string(),
        properties: None,
    }
}

fn test_resource(now_ms: i64) -> AuthzResourceAccessSnapshot {
    AuthzResourceAccessSnapshot {
        tenant_id: TENANT_ID.to_string(),
        resource_type: RESOURCE_TYPE.to_string(),
        resource_id: RESOURCE_ID.to_string(),
        properties: serde_json::json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: now_ms,
    }
}

fn configuration_model() -> ConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: RESOURCE_TYPE.to_string(),
            name: "Document".to_string(),
            description: None,
            actions: vec![ActionDefinition {
                name: "read".to_string(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![Permission {
            id: "document:read".to_string(),
            name: "Document Read".to_string(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: RESOURCE_TYPE.to_string(),
                action_name: "read".to_string(),
            }],
            not_actions: Vec::new(),
        }],
        roles: vec![Role {
            assignment_policy: authz_types::AccessAssignmentPolicySpec {
                assignment_mode: authz_types::AccessAssignmentMode::PermanentOrTemporary,
                maximum_duration_seconds: None,
            },
            id: ROLE_ID.to_string(),
            name: "Viewer".to_string(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:read").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: Vec::new(),
            not_actions: Vec::new(),
        }],
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
}
