use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicUsize},
};

use authz_cedar::compile_policy_bundle;
use authz_runtime::{EffectiveRoleAssignment, build_subject_parent_template};
use authz_types::{
    ActionDefinition, ConfigurationModel, Permission, PermissionActionRef, PermissionId, Role,
    RolePermission, Scope,
};
use sidecar_contract::{
    ApiAction, ApiEvaluationRequest, ApiEvaluationResponse, ApiResource, ApiSubject,
    AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest, AuthzParentRef,
    AuthzPolicySnapshot, AuthzPolicyVersionSnapshot, AuthzResourceAccessSnapshot,
    AuthzSubjectAccessSnapshot, RequestContext, UpstreamAuthzResponse,
};

use crate::{
    LocalAuthzMode, SidecarEngineConfig, SidecarFuture, SidecarTransport,
    performance_support_tests::config,
};

const TENANT_ID: &str = "tenant_perf";
const POLICY_VERSION: u64 = 7;
const SUBJECT_ID: &str = "user_perf";
const RESOURCE_TYPE: &str = "document";
const RESOURCE_ID: &str = "doc_perf";
const ROLE_ID: &str = "viewer";

#[derive(Debug, Clone)]
pub(super) struct PerfSnapshotTransport {
    fixture: Arc<AuthzFixture>,
    pub(super) remote_count: Arc<AtomicUsize>,
}

impl PerfSnapshotTransport {
    pub(super) fn new() -> Self {
        Self {
            fixture: Arc::new(AuthzFixture::new()),
            remote_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SidecarTransport for PerfSnapshotTransport {
    fn acquire_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitAcquireLeaseResponse> {
        unimplemented_future()
    }

    fn give_back_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitGiveBackLeaseResponse> {
        unimplemented_future()
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitConfig> {
        unimplemented_future()
    }

    fn decide_blocklist<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimeBlocklistDecisionResponse> {
        unimplemented_future()
    }

    fn decide_policy<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimePolicyDecisionResponse> {
        unimplemented_future()
    }

    fn evaluate_authz<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a ApiEvaluationRequest,
    ) -> SidecarFuture<'a, UpstreamAuthzResponse> {
        self.remote_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Box::pin(async {
            Ok(UpstreamAuthzResponse {
                status_code: 200,
                response: ApiEvaluationResponse {
                    decision: true,
                    challenge: None,
                    context: None,
                },
                www_authenticate: None,
            })
        })
    }

    fn load_authz_policy_version<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, AuthzPolicyVersionSnapshot> {
        let snapshot = self.fixture.policy_version.clone();
        Box::pin(async move { Ok(snapshot) })
    }

    fn load_authz_policy_snapshot<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _version: Option<u64>,
    ) -> SidecarFuture<'a, AuthzPolicySnapshot> {
        let snapshot = self.fixture.policy_snapshot.clone();
        Box::pin(async move { Ok(snapshot) })
    }

    fn load_authz_evaluation_data<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a AuthzEvaluationDataSnapshotRequest,
    ) -> SidecarFuture<'a, AuthzEvaluationDataSnapshot> {
        let snapshot = self.fixture.evaluation_data.clone();
        Box::pin(async move { Ok(snapshot) })
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, sidecar_contract::EntitlementEvaluateResponse> {
        unimplemented_future()
    }

    fn fetch_jwks<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        unimplemented_future()
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unimplemented_future()
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unimplemented_future()
    }
}

#[derive(Debug)]
pub(super) struct AuthzFixture {
    pub(super) policy_version: AuthzPolicyVersionSnapshot,
    pub(super) policy_snapshot: AuthzPolicySnapshot,
    pub(super) evaluation_data: AuthzEvaluationDataSnapshot,
}

impl AuthzFixture {
    pub(super) fn new() -> Self {
        let now_ms = crate::state::current_time_millis();
        let config = configuration_model();
        let validated = config.clone().into_validated().expect("valid config");
        let bundle = compile_policy_bundle(&validated, POLICY_VERSION).expect("compiled bundle");
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
            .into_iter()
            .map(|(key, values)| (key, values.into_iter().collect::<Vec<_>>()))
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
                config_hash: "hash_perf".to_string(),
                config: serde_json::to_value(config).expect("config json"),
                compiled_bundle: serde_json::to_value(bundle).expect("bundle json"),
                generated_at_ms: now_ms,
                max_age_seconds: None,
            },
            evaluation_data: AuthzEvaluationDataSnapshot {
                tenant_id: TENANT_ID.to_string(),
                policy_version: POLICY_VERSION,
                generated_at_ms: now_ms,
                subjects: vec![AuthzSubjectAccessSnapshot {
                    tenant_id: TENANT_ID.to_string(),
                    subject: ApiSubject {
                        subject_type: "user".to_string(),
                        id: SUBJECT_ID.to_string(),
                        properties: None,
                    },
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
                resources: vec![AuthzResourceAccessSnapshot {
                    tenant_id: TENANT_ID.to_string(),
                    resource_type: RESOURCE_TYPE.to_string(),
                    resource_id: RESOURCE_ID.to_string(),
                    properties: serde_json::json!({}),
                    resource_parents: Vec::new(),
                    fetched_at_ms: now_ms,
                }],
            },
        }
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

pub(super) fn evaluation_request() -> ApiEvaluationRequest {
    ApiEvaluationRequest {
        subject: ApiSubject {
            subject_type: "user".to_string(),
            id: SUBJECT_ID.to_string(),
            properties: None,
        },
        resource: ApiResource {
            resource_type: RESOURCE_TYPE.to_string(),
            id: RESOURCE_ID.to_string(),
            properties: None,
        },
        action: ApiAction {
            name: "read".to_string(),
            properties: None,
        },
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    }
}

pub(super) fn local_authz_config() -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: crate::DeploymentPreset::Embedded,
        authz_local_mode: LocalAuthzMode::RemoteOnly,
        ..config()
    }
}

fn unimplemented_future<'a, T>() -> SidecarFuture<'a, T> {
    Box::pin(async {
        Err(crate::SidecarError::internal(
            "not_implemented",
            "test stub",
        ))
    })
}
