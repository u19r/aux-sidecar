pub(crate) fn combined_request(client_ip: &str) -> sidecar_contract::RuntimePolicyDecisionRequest {
    sidecar_contract::RuntimePolicyDecisionRequest::from_registry_context(
        "tenant_fixture".to_string(),
        sidecar_contract::RegistryRateLimitRequest {
            repository: "team/service".to_string(),
            user_id: "user_fixture".to_string(),
            organization_id: "org_fixture".to_string(),
            client_ip: client_ip.to_string(),
            action: sidecar_contract::RegistryRateLimitAction::Pull,
            cost: 1,
            defaults: sidecar_contract::RegistryRateLimitDefaults {
                pull_limit_per_hour: 360_000,
                push_limit_per_hour: 360_000,
            },
        },
        Vec::new(),
        sidecar_contract::RegistryMetricDimensions {
            repository: "team/service".to_string(),
            user_id: "user_fixture".to_string(),
            organization_id: "org_fixture".to_string(),
            action: sidecar_contract::RegistryRateLimitAction::Pull,
            status_class: "2xx".to_string(),
            bytes: None,
        },
    )
    .unwrap()
}

pub(crate) fn request() -> RuntimeSyncRequest {
    RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::Jwks],
        authz: None,
        entitlements: Vec::new(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    }
}

pub(crate) fn config() -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: crate::DeploymentPreset::Embedded,
        base_url: "https://tenant.example.test".to_string(),
        api_key: "redacted".to_string(),
        tenant_domain: None,
        cache_ttl: Duration::from_secs(60),
        stale_cache_ttl: Duration::from_secs(300),
        authz_local_mode: LocalAuthzMode::RemoteOnly,
        authz_cache_ttl: Duration::from_secs(10),
        authz_stale_cache_ttl: Duration::from_secs(30),
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::CacheMiss,
        jwt_validation: None,
    }
}

pub(crate) fn unused<'a, T>() -> SidecarFuture<'a, T> {
    Box::pin(async { unreachable!("unused sync test transport method") })
}
use std::time::Duration;

use sidecar_contract::{RuntimeSyncKnownVersions, RuntimeSyncRequest, SyncArtifactKind};

use crate::{LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngineConfig, SidecarFuture};
