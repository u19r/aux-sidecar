use std::time::Duration;

use sidecar_contract::RequestContext;

use super::support::{SnapshotTransport, config_with_fallback, evaluation_request};
use crate::{LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngine};

#[tokio::test]
async fn engine_enforced_mode_given_unsupported_bearer_context_then_fails_closed_without_remote() {
    let transport = SnapshotTransport::new();
    let engine = SidecarEngine::new(
        config_with_fallback(
            LocalAuthzMode::Enforced,
            LocalAuthzRemoteFallback::CacheMiss,
        ),
        transport.clone(),
    );
    let context = RequestContext {
        authorization: Some("Bearer redacted".to_string()),
        ..RequestContext::default()
    };

    let error = engine
        .evaluate_authz(&context, &evaluation_request())
        .await
        .expect_err("unsupported bearer context should fail closed");

    assert_eq!(error.code, "authz_local_bearer_context_unsupported");
    assert_eq!(transport.remote_count(), 0);
    assert_eq!(transport.policy_version_count(), 0);
    assert_eq!(transport.policy_snapshot_count(), 0);
    assert_eq!(transport.evaluation_data_count(), 0);
}

#[tokio::test]
async fn engine_enforced_mode_given_role_revoked_then_cached_allow_expires_after_ttl() {
    let transport = SnapshotTransport::new();
    let mut config =
        config_with_fallback(LocalAuthzMode::Enforced, LocalAuthzRemoteFallback::Never);
    config.authz_cache_ttl = Duration::from_millis(1);
    config.authz_stale_cache_ttl = Duration::from_millis(0);
    config.authz_refresh_after_percent = 100;
    let engine = SidecarEngine::new(config, transport.clone());

    let allowed = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect("initial enforced evaluation");

    assert!(allowed.response.decision);
    transport.revoke_subject_access();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let denied = engine
        .evaluate_authz(&RequestContext::default(), &evaluation_request())
        .await
        .expect("post-revocation enforced evaluation");

    assert!(!denied.response.decision);
    assert_eq!(transport.remote_count(), 0);
    assert!(
        transport.evaluation_data_count() >= 2,
        "expired subject snapshot should be refetched after role revocation",
    );
    assert_eq!(
        transport.policy_snapshot_count(),
        1,
        "immutable versioned policy snapshot must not be refetched after mutable TTL expiry",
    );
}
