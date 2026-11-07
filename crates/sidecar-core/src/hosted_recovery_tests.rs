use sidecar_contract::{BeginHostedLoginRequest, RefreshHostedLoginRequest, RequestContext};

use crate::{
    SidecarEngine,
    engine_tests::{TestTransport, config},
};

#[tokio::test]
async fn given_library_transport_without_native_recovery_when_requested_then_capabilities_and_failure_are_explicit_without_local_issuance()
 {
    use sidecar_contract::hosted_recovery::{BeginHostedRecoveryRequest, HostedRecoveryGrant};
    let engine = SidecarEngine::new(config(), TestTransport::new());
    let case = sidecar_fixtures::native_auth::cases().remove(0);
    let recovery = serde_json::from_value(case["body"]["aux_recovery"].clone()).unwrap();
    let result = engine
        .begin_hosted_recovery(
            &RequestContext::default(),
            &BeginHostedRecoveryRequest {
                grant: HostedRecoveryGrant::RefreshToken {
                    request: RefreshHostedLoginRequest {
                        client_id: "sidecar-hosted-login".into(),
                        refresh_token: "fixture-original-source".into(),
                        scope: None,
                        resource: None,
                    },
                    recovery,
                },
                authorization: BeginHostedLoginRequest {
                    client_id: "sidecar-hosted-login".into(),
                    redirect_uri: "http://127.0.0.1:8787/callback".into(),
                    scopes: vec!["openid".into()],
                    login_hint: None,
                    resource: None,
                },
            },
        )
        .await;
    assert_eq!(result.unwrap_err().code, "hosted_recovery_unsupported");
    assert!(
        engine
            .capabilities()
            .iter()
            .any(|cap| cap.name == "hosted_recovery" && cap.state == "unsupported")
    );
    assert!(
        engine
            .capabilities()
            .iter()
            .any(|cap| cap.name == "advanced_fraud" && cap.state == "remote_only")
    );
}
