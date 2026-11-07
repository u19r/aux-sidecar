use sidecar_contract::{BeginHostedLoginRequest, CompleteHostedLoginRequest, RequestContext};

use crate::{
    SidecarEngine,
    engine_tests::{NativeAuthTestMode, TestTransport, config},
    hosted_login::complete_hosted_login_form,
};

fn begin_attempt(engine: &SidecarEngine<TestTransport>) -> (CompleteHostedLoginRequest, String) {
    let begun = engine
        .begin_hosted_login(&BeginHostedLoginRequest {
            client_id: "fixture-client".into(),
            redirect_uri: "http://127.0.0.1:8787/callback".into(),
            scopes: vec!["openid".into()],
            resource: Some("https://api.example.test".into()),
            login_hint: None,
        })
        .unwrap();
    let url = url::Url::parse(&begun.login_url).unwrap();
    let fields = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    (
        CompleteHostedLoginRequest {
            state: fields["state"].to_string(),
            code: Some("fixture-original-code".into()),
            ..Default::default()
        },
        fields["code_challenge"].to_string(),
    )
}

fn assert_original_source(
    engine: &SidecarEngine<TestTransport>,
    request: &CompleteHostedLoginRequest,
    challenge: &str,
) {
    let fields = complete_hosted_login_form(&engine.state(), request)
        .unwrap()
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(fields["code"], "fixture-original-code");
    assert_eq!(fields["client_id"], "fixture-client");
    assert_eq!(fields["resource"], "https://api.example.test");
    assert_eq!(
        crate::hosted_login::code_challenge(&fields["code_verifier"]),
        challenge
    );
    assert!(complete_hosted_login_form(&engine.state(), request).is_err());
}

#[tokio::test]
async fn given_valid_callback_when_native_connection_fails_then_retry_preserves_original_pkce_source()
 {
    let engine = SidecarEngine::new(
        config(),
        TestTransport::with_native_auth_mode(NativeAuthTestMode::CodeUnavailable),
    );
    let (request, challenge) = begin_attempt(&engine);
    for _ in 0..2 {
        let error = engine
            .complete_hosted_login(&RequestContext::default(), &request)
            .await
            .unwrap_err();
        assert_eq!(error.code, "fixture_connection_refused");
        assert_eq!(error.status_code, 502);
    }
    assert_original_source(&engine, &request, &challenge);
}

#[tokio::test]
async fn given_valid_callback_when_exchange_is_canceled_then_original_source_is_available_again() {
    let engine = SidecarEngine::new(
        config(),
        TestTransport::with_native_auth_mode(NativeAuthTestMode::CodePending),
    );
    let (request, challenge) = begin_attempt(&engine);
    let context = RequestContext::default();
    let mut exchange = Box::pin(engine.complete_hosted_login(&context, &request));
    assert!(futures::poll!(&mut exchange).is_pending());
    assert!(complete_hosted_login_form(&engine.state(), &request).is_err());
    drop(exchange);
    assert_original_source(&engine, &request, &challenge);
}

#[tokio::test]
async fn given_original_callback_when_staging_is_canceled_then_retry_retains_exclusive_original_proof()
 {
    use sidecar_contract::hosted_recovery::{BeginHostedRecoveryRequest, HostedRecoveryGrant};
    let engine = SidecarEngine::new(
        config(),
        TestTransport::with_native_auth_mode(NativeAuthTestMode::StagePending),
    );
    let (original, challenge) = begin_attempt(&engine);
    let case = sidecar_fixtures::native_auth::cases().remove(0);
    let request = BeginHostedRecoveryRequest {
        grant: HostedRecoveryGrant::AuthorizationCode {
            state: original.state.clone(),
            code: original.code.clone().unwrap(),
            recovery: serde_json::from_value(case["body"]["aux_recovery"].clone()).unwrap(),
        },
        authorization: BeginHostedLoginRequest {
            client_id: "fixture-client".into(),
            redirect_uri: "http://127.0.0.1:8787/callback".into(),
            scopes: vec!["openid".into()],
            resource: None,
            login_hint: None,
        },
    };
    let context = RequestContext::default();
    for _ in 0..2 {
        let mut stage = Box::pin(engine.begin_hosted_recovery(&context, &request));
        assert!(futures::poll!(&mut stage).is_pending());
        assert!(complete_hosted_login_form(&engine.state(), &original).is_err());
        drop(stage);
    }
    assert_original_source(&engine, &original, &challenge);
}
