use crate::{TokenResponse, native_auth::NativeOAuthTokenFailure};

#[test]
fn given_pinned_native_auth_corpus_when_decoding_public_extensions_then_recovery_and_degraded_warnings_are_typed_without_provider_text()
 {
    let cases = sidecar_fixtures::native_auth::cases();
    for case in cases {
        if case["status"] == 200 {
            let tokens: TokenResponse = serde_json::from_value(case["body"].clone()).unwrap();
            assert_eq!(
                serde_json::to_value(tokens.aux_warnings).unwrap(),
                case["expected_warnings"]
            );
        } else {
            let failure: NativeOAuthTokenFailure =
                serde_json::from_value(case["body"].clone()).unwrap();
            assert!(!format!("{failure:?}").contains("must_not_copy_provider_diagnostic"));
        }
    }
}

#[test]
fn given_missing_or_invalid_native_warning_fields_when_decoding_success_then_incomplete_evidence_cannot_become_a_clean_result()
 {
    for warning in [
        serde_json::json!({"codes":[]}),
        serde_json::json!({"codes":["unknown_evidence_is_clean"]}),
        serde_json::json!({"codes":["evaluation_warning","evaluation_degraded","evaluation_warning"]}),
    ] {
        let mut payload = serde_json::json!({"access_token":"fixture-token","token_type":"Bearer","expires_in":300});
        payload["aux_warnings"] = warning;
        assert!(serde_json::from_value::<TokenResponse>(payload).is_err());
    }
}
