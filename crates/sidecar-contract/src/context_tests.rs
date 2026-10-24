use crate::RequestContext;

#[test]
fn bearer_token_given_valid_header_then_returns_token() {
    let context = RequestContext {
        authorization: Some("Bearer token-123".to_string()),
        ..RequestContext::default()
    };

    assert_eq!(context.bearer_token().unwrap(), Some("token-123"));
}

#[test]
fn bearer_token_given_wrong_scheme_then_rejects_header() {
    let context = RequestContext {
        authorization: Some("Basic abc".to_string()),
        ..RequestContext::default()
    };

    assert!(context.bearer_token().is_err());
}
