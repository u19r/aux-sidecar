use sidecar_contract::native_auth::{
    NativeAuthenticationFailure, NativeOAuthErrorCode, NativeOAuthTokenFailure,
};

use crate::SidecarError;

/// Native and WASM transports preserve the same public token outcome. Status
/// and typed protocol fields classify it; descriptions never supply policy.
pub fn decode_oauth_failure(
    status: u16,
    payload: serde_json::Value,
    retry_after_seconds: Option<u32>,
) -> SidecarError {
    if status == 429 || (500..600).contains(&status) {
        let mut error = SidecarError::service_unavailable(
            "oauth_token_retry_required",
            "native token exchange is temporarily unavailable",
        );
        error.authentication = Some(Box::new(NativeAuthenticationFailure::Retry {
            retry_after_seconds,
        }));
        return error;
    }
    if !(400..500).contains(&status) {
        return SidecarError::bad_gateway(
            "oauth_token_exchange_failed",
            "native token exchange failed",
        );
    }
    let Ok(failure) = serde_json::from_value::<NativeOAuthTokenFailure>(payload) else {
        return SidecarError::bad_gateway(
            "oauth_token_response_invalid",
            "native token response is invalid",
        );
    };
    prepare_oauth_denial(status, failure)
}

fn prepare_oauth_denial(status: u16, failure: NativeOAuthTokenFailure) -> SidecarError {
    let mut error = SidecarError::with_status(
        "oauth_token_exchange_denied",
        "native token exchange was denied",
        if matches!(status, 401 | 403) {
            status
        } else {
            400
        },
    );
    error.request_id = failure.request_id;
    error.authentication = Some(Box::new(NativeAuthenticationFailure::Denied {
        error: failure.error,
    }));
    if status == 400
        && failure.error == NativeOAuthErrorCode::InvalidGrant
        && let Some(recovery) = failure.aux_recovery
    {
        error.code = recovery.code.as_str();
        error.message = "complete the native bound authentication recovery".into();
        error.authentication = Some(Box::new(NativeAuthenticationFailure::RecoveryRequired {
            recovery,
        }));
    }
    error
}

/// RequestContext contains asserted service-call metadata, not a verified
/// request-bound end-user envelope. Preserve tracing, and transmit Unknown
/// rather than reusing an old browser address or service bearer credential.
pub(crate) fn prepare_native_oauth_context(
    context: &sidecar_contract::RequestContext,
) -> sidecar_contract::RequestContext {
    sidecar_contract::RequestContext {
        authorization: None,
        client_ip: None,
        tenant_domain: context.tenant_domain.clone(),
        traceparent: context.traceparent.clone(),
        tracestate: context.tracestate.clone(),
    }
}
