use std::sync::Arc;

use axum::{
    extract::State,
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, RETRY_AFTER, WWW_AUTHENTICATE},
    },
    response::IntoResponse,
};
use sidecar_contract::{
    ApiAction, ApiEvaluationRequest, ApiResource, ApiSubject, EntitlementDecision,
    EntitlementEvaluateRequest, RequestContext, ValidateAuthnJwtRequest,
};

use super::{header_string, request_context, safe_jwt_context};
use crate::{
    constants::{X_AUX_PROXY_STATUS, X_PROXY_ADAPTER},
    state::SidecarState,
};

pub async fn proxy_check(
    State(state): State<Arc<SidecarState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let nginx_adapter = header_string(&headers, X_PROXY_ADAPTER).as_deref() == Some("nginx");
    if headers.get_all(AUTHORIZATION).iter().count() > 1 {
        return crate::errors::sidecar_error_response(sidecar_core::SidecarError::bad_request(
            "invalid_request",
            "ambiguous authorization",
        ));
    }
    if !headers.contains_key(AUTHORIZATION) {
        return crate::errors::sidecar_error_response(sidecar_core::SidecarError::unauthorized(
            "oauth_token_missing",
            "credentials required",
        ));
    }
    let Some((scheme, token)) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
    else {
        return crate::errors::sidecar_error_response(sidecar_core::SidecarError::bad_request(
            "invalid_request",
            "ambiguous authorization",
        ));
    };
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return crate::errors::sidecar_error_response(sidecar_core::SidecarError::bad_request(
            "invalid_request",
            "ambiguous authorization",
        ));
    }
    let Some(policy) = state.proxy_policy.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let proxy_context = match proxy_request_context(&headers) {
        Ok(context) => context,
        Err(status) => return status.into_response(),
    };
    let validation = if crate::oauth_presenter::is_oauth_access_token(token) {
        let request = match crate::oauth_presenter::request_from_original_headers(
            &headers,
            state.external_base_url.as_deref(),
        ) {
            Ok(request) => request,
            Err(error) => return crate::errors::sidecar_error_response(error),
        };
        state
            .engine
            .validate_oauth_access_token(&proxy_context, &request)
            .await
    } else {
        // Registry auth-request deployments actively use platform ID tokens.
        // Preserve that signed token-use contract; it never authorizes DPoP or
        // cnf.
        if !scheme.eq_ignore_ascii_case("Bearer") || headers.contains_key("dpop") {
            return crate::errors::sidecar_error_response(
                sidecar_core::SidecarError::unauthorized(
                    "invalid_token",
                    "invalid platform presenter",
                ),
            );
        }
        state
            .engine
            .validate_authn_jwt(
                &proxy_context,
                &ValidateAuthnJwtRequest {
                    token: Some(token.to_owned()),
                },
            )
            .await
    };
    let validation = match validation {
        Ok(validation)
            if !validation
                .claims
                .get("token_type")
                .is_some_and(|value| value == "id")
                || validation.claims.get("cnf").is_none() =>
        {
            validation
        }
        Ok(_) => {
            return crate::errors::sidecar_error_response(
                sidecar_core::SidecarError::unauthorized(
                    "invalid_token",
                    "unsupported platform confirmation",
                ),
            );
        }
        Err(error) => return crate::errors::sidecar_error_response(error),
    };
    let Some(subject) = validation
        .claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !policy.entitlement_keys.is_empty() {
        let entitlements = state
            .engine
            .evaluate_entitlements(
                &proxy_context,
                &EntitlementEvaluateRequest {
                    org_id: policy.organization_id.clone(),
                    at_time: None,
                    keys: Some(policy.entitlement_keys.clone()),
                },
            )
            .await;
        match entitlements {
            Ok(result)
                if result
                    .response
                    .items
                    .iter()
                    .all(|item| matches!(item.decision, EntitlementDecision::Granted { .. })) => {}
            Ok(_) => return StatusCode::FORBIDDEN.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    let request = match policy.request(&headers, subject) {
        Ok(request) => request,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let authz = state
        .engine
        .evaluate_authz(
            &proxy_context,
            &ApiEvaluationRequest {
                subject: ApiSubject {
                    subject_type: request.subject.kind.clone(),
                    id: request.subject.id.clone(),
                    properties: None,
                },
                resource: ApiResource {
                    resource_type: request.resource.kind.clone(),
                    id: request.resource.id.clone(),
                    properties: None,
                },
                action: ApiAction {
                    name: request.action.name.clone(),
                    properties: None,
                },
                context: None,
                jwt_context: Some(safe_jwt_context(&validation.claims)),
                session_context: None,
                token_context: None,
            },
        )
        .await;
    match authz {
        Ok(result) if result.status_code == 200 && result.response.decision => {}
        Ok(result) if result.response.challenge.is_some() => {
            let challenge = result.www_authenticate.as_deref().unwrap_or("Bearer");
            let Ok(challenge) = challenge.parse::<axum::http::HeaderValue>() else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            return (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, challenge)]).into_response();
        }
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    match state.engine.decide_policy(&proxy_context, &request).await {
        Ok(response) if response.allowed => StatusCode::NO_CONTENT.into_response(),
        Ok(response) if response.retry_after_seconds.is_some() => {
            let Some(retry_after_seconds) = response.retry_after_seconds else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            match retry_after_seconds
                .to_string()
                .parse::<axum::http::HeaderValue>()
            {
                Ok(value) if nginx_adapter => {
                    let mut response = StatusCode::FORBIDDEN.into_response();
                    response.headers_mut().insert(RETRY_AFTER, value);
                    response.headers_mut().insert(
                        axum::http::HeaderName::from_static(X_AUX_PROXY_STATUS),
                        axum::http::HeaderValue::from_static("429"),
                    );
                    response
                }
                Ok(value) => {
                    (StatusCode::TOO_MANY_REQUESTS, [(RETRY_AFTER, value)]).into_response()
                }
                Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
        }
        Ok(_) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn proxy_request_context(headers: &HeaderMap) -> Result<RequestContext, StatusCode> {
    let client_ip = headers
        .get("x-original-client-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let mut context = request_context(headers);
    context.client_ip = Some(client_ip.to_string());
    Ok(context)
}
