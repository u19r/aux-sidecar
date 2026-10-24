use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::{self, Body},
    extract::{Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
};
use sidecar_contract::{
    ApiAction, ApiEvaluationRequest, ApiResource, ApiSubject, ValidateOAuthAccessTokenRequest,
};
use sidecar_core::route_policy::{RouteAuthn, RouteAuthnMode, RouteAuthz};

use super::{request_context, safe_jwt_context};
use crate::state::SidecarState;

/// Forward an HTTP request only after the immutable route policy has selected
/// an operation and every configured authentication/authorization condition has
/// succeeded. This path deliberately forwards the caller's bearer value
/// unchanged; it never emits a substitute identity header.
pub async fn proxy_request(State(state): State<Arc<SidecarState>>, request: Request) -> Response {
    let Some(upstream_url) = state.upstream_url.as_deref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let Some(SelectedRoute {
        authn,
        authz,
        operation_id,
        method,
        captures,
    }) = selected_route(&state, &parts)
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match authorize_route(
        &state,
        &parts,
        &authn,
        authz.as_ref(),
        &operation_id,
        &method,
        &captures,
    )
    .await
    {
        Ok(_) => {}
        Err(response) => return *response,
    }
    let request_body = match body::to_bytes(body, crate::constants::MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let url = match upstream_request_url(upstream_url, &parts.uri) {
        Ok(url) => url,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let method = match http_request::reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let mut outbound = state.proxy_http.request(method, url);
    for (name, value) in &parts.headers {
        if is_hop_by_hop(name.as_str()) || name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        let Ok(value) = http_request::reqwest::header::HeaderValue::from_bytes(value.as_bytes())
        else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        outbound = outbound.header(name.as_str(), value);
    }
    let response = match outbound.body(request_body).send().await {
        Ok(response) => response,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > crate::constants::MAX_UPSTREAM_RESPONSE_BYTES as u64)
    {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let response_headers = response.headers().clone();
    let response_body = match response.bytes().await {
        Ok(body) if body.len() <= crate::constants::MAX_UPSTREAM_RESPONSE_BYTES => body,
        _ => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mut builder = Response::builder().status(status.as_u16());
    for (name, value) in &response_headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    builder
        .body(Body::from(response_body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

fn selected_route(
    state: &SidecarState,
    parts: &axum::http::request::Parts,
) -> Option<SelectedRoute> {
    if let Some(policy) = state.route_policy.as_ref() {
        let matched = policy.match_route(parts.method.as_str(), parts.uri.path())?;
        return Some(SelectedRoute {
            authn: matched.operation.authn.clone(),
            authz: matched.operation.authz.clone(),
            operation_id: matched.operation.operation_id.clone().unwrap_or_default(),
            method: parts.method.as_str().to_ascii_lowercase(),
            captures: matched.captures,
        });
    }
    Some(SelectedRoute {
        authn: RouteAuthn {
            mode: RouteAuthnMode::Bearer,
            audiences: state.whole_upstream_audiences.clone(),
        },
        authz: None,
        operation_id: String::new(),
        method: parts.method.as_str().to_ascii_lowercase(),
        captures: BTreeMap::new(),
    })
}

struct SelectedRoute {
    authn: RouteAuthn,
    authz: Option<RouteAuthz>,
    operation_id: String,
    method: String,
    captures: BTreeMap<String, String>,
}

async fn authorize_route(
    state: &SidecarState,
    parts: &axum::http::request::Parts,
    authn: &RouteAuthn,
    authz: Option<&RouteAuthz>,
    operation_id: &str,
    method: &str,
    captures: &BTreeMap<String, String>,
) -> Result<Option<serde_json::Value>, Box<Response>> {
    let headers = &parts.headers;
    let presented = if headers.contains_key(AUTHORIZATION) {
        Some(
            crate::oauth_presenter::request_from_headers(
                headers,
                &parts.method,
                &parts.uri,
                state.external_base_url.as_deref(),
            )
            .map_err(|error| Box::new(crate::errors::sidecar_error_response(error)))?,
        )
    } else {
        None
    };
    let token = presented.as_ref();
    let claims = match (authn.mode, token) {
        (RouteAuthnMode::Public, None) => None,
        (RouteAuthnMode::Public, Some(token)) => {
            let claims = validate_proxy_token(state, headers, token).await?;
            check_revocation(state, headers, &claims, &state.whole_upstream_audiences).await?;
            Some(claims)
        }
        (RouteAuthnMode::Bearer, None) => {
            return Err(unauthorized_response(
                oauth_dpop::ResourceChallenge::MissingCredentials,
            ));
        }
        (RouteAuthnMode::Bearer, Some(token)) => {
            let claims = validate_proxy_token(state, headers, token).await?;
            if !audience_matches(&claims, &authn.audiences) {
                return Err(unauthorized_response(
                    oauth_dpop::ResourceChallenge::InvalidToken,
                ));
            }
            check_revocation(state, headers, &claims, &authn.audiences).await?;
            Some(claims)
        }
    };
    let Some(authz) = authz else {
        return Ok(claims);
    };
    let Some(claims) = claims.as_ref() else {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    };
    if !scopes_satisfy(claims, &authz.required_scopes)
        || authz
            .claims
            .as_ref()
            .is_some_and(|predicate| !predicate.evaluate(claims))
    {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    if let Some(templates) = authz.decision.as_ref() {
        let subject = claims.get("sub").and_then(serde_json::Value::as_str);
        let Some(subject) = subject.filter(|value| !value.is_empty()) else {
            return Err(unauthorized_response(
                oauth_dpop::ResourceChallenge::InvalidToken,
            ));
        };
        let action = templates
            .action
            .as_deref()
            .map(|template| render_template(template, operation_id, method, captures))
            .transpose()
            .map_err(|_| Box::new(StatusCode::FORBIDDEN.into_response()))?
            .unwrap_or_else(|| {
                if operation_id.is_empty() {
                    method.to_string()
                } else {
                    operation_id.to_string()
                }
            });
        let resource = templates
            .resource
            .as_deref()
            .map(|template| render_template(template, operation_id, method, captures))
            .transpose()
            .map_err(|_| Box::new(StatusCode::FORBIDDEN.into_response()))?
            .unwrap_or_else(|| format!("http_route:{method}"));
        let (resource_type, resource_id) = resource
            .split_once(':')
            .map_or(("http_route", resource.as_str()), |(kind, id)| (kind, id));
        let subject_type = claims
            .get("principal_type")
            .and_then(serde_json::Value::as_str)
            .filter(|value| matches!(*value, "user" | "service_principal"))
            .unwrap_or_else(|| {
                if subject.starts_with("sp_") {
                    "service_principal"
                } else {
                    "user"
                }
            });
        let result = state
            .engine
            .evaluate_authz(
                &request_context(headers),
                &ApiEvaluationRequest {
                    subject: ApiSubject {
                        subject_type: subject_type.to_string(),
                        id: subject.to_string(),
                        properties: None,
                    },
                    resource: ApiResource {
                        resource_type: resource_type.to_string(),
                        id: resource_id.to_string(),
                        properties: None,
                    },
                    action: ApiAction {
                        name: action,
                        properties: None,
                    },
                    context: None,
                    jwt_context: Some(safe_jwt_context(claims)),
                    session_context: None,
                    token_context: None,
                },
            )
            .await
            .map_err(|_| Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        if result.status_code == 401 || result.response.challenge.is_some() {
            return Err(unauthorized_response(
                oauth_dpop::ResourceChallenge::MissingCredentials,
            ));
        }
        if result.status_code >= 500 {
            return Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()));
        }
        if result.status_code != 200 || !result.response.decision {
            return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
        }
    }
    Ok(Some(claims.clone()))
}

async fn check_revocation(
    state: &SidecarState,
    headers: &HeaderMap,
    claims: &serde_json::Value,
    audiences: &[String],
) -> Result<(), Box<Response>> {
    state
        .engine
        .ensure_revocation_snapshot(&request_context(headers))
        .await
        .map_err(|_| Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
    let jti = claims
        .get("jti")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unauthorized_response(oauth_dpop::ResourceChallenge::InvalidToken))?;
    match state.engine.state().revocation_lookup_for_audiences(
        audiences,
        jti,
        sidecar_core::current_time_millis(),
    ) {
        sidecar_core::RevocationLookup::Revoked => Err(unauthorized_response(
            oauth_dpop::ResourceChallenge::InvalidToken,
        )),
        sidecar_core::RevocationLookup::Unavailable => {
            Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))
        }
        sidecar_core::RevocationLookup::NotRevoked | sidecar_core::RevocationLookup::Stale => {
            Ok(())
        }
    }
}

async fn validate_proxy_token(
    state: &SidecarState,
    headers: &HeaderMap,
    request: &ValidateOAuthAccessTokenRequest,
) -> Result<serde_json::Value, Box<Response>> {
    state
        .engine
        .validate_oauth_access_token(&request_context(headers), request)
        .await
        .map(|result| result.claims)
        .map_err(|error| Box::new(crate::errors::sidecar_error_response(error)))
}

fn audience_matches(claims: &serde_json::Value, required: &[String]) -> bool {
    let audiences = claims.get("aud").map(|audience| match audience {
        serde_json::Value::String(value) => vec![value.as_str()],
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect(),
        _ => Vec::new(),
    });
    let Some(audiences) = audiences else {
        return false;
    };
    !required.is_empty()
        && required
            .iter()
            .any(|required| audiences.iter().any(|actual| actual == required))
}

fn scopes_satisfy(claims: &serde_json::Value, required: &[String]) -> bool {
    let scopes = claims
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .map(|value| {
            value
                .split_whitespace()
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    required.iter().all(|scope| scopes.contains(scope.as_str()))
}

fn render_template(
    template: &str,
    operation_id: &str,
    method: &str,
    captures: &BTreeMap<String, String>,
) -> Result<String, ()> {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some((literal, after_open)) = rest.split_once('{') {
        output.push_str(literal);
        let (name, after_close) = after_open.split_once('}').ok_or(())?;
        let value = match name {
            "operation_id" => operation_id,
            "method" => method,
            name => captures.get(name).map(String::as_str).ok_or(())?,
        };
        output.push_str(value);
        rest = after_close;
    }
    output.push_str(rest);
    (!output.is_empty()).then_some(output).ok_or(())
}

fn upstream_request_url(upstream: &str, uri: &axum::http::Uri) -> Result<String, ()> {
    let mut url = upstream.trim_end_matches('/').to_string();
    url.push_str(uri.path());
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    Ok(url)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn unauthorized_response(challenge: oauth_dpop::ResourceChallenge) -> Box<Response> {
    Box::new(
        (
            StatusCode::UNAUTHORIZED,
            [(WWW_AUTHENTICATE, challenge.render())],
        )
            .into_response(),
    )
}
