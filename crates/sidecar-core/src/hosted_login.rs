use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::random;
use sha2::{Digest, Sha256};
use sidecar_contract::{
    BeginHostedLoginRequest, BeginHostedLoginResult, CompleteHostedLoginRequest,
    CompleteHostedLoginResult, HostedLoginTokenSet, RefreshHostedLoginRequest,
    RefreshHostedLoginResult, RequestContext,
};
use url::{Host, Url};

use crate::{
    HostedLoginSession, SidecarEngineConfig, SidecarError, SidecarResult, SidecarState,
    constants::{
        HOSTED_LOGIN_RANDOM_TOKEN_BYTES, HOSTED_LOGIN_TTL_MS, MAX_HOSTED_LOGIN_CLIENT_ID_BYTES,
        MAX_HOSTED_LOGIN_FIELD_BYTES, MAX_HOSTED_LOGIN_REDIRECT_URI_BYTES,
        MAX_HOSTED_LOGIN_SCOPE_ITEMS,
    },
    state::current_time_millis,
};

pub fn begin_hosted_login(
    config: &SidecarEngineConfig,
    state: &SidecarState,
    request: &BeginHostedLoginRequest,
) -> SidecarResult<BeginHostedLoginResult> {
    let prepared = prepare_hosted_login(config, request)?;
    state.store_hosted_login_session(prepared.session);
    Ok(prepared.result)
}

pub(crate) struct PreparedHostedLogin {
    pub(crate) session: HostedLoginSession,
    pub(crate) result: BeginHostedLoginResult,
}

pub(crate) fn prepare_hosted_login(
    config: &SidecarEngineConfig,
    request: &BeginHostedLoginRequest,
) -> SidecarResult<PreparedHostedLogin> {
    validate_begin_request(request)?;
    let auth_url = authorization_url(config, request)?;
    let code_verifier = random_url_token();
    let challenge = code_challenge(&code_verifier);
    let state_token = random_url_token();
    let expires_at_ms = current_time_millis().saturating_add(HOSTED_LOGIN_TTL_MS);
    let login_url = build_login_url(auth_url, request, &state_token, &challenge)?;

    let session = HostedLoginSession {
        resource: request.resource.clone(),
        state: state_token,
        code_verifier,
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        expires_at_ms,
    };

    Ok(PreparedHostedLogin {
        session,
        result: BeginHostedLoginResult {
            login_url,
            expires_at_ms,
        },
    })
}

pub fn complete_hosted_login_form(
    state: &SidecarState,
    request: &CompleteHostedLoginRequest,
) -> SidecarResult<Vec<(&'static str, String)>> {
    let exchange = prepare_hosted_login_exchange(state, request)?;
    exchange.attempt.consume();
    Ok(exchange.fields)
}

pub(crate) struct PreparedHostedLoginExchange<'a> {
    pub(crate) attempt: crate::state::HostedLoginAttempt<'a>,
    pub(crate) fields: Vec<(&'static str, String)>,
}

pub(crate) fn prepare_hosted_login_exchange<'a>(
    state: &'a SidecarState,
    request: &CompleteHostedLoginRequest,
) -> SidecarResult<PreparedHostedLoginExchange<'a>> {
    if let Some(error) = request.error.as_deref() {
        return Err(SidecarError::unauthorized(
            "hosted_login_denied",
            request
                .error_description
                .clone()
                .unwrap_or_else(|| error.to_string()),
        ));
    }

    let code = request
        .code
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| {
            SidecarError::bad_request("hosted_login_code_missing", "code is required")
        })?;
    let attempt = crate::state::HostedLoginAttempt::try_new(state, &request.state)?;
    let session = &attempt.session;

    let mut fields = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", session.redirect_uri.clone()),
        ("client_id", session.client_id.clone()),
        ("code_verifier", session.code_verifier.clone()),
    ];
    if let Some(resource) = &session.resource {
        fields.push(("resource", resource.clone()));
    }
    Ok(PreparedHostedLoginExchange { attempt, fields })
}

pub fn complete_hosted_login_result(
    tokens: HostedLoginTokenSet,
    access_token_claims: serde_json::Value,
) -> CompleteHostedLoginResult {
    CompleteHostedLoginResult {
        tokens,
        access_token_claims,
    }
}

pub fn refresh_hosted_login_form(
    request: &RefreshHostedLoginRequest,
) -> SidecarResult<Vec<(&'static str, String)>> {
    validate_refresh_request(request)?;
    let mut fields = vec![
        ("grant_type", "refresh_token".to_string()),
        ("client_id", request.client_id.clone()),
        ("refresh_token", request.refresh_token.clone()),
    ];
    if let Some(scope) = request
        .scope
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
    {
        fields.push(("scope", scope.to_string()));
    }
    if let Some(resource) = &request.resource {
        fields.push(("resource", resource.clone()));
    }
    Ok(fields)
}

pub fn refresh_hosted_login_result(
    tokens: HostedLoginTokenSet,
    access_token_claims: serde_json::Value,
) -> RefreshHostedLoginResult {
    RefreshHostedLoginResult {
        tokens,
        access_token_claims,
    }
}

pub fn empty_context() -> RequestContext {
    RequestContext {
        authorization: None,
        client_ip: None,
        tenant_domain: None,
        traceparent: None,
        tracestate: None,
    }
}

fn validate_begin_request(request: &BeginHostedLoginRequest) -> SidecarResult<()> {
    validate_resource_indicator(request.resource.as_deref())?;
    if request.client_id.trim().is_empty() {
        return Err(SidecarError::bad_request(
            "hosted_login_client_id_missing",
            "client_id is required",
        ));
    }
    if !bounded_text(&request.client_id, MAX_HOSTED_LOGIN_CLIENT_ID_BYTES, false) {
        return Err(SidecarError::bad_request(
            "hosted_login_input_too_large",
            "hosted-login fields exceed the configured limits",
        ));
    }
    if request.redirect_uri.trim().is_empty() {
        return Err(SidecarError::bad_request(
            "hosted_login_redirect_uri_missing",
            "redirect_uri is required",
        ));
    }
    if !bounded_text(
        &request.redirect_uri,
        MAX_HOSTED_LOGIN_REDIRECT_URI_BYTES,
        false,
    ) {
        return Err(SidecarError::bad_request(
            "hosted_login_input_too_large",
            "hosted-login fields exceed the configured limits",
        ));
    }
    let redirect_uri = Url::parse(&request.redirect_uri).map_err(|err| {
        SidecarError::bad_request("hosted_login_redirect_uri_invalid", err.to_string())
    })?;
    if !redirect_uri_is_loopback(&redirect_uri) {
        return Err(SidecarError::bad_request(
            "hosted_login_redirect_uri_untrusted",
            "redirect_uri must target localhost or loopback",
        ));
    }
    if request.scopes.len() > MAX_HOSTED_LOGIN_SCOPE_ITEMS
        || request
            .scopes
            .iter()
            .any(|scope| !bounded_text(scope, MAX_HOSTED_LOGIN_FIELD_BYTES, true))
        || request
            .login_hint
            .as_deref()
            .is_some_and(|hint| !bounded_text(hint, MAX_HOSTED_LOGIN_FIELD_BYTES, false))
    {
        return Err(SidecarError::bad_request(
            "hosted_login_input_too_large",
            "hosted-login fields exceed the configured limits",
        ));
    }
    Ok(())
}

fn redirect_uri_is_loopback(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && match url.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
}

fn validate_refresh_request(request: &RefreshHostedLoginRequest) -> SidecarResult<()> {
    validate_resource_indicator(request.resource.as_deref())?;
    if request.client_id.trim().is_empty() {
        return Err(SidecarError::bad_request(
            "hosted_login_refresh_client_id_missing",
            "client_id is required",
        ));
    }
    if !bounded_text(&request.client_id, MAX_HOSTED_LOGIN_CLIENT_ID_BYTES, false) {
        return Err(SidecarError::bad_request(
            "hosted_login_input_too_large",
            "hosted-login fields exceed the configured limits",
        ));
    }
    if request.refresh_token.trim().is_empty() {
        return Err(SidecarError::bad_request(
            "hosted_login_refresh_token_missing",
            "refresh_token is required",
        ));
    }
    if !bounded_text(&request.refresh_token, MAX_HOSTED_LOGIN_FIELD_BYTES, false) {
        return Err(SidecarError::bad_request(
            "hosted_login_refresh_token_missing",
            "refresh_token is required",
        ));
    }
    if request
        .scope
        .as_deref()
        .is_some_and(|scope| !bounded_text(scope, MAX_HOSTED_LOGIN_FIELD_BYTES, false))
    {
        return Err(SidecarError::bad_request(
            "hosted_login_input_too_large",
            "hosted-login fields exceed the configured limits",
        ));
    }
    Ok(())
}

fn bounded_text(value: &str, max_bytes: usize, non_empty: bool) -> bool {
    (!non_empty || !value.trim().is_empty())
        && value.len() <= max_bytes
        && value.chars().all(|character| !character.is_control())
}

fn authorization_url(
    config: &SidecarEngineConfig,
    request: &BeginHostedLoginRequest,
) -> SidecarResult<Url> {
    let issuer = &crate::auth::require_jwt_validation_config(config)?.issuer;
    let mut url = crate::config::parse_issuer_url(issuer)?;
    url.set_path("/oauth2/authorize");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &request.client_id)
        .append_pair("redirect_uri", &request.redirect_uri);
    if let Some(resource) = &request.resource {
        url.query_pairs_mut().append_pair("resource", resource);
    }
    Ok(url)
}

fn build_login_url(
    mut url: Url,
    request: &BeginHostedLoginRequest,
    state: &str,
    code_challenge: &str,
) -> SidecarResult<String> {
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        if !request.scopes.is_empty() {
            query.append_pair("scope", &request.scopes.join(" "));
        }
        if let Some(login_hint) = request.login_hint.as_deref() {
            query.append_pair("login_hint", login_hint);
        }
    }
    Ok(url.to_string())
}

fn random_url_token() -> String {
    URL_SAFE_NO_PAD.encode(random::<[u8; HOSTED_LOGIN_RANDOM_TOKEN_BYTES]>())
}

pub(crate) fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn validate_resource_indicator(resource: Option<&str>) -> SidecarResult<()> {
    if resource
        .is_some_and(|resource| !bounded_text(resource, MAX_HOSTED_LOGIN_REDIRECT_URI_BYTES, true))
    {
        return Err(SidecarError::bad_request(
            "hosted_login_resource_invalid",
            "resource is invalid",
        ));
    }
    Ok(())
}
