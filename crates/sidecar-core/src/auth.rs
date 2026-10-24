use std::{sync::Arc, time::Duration};

use jwt_decode::{
    Clock, JwksSource, JwtDecodeError, JwtDecodeErrorKind, JwtVerifier, VerificationPolicy,
};
use sha2::{Digest, Sha256};
use sidecar_contract::{
    CacheStatus, JwtValidationResult, RequestContext, ValidateAuthnJwtRequest,
    ValidateOAuthAccessTokenRequest,
};

use crate::{MAX_JWT_TOKEN_BYTES, SidecarEngineConfig, SidecarError, SidecarResult};

pub fn missing_authn_token(config: &SidecarEngineConfig) -> SidecarError {
    let mut error = SidecarError::unauthorized("jwt_missing", "JWT token is required");
    if let Some(validation) = config.jwt_validation.as_ref()
        && let Some(redirect_url) = validation.login_redirect_url.as_ref()
    {
        error.redirect_url = Some(redirect_url.clone());
        error.redirect_reason = Some("login_required");
    }
    error
}

pub fn required_authn_token<'a>(
    config: &SidecarEngineConfig,
    request: &'a ValidateAuthnJwtRequest,
) -> SidecarResult<&'a str> {
    request
        .token
        .as_ref()
        .filter(|token| !token.trim().is_empty())
        .map(String::as_str)
        .filter(|token| token.len() <= MAX_JWT_TOKEN_BYTES)
        .ok_or_else(|| missing_authn_token(config))
}

pub fn required_oauth_token(request: &ValidateOAuthAccessTokenRequest) -> SidecarResult<&str> {
    request
        .token
        .as_ref()
        .filter(|token| !token.trim().is_empty())
        .map(String::as_str)
        .filter(|token| token.len() <= MAX_JWT_TOKEN_BYTES)
        .ok_or_else(|| SidecarError::unauthorized("oauth_token_missing", "OAuth token is required"))
}

#[derive(Debug, Clone)]
pub struct JwtValidationPolicies {
    authn: VerificationPolicy,
    oauth: Vec<VerificationPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JwtValidationCacheKey {
    issuer: String,
    resource_audiences: Vec<String>,
    audience_check_disabled: bool,
    clock_skew_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum JwtTokenKind {
    Authn,
    OAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct JwtValidationResultCacheKey {
    kind: JwtTokenKind,
    digest: [u8; 32],
}

impl JwtValidationResultCacheKey {
    pub(crate) fn from_config(
        kind: JwtTokenKind,
        token: &str,
        config: &SidecarEngineConfig,
    ) -> SidecarResult<Self> {
        let validation = require_jwt_validation_config(config)?;
        validation.validate()?;
        let mut digest = Sha256::new();
        hash_digest_part(&mut digest, token.as_bytes());
        hash_digest_part(
            &mut digest,
            config.base_url.trim_end_matches('/').as_bytes(),
        );
        hash_digest_part(
            &mut digest,
            config
                .tenant_domain
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        hash_digest_part(&mut digest, validation.issuer.as_bytes());
        for audience in validation.resource_audiences.iter().flatten() {
            hash_digest_part(&mut digest, audience.as_bytes());
        }
        digest.update([u8::from(validation.audience_check_disabled)]);
        digest.update(validation.clock_skew_seconds.to_le_bytes());
        Ok(Self {
            kind,
            digest: digest.finalize().into(),
        })
    }
}

fn hash_digest_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}

impl JwtValidationCacheKey {
    pub fn from_config(config: &SidecarEngineConfig) -> SidecarResult<Self> {
        let validation_config = require_jwt_validation_config(config)?;
        validation_config.validate()?;
        Ok(Self {
            issuer: validation_config.issuer.clone(),
            resource_audiences: validation_config
                .resource_audiences
                .clone()
                .unwrap_or_default(),
            audience_check_disabled: validation_config.audience_check_disabled,
            clock_skew_seconds: validation_config.clock_skew_seconds,
        })
    }
}

impl JwtValidationPolicies {
    pub fn from_config(config: &SidecarEngineConfig) -> SidecarResult<Self> {
        let validation_config = require_jwt_validation_config(config)?;
        validation_config.validate()?;
        let authn = authn_policy(validation_config)?;
        let oauth = oauth_policies(validation_config)?;
        Ok(Self { authn, oauth })
    }

    pub fn authn(&self) -> &VerificationPolicy {
        &self.authn
    }

    pub fn oauth(&self) -> &[VerificationPolicy] {
        &self.oauth
    }
}

pub async fn validate_authn_jwt(
    config: &SidecarEngineConfig,
    token: &str,
    verifier: &JwtVerifier,
    cache_status: CacheStatus,
) -> SidecarResult<JwtValidationResult> {
    let validation_config = require_jwt_validation_config(config)?;
    let policy = authn_policy(validation_config)?;
    validate_authn_jwt_with_policy(token, verifier, cache_status, &policy).await
}

pub async fn validate_authn_jwt_with_policy(
    token: &str,
    verifier: &JwtVerifier,
    cache_status: CacheStatus,
    policy: &VerificationPolicy,
) -> SidecarResult<JwtValidationResult> {
    let claims = verifier
        .verify_json_claims_only(token, policy)
        .await
        .map_err(map_verify_error)?;
    Ok(JwtValidationResult {
        claims,
        cache_status,
    })
}

pub async fn validate_oauth_access_token(
    config: &SidecarEngineConfig,
    request: &ValidateOAuthAccessTokenRequest,
    verifier: &JwtVerifier,
    cache_status: CacheStatus,
) -> SidecarResult<JwtValidationResult> {
    let token = required_oauth_token(request)?;
    let validation_config = require_jwt_validation_config(config)?;
    let policies = oauth_policies(validation_config)?;
    let mut last_error = None;
    for policy in policies {
        match verifier.verify_json_claims(token, &policy).await {
            Ok(verified) => {
                validate_canonical_oauth_claims(&verified.claims)?;
                validate_oauth_presenter(request, &verified.claims)?;
                return Ok(JwtValidationResult {
                    claims: verified.claims,
                    cache_status,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error
        .map(map_verify_error)
        .unwrap_or_else(|| SidecarError::bad_request("resource_audience_missing", "no audiences"));
    Err(error)
}

pub(crate) async fn verify_oauth_authority_with_policies(
    token: &str,
    verifier: &JwtVerifier,
    cache_status: CacheStatus,
    policies: &[VerificationPolicy],
) -> SidecarResult<JwtValidationResult> {
    if policies.is_empty() {
        return Err(SidecarError::bad_request(
            "resource_audience_missing",
            "at least one resource audience must be configured",
        ));
    }

    let mut last_error = None;
    for policy in policies {
        match verifier.verify_json_claims_only(token, policy).await {
            Ok(claims) => {
                validate_canonical_oauth_claims(&claims)?;
                return Ok(JwtValidationResult {
                    claims,
                    cache_status,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error
        .map(map_verify_error)
        .unwrap_or_else(|| SidecarError::bad_request("resource_audience_missing", "no audiences"));
    Err(error)
}

pub fn validate_authn_jwt_static(
    config: &SidecarEngineConfig,
    token: &str,
    verifier: &JwtVerifier,
    cache_status: CacheStatus,
) -> SidecarResult<JwtValidationResult> {
    let validation_config = require_jwt_validation_config(config)?;
    let policy = authn_policy(validation_config)?;
    let claims = verifier
        .verify_static_json_claims_only(token, &policy)
        .map_err(map_verify_error)?;
    Ok(JwtValidationResult {
        claims,
        cache_status,
    })
}

pub fn context_without_client_ip() -> RequestContext {
    RequestContext {
        authorization: None,
        client_ip: None,
        tenant_domain: None,
        traceparent: None,
        tracestate: None,
    }
}

pub fn validate_oauth_access_token_static(
    config: &SidecarEngineConfig,
    request: &ValidateOAuthAccessTokenRequest,
    verifier: &JwtVerifier,
    cache_status: CacheStatus,
) -> SidecarResult<JwtValidationResult> {
    let token = required_oauth_token(request)?;
    let validation_config = require_jwt_validation_config(config)?;
    let policies = oauth_policies(validation_config)?;
    let mut last_error = None;
    for policy in policies {
        match verifier.verify_static_json_claims_only(token, &policy) {
            Ok(claims) => {
                validate_canonical_oauth_claims(&claims)?;
                validate_oauth_presenter(request, &claims)?;
                return Ok(JwtValidationResult {
                    claims,
                    cache_status,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error
        .map(map_verify_error)
        .unwrap_or_else(|| SidecarError::bad_request("resource_audience_missing", "no audiences"));
    Err(error)
}

fn validate_canonical_oauth_claims(claims: &serde_json::Value) -> SidecarResult<()> {
    // The legacy diagnostics endpoint can explicitly disable audience checks.
    // The general HTTP proxy rejects that configuration at startup, so only the
    // audience-bearing path is held to the canonical access-token contract.
    if claims.get("aud").is_none() {
        return Ok(());
    }
    serde_json::from_value::<authz_types::OAuthAccessTokenClaims>(claims.clone())
        .map(|_| ())
        .map_err(|_| {
            SidecarError::unauthorized("oauth_claims_invalid", "invalid OAuth access-token claims")
        })
}

pub fn verifier_from_jwks(
    raw_jwks: impl std::borrow::Borrow<serde_json::Value>,
) -> SidecarResult<JwtVerifier> {
    let raw_jwks = serde_json::to_string(raw_jwks.borrow())
        .map_err(|_| SidecarError::bad_gateway("jwks_parse_failed", "JWKS serialization failed"))?;
    let jwks_source = JwksSource::json_string(raw_jwks).map_err(map_jwks_error)?;
    JwtVerifier::builder()
        .jwks_source(jwks_source)
        .clock(platform_jwt_clock())
        .build()
        .map_err(map_jwks_error)
}

#[cfg(not(target_arch = "wasm32"))]
fn platform_jwt_clock() -> Arc<dyn Clock> {
    Arc::new(jwt_decode::SystemClock)
}

#[cfg(target_arch = "wasm32")]
fn platform_jwt_clock() -> Arc<dyn Clock> {
    Arc::new(WasmClock)
}

#[cfg(target_arch = "wasm32")]
struct WasmClock;

#[cfg(target_arch = "wasm32")]
impl Clock for WasmClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + Duration::from_millis(js_sys::Date::now() as u64)
    }
}

fn authn_policy(
    validation_config: &crate::JwtValidationConfig,
) -> SidecarResult<VerificationPolicy> {
    VerificationPolicy::id_token()
        .issuer(&validation_config.issuer)
        .map_err(map_policy_error)?
        .without_audience()
        .allow_missing_issued_at()
        .leeway(Duration::from_secs(validation_config.clock_skew_seconds))
        .build()
        .map_err(map_policy_error)
}

fn oauth_policy(
    validation_config: &crate::JwtValidationConfig,
    audience: &str,
) -> SidecarResult<VerificationPolicy> {
    VerificationPolicy::access_token()
        .issuer(&validation_config.issuer)
        .map_err(map_policy_error)?
        .audience(audience)
        .map_err(map_policy_error)?
        .token_type_value("access_token")
        .allow_application_access_token_typ()
        .leeway(Duration::from_secs(validation_config.clock_skew_seconds))
        .build()
        .map_err(map_policy_error)
}

fn oauth_policies(
    validation_config: &crate::JwtValidationConfig,
) -> SidecarResult<Vec<VerificationPolicy>> {
    if validation_config.audience_check_disabled {
        return Ok(vec![oauth_policy_without_audience(validation_config)?]);
    }
    let audiences = validation_config
        .resource_audiences
        .as_deref()
        .filter(|audiences| !audiences.is_empty())
        .ok_or_else(|| {
            SidecarError::bad_request(
                "resource_audience_missing",
                "at least one resource audience must be configured",
            )
        })?;
    audiences
        .iter()
        .map(|audience| oauth_policy(validation_config, audience))
        .collect()
}

fn oauth_policy_without_audience(
    validation_config: &crate::JwtValidationConfig,
) -> SidecarResult<VerificationPolicy> {
    VerificationPolicy::access_token()
        .issuer(&validation_config.issuer)
        .map_err(map_policy_error)?
        .without_audience()
        .token_type_value("access_token")
        .allow_application_access_token_typ()
        .leeway(Duration::from_secs(validation_config.clock_skew_seconds))
        .build()
        .map_err(map_policy_error)
}

fn map_jwks_error(error: JwtDecodeError) -> SidecarError {
    match error.kind() {
        JwtDecodeErrorKind::JwksParse => {
            SidecarError::bad_gateway("jwks_parse_failed", error.to_string())
        }
        JwtDecodeErrorKind::InvalidKey => {
            SidecarError::bad_gateway("jwk_decode_failed", error.to_string())
        }
        JwtDecodeErrorKind::PolicyInvalid(_) => map_policy_error(error),
        _ => SidecarError::bad_gateway("jwks_parse_failed", error.to_string()),
    }
}

fn map_policy_error(error: JwtDecodeError) -> SidecarError {
    SidecarError::bad_request("jwt_validation_policy_invalid", error.to_string())
}

fn map_verify_error(error: JwtDecodeError) -> SidecarError {
    match error.kind() {
        JwtDecodeErrorKind::JwksParse => {
            SidecarError::bad_gateway("jwks_parse_failed", error.to_string())
        }
        JwtDecodeErrorKind::InvalidKey => {
            SidecarError::bad_gateway("jwk_decode_failed", error.to_string())
        }
        JwtDecodeErrorKind::MalformedToken | JwtDecodeErrorKind::UnsupportedHeader => {
            SidecarError::unauthorized("jwt_header_invalid", error.to_string())
        }
        _ => SidecarError::unauthorized("jwt_invalid", error.to_string()),
    }
}

pub(crate) fn require_jwt_validation_config(
    config: &SidecarEngineConfig,
) -> SidecarResult<&crate::JwtValidationConfig> {
    config.jwt_validation.as_ref().ok_or_else(|| {
        SidecarError::bad_request(
            "jwt_validation_missing",
            "JWT validation must be configured before validating tokens",
        )
    })
}

/// Runs for every protected request, independently of the JWT authority cache.
pub fn validate_oauth_presenter(
    request: &ValidateOAuthAccessTokenRequest,
    claims: &serde_json::Value,
) -> SidecarResult<()> {
    let target = oauth_dpop::DpopTargetUri::try_from(request.target_uri.as_str())
        .map_err(|_| SidecarError::bad_request("invalid_request", "invalid request target"))?;
    if request.method.parse::<http::Method>().is_err()
        || !(request.scheme.eq_ignore_ascii_case("Bearer")
            || request.scheme.eq_ignore_ascii_case("DPoP"))
    {
        return Err(SidecarError::bad_request(
            "invalid_request",
            "invalid request presenter",
        ));
    }
    let confirmation = oauth_dpop::AccessTokenConfirmation::parse(claims.get("cnf"))
        .map_err(|_| SidecarError::unauthorized("invalid_token", "invalid token confirmation"))?;
    oauth_dpop::PresenterValidationInput {
        scheme: &request.scheme,
        access_token: required_oauth_token(request)?,
        proof: request.proof.as_deref(),
        method: &request.method,
        target_uri: &target,
        confirmation: &confirmation,
        now_seconds: crate::state::current_time_millis() / 1000,
    }
    .validate()
    .map_err(|error| match error {
        oauth_dpop::DpopError::InvalidProof => {
            SidecarError::unauthorized("invalid_dpop_proof", "invalid DPoP proof")
        }
        _ => SidecarError::unauthorized("invalid_token", "invalid token presenter"),
    })
}
