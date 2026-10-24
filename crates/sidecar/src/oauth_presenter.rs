use axum::http::{HeaderMap, Method, Uri};
use sidecar_contract::ValidateOAuthAccessTokenRequest;
use sidecar_core::{SidecarError, SidecarResult};

/// The configured external base is independent of the upstream destination.
pub(crate) fn request_from_headers(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    external_base: Option<&str>,
) -> SidecarResult<ValidateOAuthAccessTokenRequest> {
    let authorization = single_header(headers, "authorization")?.ok_or_else(|| {
        SidecarError::unauthorized("oauth_token_missing", "OAuth credentials required")
    })?;
    let (scheme, token) = authorization.split_once(' ').ok_or_else(invalid_request)?;
    if token.is_empty()
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
        || !(scheme.eq_ignore_ascii_case("Bearer") || scheme.eq_ignore_ascii_case("DPoP"))
    {
        return Err(invalid_request());
    }
    let proof = extract_proof(headers)?;
    let base = oauth_dpop::DpopTargetUri::parse_base(external_base.ok_or_else(invalid_request)?)
        .map_err(|_| invalid_request())?;
    let target = base
        .resolve_request_uri(uri)
        .map_err(|_| invalid_request())?;
    Ok(ValidateOAuthAccessTokenRequest {
        token: Some(token.to_owned()),
        scheme: scheme.to_owned(),
        proof,
        method: method.as_str().to_owned(),
        target_uri: target.as_str().to_owned(),
    })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> SidecarResult<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid_request());
    }
    value.to_str().map(Some).map_err(|_| invalid_request())
}

fn extract_proof(headers: &HeaderMap) -> SidecarResult<Option<String>> {
    let mut proofs = headers.get_all("dpop").iter();
    let Some(proof) = proofs.next() else {
        return Ok(None);
    };
    let invalid = || SidecarError::unauthorized("invalid_dpop_proof", "invalid DPoP proof");
    if proofs.next().is_some() {
        return Err(invalid());
    }
    let proof = proof.to_str().map_err(|_| invalid())?;
    if proof.is_empty()
        || proof.len() > 24 * 1024
        || proof
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
    {
        return Err(invalid());
    }
    Ok(Some(proof.to_owned()))
}

fn invalid_request() -> SidecarError {
    SidecarError::bad_request("invalid_request", "invalid request presenter")
}

/// This discriminator selects a verifier only. Each verifier authenticates its
/// own token-use claim.
pub(crate) fn is_oauth_access_token(token: &str) -> bool {
    use base64::Engine as _;
    if token.len() > sidecar_core::MAX_JWT_TOKEN_BYTES {
        return false;
    }
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(payload) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return false;
    };
    claims["token_type"] == "access_token"
}

pub(crate) fn request_from_original_headers(
    headers: &HeaderMap,
    external_base: Option<&str>,
) -> SidecarResult<ValidateOAuthAccessTokenRequest> {
    let method = single_header(headers, "x-original-method")?
        .ok_or_else(invalid_request)?
        .parse::<Method>()
        .map_err(|_| invalid_request())?;
    let uri = single_header(headers, "x-original-uri")?
        .ok_or_else(invalid_request)?
        .parse::<Uri>()
        .map_err(|_| invalid_request())?;
    request_from_headers(headers, &method, &uri, external_base)
}
