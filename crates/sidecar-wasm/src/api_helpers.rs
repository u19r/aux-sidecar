use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct WasmAuthnJwtRequest {
    pub(super) request: ValidateAuthnJwtRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct WasmOAuthAccessTokenRequest {
    pub(super) request: ValidateOAuthAccessTokenRequest,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct TrustedJwtConfigInput {
    pub(super) jwks: serde_json::Value,
    pub(super) issuer: String,
    #[serde(default)]
    pub(super) base_url: Option<String>,
    #[serde(default)]
    pub(super) resource_audiences: Vec<String>,
    #[serde(default)]
    pub(super) api_key: String,
    #[serde(default)]
    pub(super) tenant_domain: Option<String>,
    #[serde(default)]
    pub(super) authorization: Option<String>,
    #[serde(default)]
    pub(super) authz_local_mode: Option<String>,
    #[serde(default)]
    pub(super) authz_remote_fallback: Option<String>,
    #[serde(default)]
    pub(super) traceparent: Option<String>,
    #[serde(default)]
    pub(super) tracestate: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct TrustedJwtConfig {
    pub(super) jwks: serde_json::Value,
    pub(super) issuer: String,
    pub(super) base_url: String,
    pub(super) resource_audiences: Vec<String>,
    pub(super) api_key: String,
    pub(super) tenant_domain: Option<String>,
    pub(super) authorization: Option<String>,
    pub(super) authz_local_mode: LocalAuthzMode,
    pub(super) authz_remote_fallback: LocalAuthzRemoteFallback,
    pub(super) traceparent: Option<String>,
    pub(super) tracestate: Option<String>,
}

impl TrustedJwtConfig {
    pub(super) fn engine_config(&self) -> sidecar_core::SidecarEngineConfig {
        sidecar_core::SidecarEngineConfig {
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
            tenant_domain: self.tenant_domain.clone(),
            authz_local_mode: self.authz_local_mode,
            authz_remote_fallback: self.authz_remote_fallback,
            jwt_validation: Some(sidecar_core::JwtValidationConfig {
                issuer: self.issuer.clone(),
                login_redirect_url: None,
                resource_audiences: Some(self.resource_audiences.clone()),
                audience_check_disabled: false,
                clock_skew_seconds: crate::constants::DEFAULT_JWT_CLOCK_SKEW_SECONDS,
            }),
            ..default_config()
        }
    }

    pub(super) fn from_input(input: TrustedJwtConfigInput) -> sidecar_core::SidecarResult<Self> {
        sidecar_core::config::parse_issuer_url(&input.issuer)?;
        Ok(Self {
            jwks: input.jwks,
            issuer: input.issuer,
            base_url: validate_base_url(input.base_url)?,
            resource_audiences: validate_resource_audiences(input.resource_audiences)?,
            api_key: validate_optional_config_string(
                (!input.api_key.is_empty()).then_some(input.api_key),
                "wasm_api_key_invalid",
            )?
            .unwrap_or_default(),
            tenant_domain: validate_optional_config_string(
                input.tenant_domain,
                "wasm_tenant_domain_invalid",
            )?,
            authorization: validate_optional_config_string(
                input.authorization,
                "wasm_authorization_invalid",
            )?,
            authz_local_mode: parse_authz_local_mode(input.authz_local_mode.as_deref())?,
            authz_remote_fallback: parse_authz_remote_fallback(
                input.authz_remote_fallback.as_deref(),
            )?,
            traceparent: validate_optional_config_string(
                input.traceparent,
                "wasm_traceparent_invalid",
            )?,
            tracestate: validate_optional_config_string(
                input.tracestate,
                "wasm_tracestate_invalid",
            )?,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for SidecarClient {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn result_json<T>(value: T) -> String
where T: serde::Serialize {
    serde_json::to_string(&value).unwrap_or_else(|_| {
        error_json(
            "wasm_response_encode_failed",
            "failed to encode wasm response",
        )
    })
}

pub(super) fn parse_json_input<T>(raw: &str) -> Result<T, String>
where T: DeserializeOwned {
    if raw.len() > crate::host::MAX_WASM_REQUEST_BYTES {
        return Err(error_json(
            "wasm_request_too_large",
            "request exceeds the configured byte limit",
        ));
    }
    serde_json::from_str(raw).map_err(|_| {
        error_json(
            "wasm_request_decode_failed",
            "request does not match the public sidecar contract",
        )
    })
}

pub(super) fn sidecar_error_json(error: SidecarError) -> String {
    serde_json::to_string(&serde_json::json!({
        "code": error.code, "message": error.message, "status_code": error.status_code,
        "www_authenticate": error.oauth_challenge(),
    }))
    .unwrap_or_else(|_| error_json("wasm_error_encode_failed", "failed to encode error"))
}

pub(super) fn error_json(code: &'static str, message: impl Into<String>) -> String {
    let fallback =
        "{\"code\":\"wasm_error_encode_failed\",\"message\":\"failed to encode wasm error\"}";
    serde_json::to_string(&serde_json::json!({
        "code": code,
        "message": message.into(),
    }))
    .unwrap_or_else(|_| fallback.to_string())
}

#[cfg(target_arch = "wasm32")]
pub(super) fn wasm_request<T>(value: JsValue) -> Result<T, JsValue>
where T: serde::de::DeserializeOwned {
    let json = js_sys::JSON::stringify(&value)
        .map_err(|_| {
            JsValue::from_str(&error_json(
                "wasm_request_decode_failed",
                "request is not JSON",
            ))
        })?
        .as_string()
        .ok_or_else(|| {
            JsValue::from_str(&error_json(
                "wasm_request_decode_failed",
                "request is not a JSON object",
            ))
        })?;
    if json.len() > crate::host::MAX_WASM_REQUEST_BYTES {
        return Err(JsValue::from_str(&error_json(
            "wasm_request_too_large",
            "request exceeds the configured byte limit",
        )));
    }
    serde_json::from_str(&json).map_err(|_| {
        JsValue::from_str(&error_json(
            "wasm_request_decode_failed",
            "request object does not match the public sidecar contract",
        ))
    })
}

#[cfg(target_arch = "wasm32")]
pub(super) fn wasm_result<T>(result: sidecar_core::SidecarResult<T>) -> Result<JsValue, JsValue>
where T: serde::Serialize {
    match result {
        Ok(value) => value
            .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
            .map_err(|_| {
                JsValue::from_str(&error_json(
                    "wasm_response_encode_failed",
                    "response object could not be encoded",
                ))
            }),
        Err(error) => Err(JsValue::from_str(&sidecar_error_json(error))),
    }
}
