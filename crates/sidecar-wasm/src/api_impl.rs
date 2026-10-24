use serde::{Deserialize, de::DeserializeOwned};
#[cfg(target_arch = "wasm32")]
use sidecar_contract::{
    ApiEvaluationRequest, EntitlementEvaluateRequest, RateLimitAcquireLeaseRequest,
    RateLimitCheckRequest, RateLimitGiveBackLeaseRequest, RuntimeBlocklistDecisionRequest,
    RuntimePolicyDecisionRequest, RuntimeSyncRequest,
};
use sidecar_contract::{
    BeginHostedLoginRequest, CacheStatus, CompleteHostedLoginRequest, RefreshHostedLoginRequest,
    RequestContext, ValidateAuthnJwtRequest, ValidateOAuthAccessTokenRequest,
};
use sidecar_core::{LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngine, SidecarError, auth};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{api_config::*, host::WasmHostTransport};

#[path = "api_helpers.rs"]
mod api_helpers;
use api_helpers::{
    TrustedJwtConfig, TrustedJwtConfigInput, WasmAuthnJwtRequest, WasmOAuthAccessTokenRequest,
    error_json, parse_json_input, result_json, sidecar_error_json,
};
#[cfg(target_arch = "wasm32")]
use api_helpers::{wasm_request, wasm_result};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SidecarClient {
    engine: SidecarEngine<WasmHostTransport>,
    transport: WasmHostTransport,
    trusted_jwt: Option<TrustedJwtConfig>,
    context: RequestContext,
}

impl std::fmt::Debug for SidecarClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SidecarClient")
            .field("configured", &self.trusted_jwt.is_some())
            .field("engine", &self.engine)
            .field("context_configured", &self.context.authorization.is_some())
            .finish()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SidecarClient {
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(constructor)]
    pub fn new(fetch: js_sys::Function) -> Self {
        Self::from_transport(WasmHostTransport::new(fetch))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn new() -> Self {
        Self::from_transport(WasmHostTransport::default())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = isReady))]
    pub fn is_ready(&self) -> bool {
        true
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = capabilities)]
    pub fn capabilities_js(&self) -> Result<JsValue, JsValue> {
        wasm_result::<Vec<sidecar_core::CapabilityStatus>>(Ok(self.engine.capabilities()))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn capabilities(&self) -> String {
        result_json(self.engine.capabilities())
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = live)]
    pub fn live_js(&self) -> Result<JsValue, JsValue> {
        wasm_result(Ok(self.engine.live()))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn live(&self) -> String {
        result_json(self.engine.live())
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = ready)]
    pub fn ready_js(&self) -> Result<JsValue, JsValue> {
        wasm_result(Ok(self.engine.ready()))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn ready(&self) -> String {
        result_json(self.engine.ready())
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = status)]
    pub fn status_js(&self) -> Result<JsValue, JsValue> {
        wasm_result(Ok(self.engine.status()))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn status(&self) -> String {
        result_json(self.engine.status())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = configureTrustedJwt))]
    pub fn configure_trusted_jwt(&mut self, config_json: &str) -> String {
        match parse_json_input::<TrustedJwtConfigInput>(config_json) {
            Ok(input) => {
                let config = match TrustedJwtConfig::from_input(input) {
                    Ok(config) => config,
                    Err(error) => return sidecar_error_json(error),
                };
                self.engine = SidecarEngine::new(config.engine_config(), self.transport.clone());
                self.context = RequestContext {
                    authorization: config.authorization.clone(),
                    tenant_domain: config.tenant_domain.clone(),
                    traceparent: config.traceparent.clone(),
                    tracestate: config.tracestate.clone(),
                    ..RequestContext::default()
                };
                self.trusted_jwt = Some(config);
                result_json(serde_json::json!({ "configured": true }))
            }
            Err(error) => error,
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = beginHostedLogin))]
    pub fn begin_hosted_login(&self, request_json: &str) -> String {
        let request = match parse_json_input::<BeginHostedLoginRequest>(request_json) {
            Ok(request) => request,
            Err(error) => return error,
        };
        match self.engine.begin_hosted_login(&request) {
            Ok(response) => result_json(response),
            Err(error) => sidecar_error_json(error),
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = validateAuthnJwt))]
    pub fn validate_authn_jwt(&self, request_json: &str) -> String {
        let request = match parse_json_input::<WasmAuthnJwtRequest>(request_json) {
            Ok(request) => request,
            Err(error) => return error,
        };
        let Some(trusted_jwt) = self.trusted_jwt.as_ref() else {
            return error_json(
                "wasm_trusted_jwt_missing",
                "configure trusted JWT issuer and JWKS before validating tokens",
            );
        };
        let config = trusted_jwt.engine_config();
        let token = match auth::required_authn_token(&config, &request.request) {
            Ok(token) => token,
            Err(error) => return sidecar_error_json(error),
        };
        let verifier = match auth::verifier_from_jwks(trusted_jwt.jwks.clone()) {
            Ok(verifier) => verifier,
            Err(error) => return sidecar_error_json(error),
        };
        match auth::validate_authn_jwt_static(&config, token, &verifier, CacheStatus::Miss) {
            Ok(response) => result_json(response),
            Err(error) => sidecar_error_json(error),
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = oauthChallenge))]
    pub fn oauth_challenge(&self, invalid_proof: bool) -> String {
        if invalid_proof {
            oauth_dpop::ResourceChallenge::InvalidDpopProof
        } else {
            oauth_dpop::ResourceChallenge::MissingCredentials
        }
        .render()
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = validateOAuthAccessToken))]
    pub fn validate_oauth_access_token(&self, request_json: &str) -> String {
        let request = match parse_json_input::<WasmOAuthAccessTokenRequest>(request_json) {
            Ok(request) => request,
            Err(error) => return error,
        };
        let Some(trusted_jwt) = self.trusted_jwt.as_ref() else {
            return error_json(
                "wasm_trusted_jwt_missing",
                "configure trusted JWT issuer and JWKS before validating tokens",
            );
        };
        let config = trusted_jwt.engine_config();
        let verifier = match auth::verifier_from_jwks(trusted_jwt.jwks.clone()) {
            Ok(verifier) => verifier,
            Err(error) => return sidecar_error_json(error),
        };
        match auth::validate_oauth_access_token_static(
            &config,
            &request.request,
            &verifier,
            CacheStatus::Miss,
        ) {
            Ok(response) => result_json(response),
            Err(error) => sidecar_error_json(error),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn complete_hosted_login(&self, request_json: &str) -> String {
        if let Err(error) = parse_json_input::<CompleteHostedLoginRequest>(request_json) {
            return error;
        }
        error_json(
            "wasm_host_transport_required",
            "configure the JavaScript host HTTP bridge before hosted login token exchange",
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn refresh_hosted_login(&self, request_json: &str) -> String {
        if let Err(error) = parse_json_input::<RefreshHostedLoginRequest>(request_json) {
            return error;
        }
        error_json(
            "wasm_host_transport_required",
            "configure the JavaScript host HTTP bridge before hosted login token exchange",
        )
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync_runtime(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RuntimeSyncRequest>(request)?;
        wasm_result(self.engine.sync_runtime(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = getRateLimitConfig)]
    pub async fn get_rate_limit_config(&self) -> Result<JsValue, JsValue> {
        wasm_result(self.engine.get_rate_limit_config(&self.context).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = checkRateLimit)]
    pub async fn check_rate_limit(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RateLimitCheckRequest>(request)?;
        wasm_result(self.engine.check_rate_limit(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = acquireLeases)]
    pub async fn acquire_leases(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RateLimitAcquireLeaseRequest>(request)?;
        wasm_result(self.engine.acquire_leases(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = giveBackLeases)]
    pub async fn give_back_leases(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RateLimitGiveBackLeaseRequest>(request)?;
        wasm_result(self.engine.give_back_leases(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = decideBlocklist)]
    pub async fn decide_blocklist(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RuntimeBlocklistDecisionRequest>(request)?;
        wasm_result(self.engine.decide_blocklist(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = decidePolicy)]
    pub async fn decide_policy(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RuntimePolicyDecisionRequest>(request)?;
        wasm_result(self.engine.decide_policy(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = evaluateAuthz)]
    pub async fn evaluate_authz(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<ApiEvaluationRequest>(request)?;
        wasm_result(self.engine.evaluate_authz(&self.context, &request).await)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = evaluateEntitlements)]
    pub async fn evaluate_entitlements(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<EntitlementEvaluateRequest>(request)?;
        wasm_result(
            self.engine
                .evaluate_entitlements(&self.context, &request)
                .await,
        )
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = completeHostedLogin)]
    pub async fn complete_hosted_login(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<CompleteHostedLoginRequest>(request)?;
        wasm_result(
            self.engine
                .complete_hosted_login(&self.context, &request)
                .await,
        )
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = refreshHostedLogin)]
    pub async fn refresh_hosted_login(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = wasm_request::<RefreshHostedLoginRequest>(request)?;
        wasm_result(
            self.engine
                .refresh_hosted_login(&self.context, &request)
                .await,
        )
    }
}

impl SidecarClient {
    fn from_transport(transport: WasmHostTransport) -> Self {
        Self {
            engine: SidecarEngine::new(default_config(), transport.clone()),
            transport,
            trusted_jwt: None,
            context: RequestContext::default(),
        }
    }
}
