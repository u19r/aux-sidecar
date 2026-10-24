use sidecar_contract::{
    ApiEvaluationRequest, AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest,
    AuthzPolicySnapshot, AuthzPolicyVersionSnapshot, EntitlementEvaluateRequest,
    EntitlementEvaluateResponse, RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseResponse,
    RateLimitConfig, RateLimitConfigResponse, RateLimitGiveBackLeaseRequest,
    RateLimitGiveBackLeaseResponse, RequestContext, RuntimeBlocklistDecisionRequest,
    RuntimeBlocklistDecisionResponse, RuntimePolicyDecisionRequest, RuntimePolicyDecisionResponse,
    RuntimeSyncRequest, RuntimeSyncResponse, TokenResponse, UpstreamAuthzResponse,
};
#[cfg(not(target_arch = "wasm32"))]
use sidecar_core::SidecarError;
use sidecar_core::{SidecarEngineConfig, SidecarFuture, SidecarTransport};

pub(crate) const MAX_WASM_REQUEST_BYTES: usize = 2 * 1024 * 1024;
#[cfg(target_arch = "wasm32")]
pub(crate) const MAX_WASM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Default))]
pub struct WasmHostTransport {
    #[cfg(target_arch = "wasm32")]
    fetch: js_sys::Function,
}

impl std::fmt::Debug for WasmHostTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WasmHostTransport")
    }
}

#[cfg(target_arch = "wasm32")]
struct BoundHostTransport<'a> {
    transport: &'a WasmHostTransport,
    config: &'a SidecarEngineConfig,
    context: &'a RequestContext,
}

#[cfg(not(target_arch = "wasm32"))]
struct BoundHostTransport<'a>(std::marker::PhantomData<&'a WasmHostTransport>);

impl WasmHostTransport {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new(fetch: js_sys::Function) -> Self {
        Self { fetch }
    }

    fn bind_request<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> BoundHostTransport<'a> {
        #[cfg(target_arch = "wasm32")]
        {
            BoundHostTransport {
                transport: self,
                config,
                context,
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (config, context);
            BoundHostTransport(std::marker::PhantomData)
        }
    }
}

impl SidecarTransport for WasmHostTransport {
    fn host_available(&self) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::{JsCast, JsValue};
            let global = js_sys::global();
            let timeout_available = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
                .ok()
                .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
                .is_some();
            let clear_timeout_available =
                js_sys::Reflect::get(&global, &JsValue::from_str("clearTimeout"))
                    .ok()
                    .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
                    .is_some();
            return timeout_available && clear_timeout_available;
        }
        #[cfg(not(target_arch = "wasm32"))]
        true
    }

    fn sync_runtime<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimeSyncRequest,
    ) -> SidecarFuture<'a, RuntimeSyncResponse> {
        self.bind_request(config, context)
            .fetch_json("POST", "/runtime/local/sync", Some(request))
    }

    fn acquire_leases<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, RateLimitAcquireLeaseResponse> {
        self.bind_request(config, context).fetch_json(
            "POST",
            "/rate-limit/runtime/leases/acquire",
            Some(request),
        )
    }

    fn give_back_leases<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, RateLimitGiveBackLeaseResponse> {
        self.bind_request(config, context).fetch_json(
            "POST",
            "/rate-limit/runtime/leases/giveback",
            Some(request),
        )
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, RateLimitConfig> {
        Box::pin(async move {
            let payload: RateLimitConfigResponse = self
                .bind_request(config, context)
                .fetch_json_value("GET", "/rate-limit/runtime/config", Option::<&()>::None)
                .await?;
            Ok(payload.into_rate_limit_config())
        })
    }

    fn decide_blocklist<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, RuntimeBlocklistDecisionResponse> {
        self.bind_request(config, context).fetch_json(
            "POST",
            "/blocklist/runtime/decision",
            Some(request),
        )
    }

    fn decide_policy<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, RuntimePolicyDecisionResponse> {
        self.bind_request(config, context).fetch_json(
            "POST",
            "/rate-limit/runtime/policy/decision",
            Some(request),
        )
    }

    fn evaluate_authz<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a ApiEvaluationRequest,
    ) -> SidecarFuture<'a, UpstreamAuthzResponse> {
        Box::pin(async move {
            let response = self
                .bind_request(config, context)
                .fetch_json_value(
                    "POST",
                    "/authz/runtime/evaluation",
                    Some(&sidecar_contract::authz::RuntimeEvaluationRequest::from(
                        request,
                    )),
                )
                .await?;
            Ok(UpstreamAuthzResponse {
                status_code: 200,
                response,
                www_authenticate: None,
            })
        })
    }

    fn load_authz_policy_version<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, AuthzPolicyVersionSnapshot> {
        self.bind_request(config, context).fetch_json(
            "GET",
            "/authz/runtime/local/policy-version",
            Option::<&()>::None,
        )
    }

    fn load_authz_policy_snapshot<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        version: Option<u64>,
    ) -> SidecarFuture<'a, AuthzPolicySnapshot> {
        Box::pin(async move {
            let path = version.map_or_else(
                || "/authz/runtime/local/policy-snapshot".to_string(),
                |version| format!("/authz/runtime/local/policy-snapshot?version={version}"),
            );
            self.bind_request(config, context)
                .fetch_json_value("GET", &path, Option::<&()>::None)
                .await
        })
    }

    fn load_authz_evaluation_data<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a AuthzEvaluationDataSnapshotRequest,
    ) -> SidecarFuture<'a, AuthzEvaluationDataSnapshot> {
        self.bind_request(config, context).fetch_json(
            "POST",
            "/authz/runtime/local/evaluation-data",
            Some(request),
        )
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        request: &'a EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, EntitlementEvaluateResponse> {
        self.bind_request(config, context).fetch_json(
            "POST",
            "/entitlements/evaluate",
            Some(request),
        )
    }

    fn fetch_jwks<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        self.bind_request(config, context).fetch_json(
            "GET",
            "/.well-known/jwks.json",
            Option::<&()>::None,
        )
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, TokenResponse> {
        self.bind_request(config, context)
            .fetch_form("/oauth2/token", form_fields)
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        config: &'a SidecarEngineConfig,
        context: &'a RequestContext,
        form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, TokenResponse> {
        self.bind_request(config, context)
            .fetch_form("/oauth2/token", form_fields)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl BoundHostTransport<'_> {
    fn fetch_json<'a, Request, Response>(
        &self,
        _method: &'a str,
        _path: &'a str,
        _request: Option<&'a Request>,
    ) -> SidecarFuture<'a, Response> {
        host_transport_required()
    }

    async fn fetch_json_value<Request, Response>(
        &self,
        _method: &str,
        _path: &str,
        _request: Option<&Request>,
    ) -> Result<Response, SidecarError> {
        host_transport_required().await
    }

    fn fetch_form<'a, Response>(
        &self,
        _path: &'static str,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, Response> {
        host_transport_required()
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn host_transport_required<'a, T>() -> SidecarFuture<'a, T> {
    Box::pin(async {
        Err(SidecarError::bad_gateway(
            "wasm_host_transport_required",
            "wasm host transport bridge is not configured",
        ))
    })
}
