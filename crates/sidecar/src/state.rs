use std::sync::Arc;

use sidecar_core::{CompiledRoutePolicy, SidecarEngine};

use crate::{config::SidecarConfig, transport::NativeSidecarTransport};

#[derive(Debug, Clone)]
pub struct SidecarState {
    pub engine: Arc<SidecarEngine<NativeSidecarTransport>>,
    pub proxy_policy: Option<Arc<crate::proxy::ProxyPolicyConfig>>,
    /// Immutable route policy compiled once before the listener accepts
    /// traffic.
    pub route_policy: Option<Arc<CompiledRoutePolicy>>,
    /// HTTP upstream for the general route-aware/whole-upstream proxy.
    pub upstream_url: Option<String>,
    pub external_base_url: Option<String>,
    /// Configured audiences used by whole-upstream validation and supplied
    /// bearer checks.
    pub whole_upstream_audiences: Vec<String>,
    pub(crate) proxy_http: http_request::reqwest::Client,
}

pub fn build_state(config: SidecarConfig) -> Result<Arc<SidecarState>, String> {
    config.validate()?;
    let proxy_policy = config
        .proxy_policy_path
        .as_deref()
        .map(crate::proxy::ProxyPolicyConfig::load)
        .transpose()?
        .map(Arc::new);
    let route_policy = config
        .route_policy_path
        .as_deref()
        .map(|path| {
            let source = std::fs::read(path).map_err(|error| {
                format!("failed to read route policy {}: {error}", path.display())
            })?;
            CompiledRoutePolicy::compile(&source)
                .map(Arc::new)
                .map_err(|error| {
                    format!("failed to compile route policy {}: {error}", path.display())
                })
        })
        .transpose()?;
    if let Some(policy) = route_policy.as_ref() {
        for operation in policy.operations() {
            if matches!(
                operation.authn.mode,
                sidecar_core::route_policy::RouteAuthnMode::Bearer
            ) && (config.audience_check_disabled
                || operation.authn.audiences.iter().any(|audience| {
                    !config
                        .resource_audiences
                        .iter()
                        .any(|configured| configured == audience)
                }))
            {
                return Err(
                    "route policy audience is not configured for OAuth validation".to_string(),
                );
            }
        }
    }
    let transport = NativeSidecarTransport::new(config.config_path.clone());
    let proxy_http = transport.http.clone();
    let proxy_audiences = config.resource_audiences.clone();
    let engine = Arc::new(SidecarEngine::new(config.engine_config(), transport));
    if config.upstream_url.is_some() {
        engine.state().mark_revocation_required(proxy_audiences);
    }
    Ok(Arc::new(SidecarState {
        engine,
        proxy_policy,
        route_policy,
        upstream_url: config.upstream_url,
        external_base_url: config.external_base_url,
        whole_upstream_audiences: config.resource_audiences,
        proxy_http,
    }))
}
