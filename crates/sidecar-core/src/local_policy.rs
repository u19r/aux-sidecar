use std::sync::Arc;

use sha2::{Digest, Sha256};
use sidecar_contract::{
    RegistryRateLimitAction, RequestContext, RuntimeBlocklistDecisionRequest,
    RuntimePolicyDecisionRequest, RuntimePolicyDecisionResponse,
};

use crate::{SidecarEngineConfig, SidecarError, SidecarResult, SidecarState, SidecarTransport};

pub(crate) async fn decide<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: &RuntimePolicyDecisionRequest,
) -> SidecarResult<RuntimePolicyDecisionResponse>
where
    T: SidecarTransport + 'static,
{
    request.validate()?;
    let blocklist = if request.blocklist.enabled {
        let blocklist_request = blocklist_request(request)?;
        Some(
            crate::local_blocklist::decide(config, state, transport, context, &blocklist_request)
                .await?,
        )
    } else {
        None
    };
    if let Some(blocklist) = blocklist.as_ref()
        && blocklist.blocked
    {
        return Ok(RuntimePolicyDecisionResponse {
            allowed: false,
            status: "denied".to_string(),
            reason: "blocklisted".to_string(),
            retry_after_seconds: None,
            matched_policy: blocklist
                .matches
                .first()
                .and_then(|matched| matched.policy.clone()),
            policy_generation: request.policy_generation.clone(),
            controls: serde_json::json!({"blocklist": blocklist}),
        });
    }

    let mut rate_limit_controls = Vec::new();
    if request.rate_limit.enabled {
        let checks = request
            .rate_limit
            .limits
            .iter()
            .map(windowed_rate_limit)
            .collect::<SidecarResult<Vec<_>>>()?;
        let results = state.check_windowed_rate_limits(&checks);
        for result in results {
            let denied = !result.allowed;
            let retry_after_seconds = result
                .retry_after_ms
                .map(|milliseconds| milliseconds.saturating_add(999) / 1_000);
            rate_limit_controls.push(result);
            if denied {
                return Ok(RuntimePolicyDecisionResponse {
                    allowed: false,
                    status: "denied".to_string(),
                    reason: "rate_limited".to_string(),
                    retry_after_seconds,
                    matched_policy: None,
                    policy_generation: request.policy_generation.clone(),
                    controls: serde_json::json!({
                        "blocklist": blocklist,
                        "rate_limit": rate_limit_controls,
                    }),
                });
            }
        }
    }

    Ok(RuntimePolicyDecisionResponse {
        allowed: true,
        status: "allowed".to_string(),
        reason: "allowed".to_string(),
        retry_after_seconds: None,
        matched_policy: None,
        policy_generation: request.policy_generation.clone(),
        controls: serde_json::json!({
            "blocklist": blocklist,
            "rate_limit": rate_limit_controls,
        }),
    })
}

fn blocklist_request(
    request: &RuntimePolicyDecisionRequest,
) -> SidecarResult<RuntimeBlocklistDecisionRequest> {
    Ok(RuntimeBlocklistDecisionRequest {
        tenant_id: request.tenant_id.clone(),
        org_id: request.org_id.clone(),
        product_domain: "registry".to_string(),
        resource: request.resource.id.clone(),
        action: parse_action(&request.action.name)?,
        client_ip: request.network.client_ip.clone(),
        network_identity: request.network.identity.clone(),
        country: request.network.country.clone(),
        policy_refs: request.blocklist.policies.clone(),
    })
}

fn windowed_rate_limit(
    limit: &sidecar_contract::RuntimePolicyWindowedLimit,
) -> SidecarResult<crate::windowed_rate_limit::WindowedRateLimitRequest> {
    if limit.limit == 0 || limit.window_seconds == 0 || limit.cost == 0 {
        return Err(invalid_policy());
    }
    if limit.cost > limit.limit {
        return Err(invalid_policy());
    }
    let descriptor = serde_json::to_vec(&limit.descriptor).map_err(|_| invalid_policy())?;
    let key = format!("policy:{}", hex_digest(&descriptor));
    Ok(crate::windowed_rate_limit::WindowedRateLimitRequest {
        key,
        limit: limit.limit,
        window_seconds: limit.window_seconds,
        cost: limit.cost,
    })
}

fn parse_action(value: &str) -> SidecarResult<RegistryRateLimitAction> {
    match value {
        "pull" => Ok(RegistryRateLimitAction::Pull),
        "push" => Ok(RegistryRateLimitAction::Push),
        "admin" => Ok(RegistryRateLimitAction::Admin),
        "metrics" => Ok(RegistryRateLimitAction::Metrics),
        _ => Err(invalid_policy()),
    }
}

fn hex_digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invalid_policy() -> SidecarError {
    SidecarError::bad_request(
        "runtime_policy_request_invalid",
        "combined policy request is invalid",
    )
}
