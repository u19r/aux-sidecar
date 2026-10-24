use std::sync::Arc;

use futures::FutureExt;
use sidecar_contract::{
    RequestContext, RuntimeSyncKnownVersions, RuntimeSyncRequest, RuntimeSyncResponse,
};

use crate::{SidecarEngineConfig, SidecarResult, SidecarState, SidecarTransport};

pub(crate) async fn synchronize<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    mut request: RuntimeSyncRequest,
    return_response: bool,
) -> SidecarResult<Option<RuntimeSyncResponse>>
where
    T: SidecarTransport + 'static,
{
    let cached_versions = state.runtime_sync_known_versions_for(&request);
    merge_known_versions(&mut request, cached_versions);
    request.validate()?;
    let request = Arc::new(request);
    let flight_key = (Arc::clone(&request), return_response);
    let config = config.clone();
    let context = context.clone();
    let transport = Arc::clone(transport);
    let flight_state = Arc::clone(state);
    let (flight_id, future) = state.sync_flight(flight_key, || {
        #[cfg(not(target_arch = "wasm32"))]
        {
            async move {
                let response = transport.sync_runtime(&config, &context, &request).await?;
                if return_response {
                    flight_state.apply_runtime_sync(response.clone())?;
                    Ok(Some(response))
                } else {
                    flight_state.apply_runtime_sync(response)?;
                    Ok(None)
                }
            }
            .boxed()
            .shared()
        }
        #[cfg(target_arch = "wasm32")]
        {
            async move {
                let response = transport.sync_runtime(&config, &context, &request).await?;
                if return_response {
                    flight_state.apply_runtime_sync(response.clone())?;
                    Ok(Some(response))
                } else {
                    flight_state.apply_runtime_sync(response)?;
                    Ok(None)
                }
            }
            .boxed_local()
            .shared()
        }
    });
    let result = future.await;
    state.finish_sync_flight(flight_id);
    result
}

fn merge_known_versions(request: &mut RuntimeSyncRequest, cached: RuntimeSyncKnownVersions) {
    request.known.jwks = request.known.jwks.take().or(cached.jwks);
    request.known.authz_policy = request.known.authz_policy.take().or(cached.authz_policy);
    request.known.rate_limit_config = request
        .known
        .rate_limit_config
        .take()
        .or(cached.rate_limit_config);
    request.known.blocklist = request.known.blocklist.take().or(cached.blocklist);
    request.known.revocations = request.known.revocations.take().or(cached.revocations);
    for (key, version) in cached.entitlements {
        request.known.entitlements.entry(key).or_insert(version);
    }
}
