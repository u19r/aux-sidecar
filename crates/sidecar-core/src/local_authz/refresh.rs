use std::sync::Arc;

use crate::{SidecarResult, SidecarState, state::AuthzRefreshKey};

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn spawn_refresh<T, F>(key: AuthzRefreshKey, state: Arc<SidecarState>, future: F)
where
    T: Send + 'static,
    F: std::future::Future<Output = SidecarResult<T>> + Send + 'static,
{
    spawn_refreshes(vec![key], state, future);
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn spawn_refreshes<T, F>(keys: Vec<AuthzRefreshKey>, state: Arc<SidecarState>, future: F)
where
    T: Send + 'static,
    F: std::future::Future<Output = SidecarResult<T>> + Send + 'static,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        for key in &keys {
            state.finish_authz_refresh(key);
        }
        tracing::debug!(
            "local AuthZ background refresh skipped because no Tokio runtime is active"
        );
        return;
    };

    handle.spawn(async move {
        if let Err(error) = future.await {
            tracing::warn!(code = error.code, "local AuthZ background refresh failed");
        }
        for key in &keys {
            state.finish_authz_refresh(key);
        }
    });
}

#[cfg(target_arch = "wasm32")]
pub(super) fn spawn_refresh<T, F>(key: AuthzRefreshKey, state: Arc<SidecarState>, _future: F)
where F: std::future::Future<Output = SidecarResult<T>> + 'static {
    state.finish_authz_refresh(&key);
}

#[cfg(target_arch = "wasm32")]
pub(super) fn spawn_refreshes<T, F>(
    keys: Vec<AuthzRefreshKey>,
    state: Arc<SidecarState>,
    _future: F,
) where
    F: std::future::Future<Output = SidecarResult<T>> + 'static,
{
    for key in &keys {
        state.finish_authz_refresh(key);
    }
}
