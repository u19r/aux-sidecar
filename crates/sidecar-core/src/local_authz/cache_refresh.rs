use std::sync::Arc;

use sidecar_contract::{AuthzResourceAccessSnapshot, AuthzSubjectAccessSnapshot, RequestContext};

use crate::{
    LocalAuthzFallbackReason, SidecarEngineConfig, SidecarState, SidecarTransport,
    local_authz::{
        cache::{fetch_evaluation_data, fetch_policy_version},
        cache_models::{CachedEvaluationData, OwnedEvaluationDataRequest},
        refresh::{spawn_refresh, spawn_refreshes},
    },
    state::{AuthzRefreshKey, AuthzResourceCacheKey, AuthzSubjectCacheKey},
};

pub(super) fn start_policy_version_refresh<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
) where
    T: SidecarTransport + 'static,
{
    let key = AuthzRefreshKey::PolicyVersion;
    if !state.try_begin_authz_refresh(key.clone()) {
        return;
    }
    let config = config.clone();
    let state = Arc::clone(state);
    let transport = Arc::clone(transport);
    let context = context.clone();
    spawn_refresh(key, Arc::clone(&state), async move {
        fetch_policy_version(
            &config,
            &state,
            &transport,
            &context,
            LocalAuthzFallbackReason::RefreshError,
        )
        .await
    });
}

pub(super) fn start_subject_refresh<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: OwnedEvaluationDataRequest,
    cached_resource: Arc<AuthzResourceAccessSnapshot>,
) where
    T: SidecarTransport + 'static,
{
    let key = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::from_request(
        request.tenant_id.clone(),
        request.policy_version,
        &request.subject,
    ));
    if !state.try_begin_authz_refresh(key.clone()) {
        return;
    }
    let config = config.clone();
    let state = Arc::clone(state);
    let transport = Arc::clone(transport);
    let context = context.clone();
    spawn_refresh(key, Arc::clone(&state), async move {
        let request = request.as_borrowed();
        fetch_evaluation_data(
            &config,
            &state,
            &transport,
            &context,
            request,
            CachedEvaluationData {
                subject: None,
                resource: Some(cached_resource),
            },
            LocalAuthzFallbackReason::RefreshError,
        )
        .await
    });
}

pub(super) fn start_combined_evaluation_data_refresh<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: OwnedEvaluationDataRequest,
) where
    T: SidecarTransport + 'static,
{
    let subject_key = AuthzRefreshKey::Subject(AuthzSubjectCacheKey::from_request(
        request.tenant_id.clone(),
        request.policy_version,
        &request.subject,
    ));
    let resource_key = AuthzRefreshKey::Resource(AuthzResourceCacheKey::from_request(
        request.tenant_id.clone(),
        request.policy_version,
        &request.resource,
    ));
    if !state.try_begin_authz_refresh(subject_key.clone()) {
        return;
    }
    if !state.try_begin_authz_refresh(resource_key.clone()) {
        state.finish_authz_refresh(&subject_key);
        return;
    }
    let config = config.clone();
    let state = Arc::clone(state);
    let transport = Arc::clone(transport);
    let context = context.clone();
    spawn_refreshes(
        vec![subject_key, resource_key],
        Arc::clone(&state),
        async move {
            let request = request.as_borrowed();
            fetch_evaluation_data(
                &config,
                &state,
                &transport,
                &context,
                request,
                CachedEvaluationData {
                    subject: None,
                    resource: None,
                },
                LocalAuthzFallbackReason::RefreshError,
            )
            .await
        },
    );
}

pub(super) fn start_resource_refresh<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: OwnedEvaluationDataRequest,
    cached_subject: Arc<AuthzSubjectAccessSnapshot>,
) where
    T: SidecarTransport + 'static,
{
    let key = AuthzRefreshKey::Resource(AuthzResourceCacheKey::from_request(
        request.tenant_id.clone(),
        request.policy_version,
        &request.resource,
    ));
    if !state.try_begin_authz_refresh(key.clone()) {
        return;
    }
    let config = config.clone();
    let state = Arc::clone(state);
    let transport = Arc::clone(transport);
    let context = context.clone();
    spawn_refresh(key, Arc::clone(&state), async move {
        let request = request.as_borrowed();
        fetch_evaluation_data(
            &config,
            &state,
            &transport,
            &context,
            request,
            CachedEvaluationData {
                subject: Some(cached_subject),
                resource: None,
            },
            LocalAuthzFallbackReason::RefreshError,
        )
        .await
    });
}
