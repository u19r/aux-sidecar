use std::sync::Arc;

use sidecar_contract::{
    AuthzEvaluationDataSnapshot, AuthzEvaluationDataSnapshotRequest, AuthzPolicySnapshot,
    AuthzPolicyVersionSnapshot, AuthzResourceAccessSnapshot, AuthzResourceAccessSnapshotRequest,
    AuthzSubjectAccessSnapshot, AuthzSubjectAccessSnapshotRequest, CacheStatus, RequestContext,
};

use crate::{
    LocalAuthzFallbackReason, SidecarEngineConfig, SidecarError, SidecarResult, SidecarState,
    SidecarTransport,
    local_authz::{
        cache_models::{CachedEvaluationData, EvaluationDataRequest, OwnedEvaluationDataRequest},
        cache_refresh::{
            start_combined_evaluation_data_refresh, start_policy_version_refresh,
            start_resource_refresh, start_subject_refresh,
        },
        sync::{sync_authz_evaluation_data, sync_authz_policy},
    },
    state::{
        AuthzCachedValueState, AuthzResourceCacheKey, AuthzSubjectCacheKey, current_time_millis,
    },
};

pub(super) async fn load_policy_version<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    cache_summary: &mut LocalAuthzCacheSummary,
) -> SidecarResult<AuthzPolicyVersionSnapshot>
where
    T: SidecarTransport + 'static,
{
    let now_ms = current_time_millis();
    match state.authz_policy_version(now_ms) {
        Some((snapshot, AuthzCachedValueState::Fresh)) => {
            cache_summary.observe_cached(AuthzCachedValueState::Fresh);
            Ok(snapshot)
        }
        Some((snapshot, AuthzCachedValueState::RefreshDue)) => {
            cache_summary.observe_cached(AuthzCachedValueState::RefreshDue);
            start_policy_version_refresh(config, state, transport, context);
            Ok(snapshot)
        }
        Some((_, AuthzCachedValueState::Stale)) => {
            cache_summary.observe_miss();
            fetch_policy_version(
                config,
                state,
                transport,
                context,
                LocalAuthzFallbackReason::RefreshError,
            )
            .await
        }
        None => {
            cache_summary.observe_miss();
            fetch_policy_version(
                config,
                state,
                transport,
                context,
                LocalAuthzFallbackReason::CacheMiss,
            )
            .await
        }
    }
}

pub(super) async fn fetch_policy_version<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    fallback_reason: LocalAuthzFallbackReason,
) -> SidecarResult<AuthzPolicyVersionSnapshot>
where
    T: SidecarTransport + 'static,
{
    if let Some((version, policy)) = sync_authz_policy(config, state, transport, context).await? {
        state.store_authz_policy_snapshot(policy);
        state.store_authz_policy_version(
            version.clone(),
            config.authz_cache_ttl,
            config.authz_stale_cache_ttl,
            config.authz_refresh_after_percent,
        );
        return Ok(version);
    }
    let snapshot = transport
        .load_authz_policy_version(config, context)
        .await
        .map_err(|error| error.with_local_authz_fallback_reason(fallback_reason))?;
    state.store_authz_policy_version(
        snapshot.clone(),
        config.authz_cache_ttl,
        config.authz_stale_cache_ttl,
        config.authz_refresh_after_percent,
    );
    Ok(snapshot)
}

pub(super) async fn load_policy_snapshot<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    version: u64,
    cache_summary: &mut LocalAuthzCacheSummary,
) -> SidecarResult<Arc<AuthzPolicySnapshot>>
where
    T: SidecarTransport + 'static,
{
    let now_ms = current_time_millis();
    if let Some((snapshot, _)) = state.authz_policy_snapshot(version, now_ms) {
        cache_summary.observe_cached(AuthzCachedValueState::Fresh);
        return Ok(snapshot);
    }
    cache_summary.observe_miss();
    fetch_policy_snapshot(
        config,
        state,
        transport,
        context,
        version,
        LocalAuthzFallbackReason::CacheMiss,
    )
    .await
}

async fn fetch_policy_snapshot<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    version: u64,
    fallback_reason: LocalAuthzFallbackReason,
) -> SidecarResult<Arc<AuthzPolicySnapshot>>
where
    T: SidecarTransport + 'static,
{
    let snapshot = Arc::new(
        match sync_authz_policy(config, state, transport, context).await? {
            Some((policy_version, snapshot)) => {
                state.store_authz_policy_version(
                    policy_version,
                    config.authz_cache_ttl,
                    config.authz_stale_cache_ttl,
                    config.authz_refresh_after_percent,
                );
                snapshot
            }
            None => transport
                .load_authz_policy_snapshot(config, context, Some(version))
                .await
                .map_err(|error| error.with_local_authz_fallback_reason(fallback_reason))?,
        },
    );
    if snapshot.policy_version != version {
        return Err(SidecarError::bad_gateway(
            "authz_policy_snapshot_version_mismatch",
            "policy snapshot version does not match requested version",
        ));
    }
    state.store_authz_policy_snapshot(Arc::clone(&snapshot));
    Ok(snapshot)
}

pub(super) async fn load_evaluation_data<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: EvaluationDataRequest<'_>,
    cache_summary: &mut LocalAuthzCacheSummary,
) -> SidecarResult<(
    Arc<AuthzSubjectAccessSnapshot>,
    Arc<AuthzResourceAccessSnapshot>,
)>
where
    T: SidecarTransport + 'static,
{
    let now_ms = current_time_millis();
    let subject_key = AuthzSubjectCacheKey::from_request(
        request.tenant_id.to_string(),
        request.policy_version,
        request.subject,
    );
    let resource_key = AuthzResourceCacheKey::from_request(
        request.tenant_id.to_string(),
        request.policy_version,
        request.resource,
    );
    let subject = state.authz_subject_access(&subject_key, now_ms);
    let resource = state.authz_resource_access(&resource_key, now_ms);

    let subject = usable_snapshot(subject, cache_summary);
    let resource = usable_snapshot(resource, cache_summary);
    if let (Some((subject_value, subject_state)), Some((resource_value, resource_state))) =
        (subject.as_ref(), resource.as_ref())
    {
        match (*subject_state, *resource_state) {
            (AuthzCachedValueState::RefreshDue, AuthzCachedValueState::RefreshDue) => {
                start_combined_evaluation_data_refresh(
                    config,
                    state,
                    transport,
                    context,
                    OwnedEvaluationDataRequest::from(request),
                );
            }
            (AuthzCachedValueState::RefreshDue, _) => start_subject_refresh(
                config,
                state,
                transport,
                context,
                OwnedEvaluationDataRequest::from(request),
                resource_value.clone(),
            ),
            (_, AuthzCachedValueState::RefreshDue) => start_resource_refresh(
                config,
                state,
                transport,
                context,
                OwnedEvaluationDataRequest::from(request),
                subject_value.clone(),
            ),
            _ => {}
        }
        return Ok((subject_value.clone(), resource_value.clone()));
    }

    cache_summary.observe_miss();
    let fallback_reason = if subject.is_some() || resource.is_some() {
        LocalAuthzFallbackReason::RefreshError
    } else {
        LocalAuthzFallbackReason::CacheMiss
    };
    fetch_evaluation_data(
        config,
        state,
        transport,
        context,
        request,
        CachedEvaluationData {
            subject: subject.map(|(value, _)| value),
            resource: resource.map(|(value, _)| value),
        },
        fallback_reason,
    )
    .await
}

fn usable_snapshot<T>(
    snapshot: Option<(T, AuthzCachedValueState)>,
    cache_summary: &mut LocalAuthzCacheSummary,
) -> Option<(T, AuthzCachedValueState)> {
    let (value, state) = snapshot?;
    cache_summary.observe_cached(state);
    if state == AuthzCachedValueState::Stale {
        return None;
    }
    Some((value, state))
}

pub(super) async fn fetch_evaluation_data<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: EvaluationDataRequest<'_>,
    cached: CachedEvaluationData,
    fallback_reason: LocalAuthzFallbackReason,
) -> SidecarResult<(
    Arc<AuthzSubjectAccessSnapshot>,
    Arc<AuthzResourceAccessSnapshot>,
)>
where
    T: SidecarTransport + 'static,
{
    let snapshot_request = AuthzEvaluationDataSnapshotRequest {
        policy_version: request.policy_version,
        subjects: if cached.subject.is_none() {
            vec![request.subject.clone()]
        } else {
            Vec::new()
        },
        resources: if cached.resource.is_none() {
            vec![request.resource.clone()]
        } else {
            Vec::new()
        },
    };
    let snapshot = match sync_authz_evaluation_data(
        config,
        state,
        transport,
        context,
        snapshot_request.clone(),
    )
    .await?
    {
        Some(snapshot) => snapshot,
        None => transport
            .load_authz_evaluation_data(config, context, &snapshot_request)
            .await
            .map_err(|error| error.with_local_authz_fallback_reason(fallback_reason))?,
    };
    store_evaluation_data(state, config, request, snapshot, cached)
}

fn store_evaluation_data(
    state: &SidecarState,
    config: &SidecarEngineConfig,
    request: EvaluationDataRequest<'_>,
    snapshot: AuthzEvaluationDataSnapshot,
    cached: CachedEvaluationData,
) -> SidecarResult<(
    Arc<AuthzSubjectAccessSnapshot>,
    Arc<AuthzResourceAccessSnapshot>,
)> {
    if snapshot.policy_version != request.policy_version {
        return Err(SidecarError::bad_gateway(
            "authz_evaluation_data_version_mismatch",
            "evaluation-data snapshot version does not match requested policy version",
        ));
    }
    if snapshot.tenant_id != request.tenant_id {
        return Err(SidecarError::bad_gateway(
            "authz_evaluation_data_tenant_mismatch",
            "evaluation-data snapshot tenant does not match the requested tenant",
        ));
    }
    let AuthzEvaluationDataSnapshot {
        subjects,
        resources,
        ..
    } = snapshot;
    if subjects
        .iter()
        .any(|subject| subject.tenant_id != request.tenant_id)
        || resources
            .iter()
            .any(|resource| resource.tenant_id != request.tenant_id)
    {
        return Err(SidecarError::bad_gateway(
            "authz_evaluation_data_tenant_mismatch",
            "evaluation-data child snapshot tenant does not match the requested tenant",
        ));
    }

    let subject = match cached.subject {
        Some(subject) if subject.tenant_id == request.tenant_id => subject,
        Some(_) => {
            return Err(SidecarError::bad_gateway(
                "authz_evaluation_data_tenant_mismatch",
                "cached subject snapshot tenant does not match the requested tenant",
            ));
        }
        None => Arc::new(
            subjects
                .iter()
                .find(|subject| subject_matches_request(subject, request.subject))
                .cloned()
                .ok_or_else(|| {
                    SidecarError::bad_gateway(
                        "authz_subject_snapshot_missing",
                        "evaluation-data response did not include the requested subject snapshot",
                    )
                })?,
        ),
    };
    let resource = match cached.resource {
        Some(resource) if resource.tenant_id == request.tenant_id => resource,
        Some(_) => {
            return Err(SidecarError::bad_gateway(
                "authz_evaluation_data_tenant_mismatch",
                "cached resource snapshot tenant does not match the requested tenant",
            ));
        }
        None => Arc::new(
            resources
                .iter()
                .find(|resource| resource_matches_request(resource, request.resource))
                .cloned()
                .ok_or_else(|| {
                    SidecarError::bad_gateway(
                        "authz_resource_snapshot_missing",
                        "evaluation-data response did not include the requested resource snapshot",
                    )
                })?,
        ),
    };

    state.store_authz_subject_access(
        AuthzSubjectCacheKey::from_request(
            request.tenant_id.to_string(),
            request.policy_version,
            request.subject,
        ),
        Arc::clone(&subject),
        config.authz_cache_ttl,
        config.authz_stale_cache_ttl,
        config.authz_refresh_after_percent,
    );
    state.store_authz_resource_access(
        AuthzResourceCacheKey::from_request(
            request.tenant_id.to_string(),
            request.policy_version,
            request.resource,
        ),
        Arc::clone(&resource),
        config.authz_cache_ttl,
        config.authz_stale_cache_ttl,
        config.authz_refresh_after_percent,
    );
    Ok((subject, resource))
}

fn subject_matches_request(
    subject: &AuthzSubjectAccessSnapshot,
    request: &AuthzSubjectAccessSnapshotRequest,
) -> bool {
    subject.subject.subject_type == request.subject_type && subject.subject.id == request.id
}

fn resource_matches_request(
    resource: &AuthzResourceAccessSnapshot,
    request: &AuthzResourceAccessSnapshotRequest,
) -> bool {
    resource.resource_type == request.resource_type && resource.resource_id == request.id
}

#[derive(Debug, Default)]
pub(super) struct LocalAuthzCacheSummary {
    saw_miss: bool,
    saw_stale: bool,
}

impl LocalAuthzCacheSummary {
    fn observe_miss(&mut self) {
        self.saw_miss = true;
    }

    fn observe_cached(&mut self, state: AuthzCachedValueState) {
        if state == AuthzCachedValueState::Stale {
            self.saw_stale = true;
        }
    }

    pub(super) fn cache_status(&self) -> CacheStatus {
        if self.saw_miss {
            return CacheStatus::Miss;
        }
        if self.saw_stale {
            return CacheStatus::Stale;
        }
        CacheStatus::Fresh
    }
}
