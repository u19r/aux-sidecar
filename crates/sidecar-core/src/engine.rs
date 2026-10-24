use std::{fmt, sync::Arc};

use serde::Deserialize;
use sidecar_contract::{
    ApiEvaluationRequest, AuthzEvaluationResult, CacheStatus, ConfigResult,
    EntitlementEvaluateRequest, EntitlementsEvaluationResult, RateLimitAcquireLeaseRequest,
    RateLimitAcquireLeaseResponse, RateLimitCheckRequest, RateLimitCheckResponse,
    RateLimitConfigResponse, RateLimitGiveBackLeaseRequest, RateLimitGiveBackLeaseResponse,
    RequestContext, RuntimeBlocklistDecisionRequest, RuntimeBlocklistDecisionResponse,
    RuntimePolicyDecisionRequest, RuntimePolicyDecisionResponse, RuntimeSyncKnownVersions,
    RuntimeSyncRequest, RuntimeSyncResponse, SyncArtifactKind,
};

use crate::{
    LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngineConfig, SidecarResult, SidecarState,
    SidecarTransport, local_authz,
    state::{CachedValueState, current_time_millis},
};

#[path = "engine/revocation.rs"]
mod revocation_engine;

pub struct SidecarEngine<T>
where T: SidecarTransport
{
    pub(crate) config: SidecarEngineConfig,
    pub(crate) state: Arc<SidecarState>,
    pub(crate) transport: Arc<T>,
}

impl<T> fmt::Debug for SidecarEngine<T>
where T: SidecarTransport
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SidecarEngine")
            .field("preset", &self.config.preset)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T> SidecarEngine<T>
where T: SidecarTransport + 'static
{
    pub fn new(config: SidecarEngineConfig, transport: T) -> Self {
        Self {
            config,
            state: Arc::new(SidecarState::new()),
            transport: Arc::new(transport),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_state(
        config: SidecarEngineConfig,
        state: Arc<SidecarState>,
        transport: T,
    ) -> Self {
        Self {
            config,
            state,
            transport: Arc::new(transport),
        }
    }

    pub fn preset(&self) -> crate::DeploymentPreset {
        self.config.preset
    }

    pub fn state(&self) -> Arc<SidecarState> {
        Arc::clone(&self.state)
    }

    pub async fn sync_runtime(
        &self,
        context: &RequestContext,
        request: &RuntimeSyncRequest,
    ) -> SidecarResult<RuntimeSyncResponse> {
        crate::runtime_sync::synchronize(
            &self.config,
            &self.state,
            &self.transport,
            context,
            request.clone(),
            true,
        )
        .await?
        .ok_or_else(|| {
            crate::SidecarError::internal(
                "runtime_sync_response_missing",
                "runtime sync response is unavailable",
            )
        })
    }

    pub(crate) async fn try_sync_runtime(
        &self,
        context: &RequestContext,
        request: RuntimeSyncRequest,
    ) -> SidecarResult<bool> {
        match crate::runtime_sync::synchronize(
            &self.config,
            &self.state,
            &self.transport,
            context,
            request,
            false,
        )
        .await
        {
            Ok(_) => Ok(true),
            Err(error) if error.code == "runtime_sync_unavailable" => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn get_rate_limit_config(
        &self,
        context: &RequestContext,
    ) -> SidecarResult<ConfigResult> {
        let now_ms = current_time_millis();
        if let Some((config, state)) = self.state.rate_limit_config(now_ms) {
            return Ok(ConfigResult {
                config,
                cache_status: cache_status(state),
            });
        }

        let config = if self
            .try_sync_runtime(
                context,
                runtime_sync_request(vec![SyncArtifactKind::RateLimitConfig]),
            )
            .await?
        {
            let artifact = self
                .state
                .shared_runtime_sync_artifact(SyncArtifactKind::RateLimitConfig, "tenant")
                .ok_or_else(|| {
                    crate::SidecarError::bad_gateway(
                        "runtime_sync_artifact_missing",
                        "runtime sync omitted required rate-limit configuration",
                    )
                })?;
            RateLimitConfigResponse::deserialize(&artifact.payload)
                .map_err(|_| {
                    crate::SidecarError::bad_gateway(
                        "runtime_sync_artifact_invalid",
                        "runtime sync rate-limit configuration could not be decoded",
                    )
                })?
                .into_rate_limit_config()
        } else {
            self.transport
                .load_rate_limit_config(&self.config, context)
                .await?
        };
        self.state.store_rate_limit_config(
            config.clone(),
            self.config.cache_ttl,
            self.config.stale_cache_ttl,
        );

        Ok(ConfigResult {
            config,
            cache_status: CacheStatus::Miss,
        })
    }

    pub async fn acquire_leases(
        &self,
        context: &RequestContext,
        request: &RateLimitAcquireLeaseRequest,
    ) -> SidecarResult<RateLimitAcquireLeaseResponse> {
        request.validate()?;
        let response = self
            .transport
            .acquire_leases(&self.config, context, request)
            .await?;
        response.validate_for_request(request)?;
        Ok(response)
    }

    pub async fn check_rate_limit(
        &self,
        context: &RequestContext,
        request: &RateLimitCheckRequest,
    ) -> SidecarResult<RateLimitCheckResponse> {
        crate::local_rate_limit::check(
            self.state.lease_pool(),
            &self.config,
            &self.transport,
            context,
            request,
        )
        .await
    }

    pub async fn give_back_leases(
        &self,
        context: &RequestContext,
        request: &RateLimitGiveBackLeaseRequest,
    ) -> SidecarResult<RateLimitGiveBackLeaseResponse> {
        request.validate()?;
        let response = self
            .transport
            .give_back_leases(&self.config, context, request)
            .await?;
        response.validate_for_request(request)?;
        Ok(response)
    }

    pub async fn decide_blocklist(
        &self,
        context: &RequestContext,
        request: &RuntimeBlocklistDecisionRequest,
    ) -> SidecarResult<RuntimeBlocklistDecisionResponse> {
        crate::local_blocklist::decide(&self.config, &self.state, &self.transport, context, request)
            .await
    }

    pub async fn decide_policy(
        &self,
        context: &RequestContext,
        request: &RuntimePolicyDecisionRequest,
    ) -> SidecarResult<RuntimePolicyDecisionResponse> {
        crate::local_policy::decide(&self.config, &self.state, &self.transport, context, request)
            .await
    }

    pub async fn evaluate_authz(
        &self,
        context: &RequestContext,
        request: &ApiEvaluationRequest,
    ) -> SidecarResult<AuthzEvaluationResult> {
        if self.config.authz_local_mode == LocalAuthzMode::Shadow {
            let remote = self.evaluate_authz_remote(context, request).await?;
            match local_authz::evaluate(
                &self.config,
                &self.state,
                &self.transport,
                context,
                request,
            )
            .await
            {
                Ok(local) => record_shadow_result(&self.state, &remote, &local),
                Err(error) => {
                    self.state.record_authz_shadow_error();
                    tracing::warn!(code = error.code, "local AuthZ shadow evaluation skipped");
                }
            }
            return Ok(remote);
        }

        if self.config.authz_local_mode == LocalAuthzMode::Enforced {
            match local_authz::evaluate(
                &self.config,
                &self.state,
                &self.transport,
                context,
                request,
            )
            .await
            {
                Ok(local) => return Ok(local),
                Err(error) if enforced_remote_fallback_allowed(&self.config, &error) => {
                    tracing::warn!(
                        code = error.code,
                        "local AuthZ enforced evaluation fell back to remote"
                    );
                    return self.evaluate_authz_remote(context, request).await;
                }
                Err(error) => return Err(error),
            }
        }

        self.evaluate_authz_remote(context, request).await
    }

    async fn evaluate_authz_remote(
        &self,
        context: &RequestContext,
        request: &ApiEvaluationRequest,
    ) -> SidecarResult<AuthzEvaluationResult> {
        let upstream = self
            .transport
            .evaluate_authz(&self.config, context, request)
            .await?;
        Ok(AuthzEvaluationResult {
            response: upstream.response,
            cache_status: CacheStatus::Miss,
            status_code: upstream.status_code,
            www_authenticate: upstream.www_authenticate,
        })
    }

    pub async fn evaluate_entitlements(
        &self,
        context: &RequestContext,
        request: &EntitlementEvaluateRequest,
    ) -> SidecarResult<EntitlementsEvaluationResult> {
        request.validate()?;
        if request.at_time.is_none()
            && let Some(snapshot) = self.local_entitlement_snapshot(request)?
        {
            return Ok(EntitlementsEvaluationResult {
                response: snapshot.evaluate(request),
                cache_status: CacheStatus::Fresh,
            });
        }
        let sync_request = RuntimeSyncRequest {
            protocol_version: 1,
            known: RuntimeSyncKnownVersions::default(),
            want: vec![SyncArtifactKind::Entitlements],
            authz: None,
            entitlements: vec![request.clone()],
            blocklist_policy_refs: Vec::new(),
            revocation_audiences: Vec::new(),
        };
        match self.try_sync_runtime(context, sync_request).await {
            Ok(true) => {
                let snapshot = self.local_entitlement_snapshot(request)?.ok_or_else(|| {
                    crate::SidecarError::bad_gateway(
                        "runtime_sync_artifact_missing",
                        "runtime sync omitted required entitlement state",
                    )
                })?;
                Ok(EntitlementsEvaluationResult {
                    response: snapshot.evaluate(request),
                    cache_status: CacheStatus::Miss,
                })
            }
            Ok(false) => {
                let response = self
                    .transport
                    .evaluate_entitlements(&self.config, context, request)
                    .await?;
                response.validate_for_request(request)?;
                Ok(EntitlementsEvaluationResult {
                    response,
                    cache_status: CacheStatus::Miss,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn local_entitlement_snapshot(
        &self,
        request: &EntitlementEvaluateRequest,
    ) -> SidecarResult<Option<Arc<crate::local_entitlements::LocalEntitlementSnapshot>>> {
        let Some(artifact) = self
            .state
            .shared_runtime_sync_artifact(SyncArtifactKind::Entitlements, &request.org_id)
        else {
            return Ok(None);
        };
        if let Some(snapshot) = self.state.local_entitlement_snapshot(
            &request.org_id,
            &artifact.etag,
            current_time_millis(),
        ) {
            return Ok(snapshot.covers(request).then_some(snapshot));
        }
        let etag = artifact.etag.clone();
        let snapshot = Arc::new(
            crate::local_entitlements::LocalEntitlementSnapshot::compile_borrowed(
                &artifact.payload,
            )?,
        );
        self.state.store_local_entitlement_snapshot(
            request.org_id.clone(),
            etag.clone(),
            Arc::clone(&snapshot),
        );
        Ok(
            (snapshot.is_valid(current_time_millis()) && snapshot.covers(request))
                .then_some(snapshot),
        )
    }
}

pub(crate) fn runtime_sync_request(want: Vec<SyncArtifactKind>) -> RuntimeSyncRequest {
    RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want,
        authz: None,
        entitlements: Vec::new(),
        blocklist_policy_refs: Vec::new(),
        revocation_audiences: Vec::new(),
    }
}

pub(crate) fn cache_status(state: CachedValueState) -> CacheStatus {
    match state {
        CachedValueState::Fresh => CacheStatus::Fresh,
        CachedValueState::Stale => CacheStatus::Stale,
    }
}

fn enforced_remote_fallback_allowed(
    config: &SidecarEngineConfig,
    error: &crate::SidecarError,
) -> bool {
    matches!(
        (
            config.authz_remote_fallback,
            error.local_authz_fallback_reason,
        ),
        (
            LocalAuthzRemoteFallback::CacheMiss,
            Some(crate::error::LocalAuthzFallbackReason::CacheMiss),
        ) | (
            LocalAuthzRemoteFallback::RefreshError,
            Some(crate::error::LocalAuthzFallbackReason::RefreshError),
        )
    )
}

fn record_shadow_result(
    state: &SidecarState,
    remote: &AuthzEvaluationResult,
    local: &AuthzEvaluationResult,
) {
    if remote.response == local.response && remote.status_code == local.status_code {
        state.record_authz_shadow_match();
        tracing::debug!("local AuthZ shadow evaluation matched remote decision");
        return;
    }

    state.record_authz_shadow_mismatch();
    tracing::warn!(
        remote_decision = remote.response.decision,
        local_decision = local.response.decision,
        remote_status_code = remote.status_code,
        local_status_code = local.status_code,
        "local AuthZ shadow mismatch"
    );
}
