use std::sync::Arc;

use sidecar_contract::{
    CacheStatus, JwtValidationResult, RequestContext, SyncArtifactKind, ValidateAuthnJwtRequest,
    ValidateOAuthAccessTokenRequest,
};

use crate::{
    SidecarEngine, SidecarResult, SidecarTransport, auth,
    engine::{cache_status, runtime_sync_request},
    state::{JwtVerifierCacheKey, current_time_millis},
};

impl<T> SidecarEngine<T>
where T: SidecarTransport + 'static
{
    pub async fn validate_authn_jwt(
        &self,
        context: &RequestContext,
        request: &ValidateAuthnJwtRequest,
    ) -> SidecarResult<JwtValidationResult> {
        let token = auth::required_authn_token(&self.config, request)?;
        let result_key = auth::JwtValidationResultCacheKey::from_config(
            auth::JwtTokenKind::Authn,
            token,
            &self.config,
        )?;
        if let Some(claims) = self
            .state
            .jwt_validation_result(&result_key, current_time_millis())
        {
            return Ok(JwtValidationResult {
                claims,
                cache_status: CacheStatus::Fresh,
            });
        }
        let policies = self.jwt_validation_policies()?;
        let (verifier, cache_status) = self.jwt_verifier(context).await?;
        let result =
            auth::validate_authn_jwt_with_policy(token, &verifier, cache_status, policies.authn())
                .await?;
        self.state.store_jwt_validation_result(
            result_key,
            result.claims.clone(),
            self.config.cache_ttl,
        );
        Ok(result)
    }

    pub async fn validate_oauth_access_token(
        &self,
        context: &RequestContext,
        request: &ValidateOAuthAccessTokenRequest,
    ) -> SidecarResult<JwtValidationResult> {
        let token = auth::required_oauth_token(request)?;
        let result = self.verify_oauth_token_authority(context, token).await?;
        auth::validate_oauth_presenter(request, &result.claims)?;
        Ok(result)
    }

    // Token-endpoint responses prove grant ownership, not presentation at a
    // resource. Hosted login uses this authority-only operation before
    // returning the exchanged token.
    pub(crate) async fn verify_oauth_token_authority(
        &self,
        context: &RequestContext,
        token: &str,
    ) -> SidecarResult<JwtValidationResult> {
        let result_key = auth::JwtValidationResultCacheKey::from_config(
            auth::JwtTokenKind::OAuth,
            token,
            &self.config,
        )?;
        if let Some(claims) = self
            .state
            .jwt_validation_result(&result_key, current_time_millis())
        {
            return Ok(JwtValidationResult {
                claims,
                cache_status: CacheStatus::Fresh,
            });
        }
        let policies = self.jwt_validation_policies()?;
        let (verifier, cache_status) = self.jwt_verifier(context).await?;
        let result = auth::verify_oauth_authority_with_policies(
            token,
            &verifier,
            cache_status,
            policies.oauth(),
        )
        .await?;
        self.state.store_jwt_validation_result(
            result_key,
            result.claims.clone(),
            self.config.cache_ttl,
        );
        Ok(result)
    }

    async fn jwt_verifier(
        &self,
        context: &RequestContext,
    ) -> SidecarResult<(Arc<jwt_decode::JwtVerifier>, CacheStatus)> {
        let now_ms = current_time_millis();
        let key = JwtVerifierCacheKey::from_config(&self.config);
        if let Some((verifier, state)) = self.state.jwt_verifier(&key, now_ms) {
            return Ok((verifier, cache_status(state)));
        }

        let verifier =
            self.fetch_jwt_verifier(context)
                .await
                .map_err(|error| crate::SidecarError {
                    status_code: 503,
                    ..error
                })?;
        let verifier = Arc::new(verifier);
        self.state.store_jwt_verifier(
            key,
            Arc::clone(&verifier),
            self.config.cache_ttl,
            self.config.stale_cache_ttl,
        );
        Ok((verifier, CacheStatus::Miss))
    }

    async fn fetch_jwt_verifier(
        &self,
        context: &RequestContext,
    ) -> SidecarResult<jwt_decode::JwtVerifier> {
        if self
            .try_sync_runtime(context, runtime_sync_request(vec![SyncArtifactKind::Jwks]))
            .await?
        {
            let artifact = self
                .state
                .shared_runtime_sync_artifact(SyncArtifactKind::Jwks, "tenant")
                .ok_or_else(|| {
                    crate::SidecarError::bad_gateway(
                        "runtime_sync_artifact_missing",
                        "runtime sync omitted required JWKS",
                    )
                })?;
            auth::verifier_from_jwks(&artifact.payload)
        } else {
            let raw_jwks = self.transport.fetch_jwks(&self.config, context).await?;
            auth::verifier_from_jwks(raw_jwks)
        }
    }

    fn jwt_validation_policies(&self) -> SidecarResult<Arc<auth::JwtValidationPolicies>> {
        let key = auth::JwtValidationCacheKey::from_config(&self.config)?;
        if let Some(policies) = self.state.jwt_validation_policies(&key) {
            return Ok(policies);
        }

        let policies = Arc::new(auth::JwtValidationPolicies::from_config(&self.config)?);
        self.state
            .store_jwt_validation_policies(key, Arc::clone(&policies));
        Ok(policies)
    }
}
