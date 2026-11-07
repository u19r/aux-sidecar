use sidecar_contract::{
    RequestContext,
    hosted_recovery::{
        BeginHostedRecoveryRequest, BeginHostedRecoveryResult, HostedRecoveryGrant,
        NativeRecoveryAuthorization, NativeRecoveryGrant, NativeRecoveryStageRequest,
    },
};

use crate::{
    SidecarEngine, SidecarError, SidecarResult, SidecarState, SidecarTransport, hosted_login,
    state::HostedLoginAttempt,
};

impl<T: SidecarTransport + 'static> SidecarEngine<T> {
    /// Only the native service stages the held source. Local state retains
    /// the PKCE verifier for the eventual native-issued replacement callback.
    pub async fn begin_hosted_recovery(
        &self,
        context: &RequestContext,
        request: &BeginHostedRecoveryRequest,
    ) -> SidecarResult<BeginHostedRecoveryResult> {
        if !self.transport.supports_native_recovery() {
            return Err(SidecarError::bad_request(
                "hosted_recovery_unsupported",
                "this transport does not support native recovery staging",
            ));
        }
        let context = crate::oauth_token::prepare_native_oauth_context(context);
        let mut next = hosted_login::prepare_hosted_login(&self.config, &request.authorization)?;
        let original = PreparedRecoveryGrant::try_new(&self.state, &request.grant)?;
        next.session.resource = original.grant.resource().map(str::to_owned);
        let authorization = next.prepare_recovery_authorization(&request.authorization.scopes);
        let input = NativeRecoveryStageRequest {
            grant: original.grant,
            authorization,
        };
        let stage = self
            .transport
            .stage_oauth_recovery(&self.config, &context, &input)
            .await?;
        if let Some(attempt) = original.attempt {
            attempt.consume();
        }
        let state = next.session.state.clone();
        self.state.store_hosted_login_session(next.session);
        Ok(BeginHostedRecoveryResult { stage, state })
    }
}

struct PreparedRecoveryGrant<'a> {
    grant: NativeRecoveryGrant,
    attempt: Option<HostedLoginAttempt<'a>>,
}

impl<'a> PreparedRecoveryGrant<'a> {
    fn try_new(state: &'a SidecarState, grant: &HostedRecoveryGrant) -> SidecarResult<Self> {
        match grant {
            HostedRecoveryGrant::AuthorizationCode {
                state: key,
                code,
                recovery,
            } => Self::prepare_code_grant(state, key, code, recovery),
            HostedRecoveryGrant::RefreshToken { request, recovery } => {
                Self::prepare_refresh_grant(request, recovery)
            }
        }
    }

    fn prepare_code_grant(
        state: &'a SidecarState,
        key: &str,
        code: &str,
        recovery: &sidecar_contract::native_auth::NativeAuthenticationRecovery,
    ) -> SidecarResult<Self> {
        let attempt = HostedLoginAttempt::try_new(state, key)?;
        let session = &attempt.session;
        Ok(Self {
            grant: NativeRecoveryGrant::AuthorizationCode {
                client_id: session.client_id.clone(),
                code: code.to_owned(),
                redirect_uri: session.redirect_uri.clone(),
                code_verifier: session.code_verifier.clone(),
                continuation_id: recovery.continuation_id.clone(),
                resource: session.resource.clone(),
            },
            attempt: Some(attempt),
        })
    }

    fn prepare_refresh_grant(
        request: &sidecar_contract::RefreshHostedLoginRequest,
        recovery: &sidecar_contract::native_auth::NativeAuthenticationRecovery,
    ) -> SidecarResult<Self> {
        hosted_login::refresh_hosted_login_form(request)?;
        Ok(Self {
            grant: NativeRecoveryGrant::RefreshToken {
                client_id: request.client_id.clone(),
                refresh_token: request.refresh_token.clone(),
                scope: request.scope.clone(),
                continuation_id: recovery.continuation_id.clone(),
                resource: request.resource.clone(),
            },
            attempt: None,
        })
    }
}

impl hosted_login::PreparedHostedLogin {
    fn prepare_recovery_authorization(&self, scopes: &[String]) -> NativeRecoveryAuthorization {
        NativeRecoveryAuthorization {
            response_type: "code".into(),
            client_id: self.session.client_id.clone(),
            redirect_uri: self.session.redirect_uri.clone(),
            scope: scopes.join(" "),
            resource: self.session.resource.iter().cloned().collect(),
            state: self.session.state.clone(),
            code_challenge: hosted_login::code_challenge(&self.session.code_verifier),
            code_challenge_method: "S256".into(),
        }
    }
}
