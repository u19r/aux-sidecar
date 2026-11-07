use sidecar_contract::{
    BeginHostedLoginRequest, BeginHostedLoginResult, CompleteHostedLoginRequest,
    CompleteHostedLoginResult, RefreshHostedLoginRequest, RefreshHostedLoginResult, RequestContext,
};

use crate::{SidecarEngine, SidecarResult, SidecarTransport, hosted_login};

impl<T> SidecarEngine<T>
where T: SidecarTransport + 'static
{
    pub fn begin_hosted_login(
        &self,
        request: &BeginHostedLoginRequest,
    ) -> SidecarResult<BeginHostedLoginResult> {
        hosted_login::begin_hosted_login(&self.config, &self.state, request)
    }

    pub async fn complete_hosted_login(
        &self,
        context: &RequestContext,
        request: &CompleteHostedLoginRequest,
    ) -> SidecarResult<CompleteHostedLoginResult> {
        let context = crate::oauth_token::prepare_native_oauth_context(context);
        let exchange = hosted_login::prepare_hosted_login_exchange(&self.state, request)?;
        let tokens = match self
            .transport
            .exchange_oauth_code(&self.config, &context, &exchange.fields)
            .await
        {
            Ok(tokens) => {
                exchange.attempt.consume();
                tokens
            }
            Err(error) => {
                if error.status_code < 500 && !matches!(error.authentication.as_deref(),
                    Some(sidecar_contract::native_auth::NativeAuthenticationFailure::RecoveryRequired { .. }
                        | sidecar_contract::native_auth::NativeAuthenticationFailure::Retry { .. })) {
                    exchange.attempt.consume();
                }
                return Err(error);
            }
        };
        let claims = self
            .verify_oauth_token_authority(&context, &tokens.access_token)
            .await?
            .claims;
        Ok(hosted_login::complete_hosted_login_result(tokens, claims))
    }

    pub async fn refresh_hosted_login(
        &self,
        context: &RequestContext,
        request: &RefreshHostedLoginRequest,
    ) -> SidecarResult<RefreshHostedLoginResult> {
        let context = crate::oauth_token::prepare_native_oauth_context(context);
        let form_fields = hosted_login::refresh_hosted_login_form(request)?;
        let tokens = self
            .transport
            .exchange_oauth_refresh_token(&self.config, &context, &form_fields)
            .await?;
        let claims = self
            .verify_oauth_token_authority(&context, &tokens.access_token)
            .await?
            .claims;
        Ok(hosted_login::refresh_hosted_login_result(tokens, claims))
    }
}
