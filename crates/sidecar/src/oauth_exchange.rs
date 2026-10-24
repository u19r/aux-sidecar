use super::*;

pub(super) fn exchange_oauth_token<'a>(
    transport: &'a NativeSidecarTransport,
    config: &'a SidecarEngineConfig,
    context: &'a RequestContext,
    form_fields: &'a [(&'a str, String)],
) -> SidecarFuture<'a, TokenResponse> {
    Box::pin(async move {
        let response = with_context_headers(
            transport
                .http
                .post(tenant_url(&config.base_url, "/oauth2/token"))
                .form(form_fields),
            context,
            config.tenant_domain.as_deref(),
        )
        .send()
        .await
        .map_err(|err| SidecarError::bad_gateway("oauth_token_exchange_error", err.to_string()))?;

        if !response.status().is_success() {
            return Err(SidecarError::unauthorized(
                "oauth_token_exchange_failed",
                response.status().to_string(),
            ));
        }

        decode_json_body(response, "oauth_token_decode_failed").await
    })
}
