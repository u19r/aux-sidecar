#[derive(Clone, PartialEq, Eq)]
pub struct HostedLoginSession {
    pub state: String,
    pub code_verifier: String,
    pub client_id: String,
    pub resource: Option<String>,
    pub redirect_uri: String,
    pub expires_at_ms: i64,
}

impl std::fmt::Debug for HostedLoginSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostedLoginSession")
            .field("state", &self.state)
            .field("code_verifier", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Exclusively owns a callback source across an async operation. Until the
/// native response is definitive, failure or cancellation restores its proof.
pub(crate) struct HostedLoginAttempt<'a> {
    pub(crate) session: HostedLoginSession,
    restore_to: Option<&'a super::SidecarState>,
}

impl<'a> HostedLoginAttempt<'a> {
    pub(crate) fn try_new(state: &'a super::SidecarState, key: &str) -> crate::SidecarResult<Self> {
        let session = state
            .take_hosted_login_session(key, super::current_time_millis())
            .ok_or_else(|| {
                crate::SidecarError::unauthorized("hosted_login_state_invalid", "state is invalid")
            })?;
        Ok(Self {
            session,
            restore_to: Some(state),
        })
    }

    pub(crate) fn consume(mut self) {
        self.restore_to = None;
    }
}

impl Drop for HostedLoginAttempt<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.restore_to {
            state.store_hosted_login_session(self.session.clone());
        }
    }
}
