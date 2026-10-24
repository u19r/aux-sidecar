use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use sidecar_contract::{RequestContext, ValidateAuthnJwtRequest};

use crate::{
    JwtValidationConfig, LocalAuthzMode, LocalAuthzRemoteFallback, SidecarEngine,
    SidecarEngineConfig, SidecarFuture, SidecarTransport,
};

#[derive(Debug)]
pub(crate) struct TestTransport {
    jwks: serde_json::Value,
    jwks_fetch_count: Arc<AtomicUsize>,
}

impl TestTransport {
    pub(crate) fn new() -> Self {
        Self {
            jwks: test_jwks(),
            jwks_fetch_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SidecarTransport for TestTransport {
    fn acquire_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitAcquireLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitAcquireLeaseResponse> {
        unimplemented_future()
    }

    fn give_back_leases<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RateLimitGiveBackLeaseRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitGiveBackLeaseResponse> {
        unimplemented_future()
    }

    fn load_rate_limit_config<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, sidecar_contract::RateLimitConfig> {
        unimplemented_future()
    }

    fn decide_blocklist<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimeBlocklistDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimeBlocklistDecisionResponse> {
        unimplemented_future()
    }

    fn decide_policy<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::RuntimePolicyDecisionRequest,
    ) -> SidecarFuture<'a, sidecar_contract::RuntimePolicyDecisionResponse> {
        unimplemented_future()
    }

    fn evaluate_authz<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::ApiEvaluationRequest,
    ) -> SidecarFuture<'a, sidecar_contract::UpstreamAuthzResponse> {
        unimplemented_future()
    }

    fn evaluate_entitlements<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _request: &'a sidecar_contract::EntitlementEvaluateRequest,
    ) -> SidecarFuture<'a, sidecar_contract::EntitlementEvaluateResponse> {
        unimplemented_future()
    }

    fn fetch_jwks<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
    ) -> SidecarFuture<'a, serde_json::Value> {
        self.jwks_fetch_count.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(self.jwks.clone()) })
    }

    fn exchange_oauth_code<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unimplemented_future()
    }

    fn exchange_oauth_refresh_token<'a>(
        &'a self,
        _config: &'a SidecarEngineConfig,
        _context: &'a RequestContext,
        _form_fields: &'a [(&'a str, String)],
    ) -> SidecarFuture<'a, sidecar_contract::TokenResponse> {
        unimplemented_future()
    }
}

pub(crate) async fn prime_jwt_verifier_cache<T>(engine: &SidecarEngine<T>)
where T: SidecarTransport + 'static {
    let request = ValidateAuthnJwtRequest {
        token: Some(test_token()),
    };
    let result = engine
        .validate_authn_jwt(&RequestContext::default(), &request)
        .await
        .unwrap();
    assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Miss);
}

pub(crate) fn measure_allocations(
    label: &'static str,
    run: impl FnOnce(),
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run();
    guard.finish()
}

pub(crate) async fn measure_allocations_async(
    label: &'static str,
    run: impl Future<Output = ()>,
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run.await;
    guard.finish()
}

pub(crate) fn best_of_three(mut run: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = cpu_time::ThreadTime::now();
        run();
        best = best.min(started.elapsed());
    }
    best
}

pub(crate) async fn best_of_three_async<Fut>(mut run: impl FnMut() -> Fut) -> Duration
where Fut: Future<Output = ()> {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let thread = std::thread::current().id();
        let started = cpu_time::ThreadTime::now();
        run().await;
        assert_eq!(
            std::thread::current().id(),
            thread,
            "CPU samples require a current-thread runtime"
        );
        best = best.min(started.elapsed());
    }
    best
}

pub(crate) fn percent_improvement(baseline: Duration, optimized: Duration) -> f64 {
    let baseline = baseline.as_nanos() as f64;
    let optimized = optimized.as_nanos() as f64;
    ((baseline - optimized) / baseline) * 100.0
}

pub(crate) fn config() -> SidecarEngineConfig {
    SidecarEngineConfig {
        preset: crate::DeploymentPreset::Embedded,
        base_url: "http://127.0.0.1:3000".to_string(),
        api_key: "key".to_string(),
        tenant_domain: None,
        cache_ttl: Duration::from_secs(60),
        stale_cache_ttl: Duration::from_secs(300),
        authz_local_mode: LocalAuthzMode::RemoteOnly,
        authz_cache_ttl: Duration::from_secs(10),
        authz_stale_cache_ttl: Duration::from_secs(30),
        authz_refresh_after_percent: 50,
        authz_remote_fallback: LocalAuthzRemoteFallback::CacheMiss,
        jwt_validation: Some(JwtValidationConfig {
            issuer: sidecar_fixtures::jwt::issuer().to_string(),
            login_redirect_url: None,
            resource_audiences: Some(vec![sidecar_fixtures::jwt::audience().to_string()]),
            audience_check_disabled: false,
            clock_skew_seconds: 0,
        }),
    }
}

pub(crate) fn test_jwks() -> serde_json::Value {
    sidecar_fixtures::jwt::jwks()
}

pub(crate) fn test_token() -> String {
    sidecar_fixtures::jwt::authn_token()
}

pub(crate) fn test_oauth_token() -> String {
    sidecar_fixtures::jwt::oauth_token()
}

fn unimplemented_future<'a, T>() -> SidecarFuture<'a, T> {
    Box::pin(async {
        Err(crate::SidecarError::internal(
            "not_implemented",
            "test stub",
        ))
    })
}

#[tokio::test]
async fn given_sleeping_work_when_cpu_samples_are_taken_then_descheduled_time_is_excluded() {
    let duration = Duration::from_millis(20);
    let sync_cpu = best_of_three(|| std::thread::sleep(duration));
    let async_cpu = best_of_three_async(|| tokio::time::sleep(duration)).await;
    assert!(
        sync_cpu < duration,
        "sleep was charged as CPU: {sync_cpu:?}"
    );
    assert!(
        async_cpu < duration,
        "timer wait was charged as CPU: {async_cpu:?}"
    );
}
