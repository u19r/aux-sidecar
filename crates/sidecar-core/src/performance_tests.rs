use sidecar_contract::{RequestContext, ValidateAuthnJwtRequest, ValidateOAuthAccessTokenRequest};

use crate::{
    SidecarEngine, auth,
    performance_support_tests::{
        TestTransport, best_of_three, best_of_three_async, config, measure_allocations,
        measure_allocations_async, percent_improvement, prime_jwt_verifier_cache, test_jwks,
        test_oauth_token, test_token,
    },
};

#[test]
fn perf_loop_cached_verifier_given_rebuild_then_reuse_reduces_allocations() {
    let config = config();
    let token = test_token();
    let jwks = test_jwks();
    let verifier = auth::verifier_from_jwks(jwks.clone()).unwrap();

    let baseline = measure_allocations("baseline_rebuild_jwt_verifier", || {
        for _ in 0..100 {
            let verifier = auth::verifier_from_jwks(jwks.clone()).unwrap();
            let result = auth::validate_authn_jwt_static(
                &config,
                &token,
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    });

    let optimized = measure_allocations("optimized_reuse_jwt_verifier", || {
        for _ in 0..100 {
            let result = auth::validate_authn_jwt_static(
                &config,
                &token,
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    });

    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");

    assert!(
        optimized.allocation_count < baseline.allocation_count,
        "optimized allocations={} baseline allocations={}",
        optimized.allocation_count,
        baseline.allocation_count
    );
    assert!(
        optimized.allocated_bytes < baseline.allocated_bytes,
        "optimized bytes={} baseline bytes={}",
        optimized.allocated_bytes,
        baseline.allocated_bytes
    );
}

#[test]
fn perf_loop_required_token_given_clone_then_borrow_reduces_allocations() {
    let config = config();
    let request = ValidateAuthnJwtRequest {
        token: Some(test_token()),
    };

    let baseline = measure_allocations("baseline_required_token_clone", || {
        let mut bytes = 0;
        for _ in 0..1_000 {
            let token = request
                .token
                .as_ref()
                .filter(|token| !token.trim().is_empty());
            let token = token
                .cloned()
                .ok_or_else(|| auth::missing_authn_token(&config));
            bytes += token.unwrap().len();
        }
        assert!(bytes > 0);
    });

    let optimized = measure_allocations("optimized_required_token_borrow", || {
        let mut bytes = 0;
        for _ in 0..1_000 {
            let token = auth::required_authn_token(&config, &request).unwrap();
            bytes += token.len();
        }
        assert!(bytes > 0);
    });

    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");

    assert!(
        optimized.allocation_count < baseline.allocation_count,
        "optimized allocations={} baseline allocations={}",
        optimized.allocation_count,
        baseline.allocation_count
    );
    assert!(
        optimized.allocated_bytes < baseline.allocated_bytes,
        "optimized bytes={} baseline bytes={}",
        optimized.allocated_bytes,
        baseline.allocated_bytes
    );
}

#[tokio::test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
async fn perf_loop_sidecar_candidate_matrix_reports_allocations_and_cpu() {
    let config = config();
    let verifier = auth::verifier_from_jwks(test_jwks()).unwrap();
    let engine = SidecarEngine::new(config.clone(), TestTransport::new());
    prime_jwt_verifier_cache(&engine).await;

    let authn_request = ValidateAuthnJwtRequest {
        token: Some(test_token()),
    };
    let oauth_request = ValidateOAuthAccessTokenRequest {
        scheme: "Bearer".into(),
        method: "GET".into(),
        target_uri: "https://sidecar-resource.test/a".into(),
        proof: None,
        token: Some(test_oauth_token()),
    };

    let authn_static = measure_allocations("matrix_sidecar_authn_static", || {
        for _ in 0..100 {
            let result = auth::validate_authn_jwt_static(
                &config,
                auth::required_authn_token(&config, &authn_request).unwrap(),
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    });
    let oauth_static = measure_allocations("matrix_sidecar_oauth_static", || {
        for _ in 0..100 {
            let result = auth::validate_oauth_access_token_static(
                &config,
                &oauth_request,
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    });
    let authn_required = measure_allocations("matrix_sidecar_required_authn_token", || {
        let mut bytes = 0;
        for _ in 0..1_000 {
            bytes += auth::required_authn_token(&config, &authn_request)
                .unwrap()
                .len();
        }
        assert!(bytes > 0);
    });
    let oauth_required = measure_allocations("matrix_sidecar_required_oauth_token", || {
        let mut bytes = 0;
        for _ in 0..1_000 {
            bytes += auth::required_oauth_token(&oauth_request).unwrap().len();
        }
        assert!(bytes > 0);
    });
    let engine_authn = measure_allocations_async("matrix_sidecar_engine_authn_cached", async {
        for _ in 0..100 {
            let result = engine
                .validate_authn_jwt(&RequestContext::default(), &authn_request)
                .await
                .unwrap();
            assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Fresh);
        }
    })
    .await;
    let engine_oauth = measure_allocations_async("matrix_sidecar_engine_oauth_cached", async {
        for _ in 0..100 {
            let result = engine
                .validate_oauth_access_token(&RequestContext::default(), &oauth_request)
                .await
                .unwrap();
            assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Fresh);
        }
    })
    .await;

    for report in [
        authn_static,
        oauth_static,
        authn_required,
        oauth_required,
        engine_authn,
        engine_oauth,
    ] {
        alloc_counter::emit_report(&report).expect("allocation report must be emitted");
    }

    let authn_static_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            auth::validate_authn_jwt_static(
                &config,
                auth::required_authn_token(&config, &authn_request).unwrap(),
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
        }
    });
    let oauth_static_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            auth::validate_oauth_access_token_static(
                &config,
                &oauth_request,
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
        }
    });
    let authn_required_cpu = best_of_three(|| {
        let mut bytes = 0;
        for _ in 0..100_000 {
            bytes += auth::required_authn_token(&config, &authn_request)
                .unwrap()
                .len();
        }
        assert!(bytes > 0);
    });
    let oauth_required_cpu = best_of_three(|| {
        let mut bytes = 0;
        for _ in 0..100_000 {
            bytes += auth::required_oauth_token(&oauth_request).unwrap().len();
        }
        assert!(bytes > 0);
    });
    let engine_authn_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            engine
                .validate_authn_jwt(&RequestContext::default(), &authn_request)
                .await
                .unwrap();
        }
    })
    .await;
    let engine_oauth_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            engine
                .validate_oauth_access_token(&RequestContext::default(), &oauth_request)
                .await
                .unwrap();
        }
    })
    .await;

    println!(
        "sidecar_candidate_matrix_cpu_ns authn_static={} oauth_static={} required_authn_100k={} \
         required_oauth_100k={} engine_authn={} engine_oauth={}",
        authn_static_cpu.as_nanos(),
        oauth_static_cpu.as_nanos(),
        authn_required_cpu.as_nanos(),
        oauth_required_cpu.as_nanos(),
        engine_authn_cpu.as_nanos(),
        engine_oauth_cpu.as_nanos()
    );
}

#[tokio::test]
async fn cached_jwt_verifier_engine_validation_records_allocation_baseline() {
    let engine = SidecarEngine::new(config(), TestTransport::new());
    prime_jwt_verifier_cache(&engine).await;

    let request = ValidateAuthnJwtRequest {
        token: Some(test_token()),
    };
    let report = measure_allocations_async("engine_cached_jwt_verifier_authn_validation", async {
        for _ in 0..100 {
            let result = engine
                .validate_authn_jwt(&RequestContext::default(), &request)
                .await
                .unwrap();
            assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Fresh);
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    })
    .await;

    alloc_counter::emit_report(&report).expect("allocation report must be emitted");
    assert!(report.allocation_count > 0);
}

#[tokio::test]
async fn jwt_validation_result_cache_perf_loop_reuses_verified_claims() {
    let config = config();
    let verifier = auth::verifier_from_jwks(test_jwks()).expect("verifier");
    let engine = SidecarEngine::new(config.clone(), TestTransport::new());
    let request = ValidateAuthnJwtRequest {
        token: Some(test_token()),
    };
    prime_jwt_verifier_cache(&engine).await;

    let baseline_allocations =
        measure_allocations("baseline_repeat_jwt_signature_validation", || {
            for _ in 0..100 {
                auth::validate_authn_jwt_static(
                    &config,
                    request.token.as_deref().expect("token"),
                    &verifier,
                    sidecar_contract::CacheStatus::Fresh,
                )
                .expect("signature validation");
            }
        });
    let optimized_allocations =
        measure_allocations_async("optimized_cached_jwt_validation_result", async {
            for _ in 0..100 {
                engine
                    .validate_authn_jwt(&RequestContext::default(), &request)
                    .await
                    .expect("cached validation");
            }
        })
        .await;
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            auth::validate_authn_jwt_static(
                &config,
                request.token.as_deref().expect("token"),
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .expect("signature validation");
        }
    });
    let optimized_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            engine
                .validate_authn_jwt(&RequestContext::default(), &request)
                .await
                .expect("cached validation");
        }
    })
    .await;
    println!(
        "jwt_validation_result_cache_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized_allocations.allocation_count < baseline_allocations.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[tokio::test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
async fn perf_loop_engine_cached_jwt_verifier_reports_allocations_and_cpu() {
    let engine = SidecarEngine::new(config(), TestTransport::new());
    prime_jwt_verifier_cache(&engine).await;

    let request = ValidateAuthnJwtRequest {
        token: Some(test_token()),
    };
    let allocation_report =
        measure_allocations_async("engine_cached_jwt_verifier_authn_validation", async {
            for _ in 0..100 {
                let result = engine
                    .validate_authn_jwt(&RequestContext::default(), &request)
                    .await
                    .unwrap();
                assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Fresh);
            }
        })
        .await;
    alloc_counter::emit_report(&allocation_report).expect("allocation report must be emitted");

    let duration = best_of_three_async(|| async {
        for _ in 0..1_000 {
            let result = engine
                .validate_authn_jwt(&RequestContext::default(), &request)
                .await
                .unwrap();
            assert_eq!(result.cache_status, sidecar_contract::CacheStatus::Fresh);
        }
    })
    .await;

    println!(
        "engine_cached_jwt_verifier_authn_validation_1000_ns={}",
        duration.as_nanos()
    );
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_cached_verifier_reports_baseline_and_optimized_cpu() {
    let config = config();
    let token = test_token();
    let jwks = test_jwks();
    let verifier = auth::verifier_from_jwks(jwks.clone()).unwrap();

    let baseline = best_of_three(|| {
        for _ in 0..1_000 {
            let verifier = auth::verifier_from_jwks(jwks.clone()).unwrap();
            let result = auth::validate_authn_jwt_static(
                &config,
                &token,
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    });

    let optimized = best_of_three(|| {
        for _ in 0..1_000 {
            let result = auth::validate_authn_jwt_static(
                &config,
                &token,
                &verifier,
                sidecar_contract::CacheStatus::Fresh,
            )
            .unwrap();
            assert_eq!(result.claims["sub"], "user_fixture");
        }
    });

    println!(
        "cached_jwt_verifier_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline.as_nanos(),
        optimized.as_nanos(),
        percent_improvement(baseline, optimized)
    );
}
