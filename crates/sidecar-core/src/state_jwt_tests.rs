use std::time::Duration;

use crate::SidecarState;

#[test]
fn jwt_validation_result_cache_never_outlives_configured_ttl() {
    let state = SidecarState::new();
    let key = crate::auth::JwtValidationResultCacheKey::from_config(
        crate::auth::JwtTokenKind::Authn,
        "sensitive-token",
        &crate::performance_support_tests::config(),
    )
    .expect("cache key");
    state.store_jwt_validation_result(
        key.clone(),
        serde_json::json!({"sub": "user", "exp": 4_102_444_800_i64}),
        Duration::ZERO,
    );

    assert!(
        state
            .jwt_validation_result(&key, crate::state::current_time_millis())
            .is_none()
    );
}

#[test]
fn jwt_validation_result_cache_rejects_oversized_claims_before_retention() {
    let state = SidecarState::new();
    let key = crate::auth::JwtValidationResultCacheKey::from_config(
        crate::auth::JwtTokenKind::Authn,
        "oversized-token",
        &crate::performance_support_tests::config(),
    )
    .expect("cache key");
    state.store_jwt_validation_result(
        key.clone(),
        serde_json::json!({
            "sub": "user",
            "exp": 4_102_444_800_i64,
            "claims": "x".repeat(crate::constants::MAX_JWT_VALIDATION_RESULT_CACHE_BYTES)
        }),
        Duration::from_secs(60),
    );

    assert!(
        state
            .jwt_validation_result(&key, crate::state::current_time_millis())
            .is_none()
    );
}
