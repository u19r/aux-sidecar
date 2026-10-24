use crate::windowed_rate_limit::{
    MAX_WINDOWED_RATE_LIMIT_KEYS, WindowedRateLimitPool, WindowedRateLimitRequest,
};

fn request(key: &str, limit: u32, window_seconds: u32, cost: u32) -> WindowedRateLimitRequest {
    WindowedRateLimitRequest {
        key: key.to_string(),
        limit,
        window_seconds,
        cost,
    }
}

#[test]
fn hourly_quota_remains_bounded_until_the_fixed_window_changes() {
    let mut pool = WindowedRateLimitPool::default();
    let request = request("organization", 100, 3_600, 1);

    for _ in 0..100 {
        assert!(
            pool.check_many(std::slice::from_ref(&request), 3_600_000)
                .remove(0)
                .allowed
        );
    }
    let denied = pool
        .check_many(std::slice::from_ref(&request), 3_600_000)
        .remove(0);
    assert!(!denied.allowed);
    assert_eq!(denied.remaining_tokens, 0);
    assert_eq!(denied.retry_after_ms, Some(3_600_000));

    assert!(
        pool.check_many(std::slice::from_ref(&request), 7_200_000)
            .remove(0)
            .allowed
    );
}

#[test]
fn windowed_quota_evicts_old_keys_at_the_explicit_bound() {
    let mut pool = WindowedRateLimitPool::default();
    for index in 0..MAX_WINDOWED_RATE_LIMIT_KEYS {
        let key = format!("key-{index}");
        assert!(
            pool.check_many(&[request(&key, 1, 60, 1)], 0)
                .remove(0)
                .allowed
        );
    }

    assert!(
        pool.check_many(&[request("new-key", 1, 60, 1)], 0)
            .remove(0)
            .allowed
    );
}
