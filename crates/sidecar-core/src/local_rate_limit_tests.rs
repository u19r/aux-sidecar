use std::{collections::HashMap, hint::black_box};

use proptest::prelude::*;
use sidecar_contract::RateLimitParameters;

use crate::{
    local_rate_limit::{LeasePool, LeasePoolKey, bounded_lease_expiry},
    performance_support_tests::{best_of_three, measure_allocations, percent_improvement},
};

#[test]
fn lease_pool_consume_perf_loop_keeps_inline_lru_metadata() {
    let key = key();
    let baseline = measure_allocations("baseline_lease_consume_separate_lru_map", || {
        let mut pool = BaselineLeasePool::new(key.clone(), 200_000);
        for _ in 0..100_000 {
            black_box(pool.consume(&key, 1));
        }
    });
    let optimized = measure_allocations("optimized_lease_consume_inline_lru", || {
        let mut pool = LeasePool::default();
        pool.insert(&key, "lease".to_string(), 200_000, 200);
        for _ in 0..100_000 {
            black_box(pool.consume(&key, 1, 100));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        let mut pool = BaselineLeasePool::new(key.clone(), 200_000);
        for _ in 0..100_000 {
            black_box(pool.consume(&key, 1));
        }
    });
    let optimized_cpu = best_of_three(|| {
        let mut pool = LeasePool::default();
        pool.insert(&key, "lease".to_string(), 200_000, 200);
        for _ in 0..100_000 {
            black_box(pool.consume(&key, 1, 100));
        }
    });
    println!(
        "lease_pool_consume_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

#[test]
fn lease_pool_lookup_perf_loop_keeps_single_entry_lookup() {
    const ITERATIONS: usize = 1_000_000;
    let key = key();
    let baseline_cpu = best_of_three(|| {
        let mut entries = HashMap::from([(key.clone(), 1_u64)]);
        for _ in 0..ITERATIONS {
            black_box(entries.get_mut(&key));
            black_box(entries.get_mut(&key));
        }
    });
    let optimized_cpu = best_of_three(|| {
        let mut entries = HashMap::from([(key.clone(), 1_u64)]);
        for _ in 0..ITERATIONS {
            black_box(entries.get_mut(&key));
        }
    });
    println!(
        "lease_pool_lookup_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(percent_improvement(baseline_cpu, optimized_cpu) >= 15.0);
}

struct BaselineLeasePool {
    items: HashMap<LeasePoolKey, u64>,
    last_used: HashMap<LeasePoolKey, u64>,
    clock: u64,
}

impl BaselineLeasePool {
    fn new(key: LeasePoolKey, tokens: u64) -> Self {
        Self {
            items: HashMap::from([(key, tokens)]),
            last_used: HashMap::new(),
            clock: 0,
        }
    }

    fn consume(&mut self, key: &LeasePoolKey, cost: u64) -> Option<u64> {
        if !self.items.contains_key(key) {
            return None;
        }
        self.clock = self.clock.saturating_add(1);
        self.last_used.insert(key.clone(), self.clock);
        let remaining = self.items.get_mut(key)?;
        if *remaining < cost {
            return None;
        }
        *remaining -= cost;
        Some(*remaining)
    }
}

#[test]
fn lease_pool_given_exact_grant_then_never_consumes_beyond_granted_tokens() {
    let key = key();
    let mut pool = LeasePool::default();
    pool.insert(&key, "lease-1".to_string(), 3, 101);

    assert_eq!(pool.consume(&key, 1, 100), Some(2));
    assert_eq!(pool.consume(&key, 2, 100), Some(0));
    assert_eq!(pool.consume(&key, 1, 100), None);
}

#[test]
fn lease_pool_given_expiry_boundary_then_expired_tokens_are_unusable() {
    let key = key();
    let mut pool = LeasePool::default();
    pool.insert(&key, "lease-1".to_string(), 2, 100);

    assert_eq!(pool.consume(&key, 1, 100), None);
    assert_eq!(pool.remaining(&key, 100), 0);
}

#[test]
fn lease_pool_given_duplicate_response_then_grant_is_counted_once() {
    let key = key();
    let mut pool = LeasePool::default();
    pool.insert(&key, "lease-1".to_string(), 2, 200);
    pool.insert(&key, "lease-1".to_string(), 2, 200);

    assert_eq!(pool.remaining(&key, 100), 2);
}

#[test]
fn lease_pool_given_server_expiry_beyond_local_safety_cap_then_cap_prevents_overuse() {
    let key = key();
    let mut pool = LeasePool::default();
    let acquired_at = 100_i64;
    let safe_expiry = bounded_lease_expiry(i64::MAX, acquired_at, key.params.lease_duration_ms);
    pool.insert(&key, "lease-skew".to_string(), 2, safe_expiry);

    assert_eq!(pool.consume(&key, 1, safe_expiry), None);
}

#[test]
fn lease_pool_given_partial_items_then_consumes_atomically_across_items() {
    let key = key();
    let mut pool = LeasePool::default();
    pool.insert(&key, "lease-1".to_string(), 1, 200);
    pool.insert(&key, "lease-2".to_string(), 2, 200);

    assert_eq!(pool.consume(&key, 3, 100), Some(0));
    assert_eq!(pool.consume(&key, 1, 100), None);
}

#[test]
fn bounded_lease_model_given_all_small_operation_sequences_then_consumption_never_exceeds_grants() {
    for grant_a in 0..=4_u32 {
        for grant_b in 0..=4_u32 {
            for first_cost in 0..=5_u32 {
                for second_cost in 0..=5_u32 {
                    let key = key();
                    let mut pool = LeasePool::default();
                    pool.insert(&key, "a".to_string(), grant_a, 200);
                    pool.insert(&key, "b".to_string(), grant_b, 200);
                    let total = u64::from(grant_a) + u64::from(grant_b);
                    let before = pool.remaining(&key, 100);
                    let first = pool.consume(&key, first_cost, 100);
                    let after_first = pool.remaining(&key, 100);
                    let second = pool.consume(&key, second_cost, 100);
                    let after_second = pool.remaining(&key, 100);
                    let consumed = before.saturating_sub(after_second);

                    assert!(consumed <= total);
                    if first.is_none() {
                        assert_eq!(after_first, before);
                    }
                    if second.is_none() {
                        assert_eq!(after_second, after_first);
                    }
                }
            }
        }
    }
}

proptest! {
    #[test]
    fn lease_pool_generated_operation_sequences_never_consume_beyond_grants(
        grants in proptest::collection::vec(0_u32..1_000, 0..16),
        costs in proptest::collection::vec(1_u32..1_000, 0..64),
    ) {
        let key = key();
        let mut pool = LeasePool::default();
        for (index, grant) in grants.iter().copied().enumerate() {
            pool.insert(&key, format!("generated-{index}"), grant, 200);
        }
        let total_granted = grants.iter().map(|grant| u64::from(*grant)).sum::<u64>();
        let mut expected_remaining = total_granted;

        for cost in costs {
            let result = pool.consume(&key, cost, 100);
            if expected_remaining >= u64::from(cost) {
                expected_remaining -= u64::from(cost);
                prop_assert_eq!(result, Some(expected_remaining));
            } else {
                prop_assert_eq!(result, None);
            }
            prop_assert_eq!(pool.remaining(&key, 100), expected_remaining);
        }
        prop_assert!(pool.metrics().consumed_tokens <= total_granted);
    }
}

#[test]
fn lease_pool_given_entry_budget_then_evicts_least_recently_used_key() {
    let mut pool = LeasePool::default();
    for index in 0..crate::constants::MAX_LEASE_POOL_KEYS {
        let key = key_named(format!("key-{index}"));
        pool.insert(&key, format!("lease-{index}"), 1, 200);
    }
    let retained = key_named("key-0".to_string());
    let evicted = key_named("key-1".to_string());
    assert_eq!(pool.remaining(&retained, 100), 1);

    let replacement = key_named("replacement".to_string());
    pool.insert(&replacement, "replacement-lease".to_string(), 1, 200);

    assert_eq!(pool.remaining(&retained, 100), 1);
    assert_eq!(pool.remaining(&evicted, 100), 0);
    assert_eq!(pool.remaining(&replacement, 100), 1);
}

fn key() -> LeasePoolKey {
    key_named("tenant:user".to_string())
}

fn key_named(key: String) -> LeasePoolKey {
    LeasePoolKey {
        params: RateLimitParameters {
            limit_per_second: 10,
            burst: 10,
            lease_duration_ms: 1_000,
            estimated_nodes: 1,
            giveback_grace_ms: 100,
        },
        key,
    }
}
