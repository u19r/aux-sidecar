use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hint::black_box,
    sync::{Arc, RwLock},
};

use sha2::{Digest, Sha256};

use crate::performance_support_tests::{best_of_three, measure_allocations, percent_improvement};

#[test]
#[ignore = "candidate screen; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_collection_candidate_screen_reports_keep_or_reject_evidence() {
    let strings = (0..64)
        .map(|index| format!("value-{index}"))
        .collect::<Vec<_>>();
    screen_candidate(
        "parent_vec_collect",
        "parent_vec_reserved",
        || {
            black_box(strings.to_vec());
        },
        || {
            let mut values = Vec::with_capacity(strings.len());
            values.extend(strings.iter().cloned());
            black_box(values);
        },
    );
    screen_candidate(
        "scope_hashset_collect",
        "scope_hashset_reserved",
        || {
            black_box(strings.iter().cloned().collect::<HashSet<_>>());
        },
        || {
            let mut values = HashSet::with_capacity(strings.len());
            values.extend(strings.iter().cloned());
            black_box(values);
        },
    );
    let value = "snapshot-request".to_string();
    screen_candidate(
        "optional_vector_collect",
        "direct_single_vector",
        || {
            black_box(Some(value.clone()).into_iter().collect::<Vec<_>>());
        },
        || {
            black_box(vec![value.clone()]);
        },
    );
    let request = crate::runtime_sync_test_support::request();
    let serialized = serde_json::to_string(&request).expect("serialize request");
    screen_candidate(
        "serialized_sync_flight_key",
        "typed_sync_flight_key",
        || {
            let candidate = serde_json::to_string(&request).expect("serialize request");
            black_box(candidate == serialized);
        },
        || {
            let candidate = request.clone();
            black_box(candidate == request);
        },
    );
    screen_candidate(
        "returned_snapshot_find_and_clone",
        "returned_snapshot_consume",
        || {
            let values = strings.clone();
            black_box(values.iter().find(|value| value.ends_with("63")).cloned());
        },
        || {
            let values = strings.clone();
            black_box(values.into_iter().find(|value| value.ends_with("63")));
        },
    );
    screen_candidate(
        "duplicate_owned_refresh_request",
        "single_owned_refresh_request",
        || {
            black_box((request.clone(), request.clone()));
        },
        || {
            black_box(request.clone());
        },
    );
    let cached = RwLock::new(Some(42_u64));
    screen_candidate(
        "stale_cache_double_read",
        "stale_cache_single_read",
        || {
            black_box(*cached.read().expect("cache"));
            black_box(*cached.read().expect("cache"));
        },
        || {
            black_box(*cached.read().expect("cache"));
        },
    );
    screen_candidate(
        "runtime_sync_request_clone",
        "runtime_sync_request_borrow",
        || {
            black_box(request.clone());
        },
        || {
            black_box(&request);
        },
    );
}

#[test]
#[ignore = "second-pass candidate screen; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_second_pass_candidate_screen_reports_keep_or_reject_evidence() {
    let lease_key = crate::local_rate_limit::LeasePoolKey {
        params: sidecar_contract::RateLimitParameters {
            limit_per_second: 10,
            burst: 10,
            lease_duration_ms: 1_000,
            estimated_nodes: 1,
            giveback_grace_ms: 0,
        },
        key: "tenant:user".to_string(),
    };
    screen_candidate(
        "compound_lease_key_clone",
        "compound_lease_key_borrow",
        || black_box(lease_key.clone()),
        || black_box(&lease_key),
    );

    let lease_ids = (0..64)
        .map(|index| format!("lease-{index}"))
        .collect::<Vec<_>>();
    let lease_id_set = lease_ids.iter().cloned().collect::<HashSet<_>>();
    screen_candidate(
        "lease_id_vec_duplicate_scan",
        "lease_id_hashset_duplicate_lookup",
        || black_box(lease_ids.iter().any(|id| id == "lease-63")),
        || black_box(lease_id_set.contains("lease-63")),
    );

    let single_result = ["tenant:user".to_string()];
    screen_candidate(
        "single_lease_result_find",
        "single_lease_result_first",
        || {
            black_box(
                single_result
                    .iter()
                    .find(|key| key.as_str() == "tenant:user"),
            )
        },
        || black_box(single_result.first()),
    );

    let btree = (0..128)
        .map(|index| (index, index))
        .collect::<BTreeMap<_, _>>();
    let hash = btree
        .iter()
        .map(|(key, value)| (*key, *value))
        .collect::<HashMap<_, _>>();
    screen_candidate(
        "runtime_artifact_btree_lookup",
        "runtime_artifact_hash_lookup",
        || black_box(btree.get(&127)),
        || black_box(hash.get(&127)),
    );

    let countries = (0..128)
        .map(|index| format!("{index:02X}"))
        .collect::<Vec<_>>();
    let country_tree = countries.iter().cloned().collect::<BTreeSet<_>>();
    let country_hash = countries.iter().cloned().collect::<HashSet<_>>();
    screen_candidate(
        "blocklist_country_btree_lookup",
        "blocklist_country_hash_lookup",
        || black_box(country_tree.contains("7F")),
        || black_box(country_hash.contains("7F")),
    );

    let digest = Sha256::digest(b"policy descriptor");
    screen_candidate(
        "policy_digest_format_each_byte",
        "policy_digest_table_encoding",
        || {
            black_box(
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
        },
        || black_box(hex_bytes(&digest)),
    );

    let artifact_groups = (0..8)
        .map(|kind| {
            (
                kind,
                (0..128).map(|key| (key, key)).collect::<BTreeMap<_, _>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let artifact_count = artifact_groups.values().map(BTreeMap::len).sum::<usize>();
    screen_candidate(
        "runtime_artifact_count_recompute",
        "runtime_artifact_count_cached",
        || black_box(artifact_groups.values().map(BTreeMap::len).sum::<usize>()),
        || black_box(artifact_count),
    );

    let freshness = (0..128).map(|index| index == 127).collect::<Vec<_>>();
    screen_candidate(
        "runtime_kind_state_scan",
        "runtime_kind_state_cached",
        || black_box(freshness.iter().any(|fresh| *fresh)),
        || black_box(true),
    );

    let claims = Arc::new(serde_json::json!({
        "sub": "user_fixture",
        "roles": (0..32).map(|index| format!("role-{index}")).collect::<Vec<_>>(),
        "permissions": (0..64).map(|index| format!("permission-{index}")).collect::<Vec<_>>()
    }));
    screen_candidate(
        "jwt_claims_value_clone",
        "jwt_claims_arc_clone",
        || black_box((*claims).clone()),
        || black_box(Arc::clone(&claims)),
    );

    let versions = (0..128)
        .map(|index| (format!("org-{index:03}"), format!("v{index}")))
        .collect::<BTreeMap<_, _>>();
    screen_candidate(
        "runtime_known_versions_rebuild",
        "runtime_known_versions_cached_clone",
        || {
            black_box(
                versions
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>(),
            )
        },
        || black_box(versions.clone()),
    );

    let response = Arc::new(serde_json::json!({
        "artifacts": (0..128)
            .map(|index| serde_json::json!({"key": format!("org-{index}"), "values": vec!["x"; 16]}))
            .collect::<Vec<_>>()
    }));
    screen_candidate(
        "public_sync_response_value_clone",
        "public_sync_response_arc_clone",
        || black_box((*response).clone()),
        || black_box(Arc::clone(&response)),
    );

    let context = sidecar_contract::RequestContext::default();
    screen_candidate(
        "request_context_rebuild",
        "request_context_borrow",
        || black_box(sidecar_contract::RequestContext::default()),
        || black_box(&context),
    );
}

#[test]
#[ignore = "third-pass lower-priority candidate screen; run isolated with --ignored"]
fn perf_loop_third_pass_candidate_screen_reports_keep_or_reject_evidence() {
    let kinds = [
        sidecar_contract::SyncArtifactKind::Jwks,
        sidecar_contract::SyncArtifactKind::AuthzPolicy,
        sidecar_contract::SyncArtifactKind::RateLimitConfig,
        sidecar_contract::SyncArtifactKind::Blocklist,
        sidecar_contract::SyncArtifactKind::Entitlements,
    ];
    let identities = (0..64)
        .map(|index| {
            (
                kinds[index % kinds.len()].clone(),
                format!("key-{index:03}"),
            )
        })
        .collect::<Vec<_>>();
    screen_candidate(
        "sync_duplicate_identities_owned",
        "sync_duplicate_identities_borrowed",
        || {
            black_box(
                identities
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<(sidecar_contract::SyncArtifactKind, String)>>(),
            )
        },
        || {
            black_box(
                identities
                    .iter()
                    .map(|(kind, key)| (kind, key.as_str()))
                    .collect::<BTreeSet<_>>(),
            )
        },
    );

    let server_time = "2026-07-12T12:34:56.123456Z";
    let parsed = chrono::DateTime::parse_from_rfc3339(server_time).expect("time");
    screen_candidate(
        "sync_server_time_reparse",
        "sync_server_time_cached",
        || black_box(chrono::DateTime::parse_from_rfc3339(server_time).expect("time")),
        || black_box(parsed),
    );

    let org = "o".repeat(512);
    let version = "v".repeat(512);
    screen_candidate(
        "known_duplicate_org_replace",
        "known_duplicate_org_entry",
        || {
            let mut known = BTreeMap::new();
            for _ in 0..128 {
                known.insert(org.clone(), version.clone());
            }
            black_box(known)
        },
        || {
            let mut known = BTreeMap::new();
            for _ in 0..128 {
                if !known.contains_key(org.as_str()) {
                    known.insert(org.clone(), version.clone());
                }
            }
            black_box(known)
        },
    );

    let wanted = kinds.iter().cloned().collect::<BTreeSet<_>>();
    screen_candidate(
        "sync_want_repeated_vec_scan",
        "sync_want_prebuilt_set",
        || black_box(kinds.iter().all(|kind| kinds.as_slice().contains(kind))),
        || black_box(kinds.iter().all(|kind| wanted.contains(kind))),
    );

    let artifact_groups = (0..8)
        .map(|kind| {
            (
                kind,
                Arc::new((0..64).map(|key| (key, key)).collect::<BTreeMap<_, _>>()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let artifact_count = 512_usize;
    screen_candidate(
        "shared_runtime_artifact_count_sum",
        "shared_runtime_artifact_count_cached",
        || {
            black_box(
                artifact_groups
                    .values()
                    .map(|group| group.len())
                    .sum::<usize>(),
            )
        },
        || black_box(artifact_count),
    );

    let long_version = "v".repeat(4_096);
    let shared_version = Arc::<str>::from(long_version.as_str());
    screen_candidate(
        "runtime_version_string_clone",
        "runtime_version_arc_clone",
        || black_box(long_version.clone()),
        || black_box(Arc::clone(&shared_version)),
    );

    let jwt_entries = (0..4_095).map(|key| (key, key)).collect::<HashMap<_, _>>();
    screen_candidate(
        "jwt_store_unconditional_prune",
        "jwt_store_prune_at_capacity",
        || {
            let mut entries = jwt_entries.clone();
            entries.retain(|_, value| *value != i32::MIN);
            black_box(entries)
        },
        || {
            let entries = jwt_entries.clone();
            black_box(entries)
        },
    );

    let sessions = (0..1_023).map(|key| (key, key)).collect::<HashMap<_, _>>();
    screen_candidate(
        "hosted_session_unconditional_prune",
        "hosted_session_prune_at_capacity",
        || {
            let mut entries = sessions.clone();
            entries.retain(|_, value| *value != i32::MIN);
            black_box(entries)
        },
        || black_box(sessions.clone()),
    );

    let flights = (0..8)
        .map(|index| format!("flight-{index}"))
        .collect::<Vec<_>>();
    screen_candidate(
        "keyed_sync_flight_linear_lookup",
        "keyed_sync_flight_hash_lookup",
        || black_box(flights.iter().find(|flight| flight.as_str() == "flight-7")),
        || {
            let lookup = flights.iter().map(String::as_str).collect::<HashSet<_>>();
            black_box(lookup.contains("flight-7"))
        },
    );

    let response = Arc::new(serde_json::json!({"data": "x".repeat(1024 * 1024)}));
    screen_candidate(
        "public_large_sync_response_clone",
        "public_large_sync_response_arc",
        || black_box((*response).clone()),
        || black_box(Arc::clone(&response)),
    );
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn screen_candidate<BaselineOutput, OptimizedOutput>(
    baseline_label: &'static str,
    optimized_label: &'static str,
    mut baseline: impl FnMut() -> BaselineOutput,
    mut optimized: impl FnMut() -> OptimizedOutput,
) {
    const ITERATIONS: usize = 10_000;
    let baseline_allocations = measure_allocations(baseline_label, || {
        for _ in 0..ITERATIONS {
            black_box(baseline());
        }
    });
    let optimized_allocations = measure_allocations(optimized_label, || {
        for _ in 0..ITERATIONS {
            black_box(optimized());
        }
    });
    alloc_counter::emit_report(&baseline_allocations).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized_allocations).expect("allocation report must be emitted");
    let baseline_cpu = best_of_three(|| {
        for _ in 0..ITERATIONS {
            black_box(baseline());
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..ITERATIONS {
            black_box(optimized());
        }
    });
    println!(
        "candidate_cpu baseline_label={} optimized_label={} baseline_ns={} optimized_ns={} \
         improvement={:.2}%",
        baseline_label,
        optimized_label,
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
}
