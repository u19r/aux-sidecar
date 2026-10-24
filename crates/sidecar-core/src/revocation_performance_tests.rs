use std::{hint::black_box, time::Instant};

use serde_json::json;

use crate::{RevocationLookup, RevocationSnapshot, SidecarState};

#[test]
#[ignore = "P3 revocation cache replacement and local lookup receipt"]
fn revocation_cache_replacement_and_local_lookup_receipt() {
    const ENTRIES: usize = 100_000;
    const REPLACEMENTS: usize = 100;
    const LOOKUPS: usize = 100_000;
    let audiences = ["https://api.performance.example".to_string()];
    let entries = (0..ENTRIES).map(|index| (format!("jti-p3-{index}"), 2_000));
    let snapshot = RevocationSnapshot::new(audiences.clone(), entries, 0, 10_000, 60_000);
    let state = SidecarState::new();

    let replacement_started = Instant::now();
    for _ in 0..REPLACEMENTS {
        state.store_revocation_snapshot(snapshot.clone());
    }
    let replacement_ns = replacement_started.elapsed().as_nanos();

    const BASELINE_ENTRIES: usize = 10_000;
    const BASELINE_ITERATIONS: usize = 100;
    let baseline_payload = json!({
        "audiences": audiences.clone(),
        "items": (0..BASELINE_ENTRIES)
            .map(|index| json!({"jti": format!("jti-p3-{index}"), "exp": 2_000}))
            .collect::<Vec<_>>(),
        "fresh_ttl_ms": 10_000,
        "stale_ttl_ms": 60_000,
    });
    let baseline_started = Instant::now();
    for _ in 0..BASELINE_ITERATIONS {
        let parsed = RevocationSnapshot::from_payload(&baseline_payload, 0)
            .expect("decode baseline snapshot");
        let result = parsed.lookup_for_audiences(&audiences, "jti-p3-5000", 1_000);
        assert_eq!(result, RevocationLookup::Revoked);
        black_box(result);
    }
    let baseline_parse_lookup_ns = baseline_started.elapsed().as_nanos();

    let candidate_started = Instant::now();
    for _ in 0..BASELINE_ITERATIONS {
        let result = snapshot.lookup_for_audiences(&audiences, "jti-p3-5000", 1_000);
        assert_eq!(result, RevocationLookup::Revoked);
        black_box(result);
    }
    let candidate_lookup_ns = candidate_started.elapsed().as_nanos();

    let lookup_started = Instant::now();
    for _ in 0..LOOKUPS {
        let result = snapshot.lookup_for_audiences(&audiences, "jti-p3-50000", 1_000);
        assert_eq!(result, RevocationLookup::Revoked);
        black_box(result);
    }
    let lookup_ns = lookup_started.elapsed().as_nanos();
    println!(
        "p3_revocation_cache entries={ENTRIES} replacements={REPLACEMENTS} \
         replacement_ns={replacement_ns} baseline_parse_entries={BASELINE_ENTRIES} \
         baseline_iterations={BASELINE_ITERATIONS} \
         baseline_parse_lookup_ns={baseline_parse_lookup_ns} \
         candidate_lookup_ns={candidate_lookup_ns} lookups={LOOKUPS} lookup_ns={lookup_ns}"
    );
}
