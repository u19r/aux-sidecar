use super::*;

#[test]
fn snapshot_is_atomic_and_has_a_hard_stale_ceiling() {
    let snapshot = RevocationSnapshot::new(
        ["https://api.example".to_string()],
        [("jti-1".to_string(), 2_000)],
        1_000,
        10,
        60_000,
    );
    assert!(snapshot.covers(&["https://api.example".to_string()]));
    let audiences = ["https://api.example".to_string()];
    assert_eq!(
        snapshot.lookup_for_audiences(&audiences, "jti-1", 1_001),
        RevocationLookup::Revoked
    );
    assert_eq!(
        snapshot.lookup_for_audiences(&audiences, "jti-2", 1_011),
        RevocationLookup::Stale
    );
    assert_eq!(
        snapshot.lookup_for_audiences(&audiences, "jti-2", 2_000),
        RevocationLookup::Stale
    );
    assert_eq!(
        snapshot.lookup_for_audiences(&audiences, "jti-2", 61_001),
        RevocationLookup::Unavailable
    );
}

#[test]
fn payload_decode_rejects_unbounded_or_inverted_windows() {
    let payload = serde_json::json!({
        "audiences": ["https://api.example"],
        "items": [],
        "fresh_ttl_ms": 60_000,
        "stale_ttl_ms": 10_000,
    });
    assert!(RevocationSnapshot::from_payload(&payload, 0).is_err());
}
