use super::BoundedLruCache;

#[test]
fn capacity_given_recent_access_then_evicts_least_recently_used_entry() {
    let mut cache = BoundedLruCache::new(2);
    assert!(!cache.insert(1, "one"));
    assert!(!cache.insert(2, "two"));
    assert_eq!(cache.get(&1), Some("one"));

    assert!(cache.insert(3, "three"));

    assert_eq!(cache.get(&1), Some("one"));
    assert_eq!(cache.get(&2), None);
    assert_eq!(cache.get(&3), Some("three"));
}
