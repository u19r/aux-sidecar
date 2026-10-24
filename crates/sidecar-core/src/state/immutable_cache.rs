use std::{collections::HashMap, hash::Hash};

#[derive(Debug)]
pub(super) struct BoundedLruCache<K, V> {
    capacity: usize,
    access_clock: u64,
    values: HashMap<K, Entry<V>>,
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    last_access: u64,
}

impl<K, V> BoundedLruCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            access_clock: 0,
            values: HashMap::with_capacity(capacity),
        }
    }

    pub(super) fn get(&mut self, key: &K) -> Option<V> {
        self.access_clock = self.access_clock.saturating_add(1);
        let entry = self.values.get_mut(key)?;
        entry.last_access = self.access_clock;
        Some(entry.value.clone())
    }

    pub(super) fn insert(&mut self, key: K, value: V) -> bool {
        if self.capacity == 0 {
            return false;
        }
        self.access_clock = self.access_clock.saturating_add(1);
        let mut evicted = false;
        if !self.values.contains_key(&key) && self.values.len() >= self.capacity {
            self.evict_lru();
            evicted = true;
        }
        self.values.insert(
            key,
            Entry {
                value,
                last_access: self.access_clock,
            },
        );
        evicted
    }

    fn evict_lru(&mut self) {
        let Some(key) = self
            .values
            .iter()
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.values.remove(&key);
    }
}

#[cfg(test)]
#[path = "immutable_cache_tests.rs"]
mod immutable_cache_tests;
