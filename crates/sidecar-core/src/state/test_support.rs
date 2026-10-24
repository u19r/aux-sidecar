use std::cell::Cell;

thread_local! {
    static FIXED_TIME: Cell<Option<i64>> = const { Cell::new(None) };
}

/// A per-test-thread clock guard; drop restores the prior clock even after a
/// panic. Current-thread Tokio tests keep the complete operation on this
/// thread.
pub(crate) struct FixedClock(Option<i64>);

impl FixedClock {
    pub(crate) fn new(now_millis: i64) -> Self {
        Self(FIXED_TIME.replace(Some(now_millis)))
    }
}

impl Drop for FixedClock {
    fn drop(&mut self) {
        FIXED_TIME.set(self.0);
    }
}

pub(super) fn find_fixed_time() -> Option<i64> {
    FIXED_TIME.get()
}
