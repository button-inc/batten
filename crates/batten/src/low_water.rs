//! The lowest free space any disk watcher in this process has read (CLOUD-2789).
//!
//! A leaf, so a reader of the mark (`land`, judging a gate that may have died
//! of a full disk) does not depend on the watcher that writes it, and through
//! it on the collector and the forge.

use std::sync::atomic::{AtomicU64, Ordering};

/// The lowest free space, in MiB, any watcher in this process has read since the
/// last [`reset`]; `u64::MAX` while none has.
///
/// MEASURED, NEVER INFERRED FROM TEXT (#1276). A gate's failure was classified
/// disk-full by matching `No space left on device` in its log, and on #1276 that
/// phrase sat inside a mutant's diff while this watcher had read gigabytes free.
/// Whether the volume filled is what this reading answers; the log is not asked.
static LOW_WATER: AtomicU64 = AtomicU64::new(u64::MAX);

/// Start a new measurement window: the gate about to run is judged by what is
/// read from here on.
pub fn reset() {
    LOW_WATER.store(u64::MAX, Ordering::Release);
}

/// The lowest free space read since [`reset`], or `None` where no watcher read
/// the volume in the window, which decides nothing about it.
#[must_use]
pub fn read() -> Option<u64> {
    Some(LOW_WATER.load(Ordering::Acquire)).filter(|low| *low != u64::MAX)
}

/// Record one reading against the window.
pub fn observe(free_mb: u64) {
    LOW_WATER.fetch_min(free_mb, Ordering::AcqRel);
}
