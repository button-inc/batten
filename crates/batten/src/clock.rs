//! The boundary's wall clock, in whole seconds since the epoch.
//!
//! A leaf: it names nothing in this crate, so a module that only needs the time
//! does not reach up into the crate root for it. The decision path may not take
//! a clock (`ambient_authority.rs` gates that); a READER at the boundary may, and
//! what it feeds is a recorded or rendered age, never a verdict.

/// Seconds since the epoch, or zero where the clock will not read — a timestamp
/// nobody can produce is recorded as one rather than refusing the caller.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
