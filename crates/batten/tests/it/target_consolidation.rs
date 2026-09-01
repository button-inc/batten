//! Grouping 144 test targets into one changed nothing a case can observe
//! (CLOUD-1210).
//!
//! # Why this is asserted rather than cited
//!
//! nextest's design doc states the property plainly — "a key factor
//! distinguishing nextest from `cargo test` is that nextest runs **each test in a
//! separate process**", giving memory isolation, state isolation and independent
//! termination. So consolidation changes the LINK COUNT and not what a test can
//! see.
//!
//! That claim is load-bearing: if it were false, CLOUD-1210 would be trading
//! isolation for build speed, which is a trade nobody agreed to. A citation is
//! not a mechanism, and the runner is a pinned tool that could change — so the
//! property ships as a case rather than as a sentence in a commit message.
//!
//! # What each case actually discriminates
//!
//! The three below are chosen so that a runner sharing a process between tests
//! would red at least one of them, and so that none of them can pass vacuously:
//! each first ESTABLISHES the state it is about, then asserts nobody else sees
//! it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicU32, Ordering};

/// Process-global, and deliberately so. Under one process per test each case
/// sees its own zero; sharing a process would let whichever ran second see the
/// first's increment.
static TOUCHED: AtomicU32 = AtomicU32::new(0);

#[test]
fn a_grouped_test_starts_from_a_fresh_process_state() {
    assert_eq!(
        TOUCHED.fetch_add(1, Ordering::SeqCst),
        0,
        "this case sees a zeroed static, so it is not sharing a process with its \
         siblings — the isolation nextest documents and CLOUD-1210 relies on"
    );
}

#[test]
fn a_sibling_in_the_same_target_does_not_see_that_state() {
    // The same assertion from the other side. Whichever of the two runs second
    // would see 1 rather than 0 if the target boundary were what provided
    // isolation, because they are now in ONE target where they used to be in two.
    assert_eq!(
        TOUCHED.fetch_add(1, Ordering::SeqCst),
        0,
        "grouping put these two cases in one binary; they must still each get a \
         process, or consolidation would have traded isolation for link time"
    );
}

/// The other thing grouping could plausibly have broken, and the one every other
/// case in this tree depends on.
///
/// `CARGO_BIN_EXE_<name>` is set by cargo PER TEST TARGET, and `common::batten()`
/// reads it to find the binary under test. Consolidating 144 targets into one
/// changes which target that variable is set for, so a migration that got this
/// wrong would leave the whole end-to-end tier running some other `batten` off
/// `PATH` — or nothing — which is CLOUD-592's silent-stale-artifact failure
/// arriving through a different door. Asserted rather than assumed, because it is
/// the assumption the other 145 modules are built on.
#[test]
fn the_binary_under_test_is_still_addressable_from_the_grouped_target() {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_batten"));
    assert!(
        path.is_file(),
        "CARGO_BIN_EXE_batten must resolve to the built binary from inside the \
         grouped target: {}",
        path.display()
    );
}
