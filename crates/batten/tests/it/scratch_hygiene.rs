//! The scratch parent is collected once per run, and the collection is asserted
//! rather than declared (CLOUD-1879).
//!
//! # What went wrong
//!
//! `common::scratch` wipes its OWN path before writing, always. Nothing wiped the
//! PARENT, so every run left its fixtures behind — **3248 entries and ~300 MB per
//! run** — and the next run paid for them. Measured on this container, same
//! commit, same profile, same binary, idle box, varying only how many stale
//! directories `target/tmp` held at the start:
//!
//! | entries at start | wall | summed | `agentic_record` | `shell_retirement` |
//! | -- | -- | -- | -- | -- |
//! | 0 | 194.5s | 741.0s | 8.7s | 77.7s |
//! | ~1250 | 203.7s | 777.8s | 10.8s | 74.6s |
//! | 3750 | 220.9s | 846.3s | **93.5s** | 74.8s |
//!
//! **+13.5% wall clock, monotonic.** `shell_retirement` is flat across all three,
//! so the effect is specific rather than ambient noise. `agentic_record` swings
//! 10.7x on sibling count alone, uniformly across every case in that file —
//! including `a_tree_with_no_records_at_all_is_silent`, a synthetic empty-tree
//! fixture, at 0.20s → 4.51s. A 22x slowdown on a case with nothing to read is
//! not that case's own work.
//!
//! It also makes A/B measurement impossible: two arms run back to back are not
//! comparable, because the second starts with ~3250 more directories than the
//! first. Two arms of CLOUD-1878's experiment were voided by exactly that.
//!
//! # Why this asserts a RUN and not a CONFIG
//!
//! The obvious gate is "`.config/nextest.toml` declares a setup script". That is
//! the shape this repository has been bitten by: a gate that asserts a
//! declaration exists and is blind to whether it did anything —
//! `Builtins.shellcheck` read zero `.bats` files for its whole life and reported
//! green the entire time (`hk.pkl`).
//!
//! So the collector publishes its own reading through `$NEXTEST_ENV`, nextest's
//! sanctioned channel from a setup script to the tests, and this file asserts the
//! value arrived. A removed script, an unwired script, or one that failed before
//! its last statement all make the variable absent. **The gate fails when the
//! work did not happen, not when the declaration is missing.**

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

/// What the setup script publishes: how many entries the scratch parent held
/// *before* it was collected.
const COLLECTED: &str = "BATTEN_SCRATCH_COLLECTED";

/// The scratch parent itself, as the harness resolves it.
fn parent() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

#[test]
fn the_collector_ran_for_this_run() {
    let reading = std::env::var(COLLECTED).unwrap_or_else(|_| {
        panic!(
            "{COLLECTED} is unset, so the scratch parent was not collected for this run. \
             It is published by the `clear-scratch` setup script in `.config/nextest.toml` \
             through $NEXTEST_ENV. Either the script is gone, or it is no longer wired to \
             this profile, or it failed before its last statement — and without it the \
             suite gets ~13.5% slower per accumulated run and no two timing arms are \
             comparable (CLOUD-1879)."
        )
    });

    // ANTI-VACUITY. A variable set to anything would satisfy a presence check, so
    // the published value must be the shape the script actually writes: a count.
    // This is what fails if the `$NEXTEST_ENV` line is reduced to a bare marker.
    //
    // `trim` BECAUSE A COUNT IS THE CONTRACT AND ITS PADDING IS NOT. BSD `wc -l`
    // pads to a fixed width where GNU `wc -l` does not, so this read `"       0"`
    // on macos and `"0"` on the two Linux lanes — one red case out of 5007, on the
    // one lane whose libc differs. The collector now normalises it, and trimming
    // here keeps the assertion about the VALUE rather than about which `wc` ran.
    reading.trim().parse::<u64>().unwrap_or_else(|_| {
        panic!("{COLLECTED} should be the entry count the collector found, got {reading:?}")
    });
}

#[test]
fn the_parent_survives_its_own_collection() {
    // The collector removes the parent and recreates it. Recreating is not
    // optional: `common::scratch` joins onto this directory, so a collector that
    // deleted without recreating would take every fixture in the run with it —
    // and would do so only on the first run after a clean checkout, which is the
    // worst possible time to discover it.
    let parent = parent();
    assert!(
        parent.is_dir(),
        "the scratch parent {} must exist after collection — `common::scratch` joins onto it",
        parent.display()
    );
}
