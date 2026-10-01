//! `batten perf latency` over the compiled engine (CLOUD-843, retiring
//! `hook-latency-drift.yml`'s inline measurement).
//!
//! The verdict is a pure function in `perf.rs` with its own unit cases, both
//! drift directions included. What only this tier can show is the boundary:
//! the table reaches the verb through `[perf.latency]` in the committed
//! authority, a command that cannot start is could-not-look rather than a fast
//! pass, and an absent or malformed table refuses rather than measuring
//! nothing.
//!
//! THE TIMED COMMAND IS THE BINARY UNDER TEST, `--version`: it exists on every
//! platform the suite runs on and finishes inside a second, so the median is a
//! known 0 and each case below sets the budget that makes 0 the answer it wants.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{Fixture, run_with_stdin, stderr, stdout};

/// A checkout whose authority declares `latency` as its `[perf.latency]` body,
/// or no table at all when it is empty.
fn repo(name: &str, latency: &str) -> std::path::PathBuf {
    let table = if latency.is_empty() {
        String::new()
    } else {
        format!("\n[perf.latency]\n{latency}")
    };
    Fixture::new(name)
        .config(&format!(
            "version = 1\n\n[[rule]]\nid = \"noop\"\nkind = \"forbid\"\nglob = \"*.nothing\"\n\
             pattern = \"x\"\nseverity = \"warn\"\nscope = \"tree\"\n{table}"
        ))
        .git()
        .base_commit()
        .build()
}

/// `[perf.latency]` timing the binary under test, with the given budget.
fn timing_self(budget: u64, slack: u64, loose: u64) -> String {
    format!(
        "command = ['{}', '--version']\nruns = 3\nbudget_seconds = {budget}\n\
         slack_seconds = {slack}\nloose_factor = {loose}\n",
        env!("CARGO_BIN_EXE_batten")
    )
}

#[test]
fn a_median_inside_the_budget_passes_and_names_it() {
    let repo = repo("perf-latency-within", &timing_self(0, 5, 1));
    let output = run_with_stdin(&repo, &["perf", "latency"], "");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let said = stdout(&output);
    assert!(said.contains("within"), "{said}");
    assert!(said.contains("over 3 run(s)"), "{said}");
}

#[test]
fn a_budget_that_stopped_bounding_anything_is_drift() {
    // 15 / 3 = a 5s floor, and a sub-second command sits under it: the budget
    // is slack, which is drift in the other direction and exit 2 as loudly as a
    // slow command would be.
    let repo = repo("perf-latency-loose", &timing_self(15, 10, 3));
    let output = run_with_stdin(&repo, &["perf", "latency"], "");
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("drift-loose"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_command_that_cannot_start_is_could_not_look_never_a_fast_pass() {
    // The property the retired body's `command -v hk` guarded: an absent
    // program times as zero seconds if nothing asks, and zero is inside most
    // budgets.
    let repo = repo(
        "perf-latency-absent",
        "command = ['batten-perf-latency-no-such-program']\nruns = 3\n\
         budget_seconds = 0\nslack_seconds = 5\nloose_factor = 1\n",
    );
    let output = run_with_stdin(&repo, &["perf", "latency"], "");
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("unmeasurable"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn no_declared_table_is_could_not_look() {
    let repo = repo("perf-latency-undeclared", "");
    let output = run_with_stdin(&repo, &["perf", "latency"], "");
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("[perf.latency]"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_zero_run_count_is_refused_at_load() {
    let repo = repo(
        "perf-latency-zero-runs",
        "command = ['hk']\nruns = 0\nbudget_seconds = 15\nslack_seconds = 10\nloose_factor = 3\n",
    );
    let output = run_with_stdin(&repo, &["perf", "latency"], "");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("runs"), "{}", stderr(&output));
}
