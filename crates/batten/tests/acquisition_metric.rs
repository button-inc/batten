//! The acquisition series cannot be diffed against the invocation series
//! (CLOUD-935 §5).
//!
//! # The hazard
//!
//! `mise-tasks/perf-record.sh` appends measurements to `refs/notes/perf` and
//! stamps each entry with `metric=`, read from `BENCH_METRIC` and defaulting to
//! `wall-clock`. That default is the INVOCATION series — `noop`, `hook`,
//! `wired`, measured over two committed fixtures.
//!
//! CLOUD-935 measures a different axis entirely: acquisition cost over a
//! generated fixture family whose declared-document count is swept. The two
//! series share a unit and share nothing else. If both stamped `wall-clock`, a
//! later reader plotting the series would put a 256-document sweep arm next to a
//! `--help` invocation and read the gap as a regression — a step change that
//! never happened, in a series nobody re-derives.
//!
//! `.claude/rules/rust.md` records exactly this hazard for a future
//! instruction-count series, which is why `metric=` exists at all. §5 of
//! CLOUD-935 says the distinct stamp must be **asserted rather than assumed**,
//! and this is that assertion.
//!
//! # Why over `mise.toml` rather than over the helper
//!
//! The stamp is set by the task, not by the Python. A test reading the helper
//! would pass while the task that invokes it lost the variable — and the task is
//! the only caller, so the task is where the claim lives.
//! `policy/command-task-defined.rego` already establishes `mise.toml` as a parsed
//! document this repository reasons over; this is the same read in Rust.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

/// The default `perf-record` falls back to, and the one value this task must not
/// carry. Spelled here rather than read out of the shell, because the point is
/// that the two are DIFFERENT — deriving one from the other would make the
/// assertion vacuous the day somebody changed the default.
const INVOCATION_METRIC: &str = "wall-clock";

fn task_body() -> String {
    let manifest = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("the manifest is where every task in this repository is declared");
    // `toml::from_str`, which is the idiom every reader in `config.rs` and
    // `facts.rs` uses. `str::parse` resolves to a different impl here and reports
    // "unexpected content, expected nothing" over a manifest that is valid.
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed
        .get("tasks")
        .and_then(|tasks| tasks.get("acquisition-bench"))
        .and_then(|task| task.get("run"))
        .and_then(toml::Value::as_str)
        .expect("[tasks.acquisition-bench] declares a run body")
        .to_owned()
}

#[test]
fn the_acquisition_series_is_stamped_with_its_own_metric() {
    let body = task_body();
    let stamp = body
        .split_whitespace()
        .find_map(|word| word.strip_prefix("BENCH_METRIC="))
        .expect(
            "[tasks.acquisition-bench] sets BENCH_METRIC — without it perf-record \
             stamps the invocation series' default and the two become diffable",
        );

    assert!(
        !stamp.is_empty(),
        "an empty stamp is the default by another route"
    );
    assert_ne!(
        stamp, INVOCATION_METRIC,
        "the acquisition series must not share the invocation series' stamp: a \
         reader plotting `{INVOCATION_METRIC}` would put a swept fixture arm \
         beside a `--help` invocation and read the gap as a regression"
    );
}

/// ANTI-VACUITY. The case above passes over any string that is not
/// `wall-clock` — including one set by a task that does not exist, if the lookup
/// above were ever loosened to a whole-file scan. This pins that the body read is
/// the one that actually runs the harness.
#[test]
fn the_stamp_is_set_on_the_task_that_runs_the_harness() {
    let body = task_body();
    assert!(
        body.contains("bench/acquisition/sweep.py"),
        "the body carrying the stamp is the one invoking the measurement: {body}"
    );
}
