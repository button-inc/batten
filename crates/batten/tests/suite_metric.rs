//! The suite series cannot be diffed against the invocation series (CLOUD-1208).
//!
//! # The hazard
//!
//! `mise-tasks/perf-record.sh` appends measurements to `refs/notes/perf` and
//! stamps each entry with `metric=`, read from `BENCH_METRIC` and defaulting to
//! `wall-clock`. That default is the INVOCATION series — `noop`, `hook`,
//! `wired`, measured over two committed fixtures in milliseconds.
//!
//! CLOUD-1208 measures the Rust SUITE: minutes of build and execute over the
//! whole workspace. The two share a unit and share nothing else. If both stamped
//! `wall-clock`, a reader plotting the series would put a 231-second suite arm
//! next to a `--help` invocation and read the gap as a regression — a step
//! change that never happened, in a series nobody re-derives.
//!
//! This is `acquisition_metric.rs`'s assertion for the third series, and the
//! third is what turns a pair into a rule: `.claude/rules/rust.md` records the
//! same hazard for a future instruction-count series, which is why `metric=`
//! exists at all.
//!
//! # Why over `mise.toml` rather than over the helper
//!
//! The stamp is set by the task, not by the Python. A test reading the helper
//! would pass while the task that invokes it lost the variable — and the task is
//! the only caller, so the task is where the claim lives.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

/// The default `perf-record` falls back to, and one of the two values this task
/// must not carry. Spelled here rather than read out of the shell, because the
/// point is that they are DIFFERENT — deriving one from the other would make the
/// assertion vacuous the day somebody changed the default.
const INVOCATION_METRIC: &str = "wall-clock";

/// The sibling sweep's stamp. A suite arm sharing THIS one would be the same
/// defect one axis over — `acquisition-bench` measures a generated fixture
/// family in milliseconds, and this measures the committed workspace in minutes.
const ACQUISITION_METRIC: &str = "acquisition-wall-clock";

fn task_body(task: &str) -> String {
    let manifest = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("the manifest is where every task in this repository is declared");
    // `toml::from_str`, which is the idiom every reader in `config.rs` and
    // `facts.rs` uses. `str::parse` resolves to a different impl here and reports
    // "unexpected content, expected nothing" over a manifest that is valid.
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed
        .get("tasks")
        .and_then(|tasks| tasks.get(task))
        .and_then(|task| task.get("run"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("[tasks.{task}] declares a run body"))
        .to_owned()
}

fn stamp(task: &str) -> String {
    task_body(task)
        .split_whitespace()
        .find_map(|word| word.strip_prefix("BENCH_METRIC=").map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "[tasks.{task}] sets BENCH_METRIC — without it perf-record stamps \
                 the invocation series' default and the two become diffable"
            )
        })
}

#[test]
fn the_suite_series_is_stamped_with_its_own_metric() {
    let suite = stamp("suite-bench-rust");

    assert!(
        !suite.is_empty(),
        "an empty stamp is the default by another route"
    );
    assert_ne!(
        suite, INVOCATION_METRIC,
        "the suite series must not share the invocation series' stamp: a reader \
         plotting `{INVOCATION_METRIC}` would put a whole-workspace suite arm \
         beside a `--help` invocation and read the gap as a regression"
    );
}

/// The three series are pairwise distinct, which is the property the pair of
/// assertions above only gets halfway to. Asserted against the sibling's LIVE
/// stamp rather than a second literal, because the claim is about the two tasks
/// disagreeing rather than about either one's spelling.
#[test]
fn the_suite_and_acquisition_series_do_not_share_a_stamp() {
    let suite = stamp("suite-bench-rust");
    let acquisition = stamp("acquisition-bench");

    assert_eq!(
        acquisition, ACQUISITION_METRIC,
        "the sibling's stamp moved, so this comparison is no longer the one \
         `acquisition_metric.rs` pins — reconcile the two before loosening either"
    );
    assert_ne!(
        suite, acquisition,
        "a minutes-long workspace suite arm and a milliseconds-long generated \
         fixture arm would be diffable under a shared stamp"
    );
}

/// ANTI-VACUITY. The cases above pass over any string that is not one of two
/// literals — including one set by a task that does not run the harness at all.
/// This pins that the body carrying the stamp is the one invoking the
/// measurement, which is `acquisition_metric.rs`'s own second case.
#[test]
fn the_stamp_is_set_on_the_task_that_runs_the_harness() {
    let body = task_body("suite-bench-rust");
    assert!(
        body.contains("bench/rust/sweep.py"),
        "the body carrying the stamp is the one invoking the measurement: {body}"
    );
}
