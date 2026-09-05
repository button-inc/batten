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
//! `rules/rust.md` records exactly this hazard for a future
//! instruction-count series, which is why `metric=` exists at all. §5 of
//! CLOUD-935 says the distinct stamp must be **asserted rather than assumed**,
//! and this is that assertion.
//!
//! # Why over `mise.toml` rather than over the harness
//!
//! The stamp is set by the task, not by the measurement. A test reading the
//! harness would pass while the task that invokes it lost the variable — and the
//! task is the only caller, so the task is where the claim lives.
//! `policy/command-task-defined.rego` already establishes `mise.toml` as a parsed
//! document this repository reasons over; this is the same read in Rust.
//!
//! The harness was `bench/acquisition/sweep.py` until CLOUD-1229 retired it into
//! `crates/batten/examples/acquisition-bench.rs`. The anti-vacuity case below
//! moved with it, and moving it is the whole of what kept the case honest: it
//! names the invocation that actually runs the sweep, so a stamp set on some
//! other task cannot satisfy it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The default `perf-record` falls back to, and the one value this task must not
/// carry. Spelled here rather than read out of the shell, because the point is
/// that the two are DIFFERENT — deriving one from the other would make the
/// assertion vacuous the day somebody changed the default.
const INVOCATION_METRIC: &str = "wall-clock";

/// Every bench task, and the example target each one must be the invoker of.
///
/// A TABLE RATHER THAN ONE PAIR, since CLOUD-1291 added the second axis. The
/// hazard was never specific to acquisition: it is that two series sharing a unit
/// and a stamp become diffable, and a second bench makes that a property over a
/// SET rather than a comparison against one default. The anti-vacuity column
/// travels with each row for the reason it did before — a stamp set on some other
/// task cannot satisfy the row it is written for.
const BENCH_TASKS: &[(&str, &str)] = &[
    ("acquisition-bench", "--example acquisition-bench"),
    ("config-load-bench", "--example config-load-bench"),
];

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
        .and_then(|declared| declared.get("run"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("[tasks.{task}] declares a run body"))
        .to_owned()
}

fn stamp_of(task: &str, body: &str) -> String {
    body.split_whitespace()
        .find_map(|word| word.strip_prefix("BENCH_METRIC="))
        .unwrap_or_else(|| {
            panic!(
                "[tasks.{task}] sets BENCH_METRIC — without it perf-record stamps \
                 the invocation series' default and the two become diffable"
            )
        })
        .to_owned()
}

#[test]
fn every_bench_series_is_stamped_with_its_own_metric() {
    for (task, _) in BENCH_TASKS {
        let stamp = stamp_of(task, &task_body(task));
        assert!(
            !stamp.is_empty(),
            "[tasks.{task}]: an empty stamp is the default by another route"
        );
        assert_ne!(
            stamp, INVOCATION_METRIC,
            "[tasks.{task}] must not share the invocation series' stamp: a reader \
             plotting `{INVOCATION_METRIC}` would put a bench arm beside a `--help` \
             invocation and read the gap as a regression"
        );
    }
}

/// The property one task alone could not have: no two bench series collide.
///
/// Distinctness from `wall-clock` is what the single-task case asserted, and it
/// stops being the whole claim the moment a second bench exists — two benches
/// could each avoid the default and still stamp each other's axis, which is the
/// same defect with the same symptom and no gate on it.
#[test]
fn no_two_bench_series_share_a_stamp() {
    let mut seen: Vec<(&str, String)> = Vec::new();
    for (task, _) in BENCH_TASKS {
        let stamp = stamp_of(task, &task_body(task));
        if let Some((other, _)) = seen.iter().find(|(_, taken)| *taken == stamp) {
            panic!(
                "[tasks.{task}] and [tasks.{other}] both stamp `{stamp}`: their \
                 entries land in one series and a reader diffing it reads a step \
                 change between two different measurements"
            );
        }
        seen.push((task, stamp));
    }
}

/// ANTI-VACUITY. The cases above pass over any string that is not `wall-clock` —
/// including one set by a task that does not exist, if the lookup were ever
/// loosened to a whole-file scan. This pins that each body read is the one that
/// actually runs its harness.
#[test]
fn each_stamp_is_set_on_the_task_that_runs_its_harness() {
    for (task, invocation) in BENCH_TASKS {
        let body = task_body(task);
        assert!(
            body.contains(invocation),
            "[tasks.{task}]: the body carrying the stamp is the one invoking the \
             measurement (`{invocation}`): {body}"
        );
    }
}
