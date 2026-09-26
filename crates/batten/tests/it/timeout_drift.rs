//! `bound grade other` over the compiled binary (CLOUD-266, CLOUD-1717).
//!
//! # Why this tier and not the module's own `test_` rules
//!
//! Every case in `policy/timeout-drift.rego` fabricates its input with
//! `with input as`, which cannot see a fact the engine never projects — the state
//! `policy/branch-age.rego` sat in for a whole session while its own suite stayed
//! green (CLOUD-1810). These run the real module over a record the real verb
//! wrote, and one of them asserts the thing no load-time case can: that a `warn`
//! row REPORTS without failing the run.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The program's successor is `policy/timeout-drift.rego` for the
//! classification, and `[tasks.timeout-drift-record]` for the measurement. That
//! split is forced: the samples are durations of successful runs read from the
//! Actions API, and a p95 over them is arithmetic on instants — §5 makes `check`
//! `read` and incapable of spawning, and `Fact::Instant` projects `null` to every
//! module, which `clippy.toml` and `crates/batten/tests/clock_ban.rs` hold the
//! engine to.
//!
//! THE POSTURE IS PRESERVED BY SEVERITY. The retired program reported and never
//! blocked — it failed only its own scheduled run, filed no issue, posted no
//! comment — because a budget that no longer matches reality means nothing is
//! broken and no branch is at fault. `severity = "warn"` is that on the engine's
//! contract, and `a_drifted_budget_reports_without_failing_the_run` is what holds
//! it there.
//!
// carried: mise-tasks/timeout-drift.sh policy/timeout-drift.rego kind:mechanism crates/batten/tests/it/timeout_drift.rs
// carried: tests/timeout-drift.bats policy/timeout-drift.rego kind:mechanism crates/batten/tests/it/timeout_drift.rs
// carried: "a measured budget matching its measurement reports clean" policy/timeout-drift.rego kind:mechanism
// carried: "a budget the measurement has outgrown reports drift-tight, naming both numbers" policy/timeout-drift.rego kind:mechanism
// carried: "a budget gone slack because the job got faster reports drift-loose — the ratchet" policy/timeout-drift.rego kind:mechanism
// carried: "a small slack is not drift — a budget is a ceiling, not a target" policy/timeout-drift.rego kind:mechanism
// carried: "a job with fewer than the minimum samples reports unmeasurable, never a number" policy/timeout-drift.rego kind:mechanism
// carried: "a grandfathered entry with a usable sample is prompted for conversion" policy/timeout-drift.rego kind:mechanism
// carried: "a grandfathered entry with too small a sample is unmeasurable, not a conversion prompt" policy/timeout-drift.rego kind:mechanism
// changed: "matrix legs pool into one distribution — one timeout bounds them all" mise.toml the pooling is a STEP: the API reports a matrix leg as `dist (<target>)`, and matching the job key or the key followed by " (" is how the producer gathers one distribution before computing its p95. The module receives one row per job with the p95 already over the pooled samples, so there is nothing left here to pool
// changed: "a failed API query is exit 2, never a drift verdict" mise.toml the query is the producer's and so is its failure: it refuses at write time and records nothing, and an absent record is the module's silence. On the engine's contract exit 2 is a FINDING, so the shell's spelling would have made could-not-look a violation. The reason the retired program gives is the one that carries — reporting a healthy budget as drifted on a network blip is what gets a scheduled gate switched off
// changed: "an absent gh is exit 2, never a pass" mise.toml the producer needs `gh` to read the Actions API at all, so its absence refuses there and records nothing
// changed: "a missing workflow directory is exit 2, never a pass" mise.toml the declared budgets are read from the workflows by the producer, so an unreadable directory refuses before anything is recorded

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("timeout-drift-{name}"));
    let module = std::fs::read_to_string("../../policy/timeout-drift.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/timeout-drift.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[verdict]]
id = "bound pin loose"
gloss = "a job's declared timeout sits well above what its measurement justifies"
class = "A budget is a ceiling rather than a target, and past the slack it has gone slack."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run timeout-drift-record"

[[verdict]]
id = "bound pin wrong"
gloss = "a job's measurement has outgrown its declared timeout"
class = "Raise it before it starts failing healthy runs."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run timeout-drift-record"

[[verdict]]
id = "bound pin stale"
gloss = "a dated debt entry now has a usable sample"
class = "The prompt, never the conversion."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run timeout-drift-record"

[[verdict]]
id = "bound measure partial"
gloss = "too few successful runs to characterise a job"
class = "Below the minimum a job is uncharacterised rather than fast."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run timeout-drift-record"

[[rule]]
id = "bound grade other"
kind = "policy"
scope = "tree"
module = "policy/timeout-drift.rego"
severity = "warn"

[[record]]
record = "timeout-drift"
writer = "mise run timeout-drift-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Write a FINISHED census, as `mise run timeout-drift-record` now does: the job
/// lines, then the closing `census<TAB>jobs=<n>` it writes only after `emit`
/// succeeded.
fn record(dir: &std::path::Path, lines: &str) {
    let jobs = lines
        .lines()
        .filter(|line| line.starts_with("job\t"))
        .count();
    record_raw(dir, &format!("{lines}census\tjobs={jobs}\n"));
}

/// Write exactly these lines — for the torn records a finished producer never
/// writes.
fn record_raw(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "timeout-drift"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

#[test]
fn a_census_that_did_not_finish_is_not_a_short_census() {
    // THE TRUNCATION THE PIPE USED TO ALLOW: a record holding the jobs `emit`
    // reached before its `return 2`, with no close. It read as a whole census.
    for (name, lines) in [
        ("unclosed", "job\tci.yml\tbats\t6\t120\t25\tmeasured\n"),
        (
            "miscounted",
            "job\tci.yml\tbats\t6\t120\t25\tmeasured\ncensus\tjobs=4\n",
        ),
    ] {
        let dir = repo(&format!("torn-{name}"));
        record_raw(&dir, lines);
        let decided = run(&dir, &["check", "--fail-on-warning"]);
        assert_eq!(
            decided.status.code(),
            Some(2),
            "an {name} census is torn, not clean\n{}",
            said(&decided)
        );
    }
}

fn said(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_slack_budget_is_reported_as_loose_over_the_engines_projection() {
    // `justified(120s) == 6m`, so a declared 12 is past the five-minute slack.
    let dir = repo("loose");
    record(&dir, "job\tci.yml\tbats\t12\t120\t25\tmeasured\n");

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a slack budget is reported\n{}",
        said(&reported)
    );
    assert!(
        said(&reported).contains("bats"),
        "and the report names the job\n{}",
        said(&reported)
    );
}

#[test]
fn a_drifted_budget_reports_without_failing_the_run() {
    // THE PORTED POSTURE, and the case no load-time rule can make. The retired
    // program reported and never blocked; `warn` is that on this contract, so the
    // same record that fires above must leave an ordinary `check` green.
    let dir = repo("warn");
    record(&dir, "job\tci.yml\tbats\t12\t120\t25\tmeasured\n");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a report must not fail the run — nothing is broken and no branch is at fault\n{}",
        said(&quiet)
    );
}

#[test]
fn a_budget_matching_its_measurement_is_clean() {
    let dir = repo("clean");
    record(&dir, "job\tci.yml\tbats\t6\t120\t25\tmeasured\n");

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a correct budget is the state the report must be able to reach\n{}",
        said(&quiet)
    );
}

#[test]
fn a_budget_the_measurement_has_outgrown_is_reported_as_tight() {
    let dir = repo("tight");
    record(&dir, "job\tci.yml\tbats\t5\t120\t25\tmeasured\n");

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a budget below what the measurement justifies is reported\n{}",
        said(&reported)
    );
}

#[test]
fn a_job_with_too_few_samples_is_unmeasurable_rather_than_fast() {
    // A NAIVE PERCENTILE OVER TWO SAMPLES would propose tightening a release job
    // on it. Ten of the fourteen jobs here run weekly or on release, so this arm
    // is the common case rather than the defensive one.
    let dir = repo("unmeasurable");
    record(&dir, "job\tci.yml\tbats\t30\t120\t2\tmeasured\n");

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "an uncharacterised job is reported as such\n{}",
        said(&reported)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_reporting_drift() {
    // Every could-not-look arm of the retired program is now the producer
    // refusing and writing nothing. Reporting a healthy budget as drifted on a
    // network blip is the failure mode that gets a scheduled gate switched off.
    let dir = repo("absent");

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}
