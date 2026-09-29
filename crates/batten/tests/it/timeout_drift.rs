//! `bound grade other` over the compiled binary (CLOUD-266, CLOUD-1717; the
//! producer retired into forge queries under CLOUD-843).
//!
//! # Why this tier and not the module's own `test_` rules
//!
//! Every case in `policy/timeout-drift.rego` fabricates its input with
//! `with input as`, which cannot see a fact the engine never projects — the state
//! `policy/branch-age.rego` sat in for a whole session while its own suite stayed
//! green (CLOUD-1810). These run the REAL producer — the three declared
//! `[[forge.query]]` reads, against the `BATTEN_REST_FIXTURE` forge — and then the
//! real module over what it wrote, and one of them asserts the thing no load-time
//! case can: that a `warn` row REPORTS without failing the run.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The first successor was `policy/timeout-drift.rego` for the classification and
//! `[tasks.timeout-drift-record]`'s shell body for the measurement. The body is
//! gone: the reads are `[[forge.query]]` rows walked by `record query`, the one
//! subtraction the module cannot make is a `span` the producer computes, and the
//! pooling and the p95 moved into the module beside the classification.
//!
//! THE POSTURE IS PRESERVED BY SEVERITY. `severity = "warn"` is the retired
//! program's report-never-block posture on the engine's contract, and
//! `a_drifted_budget_reports_without_failing_the_run` holds it there.
//!
// carried: mise-tasks/timeout-drift.sh policy/timeout-drift.rego kind:mechanism crates/batten/tests/it/timeout_drift.rs
// carried: tests/timeout-drift.bats policy/timeout-drift.rego kind:mechanism crates/batten/tests/it/timeout_drift.rs
// carried: "[tasks.timeout-drift-record]" crates/batten/src/forge_query.rs kind:mechanism crates/batten/tests/it/timeout_drift.rs
// carried: "a measured budget matching its measurement reports clean" policy/timeout-drift.rego kind:mechanism
// carried: "a budget the measurement has outgrown reports drift-tight, naming both numbers" policy/timeout-drift.rego kind:mechanism
// carried: "a budget gone slack because the job got faster reports drift-loose — the ratchet" policy/timeout-drift.rego kind:mechanism
// carried: "a small slack is not drift — a budget is a ceiling, not a target" policy/timeout-drift.rego kind:mechanism
// carried: "a job with fewer than the minimum samples reports unmeasurable, never a number" policy/timeout-drift.rego kind:mechanism
// carried: "a grandfathered entry with a usable sample is prompted for conversion" policy/timeout-drift.rego kind:mechanism
// carried: "a grandfathered entry with too small a sample is unmeasurable, not a conversion prompt" policy/timeout-drift.rego kind:mechanism
// carried: "matrix legs pool into one distribution — one timeout bounds them all" policy/timeout-drift.rego kind:mechanism
// changed: "a failed API query is exit 2, never a drift verdict" crates/batten/src/forge_query.rs a forge that will not answer is `record query`'s could-not-look: exit 3, and the family is REMOVED, so the module reads an absent record and says nothing — `a_forge_that_will_not_answer_leaves_nothing_to_report_on` holds it
// changed: "an absent gh is exit 2, never a pass" crates/batten/src/forge_query.rs the producer spawns no `gh`: the forge is read in process, and a missing credential is the forge's refusal, which is the could-not-look above
// changed: "a missing workflow directory is exit 2, never a pass" policy/timeout-drift.rego the budgets are the workflows' own lines, read by the module; a tree with no workflow declares no budget, so there is nothing to report on

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, git_in, init_repo, run_with_stdin, scratch, stderr, stdout, write};

/// The repository the fixture forge answers for.
const REPO: &str = "acme/widgets";

/// The consumer's config: the committed module's row, the three families, and
/// the three forge reads exactly as `batten.toml` declares them.
const CONFIG: &str = r#"version = 1
scope = ["**"]

[[pattern]]
id = "workflow-job-key"
regex = '^  [A-Za-z0-9_-]+:[[:space:]]*$'

[[pattern]]
id = "workflow-top-level-key"
regex = '^[a-z][A-Za-z0-9_-]*:'

[[pattern]]
id = "job-timeout-line"
regex = '^    timeout-minutes:[[:space:]]*[0-9]+'

[[pattern]]
id = "timeout-budget-grandfathered"
regex = '^#[[:space:]]*budget:[[:space:]]*grandfathered[[:space:]]+measured=[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$'

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
line_sources = [".github/workflows/*.yml"]
severity = "warn"

[[record]]
record = "drift-workflows"
writer = "mise run timeout-drift-record"

[[record]]
record = "drift-runs"
writer = "mise run timeout-drift-record"

[[record]]
record = "drift-jobs"
writer = "mise run timeout-drift-record"

[[forge.query]]
id = "drift-workflows"
endpoint = "repos/{owner}/{repo}/actions/workflows"
rows = "workflows"
per_page = 100
max_pages = 1
select = ["id", "path"]

[[forge.query]]
id = "drift-runs"
endpoint = "repos/{owner}/{repo}/actions/workflows/{workflow}/runs"
rows = "workflow_runs"
params = { status = "success" }
per_page = 25
max_pages = 1
select = ["id", "path"]
each = { query = "drift-workflows", field = "id", input = "workflow" }

[[forge.query]]
id = "drift-jobs"
endpoint = "repos/{owner}/{repo}/actions/runs/{run}/jobs"
rows = "jobs"
per_page = 100
max_pages = 1
select = ["name", "conclusion"]
each = { query = "drift-runs", field = "id", input = "run" }

[[forge.query.span]]
name = "seconds"
from = "started_at"
to = "completed_at"
"#;

/// A committed consumer whose one workflow declares `declared` minutes for
/// `bats`, and an empty fixture forge beside it.
fn consumer(name: &str, declared: u32) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("timeout-drift-{name}"));
    init_repo(&dir);
    write(&dir, "batten.toml", CONFIG);
    write(
        &dir,
        "policy/timeout-drift.rego",
        &std::fs::read_to_string(at_root("policy/timeout-drift.rego")).expect("the module"),
    );
    write(
        &dir,
        ".github/workflows/ci.yml",
        &format!(
            "name: ci\non: push\njobs:\n  bats:\n    runs-on: ubuntu-latest\n    timeout-minutes: {declared} # budget: p95=40s x3 measured=2026-08-01\n"
        ),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "declare the reads"]);
    (dir, scratch(&format!("timeout-drift-{name}-forge")))
}

/// One canned response in the fixture's `-i` shape.
fn respond(forge: &Path, n: u32, status: u16, body: &str) {
    std::fs::write(
        forge.join(format!("resp.{n}")),
        format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("write the canned answer");
}

/// A job leg, `seconds` long, concluding `conclusion`.
fn leg(name: &str, conclusion: &str, seconds: u32) -> String {
    format!(
        r#"{{"name": "{name}", "conclusion": "{conclusion}", "started_at": "2026-08-01T00:00:00Z", "completed_at": "2026-08-01T00:{:02}:{:02}Z", "html_url": "https://example.invalid/log"}}"#,
        seconds / 60,
        seconds % 60
    )
}

/// The forge's three answers: one workflow, one successful run, and `legs`.
fn forge_answers(forge: &Path, legs: &[String]) {
    respond(
        forge,
        1,
        200,
        r#"{"total_count": 1, "workflows": [{"id": 7, "path": ".github/workflows/ci.yml", "name": "ci"}]}"#,
    );
    respond(
        forge,
        2,
        200,
        r#"{"total_count": 1, "workflow_runs": [{"id": 101, "path": ".github/workflows/ci.yml", "display_title": "a title nobody declared"}]}"#,
    );
    respond(
        forge,
        3,
        200,
        &format!(
            r#"{{"total_count": {}, "jobs": [{}]}}"#,
            legs.len(),
            legs.join(", ")
        ),
    );
}

/// `n` successful legs of a matrix job `bats`, each `seconds` long.
fn matrix(n: u32, seconds: u32) -> Vec<String> {
    (1..=n)
        .map(|index| leg(&format!("bats ({index})"), "success", seconds))
        .collect()
}

/// `batten <args>` in `dir` against the fixture forge.
fn against(dir: &Path, forge: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// `mise run timeout-drift-record`'s three reads, in its order, each asserted.
fn produce(dir: &Path, forge: &Path) {
    for id in ["drift-workflows", "drift-runs", "drift-jobs"] {
        let recorded = against(dir, forge, &["record", "query", id]);
        assert_eq!(
            recorded.status.code(),
            Some(0),
            "`record query {id}` records\n{}",
            stderr(&recorded)
        );
    }
}

fn said(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

fn report(dir: &Path, forge: &Path) -> Output {
    against(dir, forge, &["check", "--fail-on-warning"])
}

#[test]
fn a_budget_matching_its_measurement_is_clean() {
    // THE ANTI-VACUITY MIRROR: five legs of 120s justify 6 minutes exactly.
    let (dir, forge) = consumer("clean", 6);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    let quiet = report(&dir, &forge);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a correct budget is the state the report must be able to reach\n{}",
        said(&quiet)
    );
}

#[test]
fn the_job_durations_are_the_producers_subtraction() {
    // THE ONE STEP THE MODULE CANNOT TAKE, and the producer's record carries it:
    // each leg's `seconds`, tagged with the run it came from, and nothing the
    // forge sent that the row did not declare.
    let (dir, forge) = consumer("subtraction", 6);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    let branch = git_in(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let jobs = std::fs::read_to_string(batten::recorder::record_path(
        &dir.join(".git"),
        "drift-jobs",
        &branch,
        None,
    ))
    .expect("the jobs family was written where the projection reads it");
    assert!(
        jobs.starts_with(
            "row\t{\"conclusion\":\"success\",\"name\":\"bats (1)\",\"run\":101,\"seconds\":120}\n"
        ),
        "{jobs}"
    );
    assert!(
        jobs.ends_with("window\tstate=whole\tread=5\tkept=5\tmembers=1\ttruncated=0\n"),
        "{jobs}"
    );
    assert!(!jobs.contains("example.invalid"), "rule 4: {jobs}");
    let asked = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
    assert!(
        asked.contains(&format!(
            "repos/{REPO}/actions/workflows/7/runs?page=1&status=success&per_page=25"
        )),
        "the runs read is bound to the recorded workflow: {asked}"
    );
    assert!(
        asked.contains(&format!(
            "repos/{REPO}/actions/runs/101/jobs?page=1&per_page=100"
        )),
        "the jobs read is bound to the recorded run: {asked}"
    );
}

#[test]
fn a_slack_budget_is_reported_as_loose_over_the_engines_projection() {
    // `justified(120s) == 6m`, so a declared 12 is past the five-minute slack.
    let (dir, forge) = consumer("loose", 12);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    let reported = report(&dir, &forge);
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
    // THE PORTED POSTURE, and the case no load-time rule can make.
    let (dir, forge) = consumer("warn", 12);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a report must not fail the run — nothing is broken and no branch is at fault\n{}",
        said(&quiet)
    );
}

#[test]
fn a_budget_the_measurement_has_outgrown_is_reported_as_tight() {
    let (dir, forge) = consumer("tight", 5);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    let reported = report(&dir, &forge);
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
    // on it, so a declared 6 against two 120s legs is uncharacterised, not clean.
    let (dir, forge) = consumer("unmeasurable", 6);
    forge_answers(&forge, &matrix(2, 120));
    produce(&dir, &forge);
    let reported = report(&dir, &forge);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "an uncharacterised job is reported as such\n{}",
        said(&reported)
    );
}

#[test]
fn matrix_legs_pool_into_one_distribution() {
    // Five legs named `bats (<n>)` are five samples of the one job `bats`: the
    // budget is characterised and clean. Unpooled, `bats` has no sample at all.
    let (dir, forge) = consumer("pooled", 6);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    let quiet = report(&dir, &forge);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn a_failed_leg_is_not_a_sample() {
    // Four successes and a failure are four samples, below the minimum — where
    // five successes were clean. A failed leg ended early or late for a reason
    // that is not the job's cost.
    let (dir, forge) = consumer("failed-leg", 6);
    let mut legs = matrix(4, 120);
    legs.push(leg("bats (5)", "failure", 120));
    forge_answers(&forge, &legs);
    produce(&dir, &forge);
    let reported = report(&dir, &forge);
    assert_eq!(reported.status.code(), Some(2), "{}", said(&reported));
}

#[test]
fn a_census_that_did_not_finish_is_not_a_short_census() {
    // A jobs family present with no closing line was torn by something other
    // than the producer, which writes whole or removes. It is reported, never
    // read as a short census.
    let (dir, forge) = consumer("torn", 6);
    forge_answers(&forge, &matrix(5, 120));
    produce(&dir, &forge);
    // Five good rows, so the tearing is the ONLY thing wrong: without the torn
    // arm this record reads as a clean, characterised budget.
    let rows = "row\t{\"conclusion\":\"success\",\"name\":\"bats\",\"run\":101,\"seconds\":120}\n"
        .repeat(5);
    let torn = run_with_stdin(&dir, &["record", "named", "drift-jobs"], &rows);
    assert!(torn.status.success(), "{}", stderr(&torn));
    let reported = report(&dir, &forge);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a torn census is torn, not clean\n{}",
        said(&reported)
    );
}

#[test]
fn a_forge_that_will_not_answer_leaves_nothing_to_report_on() {
    // A refusal is could-not-look: exit 3, and no family, so the module says
    // nothing. Reporting a healthy budget as drifted on a network blip is the
    // failure mode that gets a scheduled gate switched off.
    let (dir, forge) = consumer("refused", 12);
    respond(&forge, 1, 403, r#"{"message": "Resource not accessible"}"#);
    let refused = against(&dir, &forge, &["record", "query", "drift-workflows"]);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    let fanned = against(&dir, &forge, &["record", "query", "drift-runs"]);
    assert_eq!(
        fanned.status.code(),
        Some(3),
        "a fan-out over an unrecorded source is could-not-look too\n{}",
        said(&fanned)
    );
    let quiet = report(&dir, &forge);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_reporting_drift() {
    let (dir, forge) = consumer("absent", 12);
    let quiet = report(&dir, &forge);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}
