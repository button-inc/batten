//! `record query`, over the compiled binary (CLOUD-843, the forge-read
//! foundation).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! Nothing is retired by this tier: it builds the facility, and the retirements
//! that walk through it (`land-divergence-record`, `nonverdict-record`,
//! `timeout-drift-record`, the release readers) are separate packages whose
//! arms land with them.
//!
//! # Why the compiled binary, and why a module at the end of it
//!
//! A `[[forge.query]]` row is worth nothing until a MODULE decides over what it
//! wrote, so the cases here drive the whole path a consumer depends on: the row
//! loads, the verb binds the placeholders and walks the fixture forge, the record
//! lands where `Fact::Records` projects it, and `batten check` decides over it.
//! A case that stopped at the record would pass over a producer writing a store
//! no module reads — CLOUD-1810's dead gate, which is exactly what this facility
//! must not reintroduce.
//!
//! The forge is `rest`'s `BATTEN_REST_FIXTURE` seam: each request is appended to
//! `args`, so the URL that went out is an assertion rather than an inference, and
//! `resp.<n>` answers the n-th call.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{git_in, init_repo, scratch, stderr, write};

/// The repository a case names — deliberately not this one, so a placeholder
/// that leaked through reads as a literal `{owner}` rather than a real slug.
const REPO: &str = "acme/widgets";

/// A module that decides from the family the query writes and nothing else: a
/// failed run is a finding, and so is a window the producer could not finish.
const READS_THE_RUNS: &str = r#"# METADATA
# description: reads the family a forge query writes.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.reads_the_runs

import rego.v1

rules contains "record read other"

recorded := input.tree.records.runs

rows contains row if {
	some line in recorded
	startswith(line, "row\t")
	row := json.unmarshal(trim_prefix(line, "row\t"))
}

violation contains {
	"rule": "record read other",
	"verdict": "record read other",
	"subjects": [{"count": row.id}],
} if {
	some row in rows
	row.conclusion == "failure"
}

violation contains {
	"rule": "record read other",
	"verdict": "record read other",
	"subjects": [{"artifact": "window"}],
} if {
	some line in recorded
	startswith(line, "window\tstate=truncated")
}
"#;

/// The consumer config: one query, the family it writes declared, and the
/// module above registered over it. `since` is a TOML fragment or empty.
fn config(since: &str) -> String {
    format!(
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "record read other"
gloss = "the record this rule reads says so"
class = "A test fixture's class."

[[verdict.route]]
id = "record read first"
kind = "document"
target = "the record this rule reads"

[[rule]]
id = "record read other"
kind = "policy"
scope = "tree"
module = "policy/reads-the-runs.rego"
severity = "deny"

[[record]]
record = "runs"
writer = "batten record query runs --input workflow=land.yml"

[[forge.query]]
id = "runs"
endpoint = "repos/{{owner}}/{{repo}}/actions/workflows/{{workflow}}/runs"
rows = "workflow_runs"
per_page = 2
max_pages = 3
select = ["id", "conclusion", "created_at"]
params = {{ status = "completed" }}
{since}"#
    )
}

/// A committed consumer repository and an empty fixture forge beside it.
fn consumer(name: &str, since: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("forge-query-{name}"));
    init_repo(&dir);
    write(&dir, "batten.toml", &config(since));
    write(&dir, "policy/reads-the-runs.rego", READS_THE_RUNS);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "declare the query"]);
    let forge = scratch(&format!("forge-query-{name}-forge"));
    (dir, forge)
}

/// One canned response in the fixture's `-i` shape.
fn respond(forge: &Path, n: u32, status: u16, body: &str) {
    std::fs::write(
        forge.join(format!("resp.{n}")),
        format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("write the canned answer");
}

/// `batten <args>` in `dir` against the fixture forge, naming the repository.
fn against(dir: &Path, forge: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// `record query runs --input workflow=land.yml`.
fn query(dir: &Path, forge: &Path) -> Output {
    against(
        dir,
        forge,
        &["record", "query", "runs", "--input", "workflow=land.yml"],
    )
}

/// What the fixture recorded about the requests that went out.
fn requests(forge: &Path) -> String {
    std::fs::read_to_string(forge.join("args")).unwrap_or_default()
}

#[test]
fn a_declared_query_is_walked_reduced_and_decided_over() {
    // THE WHOLE PATH. Two pages, a `total_count` the walk reaches, one failed
    // run — and the module reports it, which is the claim a consumer depends on.
    let (dir, forge) = consumer("decided", "");
    respond(
        &forge,
        1,
        200,
        r#"{"total_count": 3, "workflow_runs": [{"id": 11, "conclusion": "success", "display_title": "a title nobody declared"}, {"id": 12, "conclusion": "failure"}]}"#,
    );
    respond(
        &forge,
        2,
        200,
        r#"{"total_count": 3, "workflow_runs": [{"id": 13, "conclusion": "success"}]}"#,
    );

    let recorded = query(&dir, &forge);
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "the query records\n{}",
        stderr(&recorded)
    );
    assert!(
        recorded.stdout.is_empty(),
        "silent on success (house style §6)"
    );

    // THE REQUEST IS THE ASSERTION: the slug and the input are bound, the
    // declared parameter rides along, and the walk owns `page`/`per_page`.
    let asked = requests(&forge);
    assert!(
        asked.contains(&format!(
            "repos/{REPO}/actions/workflows/land.yml/runs?page=1&status=completed&per_page=2"
        )),
        "the request should name the bound endpoint; it asked: {asked}"
    );
    assert!(
        asked.contains("page=2"),
        "the walk read the second page: {asked}"
    );
    assert!(
        !asked.contains('{'),
        "no placeholder reached the wire: {asked}"
    );

    // THE RECORD, byte for byte: the declared fields and nothing else — the
    // title the forge sent is NOT recorded (rule 4, decided at the declaration)
    // — and one closing line a module can hold the row count to.
    let branch = git_in(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let record = std::fs::read_to_string(batten::recorder::record_path(
        &dir.join(".git"),
        "runs",
        &branch,
        None,
    ))
    .expect("the family was written where the projection reads it");
    assert_eq!(
        record,
        "row\t{\"conclusion\":\"success\",\"created_at\":null,\"id\":11}\n\
         row\t{\"conclusion\":\"failure\",\"created_at\":null,\"id\":12}\n\
         row\t{\"conclusion\":\"success\",\"created_at\":null,\"id\":13}\n\
         window\tstate=whole\tread=3\tkept=3\n"
    );

    let decided = against(&dir, &forge, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "the module decides over the family the query wrote\n{}",
        stderr(&decided)
    );
}

#[test]
fn a_clean_window_is_recorded_and_the_module_says_nothing() {
    // THE ANTI-VACUITY MIRROR: without it, a module that fired on any record at
    // all would pass the case above.
    let (dir, forge) = consumer("clean", "");
    respond(
        &forge,
        1,
        200,
        r#"{"total_count": 1, "workflow_runs": [{"id": 21, "conclusion": "success"}]}"#,
    );
    assert_eq!(query(&dir, &forge).status.code(), Some(0));
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a clean window is clean\n{}",
        stderr(&quiet)
    );
}

#[test]
fn a_truncated_window_reaches_the_module_as_truncated() {
    // Three pages of budget against a collection of ten: the prefix is recorded
    // and LABELLED, so the module can refuse a partial window rather than judge
    // a prefix as the population.
    let (dir, forge) = consumer("truncated", "");
    for n in 1..=3 {
        respond(
            &forge,
            n,
            200,
            &format!(
                r#"{{"total_count": 10, "workflow_runs": [{{"id": {a}, "conclusion": "success"}}, {{"id": {b}, "conclusion": "success"}}]}}"#,
                a = n * 2,
                b = n * 2 + 1
            ),
        );
    }
    let recorded = query(&dir, &forge);
    assert_eq!(recorded.status.code(), Some(0), "{}", stderr(&recorded));
    let decided = against(&dir, &forge, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a truncated window must reach the module as truncated\n{}",
        stderr(&decided)
    );
}

#[test]
fn a_refusing_forge_is_could_not_look_and_removes_the_stale_record() {
    // THE STALENESS CASE. A first run records a failed run; the second is
    // refused by the forge. Leaving the first record would let a module decide
    // over a window nobody can date — so could-not-look REMOVES it, exits 3, and
    // the module goes quiet rather than repeating an old answer.
    let (dir, forge) = consumer("refused", "");
    respond(
        &forge,
        1,
        200,
        r#"{"total_count": 1, "workflow_runs": [{"id": 31, "conclusion": "failure"}]}"#,
    );
    assert_eq!(query(&dir, &forge).status.code(), Some(0));
    assert_eq!(
        against(&dir, &forge, &["check"]).status.code(),
        Some(2),
        "the first record decides"
    );

    respond(
        &forge,
        2,
        403,
        r#"{"message": "Resource not accessible by integration"}"#,
    );
    let refused = query(&dir, &forge);
    assert_eq!(refused.status.code(), Some(3), "could-not-look is exit 3");
    let said = stderr(&refused);
    assert!(said.contains("403"), "the pointer names the status: {said}");
    assert!(
        !said.contains("Resource not accessible"),
        "rule 4: the forge's body never reaches the report: {said}"
    );
    assert_eq!(
        against(&dir, &forge, &["check"]).status.code(),
        Some(0),
        "the stale record is gone, so the module says nothing"
    );
}

#[test]
fn the_since_window_keeps_recent_rows_and_drops_old_ones() {
    // Ten years back from the producer's clock: a 2026 run is inside, a 1990 one
    // is not. The failed run is the OLD one, so a window that failed to filter
    // would decide and a window that filtered stays clean.
    let (dir, forge) = consumer(
        "since",
        "\n[forge.query.since]\nfield = \"created_at\"\nseconds = 315360000\n",
    );
    respond(
        &forge,
        1,
        200,
        r#"{"total_count": 2, "workflow_runs": [{"id": 41, "conclusion": "success", "created_at": "2026-08-29T10:40:00Z"}, {"id": 42, "conclusion": "failure", "created_at": "1990-01-01T00:00:00Z"}]}"#,
    );
    let recorded = query(&dir, &forge);
    assert_eq!(recorded.status.code(), Some(0), "{}", stderr(&recorded));
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "the old failure is outside the window\n{}",
        stderr(&quiet)
    );
}

#[test]
fn an_input_the_query_does_not_read_is_a_usage_error() {
    let (dir, forge) = consumer("unread-input", "");
    let refused = against(
        &dir,
        &forge,
        &[
            "record",
            "query",
            "runs",
            "--input",
            "workflow=land.yml",
            "--input",
            "typo=x",
        ],
    );
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert!(
        requests(&forge).is_empty(),
        "nothing was asked of the forge"
    );
}

#[test]
fn a_query_nobody_declared_is_a_usage_error() {
    let (dir, forge) = consumer("undeclared-id", "");
    let refused = against(&dir, &forge, &["record", "query", "nope"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
}

#[test]
fn a_query_whose_family_no_record_row_declares_is_refused_at_load() {
    // CLOUD-1810's dead gate, refused while its author is watching: a query
    // writing a family nothing projects would record into a store no module can
    // read, and every run would look like success.
    let dir = scratch("forge-query-unprojected");
    init_repo(&dir);
    write(
        &dir,
        "batten.toml",
        &config("").replace(
            "[[record]]\nrecord = \"runs\"",
            "[[record]]\nrecord = \"other\"",
        ),
    );
    write(&dir, "policy/reads-the-runs.rego", READS_THE_RUNS);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "declare the query"]);
    let refused = common::run(&dir, &["config", "lint"]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a query no module can read is a config fault\n{}",
        stderr(&refused)
    );
}
