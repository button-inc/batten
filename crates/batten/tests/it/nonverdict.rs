//! `job grade other` over the compiled binary (CLOUD-484, CLOUD-1717).
//!
//! # Why this tier and not the module's own `test_` rules
//!
//! Every case in `policy/nonverdict.rego` fabricates its input with
//! `with input as`, which cannot see a fact the engine never projects — the state
//! `policy/branch-age.rego` sat in for a whole session while its own suite stayed
//! green (CLOUD-1810). These run the real module over a record the real verb
//! wrote.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! TWO PROGRAMS, TWO SUCCESSORS, AND THE SPLIT WAS ALREADY THERE. The pair was
//! `nonverdict-scan` (measure) and `nonverdict-assert` (decide), kept apart for
//! exactly CLOUD-1559's reason: a measurement needs the network and a token, a
//! decision needs neither. So the port carried each half to the home the engine
//! has for it — the scan to `[tasks.nonverdict-record]`, the assert to
//! `policy/nonverdict.rego` — and no decision changed hands.
//!
//! THE SCAN'S ARMS ARE `carried`, AND `ported` WOULD HAVE BEEN WRONG. That marker
//! is admissible only where the dying file's DECLARED subject lives on, read from
//! its own base header rather than from the author — it exists for the sixteen
//! suites whose `# subject:` is an immortal like `mise.toml` or `hk.pkl`. This
//! suite declares `mise-tasks/nonverdict-scan.sh`, which dies in this same delta,
//! so the subject did not survive and `ported` cannot spell it.
//!
//! THE PRODUCER'S STEPS HAVE A TIER AGAIN (CLOUD-843). CLOUD-1717 left the
//! classification in `[tasks.nonverdict-record]`'s jq, which no compiled-binary
//! case reached. That body is now `batten record nonverdict`
//! (`crates/batten/src/ci_signal.rs`), and the cases at the end of this file drive
//! it against `rest`'s `BATTEN_REST_FIXTURE` forge. The consumer's facts — the
//! roster, the fan-in, the two verdict spellings — are its arguments, never the
//! engine's literals (rule 1).
//!
//! THE RETIRED BODY DID NOT RUN, which the replay found. Its jq program was
//! single-quoted and a comment inside it read "jq's `inside`", so the apostrophe
//! closed the quote and `bash` refused the body as a syntax error before any
//! request. The scheduled job has had no record to publish since that comment
//! landed; the verb's replay over the same responses agrees with the body with
//! only that apostrophe removed.
//!
//! THE POSTURE IS PRESERVED BY SEVERITY, AND IT IS TWO CLAIMS AT ONCE. The
//! retired decider argued at length that a rate which rises has to FAIL something
//! or it becomes an artifact nobody opens (non-negotiable rule 2), and
//! `nonverdict-rate.yml` argued just as plainly that its failure is informational:
//! the platform had a bad afternoon, no branch is at fault, and nothing in the
//! tree is broken. `severity = "warn"` holds both — an ordinary `check` stays
//! green, and the scheduled job runs `--fail-on-warning` and reds on the rate.
//!
//! THE EXIT CONTRACT CHANGED, AND FOUR ARMS RIDE ON IT. The decider ran `0` under
//! budget / `1` over / `2` could-not-look. The engine runs `0/1/2/3` where `2` is a
//! FINDING, so carrying the shell's `2` over would have turned every could-not-look
//! into a violation. `unreadable` is the one case that stayed a finding, because it
//! is not blindness: it is a window read in PART, which is `bench-assert`'s
//! partial-coverage false green.
//!
// carried: mise-tasks/nonverdict-scan.sh policy/nonverdict.rego kind:mechanism crates/batten/tests/it/nonverdict.rs
// carried: tests/nonverdict-scan.bats policy/nonverdict.rego kind:mechanism crates/batten/tests/it/nonverdict.rs
// carried: mise-tasks/nonverdict-assert.sh policy/nonverdict.rego kind:mechanism crates/batten/tests/it/nonverdict.rs
// carried: tests/nonverdict-assert.bats policy/nonverdict.rego kind:mechanism crates/batten/tests/it/nonverdict.rs
// carried: "under budget is a pass, and says what it judged" policy/nonverdict.rego kind:mechanism
// carried: "THE ACCEPTANCE CASE: over budget fails and names each non-verdict failure" policy/nonverdict.rego kind:mechanism
// carried: "a VERDICT failure is not counted, however many there are" policy/nonverdict.rego kind:mechanism
// carried: "COULD NOT LOOK: an unreadable run in the window is exit 2, never a pass" policy/nonverdict.rego kind:mechanism
// carried: "an unreadable run is exit 2 even when the count is under budget" policy/nonverdict.rego kind:mechanism
// carried: "ANTI-VACUITY: an empty window exits 0 and says it judged nothing" policy/nonverdict.rego kind:mechanism
// carried: "POINTER, NEVER PAYLOAD: the report carries no step output, only coordinates" policy/nonverdict.rego kind:mechanism
// changed: "empty stdin is exit 2, not a clean window" mise.toml there is no stdin: the decider's input is the record family, and an ABSENT family is could-not-look, which on the engine's contract must read as silence rather than as the exit 2 that now means a finding. The property the case was protecting is kept on the other side of the door — the producer refuses and writes nothing rather than recording an empty window
// carried: "records with no window summary are exit 2 — there is no window to judge" policy/nonverdict.rego `torn` refuses a record present with no summary as `job read partial`. The first port read it as silence and said so here; that was the dropped refusal, restored
// carried: "two concatenated scans are exit 2 — a count over both describes neither" policy/nonverdict.rego a count over both still describes neither, so neither is judged against the budget; the record is refused as torn instead of passing silent, which is what the retired arm did
// carried: "a non-numeric count is exit 2 rather than being coerced to zero" policy/nonverdict.rego `count_of` still refuses to coerce, and `torn` now reads the undefined count as a refusal rather than leaving the window unjudged
// changed: "the budget is raise-only overridable, which is how the window is retuned" policy/nonverdict.rego the override had exactly one reader — the suite, pointing the budget at a fixture. A module's cases vary the COUNTS against a fixed `budget := 2` instead, which is `timeout-drift.rego`'s placement for its multipliers, so the knob is gone because the reader it existed for is
// carried: "THE ACCEPTANCE CASE: a job that died before any mise step is a non-verdict failure" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// carried: "a job that failed IN a mise step rendered a verdict and is not counted" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// carried: "a job that failed in a mise EXEC step rendered a verdict too" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// carried: "THE FAN-IN IS EXCLUDED: final's needs-assertion is not a non-verdict failure" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// carried: "A JOB OUTSIDE THE ROSTER IS EXCLUDED: a declining merge bot is not a failure here" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// carried: "the conditional request is actually sent once an ETag is stored" crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/forge_window.rs
// carried: "nonverdict-scan.bats::A 304 KEEPS THE PREVIOUS READING rather than reading as an empty window" crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/forge_window.rs
// carried: "nonverdict-scan.bats::a 304 with no cached body is unreadable, never an empty window" crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/forge_window.rs
// carried: "an unreadable jobs read is counted, not silently dropped" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// changed: "an empty roster is unreadable rather than a count over every job" mise.toml this one genuinely changed rather than moved: with no roster the producer now refuses and records nothing, because recording `unreadable=1` over an empty window would spell total blindness as the partial-coverage finding, and those are different facts
// carried: "a summary line is always emitted, even when nothing failed" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// carried: "POINTER, NEVER PAYLOAD: records carry coordinates, and no log is fetched" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/nonverdict.rs
// changed: "single-run mode classifies one run on stdout for land" crates/batten/src/ci_signal.rs kind:verb dropped: `--run` had no caller left in the tree once `land` read the forge in process, and a mode nobody invokes is an untested path
// changed: "BATTEN_NONVERDICT_WINDOW and BATTEN_NONVERDICT_CACHE tune the scan" crates/batten/src/ci_signal.rs kind:verb the window is the `--window` flag and the cache is `forge::window`'s one validator store; both variables had one reader, the retired suite
// changed: "a could-not-look run exits 1 and records nothing" crates/batten/src/ci_signal.rs kind:verb the exit is now the engine's 3 for could-not-look, and the verb REMOVES a stale record rather than only declining to write

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against a declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("nonverdict-{name}"));
    let module = std::fs::read_to_string("../../policy/nonverdict.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/nonverdict.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

# The module reads its count guard by id rather than spelling the expression
# inline, which `policy test` refuses: an expression is a consumer fact and
# belongs in the config (rule 1). A fixture that omitted the row would make every
# reference undefined and every rule below silent.
[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[verdict]]
id = "job read partial"
gloss = "the scan could not read part of its window, so a green verdict would cover less than it claims"
class = "Partial coverage reported as a clean window is the false green this sensor exists to report."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "batten record nonverdict --exclude-job final --verdict-step 'Run mise run ' --verdict-step 'Run mise exec -- '"

[[verdict]]
id = "job answer missing"
gloss = "a required job failed before reaching any verdict-bearing step"
class = "The run spent its minutes and answered nothing."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "batten record nonverdict --exclude-job final --verdict-step 'Run mise run ' --verdict-step 'Run mise exec -- '"

[[rule]]
id = "job grade other"
kind = "policy"
scope = "tree"
module = "policy/nonverdict.rego"
severity = "warn"

[[record]]
record = "nonverdict"
writer = "batten record nonverdict --exclude-job final --verdict-step 'Run mise run ' --verdict-step 'Run mise exec -- '"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Write a record directly, as the producer `batten record nonverdict` would.
fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "nonverdict"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

/// Both streams: which one carries a finding is the output contract's business,
/// and what these cases assert is that the pointer reaches the reader.
fn said(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn an_over_budget_window_is_reported_over_the_engines_projection() {
    let dir = repo("over");
    record(
        &dir,
        "nonverdict\trun=111\tjob=ci\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=222\tjob=msrv\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=333\tjob=cross\tstep=Set up job\n\
         window\truns=10\tfailed_jobs=3\tnonverdict=3\tverdict=0\tunreadable=0\n",
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "three non-verdict failures against a budget of two decides\n{}",
        said(&decided)
    );
    assert!(
        said(&decided).contains("cross"),
        "and the finding names each job\n{}",
        said(&decided)
    );
}

#[test]
fn an_over_budget_window_reports_without_failing_the_run() {
    // THE PORTED POSTURE, and the case no load-time rule can make. The retired
    // gate failed its own scheduled run and nothing else — it filed no issue and
    // posted no comment — because the rate is a property of the runner fleet and
    // no branch is at fault. `warn` is that on this contract: the same record that
    // reds `--fail-on-warning` above must leave an ordinary `check` green, which
    // is what keeps `verify` from going red over the platform's bad afternoon.
    let dir = repo("warn");
    record(
        &dir,
        "nonverdict\trun=111\tjob=ci\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=222\tjob=msrv\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=333\tjob=cross\tstep=Set up job\n\
         window\truns=10\tfailed_jobs=3\tnonverdict=3\tverdict=0\tunreadable=0\n",
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a report must not fail the run — nothing in the tree is broken\n{}",
        said(&quiet)
    );
}

#[test]
fn an_under_budget_window_is_clean() {
    // The state the gate must be able to reach: two is the platform having a bad
    // afternoon, and is deliberately not actionable.
    let dir = repo("under");
    record(
        &dir,
        "nonverdict\trun=111\tjob=ci\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=222\tjob=msrv\tstep=Run actions/checkout@3d3c42e\n\
         window\truns=10\tfailed_jobs=2\tnonverdict=2\tverdict=0\tunreadable=0\n",
    );

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a window inside its budget is clean\n{}",
        said(&quiet)
    );
}

#[test]
fn a_partially_read_window_is_a_finding_rather_than_a_clean_one() {
    // `bench-assert`'s partial-coverage rule: a run that measured two of three
    // paths and reported green over the two is exactly the partial-coverage false
    // green. It fires UNDER budget, which is the whole point.
    let dir = repo("partial");
    record(
        &dir,
        "window\truns=10\tfailed_jobs=0\tnonverdict=0\tverdict=0\tunreadable=3\n",
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a window read in part is a finding even with nothing over budget\n{}",
        said(&decided)
    );
}

#[test]
fn a_torn_record_is_a_finding_rather_than_a_clean_window() {
    // THE REFUSAL THE FIRST PORT DROPPED, over the real projection. Each shape
    // reaches `torn` by a different arm, and every one was a clean exit 0 before:
    // `fields` gated on exactly one summary and nothing refused the rest.
    for (name, lines) in [
        (
            "two",
            "window\truns=10\tfailed_jobs=0\tnonverdict=0\tverdict=0\tunreadable=0\n\
             window\truns=10\tfailed_jobs=9\tnonverdict=9\tverdict=0\tunreadable=0\n",
        ),
        ("none", "nonverdict\trun=111\tjob=ci\tstep=Set up job\n"),
        (
            "garbled",
            "window\truns=10\tfailed_jobs=0\tnonverdict=lots\tverdict=0\tunreadable=0\n",
        ),
    ] {
        let dir = repo(&format!("torn-{name}"));
        record(&dir, lines);
        let decided = run(&dir, &["check", "--fail-on-warning"]);
        assert_eq!(
            decided.status.code(),
            Some(2),
            "a {name} record is torn, and torn is a finding\n{}",
            said(&decided)
        );
        assert!(
            said(&decided).contains("job read partial"),
            "under the partial-coverage class\n{}",
            said(&decided)
        );
    }
}

#[test]
fn a_verdict_failure_is_never_named_however_many_there_are() {
    // A judged branch is the branch's problem. Counting verdicts here would make
    // every genuinely red PR look like a platform fault.
    let dir = repo("verdicts");
    record(
        &dir,
        "verdict\trun=111\tjob=ci\tstep=Run mise run test:cargo\n\
         verdict\trun=222\tjob=msrv\tstep=Run mise exec -- cargo check\n\
         window\truns=10\tfailed_jobs=2\tnonverdict=0\tverdict=2\tunreadable=0\n",
    );

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a window of verdicts judges nothing here\n{}",
        said(&quiet)
    );

    // AND NOT NAMED WHEN THE WINDOW IS OVER BUDGET. The half above cannot see a
    // module that reads verdict lines as failures, because nothing is named
    // until the non-verdict count passes the budget.
    let dir = repo("verdicts-over");
    record(
        &dir,
        "nonverdict\trun=111\tjob=ci\tstep=Set up job\n\
         nonverdict\trun=222\tjob=msrv\tstep=Set up job\n\
         nonverdict\trun=333\tjob=cross\tstep=Set up job\n\
         verdict\trun=444\tjob=lint\tstep=Run mise run lint\n\
         window\truns=10\tfailed_jobs=4\tnonverdict=3\tverdict=1\tunreadable=0\n",
    );
    let over = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        over.status.code(),
        Some(2),
        "over budget decides\n{}",
        said(&over)
    );
    assert!(
        !said(&over).contains("lint"),
        "a verdict job is never named\n{}",
        said(&over)
    );
}

#[test]
fn an_empty_window_is_a_reading_rather_than_a_finding() {
    // ANTI-VACUITY. A window with no runs in it cannot fire, and this repo has
    // been bitten twice by a gate that cannot fire reading the same as one that
    // found nothing (`finding-sink-check`, `bench-assert`). The record's PRESENCE
    // is what keeps the two apart, which the case below is the other half of.
    let dir = repo("empty");
    record(
        &dir,
        "window\truns=0\tfailed_jobs=0\tnonverdict=0\tverdict=0\tunreadable=0\n",
    );

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an empty window judged nothing and says so by existing\n{}",
        said(&quiet)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    // Both total-blindness arms of the retired scan — an empty roster, an
    // unreadable run list — are now the producer refusing and writing nothing.
    let dir = repo("absent");

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}

#[test]
fn the_report_names_every_job_that_answered_nothing() {
    // ONE FINDING PER JOB, which is what a reader acts on: the count is what
    // decides, and the coordinates are what sends them somewhere. A single
    // finding carrying "3 jobs" would name none of them.
    //
    // The rendered line is the LEADING subject and nothing else, which is rule 4
    // holding at the output contract — the run id and step name ride on the
    // finding for a structured reader, and `policy/nonverdict.rego`'s own
    // `test_the_finding_carries_coordinates_and_nothing_else` is where that is
    // pinned. Asserting the run id HERE would be asserting the renderer's shape,
    // not this module's.
    let dir = repo("pointer");
    record(
        &dir,
        "nonverdict\trun=111\tjob=commit-lint\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=222\tjob=msrv\tstep=Run actions/checkout@3d3c42e\n\
         nonverdict\trun=333\tjob=cross\tstep=Set up job\n\
         window\truns=10\tfailed_jobs=3\tnonverdict=3\tverdict=0\tunreadable=0\n",
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    let text = said(&decided);
    for job in ["commit-lint", "msrv", "cross"] {
        assert!(
            text.contains(job),
            "every job that spent its minutes and answered nothing is named; {job} is not\n{text}"
        );
    }
}

// --- the producer, over the compiled binary against the fixture forge ---------------
//
// `record nonverdict` replaced `[tasks.nonverdict-record]` (CLOUD-843), so the
// producer's classification — the roster, the fan-in exclusion, the two verdict
// spellings, the unreadable count — has a compiled-binary tier again.

/// The roster the cases classify against: exact names, one of them carrying a
/// matrix suffix so a bare `action` job must NOT match it.
const ROSTER: &str = "ci,msrv,cross,action (ubuntu-latest),final";

/// One failed step, or a passing one.
fn step(number: u32, name: &str, conclusion: &str) -> String {
    format!(r#"{{"number": {number}, "name": "{name}", "conclusion": "{conclusion}"}}"#)
}

/// A job carrying its steps.
fn job(name: &str, conclusion: &str, steps: &[String]) -> String {
    format!(
        r#"{{"name": "{name}", "conclusion": "{conclusion}", "steps": [{}]}}"#,
        steps.join(",")
    )
}

/// A jobs payload.
fn jobs(rows: &[String]) -> String {
    format!(
        r#"{{"total_count": {}, "jobs": [{}]}}"#,
        rows.len(),
        rows.join(",")
    )
}

/// Three failed runs and a cancelled one, and the jobs each carried.
fn window_routes() -> Vec<(&'static str, u16, String)> {
    vec![
        (
            "runs/10/jobs",
            200,
            jobs(&[
                job(
                    "ci",
                    "failure",
                    &[
                        step(1, "Set up job", "success"),
                        step(4, "Run mise run test:cargo", "failure"),
                    ],
                ),
                job(
                    "final",
                    "failure",
                    &[step(2, "Assert all required jobs passed", "failure")],
                ),
                job("action", "failure", &[step(1, "Set up job", "failure")]),
                job("lint", "failure", &[step(1, "Set up job", "failure")]),
                job("msrv", "success", &[step(1, "Set up job", "success")]),
            ]),
        ),
        (
            "runs/20/jobs",
            200,
            jobs(&[
                job(
                    "msrv",
                    "failure",
                    &[step(3, "Run actions/checkout@abc", "failure")],
                ),
                job("cross", "failure", &[step(1, "Set up job", "failure")]),
            ]),
        ),
        (
            "runs/30/jobs",
            200,
            jobs(&[
                job(
                    "ci",
                    "failure",
                    &[
                        step(3, "Run mise exec -- cargo test", "failure"),
                        step(2, "Run actions/cache@x", "failure"),
                    ],
                ),
                job("cross", "failure", &[step(5, "Install", "failure")]),
            ]),
        ),
        (
            "status=failure&per_page=30",
            200,
            String::from(
                r#"{"total_count": 4, "workflow_runs": [{"id": 30, "conclusion": "failure"}, {"id": 10, "conclusion": "failure"}, {"id": 40, "conclusion": "cancelled"}, {"id": 20, "conclusion": "failure"}]}"#,
            ),
        ),
    ]
}

/// A fixture forge answering by endpoint.
fn forge(name: &str, routes: &[(&'static str, u16, String)]) -> std::path::PathBuf {
    let dir = scratch(&format!("nonverdict-{name}-forge"));
    let mut table = String::new();
    for (index, (needle, status, body)) in routes.iter().enumerate() {
        let file = format!("r{index}");
        std::fs::write(
            dir.join(&file),
            format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
        )
        .expect("write a canned answer");
        table.push_str(needle);
        table.push('\t');
        table.push_str(&file);
        table.push('\n');
    }
    std::fs::write(dir.join("routes"), table).expect("write the route table");
    dir
}

/// `batten record nonverdict` in `dir` against `forge`, with this repo's spellings
/// passed as the consumer's arguments.
fn classify(dir: &std::path::Path, forge: &std::path::Path) -> std::process::Output {
    common::batten()
        .args([
            "record",
            "nonverdict",
            "--exclude-job",
            "final",
            "--verdict-step",
            "Run mise run ",
            "--verdict-step",
            "Run mise exec -- ",
        ])
        .env("GH_REPO", "acme/widgets")
        .env("CI_REQUIRED_CHECKS", ROSTER)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

#[test]
fn the_producer_classifies_failed_required_jobs_and_the_module_decides() {
    // THE WHOLE PATH, over the replay's own fixture: byte-for-byte what the retired
    // body printed over the same responses. `final` is the fan-in and excluded;
    // `action` and `lint` are outside the roster (`action` only as a SUBSTRING of
    // a roster entry); run 40 was cancelled, which is another sensor's case. Both
    // verdict spellings are verdicts, and three non-verdicts is over the budget.
    let dir = repo("produce");
    let forge = forge("produce", &window_routes());

    let measured = classify(&dir, &forge);
    assert_eq!(measured.status.code(), Some(0), "{}", said(&measured));
    assert_eq!(
        String::from_utf8_lossy(&measured.stdout),
        "nonverdict\trun=20\tjob=cross\tstep=Set up job\n\
         nonverdict\trun=20\tjob=msrv\tstep=Run actions/checkout@abc\n\
         nonverdict\trun=30\tjob=cross\tstep=Install\n\
         verdict\trun=10\tjob=ci\tstep=Run mise run test:cargo\n\
         verdict\trun=30\tjob=ci\tstep=Run mise exec -- cargo test\n\
         window\truns=3\tfailed_jobs=5\tnonverdict=3\tverdict=2\tunreadable=0\n"
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("job answer missing"),
        "{}",
        said(&decided)
    );
}

#[test]
fn a_run_whose_jobs_cannot_be_read_is_counted_unreadable() {
    // A JOBS READ THAT FAILS IS COUNTED, never an empty run silently dropped from
    // the window — and the module reports the partial window whatever the count.
    let dir = repo("unread");
    let routes: Vec<(&'static str, u16, String)> = window_routes()
        .into_iter()
        .map(|(needle, status, body)| {
            if needle == "runs/20/jobs" {
                (needle, 500, String::from("{}"))
            } else {
                (needle, status, body)
            }
        })
        .collect();
    let forge = forge("unread", &routes);

    let measured = classify(&dir, &forge);
    let record = String::from_utf8_lossy(&measured.stdout);
    assert_eq!(measured.status.code(), Some(0), "{}", said(&measured));
    assert!(
        record.ends_with("window\truns=3\tfailed_jobs=3\tnonverdict=1\tverdict=2\tunreadable=1\n"),
        "{record}"
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    assert!(
        said(&decided).contains("job read partial"),
        "{}",
        said(&decided)
    );
}

#[test]
fn an_unreadable_run_list_is_could_not_look_and_an_empty_roster_is_refused() {
    // Total blindness records nothing, and exits 3; a missing roster is the
    // caller's to fix, and refuses before any request.
    let dir = repo("blind");
    let forge = forge(
        "blind",
        &[("status=failure&per_page=30", 503, String::from("{}"))],
    );
    let blind = classify(&dir, &forge);
    assert_eq!(blind.status.code(), Some(3), "{}", said(&blind));
    assert!(said(&blind).contains("could not look"), "{}", said(&blind));

    let refused = common::batten()
        .args(["record", "nonverdict", "--verdict-step", "Run mise run "])
        .env_remove("CI_REQUIRED_CHECKS")
        .env("GH_REPO", "acme/widgets")
        .current_dir(&dir)
        .output()
        .expect("the compiled binary runs");
    assert_ne!(refused.status.code(), Some(0), "{}", said(&refused));
    assert_ne!(refused.status.code(), Some(3), "{}", said(&refused));
    assert!(
        said(&refused).contains("CI_REQUIRED_CHECKS"),
        "{}",
        said(&refused)
    );
}
