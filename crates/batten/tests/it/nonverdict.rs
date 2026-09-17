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
//! WHAT THE ARM CLAIMS, PRECISELY, is what `timeout-drift`'s already-landed arm
//! claims about the same shape: the RETIREMENT is carried by
//! `policy/nonverdict.rego` and this tier. It does not claim the producer's own
//! steps are covered here, and they are not — whether a failed step is a verdict
//! is read off the Actions API's `steps[]` by jq inside `[tasks.nonverdict-record]`,
//! which §5 keeps outside `check` and which no compiled-binary case reaches. That
//! is the coverage this delta spends, stated rather than implied.
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
// changed: "records with no window summary are exit 2 — there is no window to judge" mise.toml the summary is emitted unconditionally by the producer in window mode and the producer refuses in every arm that cannot reach one, so a family with records and no summary is a torn store rather than an incomplete scan; the module leaves it unjudged, which is what "there is no window to judge" means once could-not-look cannot be spelled as a finding
// changed: "two concatenated scans are exit 2 — a count over both describes neither" policy/nonverdict.rego the reading is unchanged and only its spelling moved: a count over both still describes neither, so neither is judged. `record named` replaces a family rather than appending to it, so two DIFFERENT summaries can now arrive only through a torn store, and a torn store is silence here for the same reason an unparseable line is skipped
// changed: "a non-numeric count is exit 2 rather than being coerced to zero" policy/nonverdict.rego the refusal to coerce is the whole of the case and it is kept — `count_of` is undefined for a value that is not digits, so neither rule fires. What changed is that undefinedness says "unjudged" where the shell's exit 2 would now say "violation"
// changed: "the budget is raise-only overridable, which is how the window is retuned" policy/nonverdict.rego the override had exactly one reader — the suite, pointing the budget at a fixture. A module's cases vary the COUNTS against a fixed `budget := 2` instead, which is `timeout-drift.rego`'s placement for its multipliers, so the knob is gone because the reader it existed for is
// changed: "THE ACCEPTANCE CASE: a job that died before any mise step is a non-verdict failure" mise.toml the classification reads the Actions API's own per-step conclusions, which §5 makes `check` incapable of fetching; it is the producer's jq, verbatim
// changed: "a job that failed IN a mise step rendered a verdict and is not counted" mise.toml the same jq over the same payload: naming the verdict-bearing step is the producer's half of the closed predicate
// changed: "a job that failed in a mise EXEC step rendered a verdict too" mise.toml the second spelling CLOUD-113 cost four jobs to learn, kept in the producer where the step names are read
// changed: "THE FAN-IN IS EXCLUDED: final's needs-assertion is not a non-verdict failure" mise.toml the exclusion is by job name over the API payload, before any record exists, so it is part of what the producer measures rather than of what the module judges
// changed: "A JOB OUTSIDE THE ROSTER IS EXCLUDED: a declining merge bot is not a failure here" mise.toml the roster is `$CI_REQUIRED_CHECKS` from `mise.toml [env]`, which the producer reads and the engine does not project
// changed: "the conditional request is actually sent once an ETag is stored" mise.toml an ETag is a property of an HTTP request, and the request is the producer's
// changed: "A 304 KEEPS THE PREVIOUS READING rather than reading as an empty window" mise.toml the cache lives under `.git/` and is read on the request path, so the 304 reading never reaches a record at all
// changed: "a 304 with no cached body is unreadable, never an empty window" mise.toml the same request path: with no body to fall back on the producer counts the run as unreadable, which is the input to `job read partial` rather than a decision of its own
// changed: "an unreadable jobs read is counted, not silently dropped" mise.toml counting is the producer's; what the count MEANS is the module's, and `job read partial` is where it is now decided
// changed: "an empty roster is unreadable rather than a count over every job" mise.toml this one genuinely changed rather than moved: with no roster the producer now refuses and records nothing, because recording `unreadable=1` over an empty window would spell total blindness as the partial-coverage finding, and those are different facts
// changed: "a summary line is always emitted, even when nothing failed" mise.toml the producer still emits it unconditionally, and the reason is now stronger: it is the one line that distinguishes a window that found nothing from nobody having looked
// changed: "POINTER, NEVER PAYLOAD: records carry coordinates, and no log is fetched" mise.toml no log body is ever fetched, so the property is enforced where the fetching would happen; the module's own pointer discipline is asserted below

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
target = "mise run nonverdict-record"

[[verdict]]
id = "job answer missing"
gloss = "a required job failed before reaching any verdict-bearing step"
class = "The run spent its minutes and answered nothing."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run nonverdict-record"

[[rule]]
id = "job grade other"
kind = "policy"
scope = "tree"
module = "policy/nonverdict.rego"
severity = "warn"

[[record]]
record = "nonverdict"
writer = "mise run nonverdict-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Write the producer's record, as `mise run nonverdict-record` would.
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
