//! `lane grade other` over the compiled binary (CLOUD-492, CLOUD-1717).
//!
//! # Why this tier and not the module's own `test_` rules
//!
//! Every case in `policy/land-divergence.rego` fabricates its input with
//! `with input as`, which cannot see a fact the engine never projects — the state
//! `policy/branch-age.rego` sat in for a whole session while its own suite stayed
//! green (CLOUD-1810). These run the real module over a record the real verb
//! wrote, and one of them asserts the thing no load-time case can: that a `warn`
//! row REPORTS without failing the run.
//!
//! THAT IS NOT A HYPOTHETICAL HERE EITHER. Registering this module moved
//! `policy test` from 73 bundles to 74 and from 945 cases to 960 — so before the
//! `[[rule]]` row landed, all fifteen of the module's own cases were invisible to
//! the runner while sitting in the tree looking like coverage. The same shape, one
//! level up.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! TWO PROGRAMS, TWO SUCCESSORS, AND THE SPLIT WAS ALREADY THERE.
//! `land-divergence` measured and `land-divergence-assert` decided, kept apart for
//! CLOUD-1559's reason: a measurement needs the network and a token, a decision
//! needs neither. The measurement is `[tasks.land-divergence-record]`, the
//! decision is `policy/land-divergence.rego`, and no decision changed hands. The
//! pagination walk, the `ETag` cache, the `total_count` truncation guard and every
//! instant subtraction could not move: §5 makes `check` `read` and incapable of
//! spawning, and `Fact::Instant` projects `null` to every module.
//!
//! THE EXIT CONTRACT CHANGED, AND SIX ARMS RIDE ON IT. The decider ran `0` under
//! budget / `1` over / `2` could-not-look; the engine runs `0/1/2/3` where `2` is
//! a FINDING. Both total-blindness arms — an unreadable CI run window, an
//! unreadable merged-PR list — are now the producer refusing at write time and
//! recording nothing, which reads here as silence. `unreadable` is the one that
//! stayed a finding, because it is not blindness: it is a window read in PART.
//!
//! THE POSTURE IS PRESERVED BY SEVERITY. Every metric here is a property of the
//! FLEET over a window — cancel latency, queue delay, peak concurrency, the
//! fast-forward bot's refusal ratio — and no branch causes any of them, which is
//! why the retired pair was kept out of the hk gate and out of `verify` and why
//! its own suite asserted that absence. `severity = "warn"` is that on this
//! contract, and `a_divergent_window_reports_without_failing_the_run` holds it.
//!
//! THE PRODUCER'S STEPS HAVE A TIER AGAIN (CLOUD-843). CLOUD-1717 left them in
//! `[tasks.land-divergence-record]`, where no compiled-binary case reached them —
//! the coverage that delta spent, stated at the time. That body is now `batten
//! record divergence` (`crates/batten/src/ci_signal.rs`), and the cases at the
//! end of this file drive it against `rest`'s `BATTEN_REST_FIXTURE` forge: the
//! walk, the truncation guard, the per-run join, the per-job read and the
//! merged-PR paging, each over the compiled binary and then decided by the module.
//! The conditional request and the 304 fallback moved one layer further down, into
//! `forge::window`, whose own tier holds them. The arms below that said `mise.toml`
//! for those steps are re-pointed at the homes that now carry them.
//!
// carried: mise-tasks/land-divergence-assert.sh policy/land-divergence.rego kind:mechanism crates/batten/tests/it/land_divergence.rs
// carried: tests/land-divergence-assert.bats policy/land-divergence.rego kind:mechanism crates/batten/tests/it/land_divergence.rs
// carried: mise-tasks/land-divergence.sh policy/land-divergence.rego kind:mechanism crates/batten/tests/it/land_divergence.rs
// carried: tests/land-divergence.bats policy/land-divergence.rego kind:mechanism crates/batten/tests/it/land_divergence.rs
// carried: "a linear window passes: one graded run per landing, green, uncontended" policy/land-divergence.rego kind:mechanism
// carried: "graded runs per landing over budget exits 1" policy/land-divergence.rego kind:mechanism
// carried: "red runs per landing over budget exits 1" policy/land-divergence.rego kind:mechanism
// carried: "a 20s cancellation does NOT count as waste" policy/land-divergence.rego kind:mechanism
// carried: "a 400s cancellation DOES count as waste" policy/land-divergence.rego kind:mechanism
// carried: "peak concurrency above the admitted-successor bound exits 1" policy/land-divergence.rego kind:mechanism
// carried: "a queue delay is reported as its own defect, not as contention" policy/land-divergence.rego kind:mechanism
// carried: "any fast-forward refusal at all exits 1" policy/land-divergence.rego kind:mechanism
// carried: "a partially-read window exits 2, never 0" policy/land-divergence.rego kind:mechanism
// carried: "an unreadable window exits 2 even when every other number is ideal" policy/land-divergence.rego kind:mechanism
// carried: "A JOB QUEUE DELAY IS ITS OWN BUDGET, over a clean per-run figure" policy/land-divergence.rego kind:mechanism
// carried: "a window with no landings passes, and says why" policy/land-divergence.rego kind:mechanism
// carried: "the divergent PRs are named on failure, pointer-only" policy/land-divergence.rego kind:mechanism
// changed: "the ratio is reported in hundredths rather than rounded" policy/land-divergence.rego the unit is kept and the rounding is gone, which is what the case was really asking for. Bash has no floats, so the decider computed `$((x * 100 / n))` and DISCARDED the remainder — it could report a ratio marginally under a budget it was over. Rego divides exactly, so the comparison now agrees with the number a reader computes by hand, which is the property the case's own name states
// changed: "empty stdin exits 2" mise.toml there is no stdin: the decider's input is the record family, and an ABSENT family is could-not-look, which on the engine's contract must read as silence rather than as the exit 2 that now means a finding. The property is kept on the producer's side of the door, where both total-blindness arms refuse and write nothing
// carried: "records with no window summary exit 2" policy/land-divergence.rego `torn` refuses a record present with no summary as `lane read partial`. The first port read it as silence and recorded that here; that was the dropped refusal, restored
// carried: "two concatenated measurements exit 2 rather than describing neither" policy/land-divergence.rego a count over both still describes neither, so neither is judged against a budget; the record is refused as torn instead of passing silent, as the retired arm did
// carried: "a non-numeric count exits 2" policy/land-divergence.rego `count_of` still refuses to coerce, and `torn` reads the undefined count as a refusal rather than leaving the window unjudged
// carried: "a summary missing a count exits 2 rather than reading it as zero" policy/land-divergence.rego a missing column is `not count_of(key)` for a key in `window_columns`, which `torn` refuses
// carried: "a summary missing the per-job count exits 2 rather than reading it as zero" policy/land-divergence.rego `queue_job_p90` is in `window_columns`, so its absence is torn — spelled separately for the reason the retired suite gave
// changed: "a clean per-job figure passes, and the success line reports it" policy/land-divergence.rego the pass is kept and the success line is not: a module emits findings, and non-negotiable rule 4 makes output a pointer rather than a report. The numbers a reader wanted from that line are in the record the producer writes and echoes to the step summary, which is where `land-divergence.yml` publishes them
// carried: "a linear window measures one graded run against one landing" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// carried: "the conditional request actually sends If-None-Match once an ETag is cached" crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/forge_window.rs
// carried: "land-divergence.bats::A 304 KEEPS THE PREVIOUS READING rather than reading as an empty window" crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/forge_window.rs
// carried: "land-divergence.bats::a 304 with no cached body is unreadable, never an empty window" crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/forge_window.rs
// carried: "TRUNCATION IS CAUGHT BY total_count, not by running out of pages" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// changed: "a truncated window makes the decider refuse, rather than judge a prefix" policy/land-divergence.rego kept as `lane read partial`, which fires on any non-zero `unreadable` whatever the other numbers are — the arm the truncation guard above exists to feed, and the one case in this retirement where could-not-look stays a finding rather than becoming silence
// carried: "runs after a PR merged are not attributed to it" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// carried: "a draft-era skipped run is not counted as graded" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// changed: "an unreadable run list reports rather than claiming a clean window" mise.toml this one genuinely changed rather than moved: with no run list the producer now refuses and records nothing, because recording an empty window carrying `unreadable=1` would spell total blindness as the partial-coverage finding, and those are different facts
// carried: "A JOB THAT WAITED REPORTS ITS GAP, where the run's own figure cannot" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// carried: "a job that started immediately reports zero and earns no record" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// carried: "A RUN WHOSE JOBS CANNOT BE READ IS UNREADABLE, NEVER A ZERO WAIT" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// carried: "the per-job read is bounded to graded runs, so a skipped run costs no request" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// carried: "the job record is pointer-only — a run id, a job name and seconds" crates/batten/src/ci_signal.rs kind:verb crates/batten/tests/it/land_divergence.rs
// changed: "neither half is in the hk gate" mise.toml the wiring property survives and its subject moved with the programs: there is no `land-divergence` hk step, and `[tasks.land-divergence-record]` is not in any gate list. What replaced the decider is a `warn` row, which cannot fail an hk run even when it fires
// changed: "neither half is in verify" mise.toml the same, one caller over: `verify` does not run the producer, and the `lane grade other` row it does evaluate is `warn`, so a branch cannot go red over a property of the fleet
// changed: "the scheduled workflow declares a concurrency group, like every other" .github/workflows/land-divergence.yml unchanged in substance and kept in the workflow it is about; the scheduled job still declares its group, and what moved is only which task its judge step runs
// changed: "the merged-PR list is one unpaginated page" crates/batten/src/ci_signal.rs kind:verb the retired body read one page of 100 and silently lost landings on a busier day; the verb pages and stops at the first PR updated before the window, which `the_merged_pr_list_is_paged_until_it_leaves_the_window` holds
// changed: "a could-not-look run exits 1 and records nothing" crates/batten/src/ci_signal.rs kind:verb the exit is now the engine's 3 for could-not-look, and the verb REMOVES a stale record rather than only declining to write, so yesterday's window cannot answer as today's
// changed: "the ETag cache lives under .git/batten-divergence" crates/batten/src/forge.rs kind:mechanism one validator store for every forge producer, `.git/batten-forge-validators`, keyed by the whole URL as the private cache was
// changed: "BATTEN_DIVERGENCE_MAX_PAGES bounds the walk" crates/batten/src/ci_signal.rs kind:verb the bound is the `--max-pages` flag; the variable had one reader, the retired suite

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against a declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("land-divergence-{name}"));
    let module = std::fs::read_to_string("../../policy/land-divergence.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/land-divergence.rego", &module);
    write(&dir, "batten.toml", &config());
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// The eight verdicts, the rule and the family, spelled as `batten.toml` spells
/// them. Built rather than pasted so a ninth verdict cannot be added to the module
/// and silently left undeclared here.
fn config() -> String {
    let verdicts = [
        "lane read partial",
        "lane count spent",
        "lane grade red",
        "lane reach late",
        "lease guard dropped",
        "lane measure late",
        "job measure late",
        "branch reach stale",
    ];
    let mut out = String::from(
        r#"version = 1
scope = ["**"]

# The module reads its count guard by id rather than spelling the expression
# inline, which `policy test` refuses: an expression is a consumer fact and belongs
# in the config (rule 1).
[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[rule]]
id = "lane grade other"
kind = "policy"
scope = "tree"
module = "policy/land-divergence.rego"
severity = "warn"

[[record]]
record = "land-divergence"
writer = "batten record divergence"
"#,
    );
    for id in verdicts {
        // `write!` rather than `push_str(&format!(..))`: clippy's
        // `format_push_string` refuses the second for the extra allocation, and
        // `fmt::Write` for `String` is infallible, so the `expect` cannot fire.
        write!(
            out,
            r#"
[[verdict]]
id = "{id}"
gloss = "the landing loop diverged from linear over the measured window"
class = "One matrix, run to green, landed is the claim; this is a departure from it."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "batten record divergence"
"#
        )
        .expect("writing to a String cannot fail");
    }
    out
}

/// Write a record directly, as the producer `batten record divergence` would.
fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "land-divergence"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

/// One `window` line. Every field is named, because a positional summary is what
/// the retired pair's own format avoided and because a case that silently shifts a
/// column would assert about the wrong number.
#[allow(clippy::too_many_arguments)]
fn window(
    landings: u32,
    graded: u32,
    red: u32,
    cancelled: u32,
    cancel_p50: u32,
    peak: u32,
    queue_p90: u32,
    queue_job_p90: u32,
    ff_refused: u32,
    unreadable: u32,
) -> String {
    let green = graded.saturating_sub(red).saturating_sub(cancelled);
    format!(
        "window\tsince=2026-08-12T00:00:00Z\tlandings={landings}\tgraded={graded}\t\
         green={green}\tred={red}\tcancelled={cancelled}\tcancel_p50={cancel_p50}\t\
         peak_concurrency={peak}\tqueue_p90={queue_p90}\tqueue_job_p90={queue_job_p90}\t\
         retries=0\tff_refused={ff_refused}\tff_success={landings}\tunreadable={unreadable}\n"
    )
}

/// The linear ideal: one landing, one graded green run, nothing waiting.
fn linear() -> String {
    window(1, 1, 0, 0, 0, 1, 0, 0, 0, 0)
}

fn said(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_linear_window_is_clean_over_the_engines_projection() {
    let dir = repo("linear");
    record(&dir, &linear());

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "one matrix, run to green, landed is the state the gate must reach\n{}",
        said(&quiet)
    );
}

#[test]
fn a_loop_buying_more_than_one_matrix_per_landing_is_reported() {
    let dir = repo("graded");
    record(&dir, &window(1, 3, 0, 0, 0, 1, 0, 0, 0, 0));

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "three graded runs against one landing is over the 2.00 budget\n{}",
        said(&reported)
    );
}

#[test]
fn a_divergent_window_reports_without_failing_the_run() {
    // THE PORTED POSTURE, and the case no load-time rule can make. The retired
    // pair was deliberately kept out of the hk gate and out of `verify`, and its
    // own suite asserted that absence, because every metric here is a property of
    // the fleet that no branch causes. `warn` is that on this contract: the same
    // record that reds `--fail-on-warning` above must leave an ordinary `check`
    // green.
    let dir = repo("warn");
    record(&dir, &window(1, 3, 0, 0, 0, 1, 0, 0, 0, 0));

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a branch must not go red over yesterday's runner saturation\n{}",
        said(&quiet)
    );
}

#[test]
fn an_early_cancellation_is_the_mechanism_working_and_a_late_one_is_not() {
    // THE FINDING THIS SENSOR EXISTS TO ENCODE, and the case that stops a future
    // author collapsing the rule into a count. Measured 2026-08-12: 5 green runs
    // against 5 cancelled reads as a 50% discard rate and is the opposite — those
    // cancels had p50 ~20s, the lease precondition killing an unauthorised matrix
    // for ~20 runner-seconds instead of billing ~500.
    let early = repo("cancel-early");
    record(&early, &window(1, 2, 0, 1, 20, 2, 0, 0, 0, 0));
    assert_eq!(
        run(&early, &["check", "--fail-on-warning"]).status.code(),
        Some(0),
        "a 20s cancellation is the lease precondition working"
    );

    let late = repo("cancel-late");
    record(&late, &window(1, 2, 0, 1, 400, 2, 0, 0, 0, 0));
    let reported = run(&late, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a 400s cancellation is a matrix billed for a verdict nobody reads\n{}",
        said(&reported)
    );
}

#[test]
fn a_leg_queueing_behind_its_siblings_is_its_own_finding() {
    // CLOUD-501. A run's figure is its FIRST job's start, so a matrix leg waiting
    // behind its siblings is invisible in it. The two disagreeing is exactly what
    // separates a wide matrix from a saturated pool, which is why the per-job
    // figure has its own budget rather than replacing the per-run one.
    let dir = repo("queue-job");
    record(&dir, &window(1, 1, 0, 0, 0, 1, 0, 252, 0, 0));

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    let text = said(&reported);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a leg that waited 252s at p90 is reported\n{text}"
    );
    assert!(
        text.contains("job measure late"),
        "and as the per-JOB finding, over a clean per-run figure\n{text}"
    );
}

#[test]
fn any_fast_forward_refusal_at_all_is_reported() {
    // THE ONE METRIC THAT IS NOT A THRESHOLD. A refusal means the branch went
    // behind before the bot answered — the thundering herd the landing lease
    // exists to remove (243:5 before, 0:5 after).
    let dir = repo("ff");
    record(&dir, &window(1, 1, 0, 0, 0, 1, 0, 0, 1, 0));

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "one refusal is one divergence\n{}",
        said(&reported)
    );
}

#[test]
fn a_partially_read_window_is_a_finding_rather_than_a_clean_one() {
    // `bench-assert`'s partial-coverage rule, and the arm the producer's
    // truncation guard exists to feed: the Actions runs endpoint caps pagination
    // at 1000 items while still reporting the true total, so a walk that stops on
    // a short page reads a prefix and looks like a clean finish. Measured: 1000 of
    // 1446, reporting zero fast-forward refusals over a window carrying 598.
    //
    // It fires with every other number at its ideal, which is the whole point.
    let dir = repo("partial");
    record(&dir, &window(1, 1, 0, 0, 0, 1, 0, 0, 0, 2));

    let reported = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a green verdict over a prefix would cover less than it claims\n{}",
        said(&reported)
    );
}

#[test]
fn a_torn_record_is_a_finding_rather_than_a_clean_window() {
    // THE REFUSAL THE FIRST PORT DROPPED, over the real projection: every shape
    // here was a clean exit 0 before, because `fields` gated on exactly one
    // summary and nothing refused the rest.
    let concatenated = format!("{}{}", linear(), window(1, 9, 0, 0, 0, 1, 0, 0, 0, 0));
    for (name, lines) in [
        ("two", concatenated.as_str()),
        ("none", "nonsense\n"),
        ("short", "window\tsince=2026-08-12T00:00:00Z\tlandings=1\n"),
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
            said(&decided).contains("lane read partial"),
            "under the partial-coverage class\n{}",
            said(&decided)
        );
    }
}

#[test]
fn a_window_with_no_landings_judges_nothing_but_is_still_a_reading() {
    // ANTI-VACUITY. Without a denominator every ratio is undefined, which is the
    // honest reading of a quiet day — nothing landed, so nothing diverged. This
    // repo has been bitten twice by a gate that cannot fire reading the same as one
    // that found nothing (`finding-sink-check`, `bench-assert`), and the record's
    // PRESENCE is what keeps that apart from the case below.
    let dir = repo("quiet");
    record(&dir, &window(0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a quiet day judges nothing\n{}",
        said(&quiet)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    // Both total-blindness arms of the retired measurer are now the producer
    // refusing and writing nothing. This is what that absence must read as.
    let dir = repo("absent");

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}

// --- the producer, over the compiled binary against the fixture forge ---------------
//
// `record divergence` replaced `[tasks.land-divergence-record]` (CLOUD-843), so the
// producer's own steps — the walk, the truncation guard, the per-run join, the
// per-job read, the merged-PR paging — have a compiled-binary tier again. The
// forge is `rest`'s `BATTEN_REST_FIXTURE` seam, routed by endpoint.

/// The repository a case names: not this one, so a leaked placeholder reads as a
/// literal rather than a real slug.
const SLUG: &str = "acme/widgets";

/// The window's start every producer case measures from.
const SINCE: &str = "2026-08-12T00:00:00Z";

/// A fixture forge answering by endpoint: the first needle the request contains
/// answers, with the status and body beside it.
fn forge(name: &str, routes: &[(&str, u16, &str)]) -> std::path::PathBuf {
    let dir = scratch(&format!("land-divergence-{name}-forge"));
    let mut table = String::new();
    for (index, (needle, status, body)) in routes.iter().enumerate() {
        let file = format!("r{index}");
        std::fs::write(
            dir.join(&file),
            format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
        )
        .expect("write a canned answer");
        writeln!(table, "{needle}\t{file}").expect("writing to a String cannot fail");
    }
    std::fs::write(dir.join("routes"), table).expect("write the route table");
    dir
}

/// `batten record divergence` in `dir` against `forge`, measuring from `SINCE`.
fn measure(dir: &std::path::Path, forge: &std::path::Path) -> std::process::Output {
    common::batten()
        .args([
            "record",
            "divergence",
            "--ci-workflow",
            "ci.yml",
            "--land-workflow",
            "land.yml",
            "--since",
            SINCE,
        ])
        .env("GH_REPO", SLUG)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// What the fixture forge was asked, one request per line.
fn asked(forge: &std::path::Path) -> String {
    std::fs::read_to_string(forge.join("args")).unwrap_or_default()
}

/// One run row in the Actions API's shape: `[created, started, updated]` times.
fn ci_run(id: u32, branch: &str, conclusion: &str, times: [&str; 3], attempt: u32) -> String {
    let [created, started, updated] = times;
    format!(
        r#"{{"id": {id}, "head_branch": "{branch}", "conclusion": "{conclusion}", "status": "completed", "created_at": "2026-08-12T{created}Z", "run_started_at": "2026-08-12T{started}Z", "updated_at": "2026-08-12T{updated}Z", "run_attempt": {attempt}}}"#
    )
}

/// A jobs payload of `(name, created, started)` legs.
fn jobs(legs: &[(&str, &str, &str)]) -> String {
    let rows: Vec<String> = legs
        .iter()
        .map(|(name, created, started)| {
            format!(
                r#"{{"name": "{name}", "created_at": "2026-08-12T{created}Z", "started_at": "2026-08-12T{started}Z"}}"#
            )
        })
        .collect();
    format!(
        r#"{{"total_count": {}, "jobs": [{}]}}"#,
        rows.len(),
        rows.join(",")
    )
}

/// The landing bot's two conclusion counts, off `total_count`.
const FF_NONE: &str = r#"{"total_count": 0, "workflow_runs": []}"#;
const FF_TWO: &str = r#"{"total_count": 2, "workflow_runs": [{"id": 90}]}"#;

/// The join window: two landings, a post-merge run, a draft-era skipped run, an
/// early cancellation and a leg that queued behind its creation.
fn join_routes() -> (String, [String; 4], String) {
    let ci = [
        ci_run(
            1,
            "feat-a",
            "success",
            ["10:00:00", "10:00:05", "10:10:00"],
            1,
        ),
        ci_run(
            2,
            "feat-a",
            "failure",
            ["09:00:00", "09:00:00", "09:05:00"],
            2,
        ),
        ci_run(
            3,
            "feat-a",
            "success",
            ["12:00:00", "12:00:10", "12:05:00"],
            1,
        ),
        ci_run(
            4,
            "feat-a",
            "skipped",
            ["08:00:00", "08:00:00", "08:00:01"],
            1,
        ),
        ci_run(
            5,
            "feat-b",
            "cancelled",
            ["10:05:00", "10:05:00", "10:05:20"],
            1,
        ),
    ];
    let runs = format!(
        r#"{{"total_count": 5, "workflow_runs": [{}]}}"#,
        ci.join(",")
    );
    let legs = [
        jobs(&[
            ("test", "10:00:05", "10:00:35.250"),
            ("lint", "10:00:05", "10:00:05"),
        ]),
        jobs(&[("test", "09:00:00", "09:00:00")]),
        jobs(&[("test", "12:00:10", "12:00:10")]),
        jobs(&[("test", "10:05:00", "10:05:00")]),
    ];
    let pulls = r#"[
        {"number": 8, "head": {"ref": "feat-b"}, "merged_at": "2026-08-12T11:30:00Z", "updated_at": "2026-08-12T11:30:05Z"},
        {"number": 7, "head": {"ref": "feat-a"}, "merged_at": "2026-08-12T11:00:00Z", "updated_at": "2026-08-12T11:00:05Z"},
        {"number": 9, "head": {"ref": "feat-c"}, "merged_at": null, "updated_at": "2026-08-12T10:00:00Z"},
        {"number": 6, "head": {"ref": "feat-z"}, "merged_at": "2026-08-11T19:00:00Z", "updated_at": "2026-08-11T20:00:00Z"}
    ]"#
    .to_owned();
    (runs, legs, pulls)
}

/// The record the join window must produce — byte-for-byte what the retired body
/// printed over the same responses, replayed before it was deleted.
const JOINED: &str = "cancel\trun=5\tbranch=feat-b\tlatency=20\n\
job\trun=1\tjob=test\tqueue=30\n\
pr\tnumber=7\tbranch=feat-a\tgraded=2\tgreen=1\tred=1\tcancelled=0\n\
window\tsince=2026-08-12T00:00:00Z\tlandings=2\tgraded=3\tgreen=1\tred=1\tcancelled=1\t\
cancel_p50=20\tpeak_concurrency=2\tqueue_p90=5\tqueue_job_p90=0\tretries=1\tff_refused=0\t\
ff_success=2\tunreadable=0\n";

#[test]
fn the_producer_joins_runs_to_landings_and_records_what_the_module_reads() {
    // THE WHOLE PATH, over the replay's own fixture. Run 3 was created after #7
    // merged and run 4 was skipped, so neither is graded; run 5 was cancelled 20s
    // in; run 1's `test` leg waited 30s. The module then decides over the record:
    // one red run against two landings is over the red budget.
    let dir = repo("produce");
    let (runs, legs, pulls) = join_routes();
    let forge = forge(
        "produce",
        &[
            ("status=failure&per_page=1", 200, FF_NONE),
            ("status=success&per_page=1", 200, FF_TWO),
            ("ci.yml/runs", 200, &runs),
            ("runs/1/jobs", 200, &legs[0]),
            ("runs/2/jobs", 200, &legs[1]),
            ("runs/3/jobs", 200, &legs[2]),
            ("runs/5/jobs", 200, &legs[3]),
            ("/pulls", 200, &pulls),
        ],
    );

    let measured = measure(&dir, &forge);
    assert_eq!(measured.status.code(), Some(0), "{}", said(&measured));
    assert_eq!(String::from_utf8_lossy(&measured.stdout), JOINED);

    let requests = asked(&forge);
    assert!(
        !requests.contains("runs/4/jobs"),
        "a skipped run costs no request\n{requests}"
    );
    assert!(
        requests.contains(
            "repos/acme/widgets/actions/workflows/ci.yml/runs?page=1&created=%3E%3D2026-08-12T00%3A00%3A00Z&per_page=100"
        ),
        "the window's start is bound, encoded, into the run query\n{requests}"
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("lane grade red"),
        "{}",
        said(&decided)
    );
}

#[test]
fn a_truncated_ci_walk_is_judged_as_a_prefix_and_counted_unreadable() {
    // TRUNCATION IS CAUGHT BY `total_count`, NOT BY RUNNING OUT OF PAGES. The page
    // came back short while the endpoint still says 150: the prefix is judged, and
    // the gap is one `unreadable`, which the module reports whatever else it says.
    let dir = repo("truncated");
    let runs = format!(
        r#"{{"total_count": 150, "workflow_runs": [{}]}}"#,
        ci_run(
            1,
            "feat-a",
            "success",
            ["10:00:00", "10:00:00", "10:10:00"],
            1
        )
    );
    let pulls = r#"[{"number": 7, "head": {"ref": "feat-a"}, "merged_at": "2026-08-12T11:00:00Z", "updated_at": "2026-08-12T11:00:05Z"}]"#;
    let legs = jobs(&[("test", "10:00:00", "10:00:00")]);
    let forge = forge(
        "truncated",
        &[
            ("status=failure&per_page=1", 200, FF_NONE),
            ("status=success&per_page=1", 200, FF_TWO),
            ("ci.yml/runs", 200, &runs),
            ("runs/1/jobs", 200, &legs),
            ("/pulls", 200, pulls),
        ],
    );

    let measured = measure(&dir, &forge);
    let record = String::from_utf8_lossy(&measured.stdout);
    assert_eq!(measured.status.code(), Some(0), "{}", said(&measured));
    assert!(
        record.contains("\tlandings=1\tgraded=1\t"),
        "the prefix is judged\n{record}"
    );
    assert!(
        record.ends_with("\tunreadable=1\n"),
        "and the gap is counted\n{record}"
    );

    let decided = run(&dir, &["check", "--fail-on-warning"]);
    assert!(
        said(&decided).contains("lane read partial"),
        "{}",
        said(&decided)
    );
}

#[test]
fn a_run_whose_jobs_cannot_be_read_is_unreadable_never_a_zero_wait() {
    // Dropping it would report a p90 over the legs that happened to answer — the
    // partial-coverage false green this sensor refuses.
    let dir = repo("jobs-unread");
    let (runs, legs, pulls) = join_routes();
    let forge = forge(
        "jobs-unread",
        &[
            ("status=failure&per_page=1", 200, FF_NONE),
            ("status=success&per_page=1", 200, FF_TWO),
            ("ci.yml/runs", 200, &runs),
            ("runs/1/jobs", 500, "{}"),
            ("runs/2/jobs", 200, &legs[1]),
            ("runs/3/jobs", 200, &legs[2]),
            ("runs/5/jobs", 200, &legs[3]),
            ("/pulls", 200, &pulls),
        ],
    );

    let measured = measure(&dir, &forge);
    let record = String::from_utf8_lossy(&measured.stdout);
    assert_eq!(measured.status.code(), Some(0), "{}", said(&measured));
    assert!(record.ends_with("\tunreadable=1\n"), "{record}");
    assert!(!record.contains("job\trun=1"), "{record}");
}

#[test]
fn the_merged_pr_list_is_paged_until_it_leaves_the_window() {
    // THE RETIRED BODY READ ONE PAGE, so a day with more than a hundred closed PRs
    // updated in it silently lost landings. The walk now pages, and stops at the
    // first PR updated before the window: page 2 carries one landing and then
    // rows from the day before, so page 3 is never asked for — and the fixture has
    // no page 3, so asking would be could-not-look.
    let dir = repo("paged");
    let row = |number: u32, day: &str| {
        format!(
            r#"{{"number": {number}, "head": {{"ref": "b{number}"}}, "merged_at": "2026-08-{day}T11:00:00Z", "updated_at": "2026-08-{day}T11:00:05Z"}}"#
        )
    };
    let first: Vec<String> = (1..=100).map(|n| row(n, "12")).collect();
    let mut second: Vec<String> = vec![row(101, "12")];
    second.extend((102..=200).map(|n| row(n, "11")));
    let (first, second) = (
        format!("[{}]", first.join(",")),
        format!("[{}]", second.join(",")),
    );
    let forge = forge(
        "paged",
        &[
            ("status=failure&per_page=1", 200, FF_NONE),
            ("status=success&per_page=1", 200, FF_TWO),
            (
                "ci.yml/runs",
                200,
                r#"{"total_count": 0, "workflow_runs": []}"#,
            ),
            ("pulls?page=1&", 200, &first),
            ("pulls?page=2&", 200, &second),
        ],
    );

    let measured = measure(&dir, &forge);
    let record = String::from_utf8_lossy(&measured.stdout);
    assert_eq!(measured.status.code(), Some(0), "{}", said(&measured));
    assert!(record.contains("\tlandings=101\t"), "{record}");
    assert!(record.ends_with("\tunreadable=0\n"), "{record}");
    assert!(!asked(&forge).contains("pulls?page=3"), "{}", asked(&forge));
}

#[test]
fn an_unreadable_ci_window_is_could_not_look_and_removes_the_stale_record() {
    // COULD-NOT-LOOK RECORDS NOTHING, and a stale record is not left answering as
    // the current reading: a module cannot tell yesterday's window from today's.
    let dir = repo("blind");
    record(&dir, &window(1, 3, 0, 0, 0, 1, 0, 0, 0, 0));
    assert_eq!(
        run(&dir, &["check", "--fail-on-warning"]).status.code(),
        Some(2),
        "the stale window is over budget before the producer runs"
    );
    let forge = forge(
        "blind",
        &[(
            "ci.yml/runs",
            403,
            r#"{"message": "Resource not accessible"}"#,
        )],
    );

    let measured = measure(&dir, &forge);
    let text = said(&measured);
    assert_eq!(measured.status.code(), Some(3), "{text}");
    assert!(
        text.contains("could not look") && text.contains("403"),
        "{text}"
    );
    assert!(
        !text.contains("Resource"),
        "rule 4: no body is quoted\n{text}"
    );

    let quiet = run(&dir, &["check", "--fail-on-warning"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "the stale record is gone\n{}",
        said(&quiet)
    );
}

#[test]
fn a_workflow_named_nowhere_is_a_usage_refusal() {
    // Rule 1: which workflow grades a landing is the consumer's fact. With neither
    // the flag nor `$LAND_CI_WORKFLOW`, the verb refuses rather than guessing.
    let dir = repo("unnamed");
    let refused = common::batten()
        .args(["record", "divergence", "--land-workflow", "land.yml"])
        .env_remove("LAND_CI_WORKFLOW")
        .env("GH_REPO", SLUG)
        .current_dir(&dir)
        .output()
        .expect("the compiled binary runs");
    assert_ne!(refused.status.code(), Some(0), "{}", said(&refused));
    assert_ne!(refused.status.code(), Some(3), "{}", said(&refused));
    assert!(
        said(&refused).contains("LAND_CI_WORKFLOW"),
        "{}",
        said(&refused)
    );
}
