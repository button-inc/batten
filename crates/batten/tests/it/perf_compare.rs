//! The verdict over a paired measurement, over the compiled engine
//! (CLOUD-1163 unit 10).
//!
//! # Why this tier, and why it is the whole tier
//!
//! `perf_pair.rs` next door can only exercise the SKIP, because a real
//! measurement needs two release builds and a worktree. This suite has the
//! opposite shape and is the better half of the pair for it: the decision is a
//! pure function of records on stdin, so **every verdict is reachable from a
//! fixture in milliseconds**, with no build, no hyperfine and no merge base. That
//! is what the retired `tests/perf-compare.bats` was for, and it is why the port
//! keeps a stdin channel rather than folding the comparison invisibly into
//! `gate`.
//!
//! Driven over the compiled binary rather than with `with input as`, per
//! `rules/policy-modules.md`: the exemption table reaches the predicate
//! through `[perf]` in the committed authority, and a fabricated table would
//! prove the decision works over a shape the engine may be unable to build.
//!
//! # The retirement ledger
//!
//! `mise-tasks/perf-compare.sh`, `tests/perf-compare.bats`, `mise-tasks/perf-gate.sh`
//! and `tests/perf-gate.bats` are retired here. Four file arms, because a
//! retirement owes one per deleted path.
//
// changed: mise-tasks/perf-compare.sh crates/batten/src/perf.rs kind:mechanism crates/batten/tests/it/perf_compare.rs the exit codes are Batten's rather than the shell's — see the block below
// changed: tests/perf-compare.bats crates/batten/src/perf.rs kind:mechanism crates/batten/tests/it/perf_compare.rs the cases that asserted exit 1 for a regression and 2 for could-not-look now assert 2 and 3
// carried: mise-tasks/perf-gate.sh crates/batten/src/perf.rs kind:mechanism crates/batten/tests/it/perf_compare.rs
// carried: tests/perf-gate.bats crates/batten/src/perf.rs kind:mechanism crates/batten/tests/it/perf_compare.rs
//
// `kind:mechanism` on all four, and the field is load-bearing here rather than
// ceremonial (CLOUD-1182). Neither successor is a new top-level verb: `perf` is
// an existing noun with an existing `pair`, and this adds two sub-verbs to it, so
// the command surface gains no root. Writing `kind:verb` would have counted this
// among the 77 arms that widened the core.
//
// THE EXIT CODES CHANGE, WHICH IS WHY TWO ARMS ARE `changed` AND NOT `carried`.
// `perf-compare.sh` answered 1 for a regression and 2 for could-not-look. In the
// engine `2` is the policy verdict everywhere and `1`/`3` are the only codes a
// failure produces, with no per-verb exception — so a regression is now 2 and a
// could-not-look 3. Both callers (`verify`'s body and the `perf` CI job) test for
// zero, so no caller can observe the difference; a `carried` arm would tell a
// reader the codes survived, and they did not.
//
// --- the case granularity ----------------------------------------------------
//
// `perf-compare.bats` had 20 cases and `perf-gate.bats` 6, and every title below
// is the retired suite's own — read off the deleted files rather than restated
// from the design, which is the error `bats-tests-not-deleted` caught on the
// first draft of this block.
//
// carried: "a pair within the threshold passes, and names the threshold" crates/batten/tests/it/perf_compare.rs
// carried: "a path past the threshold is a regression, named with both arms and the ratio" crates/batten/tests/it/perf_compare.rs
// carried: "a slow machine moves both arms and is not a regression" crates/batten/tests/it/perf_compare.rs
// carried: "a path that got faster passes" crates/batten/tests/it/perf_compare.rs
// carried: "the threshold is a boundary, not a suggestion" crates/batten/tests/it/perf_compare.rs
// carried: "the threshold clears the measured noise floor (n=30, max 1.102x)" crates/batten/tests/it/perf_compare.rs
// carried: "the threshold is honoured from the environment" crates/batten/tests/it/perf_compare.rs
// carried: "a head arm with no base arm is could-not-look, not a pass" crates/batten/tests/it/perf_compare.rs
// carried: "base arms alone are could-not-look — there is nothing to judge" crates/batten/tests/it/perf_compare.rs
// carried: "empty stdin is could-not-look, and names the redirect" crates/batten/tests/it/perf_compare.rs
// carried: "an unpaired record shape is could-not-look and points at the line" crates/batten/tests/it/perf_compare.rs
// carried: "an arm that is neither base nor head is malformed, not ignored" crates/batten/tests/it/perf_compare.rs
// carried: "a zero base would divide, so it is malformed rather than infinite" crates/batten/tests/it/perf_compare.rs
// carried: "every regressed path is reported, not just the first" crates/batten/tests/it/perf_compare.rs
// carried: "an accepted path passes past the threshold, and says so on every run" crates/batten/tests/it/perf_compare.rs
// carried: "the summary does not claim the accepted path was within the threshold" crates/batten/tests/it/perf_compare.rs
// carried: "SHOWN ABLE TO FAIL: a lapsed exemption stops exempting" crates/batten/tests/it/perf_compare.rs
// carried: "the exemption is scoped to the path it names" crates/batten/tests/it/perf_compare.rs
// carried: "the exemption is scoped to the ratio it names" crates/batten/tests/it/perf_compare.rs
// carried: "a path inside the ordinary threshold is judged by it, exemption or not" crates/batten/tests/it/perf_compare.rs
// carried: "a skip is a pass, never an empty stream handed to the comparison" crates/batten/tests/it/perf_compare.rs
// carried: "records reach the comparison, which is the whole composition" crates/batten/tests/it/perf_compare.rs
// subsumed: "a paired measurement that did not complete passes its code through" crates/batten/src/perf.rs kind:mechanism
// subsumed: "THE DEFECT: could-not-look is not flattened into a regression" crates/batten/src/perf.rs kind:mechanism
// subsumed: "a regression's code reaches the caller" crates/batten/src/perf.rs kind:mechanism
// subsumed: "the comparison's could-not-look reaches the caller too" crates/batten/src/perf.rs kind:mechanism
//
// THE FOUR `subsumed` ARMS ARE THE ENTRY WORTH READING, and they are all
// `perf-gate.bats`'s. Every one pinned SHELL PLUMBING that `perf-gate.sh` needed
// in order to be correct, by stubbing `perf-pair` on `PATH` and watching an exit
// code travel: `perf-pair | perf-compare` would hand the pipeline the gate's
// status alone, so a measurement that failed outright arrived as empty stdin and
// was reported as could-not-look — the right code for the wrong reason. The
// program answered with a temporary file, a `grep '^arm='` to tell a skip from a
// measurement, and an explicit passthrough of `$rc`. Those four cases held it to
// that.
//
// In process there is no pipeline to lose a status in, and no sibling program to
// stub. `gate` holds an `Outcome` as a VALUE and matches on it, so a skip and a
// failed measurement are different variants rather than two readings of one byte
// stream, and `?` propagates the failure. The property still holds, and it holds
// by construction — which is what makes these `subsumed` rather than `carried`:
// nothing re-asserts them because there is no longer a mechanism to assert about,
// and a `carried` arm would point at a case that cannot exist.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{Fixture, run_with_stdin, stderr, stdout};

/// A pair of records for one path, at the two given p50s.
fn pair(path: &str, base: f64, head: f64) -> String {
    format!(
        "arm=base path={path} p50={base} p95={base} mean={base} runs=100\n\
         arm=head path={path} p50={head} p95={head} mean={head} runs=100\n"
    )
}

/// A checkout whose authority declares `rows` under `[perf]`.
fn repo(name: &str, rows: &str) -> std::path::PathBuf {
    Fixture::new(name)
        // `version = 1` is load-bearing here in a way it is not in `perf_pair.rs`
        // next door, whose fixture omits it: `pair` skips before it ever loads an
        // authority, while every case here reaches the config to read `[perf]`. A
        // fixture missing it answers `Usage` for a reason that has nothing to do
        // with the verdict under test.
        .config(&format!(
            "version = 1\n\n[[rule]]\nid = \"noop\"\nkind = \"forbid\"\nglob = \"*.nothing\"\n\
             pattern = \"x\"\nseverity = \"warn\"\nscope = \"tree\"\n{rows}"
        ))
        .git()
        .base_commit()
        .build()
}

/// The ordinary checkout: no accepted regressions.
fn plain(name: &str) -> std::path::PathBuf {
    repo(name, "")
}

// --- what counts as a record -------------------------------------------------

#[test]
fn stdin_carrying_no_records_at_all_is_could_not_look() {
    // Empty stdin means the driver was never run or its output went somewhere
    // else. Reporting green over it would be a pass bought by measuring nothing.
    let repo = plain("perf-compare-empty");
    let output = run_with_stdin(&repo, &["perf", "compare"], "");
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("stdin is empty"));
}

#[test]
fn a_line_that_is_not_a_paired_record_is_could_not_look_never_skipped() {
    // NOISE IN A VERDICT STREAM IS NOT A PASS. A reader that skipped what it did
    // not understand would compare whatever happened to parse, and report on a
    // subset while looking like it read everything.
    let repo = plain("perf-compare-noise");
    let input = format!("{}warning: something went wrong\n", pair("noop", 3.0, 3.1));
    let output = run_with_stdin(&repo, &["perf", "compare"], &input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("stdin:3:"),
        "the refusal points at the line: {}",
        stderr(&output)
    );
}

#[test]
fn an_unknown_arm_name_is_not_a_record() {
    let repo = plain("perf-compare-arm");
    let input = "arm=middle path=noop p50=3.0 p95=3.0 mean=3.0 runs=100\n";
    let output = run_with_stdin(&repo, &["perf", "compare"], input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn a_record_with_no_path_is_not_a_record() {
    let repo = plain("perf-compare-path");
    let input = "arm=head p50=3.0 p95=3.0 mean=3.0 runs=100\n";
    let output = run_with_stdin(&repo, &["perf", "compare"], input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn a_zero_p50_is_refused_rather_than_divided_by() {
    // The denominator. Dividing by it yields an infinity that reads as a
    // catastrophic regression, so the refusal has to come before the arithmetic.
    let repo = plain("perf-compare-zero");
    let input = "arm=base path=noop p50=0 p95=0 mean=0 runs=100\n\
                 arm=head path=noop p50=3.0 p95=3.0 mean=3.0 runs=100\n";
    let output = run_with_stdin(&repo, &["perf", "compare"], input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn a_non_numeric_p50_is_not_a_record() {
    let repo = plain("perf-compare-nan");
    let input = "arm=head path=noop p50=fast p95=3.0 mean=3.0 runs=100\n";
    let output = run_with_stdin(&repo, &["perf", "compare"], input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

// --- what counts as a comparison ----------------------------------------------

#[test]
fn no_head_arm_at_all_is_could_not_look() {
    let repo = plain("perf-compare-no-head");
    let input = "arm=base path=noop p50=3.0 p95=3.0 mean=3.0 runs=100\n";
    let output = run_with_stdin(&repo, &["perf", "compare"], input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("no `head` measurements"));
}

#[test]
fn a_head_path_the_base_never_measured_is_could_not_look_never_a_pass() {
    // THE PARTIAL-COVERAGE FALSE GREEN, which this repository keeps re-meeting: an
    // unpaired path means the base build failed to measure it, and reporting green
    // over a comparison that did not happen is worse than saying so.
    let repo = plain("perf-compare-unpaired");
    let input = format!(
        "{}arm=head path=wired p50=9.0 p95=9.0 mean=9.0 runs=100\n",
        pair("noop", 3.0, 3.1)
    );
    let output = run_with_stdin(&repo, &["perf", "compare"], &input);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("'wired'"), "{}", stderr(&output));
}

// --- the verdict ---------------------------------------------------------------

#[test]
fn a_pair_inside_the_threshold_passes() {
    let repo = plain("perf-compare-inside");
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("noop", 3.0, 3.3));
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("within 1.3x of the merge base"));
}

#[test]
fn a_pair_past_the_threshold_is_a_regression_naming_both_arms() {
    // The refusal is a POINTER, and here that means the two measurements and the
    // ratio between them — enough to act on without re-running anything.
    let repo = plain("perf-compare-past");
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 3.0, 6.0));
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let said = stderr(&output);
    assert!(
        said.contains("hook: base p50=3ms -> head p50=6ms (2x)"),
        "{said}"
    );
    assert!(
        said.contains("measured noise floor 1.102x"),
        "the refusal shows the threshold is clear of the noise: {said}"
    );
}

#[test]
fn a_slow_machine_moves_both_arms_and_is_not_a_regression() {
    // THE WHOLE REASON THE VERDICT IS A RATIO. Machine noise is common-mode
    // across a pair measured back to back, so it divides out — a runner that is
    // 9x slower than the reference moves BOTH arms and changes nothing about
    // whether this commit regressed.
    let repo = plain("perf-compare-slow");
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 26.0, 26.4));
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn a_path_that_got_faster_passes() {
    // A speed-up is not a regression, however large. Worth a case because the
    // comparison is a bare `>` and an author reaching for `!=` or an absolute
    // difference would refuse an improvement.
    let repo = plain("perf-compare-faster");
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 9.10, 2.60));
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn the_threshold_is_a_boundary_not_a_suggestion() {
    // Exactly 1.30x is inside; a hair past it is not. The two arms are what pin
    // the comparison as `>` rather than `>=`, which no single-sided case can.
    let repo = plain("perf-compare-boundary");
    let at = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 2.00, 2.60));
    assert!(
        at.status.success(),
        "exactly 1.30x is inside: {}",
        stderr(&at)
    );

    let past = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 2.00, 2.62));
    assert_eq!(past.status.code(), Some(2), "{}", stderr(&past));
}

#[test]
fn the_threshold_clears_the_measured_noise_floor() {
    // THE MEASURED NULL MAXIMUM, ASSERTED AS A FLOOR UNDER THE THRESHOLD. A gate
    // set below the noise of a comparison that measures NOTHING is a coin flip,
    // and the way that happens is somebody tightening the constant without
    // re-running `perf pair --null`. This fails the moment they do.
    let repo = plain("perf-compare-floor");
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 1.000, 1.102));
    assert!(
        output.status.success(),
        "a ratio at the measured null maximum must not be a regression: {}",
        stderr(&output)
    );

    // And the same relation read off the refusal, which prints both numbers —
    // so the guard holds even if the pair above is ever re-tuned.
    let refused = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 1.0, 9.0));
    let said = stderr(&refused);
    let number = |after: &str| -> f64 {
        let rest = said.split(after).nth(1).expect("the refusal names it");
        rest.trim_start()
            .split('x')
            .next()
            .expect("a number precedes the x")
            .parse()
            .expect("it parses")
    };
    assert!(
        number("threshold") > number("measured noise floor"),
        "the threshold must stay clear of the measured floor: {said}"
    );
}

#[test]
fn every_regressed_path_is_reported_not_just_the_first() {
    // A gate that stops at the first finding makes the second one arrive on the
    // next lap, after another full measurement.
    let repo = plain("perf-compare-all");
    let input = format!("{}{}", pair("hook", 2.0, 6.0), pair("wired", 3.0, 9.0));
    let output = run_with_stdin(&repo, &["perf", "compare"], &input);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let said = stderr(&output);
    assert!(said.contains("hook:"), "{said}");
    assert!(said.contains("wired:"), "{said}");
}

#[test]
fn the_ratio_is_p50_not_p95() {
    // p95 is the right statistic for an ABSOLUTE budget and the wrong one for a
    // ratio: the tail is where a runner's contention lands. A p95-reading gate
    // would refuse this pair; a p50-reading one passes it.
    let repo = plain("perf-compare-p50");
    let input = "arm=base path=noop p50=3.0 p95=3.0 mean=3.0 runs=100\n\
                 arm=head path=noop p50=3.1 p95=99.0 mean=3.1 runs=100\n";
    let output = run_with_stdin(&repo, &["perf", "compare"], input);
    assert!(
        output.status.success(),
        "a wild tail must not decide the ratio: {}",
        stderr(&output)
    );
}

// --- the exemption table --------------------------------------------------------

/// One accepted regression, expiring far enough out that the suite does not rot.
const ACCEPTED: &str = "\n[[perf.exempt]]\npath = \"posttool\"\nratio = \"2.20\"\n\
                        expires = \"2999-12-31\"\nreason = \"the base binary performs no \
                        capture, so this arm prices the feature rather than a drift\"\n";

#[test]
fn an_exemption_raises_its_own_path_s_bar_and_no_other() {
    let repo = repo("perf-compare-exempt", ACCEPTED);
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("posttool", 3.0, 5.4));
    assert!(
        output.status.success(),
        "1.8x is under 2.20x: {}",
        stderr(&output)
    );

    // The same ratio on a path with no row is still a regression, which is what
    // makes this a table rather than a raised threshold.
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("hook", 3.0, 5.4));
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn the_exemption_is_scoped_to_the_ratio_it_names() {
    // The other half of scoping: a row raises the bar to ITS ratio and no
    // further, so a path with an accepted regression is still refused once it
    // exceeds what was accepted. Without this the row reads as "this path is
    // exempt" rather than "this path may reach 2.20x".
    let repo = repo("perf-compare-ratio-scope", ACCEPTED);
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("posttool", 3.0, 7.5));
    assert_eq!(
        output.status.code(),
        Some(2),
        "2.5x is past the accepted 2.20x: {}",
        stderr(&output)
    );
}

#[test]
fn an_exemption_never_lowers_the_bar() {
    // A row below the ordinary threshold must not narrow it: an accepted
    // regression is a licence to exceed 1.30, never a demand to stay under 1.10.
    let repo = repo(
        "perf-compare-lower",
        "\n[[perf.exempt]]\npath = \"noop\"\nratio = \"1.05\"\nexpires = \"2999-12-31\"\n\
         reason = \"a row whose ratio is below the ordinary threshold\"\n",
    );
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("noop", 3.0, 3.6));
    assert!(
        output.status.success(),
        "1.2x is inside the ordinary 1.30x and the row must not tighten it: {}",
        stderr(&output)
    );
}

#[test]
fn an_accepted_regression_is_reported_on_every_run_never_silently() {
    // AN ACCEPTED REGRESSION THAT STOPS BEING VISIBLE IS A RAISED THRESHOLD WITH
    // EXTRA STEPS. It passes, and it says so loudly, with its expiry and reason.
    let repo = repo("perf-compare-loud", ACCEPTED);
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("posttool", 3.0, 5.4));
    assert!(output.status.success());
    let said = stderr(&output);
    assert!(said.contains("::warning::"), "{said}");
    assert!(said.contains("accepted until 2999-12-31"), "{said}");
    assert!(
        said.contains("prices the feature"),
        "the reason travels: {said}"
    );
}

#[test]
fn a_lapsed_exemption_stops_exempting() {
    // A row that lapses stops exempting rather than quietly continuing, and the
    // path drops back to the ordinary threshold — a ratchet, not a cliff.
    let repo = repo(
        "perf-compare-lapsed",
        "\n[[perf.exempt]]\npath = \"posttool\"\nratio = \"2.20\"\nexpires = \"2000-01-01\"\n\
         reason = \"a row whose date has passed\"\n",
    );
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("posttool", 3.0, 5.4));
    assert_eq!(
        output.status.code(),
        Some(2),
        "a lapsed row no longer raises the bar: {}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("lapsed on 2000-01-01"));
}

#[test]
fn the_summary_does_not_claim_more_than_the_run_established() {
    // The false green one layer up, in the gate's own output: saying "every path
    // is within 1.30x" over a run that accepted one past it is exactly what this
    // gate exists to refuse.
    let repo = repo("perf-compare-summary", ACCEPTED);
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("posttool", 3.0, 5.4));
    assert!(
        stdout(&output).contains("except 1 accepted above"),
        "{}",
        stdout(&output)
    );

    // And the plain summary when nothing was accepted, so the qualifier is
    // evidence rather than decoration.
    let plain = plain("perf-compare-summary-plain");
    let output = run_with_stdin(&plain, &["perf", "compare"], &pair("noop", 3.0, 3.1));
    assert!(!stdout(&output).contains("except"), "{}", stdout(&output));
}

// --- the table is proven well formed at LOAD -------------------------------------
//
// The shell could only refuse the row it happened to READ, so a malformed row
// behind a passing one never spoke. These three are the same refusals, moved to
// where a table that would decide the wrong thing cannot load at all.

#[test]
fn an_exemption_missing_a_reason_is_refused() {
    // AN EXEMPTION NOBODY EXPLAINED IS A THRESHOLD NOBODY DEFENDS.
    let repo = repo(
        "perf-compare-no-reason",
        "\n[[perf.exempt]]\npath = \"noop\"\nratio = \"2.20\"\nexpires = \"2999-12-31\"\n\
         reason = \"\"\n",
    );
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("noop", 3.0, 3.1));
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("`reason` is empty"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_exemption_missing_an_expiry_is_refused() {
    // A malformed date still COMPARES, so a short field silently lapses a row that
    // has not — which is why the shape is checked rather than assumed.
    let repo = repo(
        "perf-compare-bad-date",
        "\n[[perf.exempt]]\npath = \"noop\"\nratio = \"2.20\"\nexpires = \"2026-9-1\"\n\
         reason = \"a date that is not fixed width\"\n",
    );
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("noop", 3.0, 3.1));
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("must be YYYY-MM-DD"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_exemption_missing_a_ratio_is_refused() {
    let repo = repo(
        "perf-compare-bad-ratio",
        "\n[[perf.exempt]]\npath = \"noop\"\nratio = \"soon\"\nexpires = \"2999-12-31\"\n\
         reason = \"a ratio that is not a number\"\n",
    );
    let output = run_with_stdin(&repo, &["perf", "compare"], &pair("noop", 3.0, 3.1));
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("must be a positive number"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_threshold_is_overridable_for_a_re_measurement() {
    // THE FLOOR STAYS CHECKABLE RATHER THAN HISTORICAL. 1.30 is derived from a
    // measured null spread, and `BENCH_REGRESSION_RATIO` is what lets someone
    // re-derive it without editing the constant that records the derivation.
    //
    // Spawned here rather than through `run_with_stdin` because that helper takes
    // no environment, and adding one to it for a single caller would widen a
    // shared helper for this suite's convenience.
    use std::io::Write as _;
    use std::process::Stdio;

    let repo = plain("perf-compare-override");
    let mut child = common::batten()
        .args(["perf", "compare"])
        .current_dir(&repo)
        .env("BENCH_REGRESSION_RATIO", "1.05")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    let records = pair("noop", 3.0, 3.3);
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(records.as_bytes())
        .expect("write the records");
    let output = child.wait_with_output().expect("collect the output");
    // The same 1.1x pair that passes at 1.30 is a regression at 1.05, which is
    // what proves the override reached the comparison rather than being ignored.
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("threshold 1.05x"),
        "{}",
        stderr(&output)
    );
}

// --- the composition -------------------------------------------------------------

#[test]
fn a_skip_is_a_pass_not_an_empty_measurement() {
    // THE PROPERTY THE RETIRED PLUMBING EXISTED TO PRESERVE, asserted over the
    // composed name. HEAD is its own merge base in this fixture, so `pair` skips —
    // and `gate` must report that as a pass rather than handing `compare` an empty
    // stream and reporting its could-not-look.
    let repo = plain("perf-gate-skip");
    let output = run_with_stdin(&repo, &["perf", "gate"], "");
    assert!(
        output.status.success(),
        "a skip is a pass: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("nothing to compare"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_gate_runs_the_pair_and_decides_it_under_one_name() {
    // ONE NAME, so a caller wires in the whole gate and cannot wire in half of it.
    // `ci-local-parity` requires every task a workflow runs to be one `verify`
    // runs, and a single name is what keeps that correspondence readable.
    let repo = plain("perf-gate-one-name");
    let output = run_with_stdin(&repo, &["perf", "gate"], "");
    assert!(output.status.success(), "{}", stderr(&output));
    // It ran the pair rather than only the comparison: the skip line is `pair`'s
    // own, and a `gate` that never called it could not print one.
    assert!(
        stdout(&output).lines().count() >= 2,
        "the pair's reason and the gate's verdict: {}",
        stdout(&output)
    );
}
