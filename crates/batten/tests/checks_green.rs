//! `batten checks green` decides over the compiled binary (CLOUD-1143).
//!
//! # Why this tier
//!
//! `checks_green.rs`'s own unit cases pin the DECISION. They cannot pin the two
//! things a caller actually branches on, because neither exists until there is a
//! process: the **exit code** each verdict maps to, and whether the red / not-yet
//! distinction survives to stdout. Both are acceptance clauses on the row, and
//! both are invisible to a test that calls `decide` directly.
//!
//! # The property that matters most here
//!
//! `every_non_green_state_exits_non_zero`. The shell this replaces used four
//! distinct codes; `exit.rs` is total over four that mean something else, so the
//! mapping had to change and the safety property had to be restated as something
//! a test can hold. A reader that branches on the code alone and ignores stdout
//! must HOLD on every state that is not green — otherwise the port re-introduces
//! CLOUD-337, where `land` fast-forwarded into a branch protection still listing
//! six checks as expected.
//!
//! That is why red and pending share `Violation` rather than getting a code
//! each: the distinction is real but it is about whether to ask again, and it
//! travels on stdout where the poller reads it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::process::Stdio;

/// The roster this repository actually declares, reduced to what these cases
/// need. Passed as flags rather than read from the environment, which is the
/// whole seam change: the crate holds no consumer's variable name.
const REQUIRED: &str = "ci,perf,final";
const ANSWERED: &str = "success,neutral,failure,timed_out,action_required";

/// Run `batten checks green` with a reading on stdin.
///
/// Spawned rather than routed through `common::run`, because the subject here is
/// what the process does with a PIPE — a helper that passes no stdin would test
/// the empty-reading path five times over and call it coverage.
fn green(reading: &str, args: &[&str]) -> (i32, String, String) {
    let mut child = common::batten()
        .arg("checks")
        .arg("green")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the compiled binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(reading.as_bytes())
        .expect("the reading reaches the child");
    let output = child.wait_with_output().expect("the child answers");
    (
        output.status.code().expect("the child exited normally"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The roster flags every case shares.
fn roster() -> Vec<&'static str> {
    vec![
        "--required",
        REQUIRED,
        "--answered",
        ANSWERED,
        "--fanin",
        "final",
    ]
}

/// A reading in which every required name is terminal and green.
fn all_green() -> String {
    ["ci", "perf", "final"]
        .iter()
        .enumerate()
        .map(|(i, name)| {
            format!(
                "completed\tsuccess\t{name}\t2026-08-12T00:00:00Z\t{}",
                i + 1
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// The exit contract, which is the whole reason this file exists.
// ---------------------------------------------------------------------------

#[test]
fn a_green_head_exits_success() {
    let (code, stdout, _) = green(&all_green(), &roster());
    assert_eq!(code, 0, "a green head is the only zero: {stdout}");
    assert!(stdout.contains("terminal and green"), "{stdout}");
}

#[test]
fn every_non_green_state_exits_non_zero() {
    // THE SAFETY PROPERTY, and it is asserted over the states rather than over
    // one of them: a reader that ignores stdout must hold on all four. Under any
    // mapping that gave one of these a `0`, `land` would fast-forward a head
    // nothing had judged — CLOUD-337, re-introduced by the port meant to
    // preserve it.
    let cases: [(&str, &str); 4] = [
        ("a required check failed", "completed\tfailure\tci\t\t0"),
        ("a draft-era skip", "completed\tskipped\tci\t\t0"),
        ("a run still going", "in_progress\t-\tci\t\t0"),
        ("nothing registered yet", ""),
    ];
    for (what, reading) in cases {
        let (code, stdout, _) = green(reading, &roster());
        assert_ne!(code, 0, "{what} must not read as green: {stdout}");
    }
}

#[test]
fn red_and_pending_share_a_code_and_differ_on_stdout() {
    // The distinction the shared code deliberately drops has to survive
    // somewhere, or the poller cannot tell "ask again" from "stop" and either
    // wedges or gives up early. Both halves are asserted, because a port that
    // collapsed them entirely would pass the exit-code case above.
    let (red_code, red_out, _) = green("completed\tfailure\tci\t\t0", &roster());
    let (pending_code, pending_out, _) = green("completed\tskipped\tci\t\t0", &roster());
    assert_eq!(red_code, pending_code, "both are the same policy verdict");
    assert!(red_out.contains("red"), "{red_out}");
    assert!(pending_out.contains("pending"), "{pending_out}");
    assert_ne!(red_out, pending_out);
}

#[test]
fn an_unusable_roster_is_a_usage_error_and_not_the_policy_verdict() {
    // A statement about the INVOCATION, never about the repository. Distinct
    // from the verdict code on purpose: an empty roster makes every check
    // unrequired, and reporting that as "not green" would hide a config error
    // inside an ordinary refusal the caller retries past.
    let (code, _, stderr) = green(&all_green(), &["--required", "", "--answered", ANSWERED]);
    assert_eq!(code, 1, "an empty roster is usage: {stderr}");
    assert!(
        stderr.contains("every check would be unrequired"),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// The rules the port had to conserve, over the real boundary.
// ---------------------------------------------------------------------------

#[test]
fn a_later_run_supersedes_a_drafts_skip_residue() {
    // CLOUD-436 through the PARSER, which the unit case cannot reach: the
    // ordering key arrives as two TSV fields and the id as text, so a reading
    // whose tie-break did not survive parsing would judge the union and veto a
    // verdict that already exists.
    let mut reading = all_green();
    for name in ["ci", "perf", "final"] {
        reading.push_str(&format!(
            "\ncompleted\tskipped\t{name}\t2026-08-11T00:00:00Z\t1"
        ));
    }
    let (code, stdout, _) = green(&reading, &roster());
    assert_eq!(code, 0, "the newer success speaks for the name: {stdout}");
}

#[test]
fn a_three_field_reading_still_answers() {
    // The predecessor's readings predate the ordering key, and answering one
    // exactly as it did then is itself a property. A parser that required five
    // fields would drop every row and report "nothing registered" — green's
    // opposite, but wrong for the wrong reason.
    let (code, stdout, _) = green("completed\tfailure\tci", &roster());
    assert_eq!(code, 2, "a three-field row is still read: {stdout}");
    assert!(stdout.contains("ci failure"), "{stdout}");
}

#[test]
fn a_tolerated_absence_is_elided_and_a_real_one_is_not() {
    // CLOUD-337 in both directions at once. `zizmor` is path-filtered and
    // produces no run at all, so requiring it would hang; `perf` not having
    // registered yet is a fresh SHA and must hold the poll open.
    let (code, stdout, _) = green(
        "completed\tsuccess\tci\t\t0",
        &[
            "--required",
            "ci,perf,zizmor",
            "--answered",
            ANSWERED,
            "--absent-ok",
            "zizmor",
        ],
    );
    assert_eq!(code, 2);
    assert!(
        stdout.contains("perf"),
        "the unregistered name is named: {stdout}"
    );
    assert!(
        !stdout.contains("zizmor"),
        "the tolerated one is elided: {stdout}"
    );
}

#[test]
fn a_non_fanin_failure_over_cancelled_siblings_is_the_verdict() {
    // CLOUD-900, the case `abandon-matrix` deliberately creates: one real
    // failure beside siblings this repository stopped on purpose. Under
    // CLOUD-363's ordering alone that reads as "not an answer", so the saving
    // would buy a wedge.
    let reading = "completed\tfailure\tci\t\t0\ncompleted\tcancelled\tperf\t\t0\ncompleted\tcancelled\tfinal\t\t0";
    let (code, stdout, _) = green(reading, &roster());
    assert_eq!(code, 2);
    assert!(stdout.contains("red"), "{stdout}");
    assert!(stdout.contains("ci failure"), "{stdout}");
}

#[test]
fn an_unnamed_fanin_leaves_every_failure_manufacturable() {
    // The safe default, and the half easiest to lose in a port: with no fan-in
    // named this is CLOUD-363's ordering intact, so the same reading answers
    // "pending" rather than promoting a failure that a cancellation may have
    // manufactured.
    let reading = "completed\tfailure\tci\t\t0\ncompleted\tcancelled\tperf\t\t0\ncompleted\tcancelled\tfinal\t\t0";
    let (code, stdout, _) = green(reading, &["--required", REQUIRED, "--answered", ANSWERED]);
    assert_eq!(code, 2, "still not landable either way");
    assert!(
        stdout.contains("pending"),
        "no failure is promoted: {stdout}"
    );
}

#[test]
fn an_unrelated_check_gets_neither_a_vote_nor_a_veto() {
    // The scoping that stops a third party vetoing a landing — the same reason
    // the roster exists rather than "any graded run".
    let reading = format!("{}\ncompleted\tfailure\tSomeAnalyzer\t\t0", all_green());
    let (code, _, _) = green(&reading, &roster());
    assert_eq!(code, 0);
}

#[test]
fn the_output_is_a_pointer_and_never_a_log() {
    // Rule 4. The type carrying a finding has room for a name and a conclusion
    // and nothing else, so this asserts the boundary honours that rather than
    // re-deriving it: a run's detail must not appear even when the caller asked
    // about a failure.
    let (_, stdout, stderr) = green("completed\tfailure\tci\t\t0", &roster());
    assert!(stdout.contains("ci failure"), "{stdout}");
    for surface in [&stdout, &stderr] {
        assert!(
            !surface.contains("http"),
            "no url reaches the output: {surface}"
        );
    }
}
