//! Guardrail bypass over the compiled binary (CLOUD-98).
//!
//! The unit tests in `src/bypass.rs` pin the correlation against explicit
//! streams. These pin the half a unit test structurally cannot reach: that the
//! detector is wired to `state record` beside CLOUD-97's, that each bypassed
//! operation reaches the store as its own advisory finding at the right tier,
//! that the run stays exit 0, and that no byte of a command line reaches any
//! stream.
//!
//! A separate target rather than more of `tests/cli.rs`, on
//! `tests/advisory_drain.rs`'s precedent and for its stated reason — the same
//! deviation from §7 that `tests/done_not_landed.rs` landed with.
//!
//! **The fixture repository is deliberately landed.** Its `HEAD` is `main`, so
//! CLOUD-97's predicate resolves to "nothing to land" and writes nothing, and
//! every record in the store here belongs to this rule. A fixture with unlanded
//! work would have two detectors answering and would assert their interaction
//! by accident.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, StateHome, batten, scratch, stderr, stdout};

/// Every sentinel the fixture transcripts carry: a prompt, a command line, a
/// deny reason, a write target and its body, a tool result, and a summary.
///
/// A command line is the likeliest thing in a transcript to carry a credential,
/// which is why rule 4 is asserted here over both channels and the listing.
const CANARIES: &[&str] = &[
    "CANARY-USER-PROMPT",
    "CANARY-COMMAND",
    "CANARY-DENY-REASON",
    "CANARY-RESULT",
    "CANARY-SUMMARY",
    "CANARY-TARGET",
    "CANARY-BODY",
];

/// A fixture transcript, read from the checked-in pack.
fn transcript(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transcripts")
        .join(format!("{name}.jsonl.in"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()))
}

/// Run any `batten` subcommand against the fixture's own state home.
fn batten_in(dir: &Path, home: &Path, args: &[&str]) -> Output {
    batten()
        .state_home(home)
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten")
}

/// `batten state record`, asserting it exited clean.
///
/// **Always exit 0 is part of the claim**: this finding is advisory, so however
/// serious a bypass is, raising it may never move an exit code.
fn record(dir: &Path, home: &Path) -> Output {
    let output = batten_in(dir, home, &["state", "record"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "state record must stay exit 0 whatever it found: {}",
        stderr(&output)
    );
    output
}

/// The store's pointer lines for the bypass rule: `<fp> <rule> <ref> <count>`.
fn recorded(dir: &Path, home: &Path) -> Vec<String> {
    let listed = batten_in(dir, home, &["state", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    stdout(&listed)
        .lines()
        .filter(|line| line.contains(batten::bypass::RULE_ID))
        .map(ToOwned::to_owned)
        .collect()
}

/// A **landed** repository carrying `transcript_body`, plus an isolated state
/// home.
fn bypass_repo(name: &str, transcript_body: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\
             must_land_on = \"main\"\n\n\
             [transcript]\n\
             path = \"session.jsonl\"\n",
        )
        .file("src/a.rs", "fn main() {}\n")
        .file(".gitignore", "session.jsonl\n")
        .git()
        .base_commit()
        .build();
    common::write(&repo, "session.jsonl", transcript_body);
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

#[test]
fn a_mediated_deny_then_the_same_op_with_enforcement_off_raises() {
    let (repo, home) = bypass_repo("cloud98-mediated", &transcript("bypass-mediated"));
    let reported = stderr(&record(&repo, &home));
    assert!(
        reported.contains("bypass: raised refs/heads/main"),
        "the report names the outcome and the ref: {reported}"
    );
    assert!(
        reported.contains("session.jsonl:3->5"),
        "and the turn pair — where it was refused, where it was forced: {reported}"
    );
    assert!(
        reported.contains("refusal mediated"),
        "and which producer answered: {reported}"
    );
    assert_eq!(recorded(&repo, &home).len(), 1);
}

#[test]
fn a_sandbox_denial_raises_too_though_no_hook_ever_saw_it() {
    // The case the issue is named for. The sandbox toggle does not route
    // through Batten, so there is no mediated record — if the failed-result
    // producer were missing, this transcript would read as clean.
    let (repo, home) = bypass_repo("cloud98-sandbox", &transcript("bypass-sandbox-denial"));
    let reported = stderr(&record(&repo, &home));
    assert!(
        reported.contains("refusal failed"),
        "the typed error boolean is the other producer: {reported}"
    );
    assert_eq!(recorded(&repo, &home).len(), 1);
}

#[test]
fn a_standalone_enforcement_disable_does_not_raise() {
    // Turning the sandbox off is a declared affordance, and flagging every use
    // of it is the alternative the issue rejects. The signal is the sequence.
    let (repo, home) = bypass_repo("cloud98-standalone", &transcript("bypass-standalone"));
    record(&repo, &home);
    assert!(recorded(&repo, &home).is_empty());
}

#[test]
fn a_deny_followed_by_a_different_op_does_not_raise() {
    // Equivalence is exact. A guardrail that fired, followed by unrelated work
    // with the sandbox off, is not somebody forcing that work through.
    let (repo, home) = bypass_repo("cloud98-different-op", &transcript("bypass-different-op"));
    record(&repo, &home);
    assert!(recorded(&repo, &home).is_empty());
}

#[test]
fn the_report_is_byte_identical_across_two_runs_over_the_same_transcript() {
    let (repo, home) = bypass_repo("cloud98-stable", &transcript("bypass-mediated"));
    // The first run binds the store, which is a one-off note about bookkeeping
    // rather than about this predicate.
    record(&repo, &home);
    let first = record(&repo, &home);
    let second = record(&repo, &home);
    assert_eq!(
        (stdout(&first), stderr(&first)),
        (stdout(&second), stderr(&second)),
        "same transcript, same answer, same bytes"
    );
}

#[test]
fn the_finding_does_not_clear_on_re_evaluation() {
    // It anchors to an immutable event, so re-running finds it again: the
    // observation stays positive and never resolves to zero. This is the
    // issue's stated assumption 1, asserted rather than assumed — and the
    // reason the finding settles by disposition instead.
    let (repo, home) = bypass_repo("cloud98-anchored", &transcript("bypass-mediated"));
    record(&repo, &home);
    record(&repo, &home);
    let lines = recorded(&repo, &home);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].ends_with(" 1"),
        "still observed, never resolved to zero: {lines:?}"
    );
}

#[test]
fn the_finding_is_stored_as_an_advisory_at_the_warning_tier() {
    let (repo, home) = bypass_repo("cloud98-shape", &transcript("bypass-mediated"));
    record(&repo, &home);
    let listed = batten_in(&repo, &home, &["state", "list", "-J"]);
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&listed)).expect("the listing is JSON");
    let stored = document
        .as_array()
        .and_then(|records| {
            records
                .iter()
                .find(|record| record["rule"] == batten::bypass::RULE_ID)
        })
        .expect("the finding is stored");
    assert_eq!(
        stored["tier"], "warning",
        "CLOUD-80's answer-now tier — above the completion rule's"
    );
    assert_eq!(
        stored["severity"], "allow",
        "a severity the exit contract cannot promote"
    );
    assert_eq!(stored["check"], "reevaluate");
    assert!(
        stored["remediation"]["no-fix"].is_string(),
        "no command un-does a bypass that happened"
    );
    // The pointer is the refusal's line, and the instance carries no operand.
    let instance = &stored["instances"][0];
    assert_eq!(instance["line"], 3);
    assert_eq!(instance["path"], "session.jsonl");
}

#[test]
fn no_transcript_text_reaches_any_output_stream() {
    for name in [
        "bypass-mediated",
        "bypass-sandbox-denial",
        "bypass-standalone",
        "bypass-different-op",
    ] {
        let (repo, home) = bypass_repo(&format!("cloud98-opaque-{name}"), &transcript(name));
        let recorded_run = record(&repo, &home);
        let listed = batten_in(&repo, &home, &["state", "list", "-J"]);
        let seen = format!(
            "{}{}{}{}",
            stdout(&recorded_run),
            stderr(&recorded_run),
            stdout(&listed),
            stderr(&listed)
        );
        for canary in CANARIES {
            assert!(
                !seen.contains(canary),
                "{name}: {canary} reached an output stream"
            );
        }
    }
}
