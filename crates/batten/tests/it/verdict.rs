//! One authority folds a run's findings and blind spots into an exit code, over
//! the compiled binary (CLOUD-1718).
//!
//! **What is decidable only here.** `exit.rs` unit-tests `ExitCode::combine`, and
//! those cases pin the fold. They cannot pin that a SHELL can reach it, which is
//! the whole justification for the verb: the bug dies with each program that
//! retires, so what pays for this row is what does NOT retire — the workflow
//! tree, which is permanently bash by declaration; the installer, which is bash
//! by construction; and consumer repositories, whose gates hit the identical
//! inversion with no campaign to save them. Every one of those calls a PROCESS
//! and branches on `$?`, so the claim under test is the process's status, and a
//! unit test over the enum cannot make it.
//!
//! The discriminating case is the inversion itself: the retiring corpus reads
//! `1` as a violation and `2` as could-not-look, and this table reads `2` as a
//! violation and `3` as could-not-look. A port that carried the old fold across
//! would not report a worse code — it would report the OPPOSITE meaning.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::process::Output;

use common::{Fixture, run, stderr, stdout};

/// The verb reads two integers off its own command line, so the repository it
/// runs in cannot change its answer. A fixture is built anyway — that
/// independence is a claim worth holding rather than assuming.
fn anywhere() -> std::path::PathBuf {
    Fixture::new("verdict-anywhere")
        .config("version = 1\n")
        .git()
        .build()
}

fn verdict(args: &[&str]) -> Output {
    let dir = anywhere();
    let mut argv = vec!["verdict"];
    argv.extend_from_slice(args);
    run(&dir, &argv)
}

#[test]
fn a_clean_run_exits_success() {
    let output = verdict(&["--findings", "0", "--unjudgeable", "0"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn findings_alone_exit_violation() {
    let output = verdict(&["--findings", "3", "--unjudgeable", "0"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn a_blind_spot_alone_exits_internal() {
    let output = verdict(&["--findings", "0", "--unjudgeable", "1"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn a_blind_spot_outranks_a_finding() {
    // THE PRECEDENCE, over the process rather than over the enum (CLOUD-251,
    // CLOUD-1718). One retiring program deliberately inverted this, and nothing
    // could notice because the rule lived in each epilogue's prose. A run that
    // could not read part of its subject has an INCOMPLETE answer: a caller told
    // `2` fixes what it names and sees green, where a caller told `3` learns the
    // gate did not run. The findings reach stderr either way, so ranking the
    // blind spot first costs nothing.
    let output = verdict(&["--findings", "3", "--unjudgeable", "1"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn the_two_contracts_disagree_on_every_nonclean_answer() {
    // THE INVERSION, which is what makes this a correctness row rather than a
    // duplication one. The retiring corpus's `1` is a violation and its `2` is
    // could-not-look; here `2` is the violation and `3` is could-not-look. The
    // dangerous half is the COLLISION: the corpus's could-not-look is this
    // table's violation, so a fold carried across does not degrade, it inverts.
    let shell_violation = 1;
    let shell_could_not_look = 2;

    let found = verdict(&["--findings", "1"]);
    assert_ne!(
        found.status.code(),
        Some(shell_violation),
        "a finding must not take the corpus's violation code"
    );
    assert_eq!(
        found.status.code(),
        Some(shell_could_not_look),
        "and the collision is exact: this table's violation IS the corpus's could-not-look"
    );

    let blind = verdict(&["--unjudgeable", "1"]);
    assert_ne!(
        blind.status.code(),
        Some(shell_could_not_look),
        "a blind spot must not take the corpus's could-not-look code"
    );
}

#[test]
fn an_absent_count_reads_as_zero() {
    // The verb's job is to be callable from a shell epilogue, where an unset
    // variable expands to the empty string. A caller with only findings to
    // report should not have to say it saw no blind spots.
    let output = verdict(&["--findings", "2"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let bare = verdict(&[]);
    assert_eq!(bare.status.code(), Some(0), "{}", stderr(&bare));
}

#[test]
fn an_unparsable_count_reads_as_zero_rather_than_replacing_the_verdict() {
    // The safe direction is the one that reports LESS: a miscounted finding is
    // still on the caller's own stderr, where a usage error would replace the
    // verdict entirely and put the caller back to hand-folding the case it came
    // here to avoid.
    let output = verdict(&["--findings", "", "--unjudgeable", "1"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn the_fold_never_reports_a_failure_of_battens_own() {
    // `1` is a statement about the INVOCATION. No count of findings or of
    // unreadable subjects can make an invocation malformed, so it is unreachable
    // through this verb — which is what lets a caller branch on `1` as "the gate
    // is misconfigured" and never as "policy says no".
    for findings in ["0", "1", "7"] {
        for unjudgeable in ["0", "1", "7"] {
            let output = verdict(&["--findings", findings, "--unjudgeable", unjudgeable]);
            assert_ne!(
                output.status.code(),
                Some(1),
                "{findings}/{unjudgeable} must not report a usage error"
            );
        }
    }
}

#[test]
fn the_verb_reads_no_repository() {
    // Its independence from the tree is what makes it callable from a consumer
    // repository, an installer or a workflow step — none of which has this
    // config, and one of which has no repository at all.
    let bare = Fixture::new("verdict-no-config").git().build();
    let output = run(&bare, &["verdict", "--findings", "1"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a tree with no batten.toml must still get a verdict: {}",
        stderr(&output)
    );
}
