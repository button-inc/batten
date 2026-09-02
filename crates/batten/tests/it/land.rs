//! The lap's replay outcome, written by the verb and read by the engine
//! (CLOUD-1335).
//!
//! # Why this tier exists and what the module's own suite cannot do
//!
//! `rebase-conflict-stops-the-lap` carries a load-time tier that pins its
//! predicate, and every case in it supplies the record with `with input as`. That
//! fabricates the very shape the engine may be unable to produce — here, the
//! COLUMN LAYOUT and the STORE the whole family turns on — so the module's suite
//! would stay green over a writer that emits three columns, or writes to a path
//! `recorder_records` never walks, or writes nothing at all.
//!
//! So these cases write through [`batten::land::record`], the real writer, and
//! read back through `batten check` over a real repository with the preset
//! enabled. The writer and the vendored module meet over the engine rather than
//! over a fixture somebody typed on both sides.
//!
//! # Why the writer rather than `land::replay`
//!
//! `replay` fetches from a remote before it replays, so reaching this writer
//! through it needs a live smart-HTTP server — which would make the case a test
//! of the network. The replay itself is already driven end to end in
//! `crates/batten/tests/it/rebase.rs`, over real fixtures and with no `git`
//! binary; what is untested until here is the join between what a lap RECORDS and
//! what a module READS.

#![cfg(unix)]

use crate::common;

use std::path::Path;

use batten::land::{self, Answered, Arm, Replay};

use common::{Fixture, batten, scratch, stderr, stdout};

/// A repository with the `landing-loop` preset enabled and nothing else.
///
/// The three sibling modules in that preset read `input.tree.forge`,
/// `input.tree.landing` and a `lease`-kind record, none of which this fixture
/// supplies — so they are silent here by construction and any finding these cases
/// see is the one under test.
fn repo(name: &str) -> std::path::PathBuf {
    Fixture::at(scratch(name).join("repo"))
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"landing\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             preset = \"landing-loop\"\n\
             severity = \"deny\"\n",
        )
        .file("lib.rs", "fine\n")
        .git()
        .base_commit()
        .build()
}

/// The branch the fixture is on, read rather than assumed.
///
/// The record is keyed by branch, so a case that hard-coded `main` would pass for
/// the wrong reason on a harness whose default changed — and would keep passing
/// if the writer stopped keying on the branch at all.
fn branch_of(repo: &Path) -> String {
    common::git_in(repo, &["rev-parse", "--abbrev-ref", "HEAD"])
        .trim()
        .to_owned()
}

/// `batten check` over the fixture: the exit code and what it said.
fn check(repo: &Path) -> (i32, String, String) {
    let output = batten()
        .args(["check"])
        .current_dir(repo)
        .output()
        .expect("run batten check");
    (
        output.status.code().expect("exit code"),
        stdout(&output),
        stderr(&output),
    )
}

/// **The case the design exists for.** A conflicted lap is refused, and the
/// refusal reaches the reader through the engine rather than through a fixture.
///
/// The anti-vacuity mirror is the second half and is not optional: the first
/// alone passes over a preset that refuses everything, and over an engine that
/// reports a finding for any record at all.
#[test]
fn a_conflicted_lap_is_refused_and_a_clean_one_is_not() {
    let repo = repo("land-conflicted");
    let branch = branch_of(&repo);

    land::record(
        &repo,
        &branch,
        &Replay::Conflicted {
            commit: String::from("abc1234"),
            paths: vec![String::from("shared.txt")],
        },
    )
    .expect("record the conflicted lap");

    let (code, out, err) = check(&repo);
    assert_eq!(
        code, 2,
        "a conflicted lap is the policy verdict: {err}{out}"
    );
    assert!(
        format!("{out}{err}").contains("rebase-conflict-stops-the-lap"),
        "the finding names its own predicate, got {out}{err}"
    );

    // THE ANTI-VACUITY MIRROR, and it is a SECOND lap on the same branch rather
    // than a fresh fixture — which is also the assertion that the store is a
    // history and the module reads its last line. A writer that replaced instead
    // of appending would pass this; so would a module reading the whole list, and
    // that one would fail it.
    land::record(
        &repo,
        &branch,
        &Replay::Replayed {
            head: String::from("def5678"),
            commits: 1,
        },
    )
    .expect("record the resolving lap");

    let (code, out, err) = check(&repo);
    assert_eq!(
        code, 0,
        "a conflict a later lap resolved stops refusing: {err}{out}"
    );
}

/// A branch that has recorded no lap at all is not refused.
///
/// The state a fresh clone is in, and the one a gate keyed on the record's
/// ABSENCE rather than on its content would get wrong — reading "no lap has run"
/// as "the last lap conflicted" would refuse every branch before its first lap.
#[test]
fn a_branch_with_no_lap_record_is_clean() {
    let repo = repo("land-no-record");
    let (code, out, err) = check(&repo);
    assert_eq!(code, 0, "a branch that has not lapped is clean: {err}{out}");
}

/// An already-current branch replayed nothing, so nothing conflicted.
#[test]
fn an_already_current_lap_is_clean() {
    let repo = repo("land-current");
    let branch = branch_of(&repo);
    land::record(&repo, &branch, &Replay::Current).expect("record the current lap");

    let (code, out, err) = check(&repo);
    assert_eq!(
        code, 0,
        "an already-current branch replayed nothing: {err}{out}"
    );
}

/// (CLOUD-1338) A lap that read both sides of its race is refused, over the real
/// writer and the real engine.
///
/// The sibling of the conflict case, and it exists for the same measured reason:
/// the module's own suite supplies its record with `with input as`, which
/// fabricates the column layout and the store. This drives
/// [`batten::land::record_wait`] — the writer that cannot record half a race —
/// and reads back through `batten check`.
#[test]
fn a_lap_that_read_both_answers_is_refused_and_one_answer_is_not() {
    let repo = repo("land-wait-both");
    let branch = branch_of(&repo);

    land::record_wait(
        &repo,
        &branch,
        &[
            Answered {
                arm: Arm::Green,
                verdict: Some(String::from("success")),
                sha: String::from("abc1234"),
            },
            Answered {
                arm: Arm::Stale,
                verdict: Some(String::from("moved")),
                sha: String::from("abc1234"),
            },
        ],
    )
    .expect("record the doubly-answered wait");

    let (code, out, err) = check(&repo);
    assert_eq!(code, 2, "a lap that read both answers: {err}{out}");
    assert!(
        format!("{out}{err}").contains("lap-waits-on-one-answer"),
        "the finding names its own predicate, got {out}{err}"
    );
}

/// THE ANTI-VACUITY MIRROR for the race, and the reading a naive port gets
/// wrong: a VOIDED loser is the design working, so a lap that raced properly
/// must not be refused.
#[test]
fn a_lap_whose_loser_was_voided_is_clean() {
    let repo = repo("land-wait-voided");
    let branch = branch_of(&repo);

    land::record_wait(
        &repo,
        &branch,
        &[
            Answered {
                arm: Arm::Green,
                verdict: Some(String::from("success")),
                sha: String::from("abc1234"),
            },
            Answered {
                arm: Arm::Stale,
                verdict: None,
                sha: String::from("abc1234"),
            },
        ],
    )
    .expect("record the raced wait");

    let (code, out, err) = check(&repo);
    assert_eq!(
        code, 0,
        "one answer beside one voided loser is the race working: {err}{out}"
    );
}

/// A CONFLICT WITH NO PATH still refuses.
///
/// The arm the module writes separately, reached over the engine: the record
/// carries `-` where the pointer would be, the module omits the `path` subject
/// rather than pointing at a file that does not exist, and the refusal stands
/// either way. A writer that emitted an empty column instead would shift every
/// column after it, the reader's length check would skip the line, and the loop's
/// one human stop would become silence — which is why this case asserts the
/// REFUSAL rather than the line.
#[test]
fn a_conflict_with_no_path_still_refuses() {
    let repo = repo("land-conflicted-pathless");
    let branch = branch_of(&repo);
    land::record(
        &repo,
        &branch,
        &Replay::Conflicted {
            commit: String::from("abc1234"),
            paths: Vec::new(),
        },
    )
    .expect("record the pathless conflict");

    let (code, out, err) = check(&repo);
    assert_eq!(
        code, 2,
        "a conflict with no path to name is still a conflict: {err}{out}"
    );
    assert!(
        format!("{out}{err}").contains("rebase-conflict-stops-the-lap"),
        "the finding names its own predicate, got {out}{err}"
    );
}
