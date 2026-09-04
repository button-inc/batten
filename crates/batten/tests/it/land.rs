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

/// A gate program in the fixture that exits `code`, and the argv naming it.
///
/// A path rather than a bare name, because `$LAND_VERIFY` is split on whitespace
/// and run as argv with no shell: `sh -c 'exit 0'` cannot survive that split, and
/// a bare `true` would resolve against whatever the runner's `PATH` happens to
/// carry — which is the harness answering a question about the engine.
fn gate(repo: &Path, name: &str, code: i32) -> String {
    let path = repo.join(name);
    std::fs::write(&path, format!("#!/bin/sh\nexit {code}\n")).expect("write the gate");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the gate executable");
    }
    path.display().to_string()
}

/// The lap record this branch has accumulated, or an empty string where the
/// writer never reached it.
fn lap_record(repo: &Path, branch: &str) -> String {
    let dir = common::git_in(repo, &["rev-parse", "--git-dir"]);
    let path = repo
        .join(dir.trim())
        .join("batten-receipts")
        .join(format!("lap.{}", branch.replace('/', "-")));
    std::fs::read_to_string(path).unwrap_or_default()
}

/// `batten land verify`, with the consumer's gate named in the environment.
fn land_verify(repo: &Path, command: &str) -> (i32, String, String) {
    let output = batten()
        .args(["land", "verify"])
        .env("LAND_VERIFY", command)
        .current_dir(repo)
        .output()
        .expect("run batten land verify");
    (
        output.status.code().expect("exit code"),
        stdout(&output),
        stderr(&output),
    )
}

/// **The verb was unreachable in every clone, and this is the pair that shows it.**
///
/// `land::verify` handed `exec::run_in` the caller's anchor — a literal `.` — and
/// `exec`'s capture store is keyed by the repository's own directory NAME, which
/// `state::derive_repo_name` cannot read off `.`. So the boundary refused before
/// starting anything, on EVERY invocation, and the `None` arm wrapped that
/// `UsageError` in a context naming the gate. Measured against the shipped
/// binary: a passing gate and a refusing gate produced byte-identical output and
/// the same exit `1`.
///
/// **The pair is what discriminates, and neither half alone does.** Asserting only
/// the clean arm passes over an engine that reports success without running
/// anything; asserting only the refusal passes over one that cannot run anything
/// at all — which is precisely the state this repairs. The record is asserted
/// too, because an exit code alone cannot tell "the gate ran and passed" from
/// "nothing ran and nobody wrote it down".
#[test]
fn a_configured_gate_is_actually_run_and_its_two_answers_are_told_apart() {
    let repo = repo("land-verify-runs");
    let branch = branch_of(&repo);

    let (code, out, err) = land_verify(&repo, &gate(&repo, "passes.sh", 0));
    assert_eq!(code, 0, "a gate that passed is exit 0: {err}{out}");
    let record = lap_record(&repo, &branch);
    assert!(
        record.contains("verify clean "),
        "the clean answer reaches the record, got {record:?}"
    );

    // THE MIRROR, on the SAME branch, so the record is a history rather than a
    // replacement — and so the two answers are told apart by their own column
    // rather than by which fixture produced them.
    let (code, out, err) = land_verify(&repo, &gate(&repo, "refuses.sh", 1));
    assert_eq!(
        code, 2,
        "a gate that refused is the policy verdict, not an error: {err}{out}"
    );
    let record = lap_record(&repo, &branch);
    assert!(
        record.contains("verify refused "),
        "the refusal reaches the record as its own token, got {record:?}"
    );
}

/// The anti-vacuity half of the pair above, and a different failure.
///
/// An unconfigured gate is a USAGE error — exit `1` — and it must stay
/// distinguishable from both answers above. Without this, the repair could be
/// "always report clean", which the pair above would not catch: `$LAND_VERIFY`
/// naming nothing is the one case where refusing to guess is the whole behaviour,
/// since a default compiled into this crate would be non-negotiable rule 1's
/// plainest violation.
#[test]
fn an_unconfigured_gate_refuses_rather_than_guessing_and_writes_no_record() {
    let repo = repo("land-verify-unconfigured");
    let branch = branch_of(&repo);

    let (code, _out, err) = land_verify(&repo, "");
    assert_eq!(code, 1, "an unconfigured gate is a usage error: {err}");
    assert!(
        err.contains("LAND_VERIFY"),
        "the refusal names the variable the caller must set, got {err}"
    );
    assert!(
        lap_record(&repo, &branch).is_empty(),
        "a lap that never ran a gate records no verdict about one"
    );
}
