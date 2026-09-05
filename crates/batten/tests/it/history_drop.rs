//! `git reset --hard` is refused when, and only when, it would leave work
//! referenced by nothing (CLOUD-462).
//!
//! # The predicate is reachability, not the verb
//!
//! The row is explicit that a literal match is the wrong shape: a reset onto a
//! ref whose commits are all on a remote loses nothing, and refusing it "would be
//! the false-positive rate that gets a guard switched off". So the negative case
//! here is the load-bearing one — `a_reset_over_pushed_work_is_allowed` is what
//! stops the easy implementation, which refuses every `--hard`, from passing.
//!
//! # Why the measured incident is a case
//!
//! 2026-08-12: a `git reset --hard HEAD~1` meant to undo a probe commit also
//! discarded `mise-tasks/semver`, a `mise.toml` pin and 39 lines of `mise.lock`,
//! because `git add -A` had swept them into the same commit. Nothing warned and
//! nothing refused. That is `a_range_mixing_pushed_and_unpushed_work_is_refused`:
//! one unreachable commit in range is enough to lose something.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, pin_origin_main, run_with_stdin, stderr};

/// The class the gate refuses under, and the rule id beside it. Both are the
/// engine's own tokens rather than strings chosen here, so a rename that broke
/// every consumer breaks this too.
const CLASS: &str = "history drop unpushed";

/// A repository whose policy is adjudicable at all.
///
/// THE `protected` SET AND THE `[[verb]]` ROW ARE LOAD-BEARING AND DO NOT MATCH
/// ANY CALL HERE. `Policy::is_empty` is `shapes.is_empty() && bundles.is_empty()
/// && (verbs.is_empty() || protected.is_empty())`, and it short-circuits
/// `adjudicate` before any gate runs — so a fixture with neither would allow
/// every reset and every case below would pass for the wrong reason. The same
/// trap `mediated_admission.rs` records at its own fixture.
fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            "version = 1\n\
             protected = [\"guarded.txt\"]\n\n\
             [[verb]]\n\
             verb = \"rm\"\n\
             effect = \"write\"\n\
             redirect = \"restore it with git\"\n",
        )
        .file("guarded.txt", "guarded\n")
        .git()
        // `base_commit` commits AND pins `refs/remotes/origin/main` at it, so
        // everything committed here is "on a remote" as far as reachability goes.
        .base_commit()
        .build()
}

/// Commit one more file AND move the remote ref onto it, so the commit counts as
/// pushed. Needed wherever a case wants a range deeper than one commit.
fn pushed(dir: &Path, name: &str) {
    common::write(dir, name, "shared\n");
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "work that is on the remote"]);
    pin_origin_main(dir);
}

/// Commit one more file, leaving it on no remote.
fn unpushed(dir: &Path, name: &str) {
    common::write(dir, name, "local only\n");
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "work that exists only here"]);
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

fn adjudicate(dir: &Path, command: &str) -> (Option<i32>, String) {
    let out = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload(command),
    );
    (out.status.code(), stderr(&out))
}

/// THE NEGATIVE CASE, AND IT IS THE ONE THAT MATTERS.
///
/// A reset over commits that are all on a remote is the ordinary undo. The row
/// insists it must not be refused, because a guard that fires on it is one people
/// switch off — and the easy implementation, which keys on `--hard`, fails
/// exactly here.
#[test]
fn a_reset_over_pushed_work_is_allowed() {
    let dir = fixture("history-drop-pushed");
    let (code, cause) = adjudicate(&dir, "git reset --hard HEAD~1");
    assert_eq!(
        code,
        Some(0),
        "a reset discarding nothing unreachable must be allowed\n{cause}"
    );
}

/// A commit that exists in this clone and nowhere else is refused.
#[test]
fn a_reset_over_unpushed_work_is_refused() {
    let dir = fixture("history-drop-unpushed");
    unpushed(&dir, "local.txt");
    let (code, cause) = adjudicate(&dir, "git reset --hard HEAD~1");
    assert_eq!(code, Some(2), "the gate must fire\n{cause}");
    assert!(
        cause.contains(CLASS),
        "and under its own class rather than a neighbour's\n{cause}"
    );
}

/// THE MEASURED INCIDENT: one unreachable commit in range is enough.
///
/// The 2026-08-12 loss was exactly this shape — a range whose commits were mostly
/// safe and whose last one was not.
#[test]
fn a_range_mixing_pushed_and_unpushed_work_is_refused() {
    let dir = fixture("history-drop-mixed");
    // Three commits: the base and this one are on the remote, the last is not.
    // `HEAD~2` therefore spans both kinds, which is the shape of the incident.
    pushed(&dir, "shared.txt");
    unpushed(&dir, "local.txt");
    let (code, cause) = adjudicate(&dir, "git reset --hard HEAD~2");
    assert_eq!(
        code,
        Some(2),
        "one unreachable commit in range is enough to lose something\n{cause}"
    );
    assert!(cause.contains(CLASS), "under its own class\n{cause}");
}

/// THE SCOPE, three ways, and each is a different reason to be silent.
///
/// * `--soft` leaves the work in the tree, so nothing is discarded.
/// * a bare `--hard` resets to `HEAD`, an empty range — it discards the working
///   tree, which is not this class's subject.
/// * `--hard -- <path>` is a pathspec reset and moves no ref at all.
#[test]
fn a_reset_that_discards_no_commit_is_silent() {
    let dir = fixture("history-drop-scope");
    unpushed(&dir, "local.txt");
    // NOT a protected path. `git` is not in this fixture's `[[verb]]` table, so
    // the unknown-program walk refuses any protected operand it is handed — and
    // a case naming `guarded.txt` here passed for that gate's reason rather than
    // this one. Found by it going red.
    common::write(&dir, "ordinary.txt", "not protected\n");
    for command in [
        "git reset --soft HEAD~1",
        "git reset --hard",
        "git reset --hard -- ordinary.txt",
    ] {
        let (code, cause) = adjudicate(&dir, command);
        assert_eq!(code, Some(0), "must be silent: {command}\n{cause}");
    }
}

/// THE REFUSAL IS A POINTER (rule 4), and this class is where that earns its
/// keep: the payload it must not print is the very work about to be discarded.
///
/// A count and short SHAs, and the recovery. Never a diff, never a message,
/// never a path.
#[test]
fn the_refusal_carries_a_count_and_shas_and_no_content() {
    let dir = fixture("history-drop-pointer");
    unpushed(&dir, "secret-ish.txt");
    let (_, cause) = adjudicate(&dir, "git reset --hard HEAD~1");
    assert!(
        cause.contains("git reflog"),
        "the remedy is the RECOVERY, not the refusal\n{cause}"
    );
    assert!(
        !cause.contains("local only"),
        "the discarded CONTENT must never travel\n{cause}"
    );
    assert!(
        !cause.contains("work that exists only here"),
        "nor the commit message\n{cause}"
    );
    assert!(
        !cause.contains("secret-ish.txt"),
        "nor the paths in the range\n{cause}"
    );
}

/// The gate reads `programs`, so shell grammar does not hide the reset
/// (CLOUD-1382). Without this the class is one keystroke from silent, which is
/// the defect that row measured six times over.
#[test]
fn a_grammar_token_does_not_hide_the_reset() {
    let dir = fixture("history-drop-grammar");
    unpushed(&dir, "local.txt");
    for command in [
        "(git reset --hard HEAD~1)",
        "time git reset --hard HEAD~1",
        "cd . && git reset --hard HEAD~1",
    ] {
        let (code, cause) = adjudicate(&dir, command);
        assert_eq!(code, Some(2), "must still refuse: {command}\n{cause}");
    }
}

/// A GIT GLOBAL OPTION DOES NOT HIDE THE RESET, and this case exists because
/// review caught the gate one construct short of its own subject.
///
/// `programs[_].arguments` is what git was handed, and git takes options of its
/// own BEFORE the subcommand. Anchoring on `arguments[0] == "reset"` therefore
/// reads `-C` or `--no-pager` and walks away — the same under-deny CLOUD-1382's
/// table measured one layer out, arrived at by the same mistake: taking the
/// first token for the thing.
///
/// SHOWN ABLE TO FAIL: measured against the version this file first shipped
/// with, every command below exited **0** while the bare spelling exited 2.
#[test]
fn a_git_global_option_does_not_hide_the_reset() {
    let dir = fixture("history-drop-git-globals");
    unpushed(&dir, "local.txt");
    for command in [
        "git -C . reset --hard HEAD~1",
        "git --no-pager reset --hard HEAD~1",
        "git -c core.pager=cat reset --hard HEAD~1",
        "git --git-dir .git reset --hard HEAD~1",
    ] {
        let (code, cause) = adjudicate(&dir, command);
        assert_eq!(code, Some(2), "must still refuse: {command}\n{cause}");
        assert!(cause.contains(CLASS), "under its own class\n{cause}");
    }
    // THE ANTI-VACUITY HALF: skipping git's own options must not make every
    // `git` call a reset. A global option in front of an innocent subcommand is
    // still innocent.
    for allowed in [
        "git -C . status",
        "git --no-pager log --oneline -1",
        "git -c core.pager=cat reset --soft HEAD~1",
    ] {
        let (code, cause) = adjudicate(&dir, allowed);
        assert_eq!(code, Some(0), "must stay silent: {allowed}\n{cause}");
    }
}

/// A PATHSPEC RESET IN AN EARLIER SEGMENT DOES NOT END THE SCAN, and this case
/// exists because review caught the opposite.
///
/// `--` means "no range to judge" for the entry that carries it — that is the
/// scope clause above and it is right. What was wrong is that it answered for
/// the whole COMMAND: the walk returned `None` rather than moving to the next
/// program, so a real history-dropping reset later in the same compound command
/// was never looked at. One innocent reset in front of a destructive one is a
/// one-keystroke silence, which is the shape CLOUD-1382 measured six times over.
///
/// SHOWN ABLE TO FAIL: measured against the version this file first shipped
/// with, the command below exited `0`.
#[test]
fn a_pathspec_reset_does_not_hide_a_later_one() {
    let dir = fixture("history-drop-pathspec-first");
    unpushed(&dir, "local.txt");
    common::write(&dir, "ordinary.txt", "not protected\n");
    let (code, cause) = adjudicate(
        &dir,
        "git reset --hard -- ordinary.txt && git reset --hard HEAD~1",
    );
    assert_eq!(
        code,
        Some(2),
        "the second reset is the one that discards, and it must still be seen\n{cause}"
    );
    assert!(cause.contains(CLASS), "under its own class\n{cause}");
}

/// COULD-NOT-LOOK ALLOWS, which is the direction this gate must fail in.
///
/// A target that resolves to nothing is not evidence that work would be lost, and
/// a gate that refused on it would refuse hardest in the repositories where the
/// answer is least knowable — the wall the row refuses to build.
#[test]
fn a_target_that_will_not_resolve_allows() {
    let dir = fixture("history-drop-unresolvable");
    unpushed(&dir, "local.txt");
    let (code, cause) = adjudicate(&dir, "git reset --hard no-such-ref");
    assert_eq!(
        code,
        Some(0),
        "could-not-look must allow rather than refuse\n{cause}"
    );
}

/// A clone with NO remote at all is the same could-not-look, reached another way,
/// and it is worth its own case: every commit is unreachable from a remote that
/// does not exist, so a careless implementation refuses every reset in a fresh
/// repository — the loudest possible false positive.
#[test]
fn a_repository_with_no_remote_refuses_nothing_it_should_not() {
    let dir = Fixture::new("history-drop-no-remote")
        .config(
            "version = 1\n\
             protected = [\"guarded.txt\"]\n\n\
             [[verb]]\n\
             verb = \"rm\"\n\
             effect = \"write\"\n\
             redirect = \"restore it with git\"\n",
        )
        .file("guarded.txt", "guarded\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "only commit"]);
    unpushed(&dir, "local.txt");
    let (code, cause) = adjudicate(&dir, "git reset --hard HEAD~1");
    // THE HONEST ANSWER IS A DENY, and this case pins which one it is rather
    // than asserting a preference: with no remote, the commit really is
    // referenced by nothing but this branch, so the class is true of it. The
    // case exists so that answer is a decision somebody made rather than a
    // behaviour discovered in a fresh clone.
    assert_eq!(
        code,
        Some(2),
        "with no remote, unpushed is the honest reading\n{cause}"
    );
}
