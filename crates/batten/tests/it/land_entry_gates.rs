//! The landing's entry gates and the retirement of a landed branch
//! (CLOUD-1471), over the compiled binary and the library.
//!
//! # Why these two are one file
//!
//! They are the two clusters `mise-tasks/land.sh` carried that no successor
//! did — its first act and its last. Neither is a step of the lap, so neither
//! landed with the pipeline; both would have gone on the floor with the program.
//! Keeping them together is what makes that pairing legible to the next reader.
//!
//! # The entry gate is driven end to end, and it can be
//!
//! It runs before the lease, the singleton and any spend, so `land lap` reaches
//! it with no forge state to fabricate beyond the pull request lookup — which is
//! `rest`'s fixture seam. A refusal there is the whole assertion: the lap stops
//! at exit 2 having spent nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

const REPO: &str = "acme/widgets";
const PR: &str = "42";

/// One open pull request, in the response shape the fixture reads.
fn one_pull_request() -> String {
    format!("HTTP/2 200\ncontent-type: application/json\n\n[{{\"number\":{PR}}}]\n")
}

/// A repository on a branch, with the pull-request lookup canned.
fn fixture(name: &str) -> std::path::PathBuf {
    let dir = common::scratch(name);
    common::init_repo(&dir);
    // A REMOTE THAT RESOLVES AND CANNOT BE REACHED, which is exactly the state
    // these cases need. `land lap` resolves `origin` before the first step, so
    // without one it stops with "no base" and the entry gate is never reached;
    // and every case here asserts that the gate stops the lap BEFORE it fetches,
    // so a remote that would answer is the wrong fixture — a case reaching the
    // fetch has already failed its own claim.
    common::git_in(&dir, &["remote", "add", "origin", "file:///nonexistent"]);
    // NO TRACKING REF IS PINNED, and the absence is the assertion's other half:
    // every case here claims the entry gate stops the lap before it looks at the
    // base at all, so a fixture that supplied one would let a case pass over a
    // gate asked too late.
    common::git_in(&dir, &["checkout", "-q", "-b", "topic"]);
    std::fs::write(dir.join("resp.last"), one_pull_request()).expect("write the canned answer");
    dir
}

/// Write an executable gate that records its argv and exits with `code`.
fn gate(dir: &std::path::Path, name: &str, code: i32) -> String {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>'{}/asked'\necho 'the gate spoke'\nexit {code}\n",
            dir.display()
        ),
    )
    .expect("write the gate");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the gate executable");
    }
    path.display().to_string()
}

/// What the gates recorded about how they were called.
fn asked(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("asked")).unwrap_or_default()
}

/// Run `batten land lap` against the fixture with `gates` declared.
fn lap(dir: &std::path::Path, gates: &str) -> (i32, String, String) {
    let output = common::batten()
        .arg("land")
        .arg("lap")
        .arg("main")
        .env("GH_REPO", REPO)
        .env("LAND_ENTRY_GATES", gates)
        .env("BATTEN_REST_FIXTURE", dir)
        // Bounded so a lap that gets PAST the entry gate cannot run away: every
        // case here is about stopping before the first step, and a runaway would
        // be reported as a hang rather than as the miss it is.
        .env("LAND_MAX_LAPS", "1")
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs");
    (
        output.status.code().expect("the child exited normally"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// **A DECLARED GATE IS ASKED ABOUT THIS PULL REQUEST, AND ITS REFUSAL STOPS THE
/// LANDING BEFORE ANYTHING IS SPENT.**
///
/// The number is appended by the ENGINE rather than spelled by the consumer,
/// which is the half a reader is most likely to get wrong: a gate reading it from
/// its own environment would be a second authority over which pull request a lap
/// is landing, and the two can name different ones.
#[test]
fn a_refusing_entry_gate_stops_the_landing_and_is_told_which_pull_request() {
    let dir = fixture("land-entry-refuses");
    let refuses = gate(&dir, "refuses.sh", 1);
    let (code, _, err) = lap(&dir, &refuses);

    assert_eq!(
        code, 2,
        "a gate's refusal is a verdict about this repository"
    );
    assert!(
        asked(&dir).trim() == PR,
        "the gate should be handed the pull request number; it got: {:?}",
        asked(&dir)
    );
    assert!(
        err.contains("refused this landing"),
        "the refusal should name itself: {err}"
    );
    // THE GATE'S OWN WORDS REACH THE OPERATOR (CLOUD-407), rather than a summary
    // written here that would be a second, staler copy of the remedy.
    assert!(err.contains("the gate spoke"), "stderr: {err}");
}

/// **THE ADVISORY MARKER IS WHAT THE PAIR ACTUALLY NEEDS, and without it the port
/// promotes an exit code the predecessor deliberately ignored.**
///
/// `land.sh` ran the drop as `… || true` and only the check as an `if !`. A
/// marked gate is still ASKED — that is the whole point of keeping the call — and
/// its verdict does not stop the lap.
///
/// The mirror is the case above: an unmarked gate with the same exit code stops
/// the landing, so this cannot be satisfied by a runner that ignores every code.
#[test]
fn an_advisory_gate_is_asked_and_its_refusal_does_not_stop_the_landing() {
    let dir = fixture("land-entry-advisory");
    let refuses = gate(&dir, "refuses.sh", 1);
    let (code, _, _) = lap(&dir, &format!("?{refuses}"));

    assert!(
        asked(&dir).trim() == PR,
        "an advisory gate is still asked; it recorded: {:?}",
        asked(&dir)
    );
    assert_ne!(
        code, 2,
        "an advisory gate's refusal must not become the landing's verdict"
    );
}

/// **A DECLARED GATE THAT CANNOT RUN IS A REFUSAL, NOT A PASS.**
///
/// The dead-gate class this engine exists to refuse: naming no entry gates is a
/// legitimate configuration, and naming one that will not run is a precondition
/// left unasked. `3` rather than `2` — nothing was decided about the repository.
#[test]
fn a_declared_entry_gate_that_will_not_run_is_refused() {
    let dir = fixture("land-entry-unrunnable");
    let (code, _, err) = lap(&dir, &dir.join("no-such-gate").display().to_string());

    assert_eq!(code, 3, "an unasked precondition is a could-not-look");
    assert!(err.contains("will not run"), "stderr: {err}");
}

/// **DECLARED GATES OVER A PULL REQUEST NOBODY CAN NAME ARE REFUSED, and this is
/// the one read in the family that does NOT fail open.**
///
/// Everywhere else could-not-look carries on, because spending nothing is the
/// safe direction for a question about CI. Here carrying on is exactly the dead
/// gate: the precondition was declared and never asked.
#[test]
fn entry_gates_over_an_unresolvable_pull_request_are_refused() {
    let dir = fixture("land-entry-no-pr");
    // An empty list: the lookup succeeds and names nothing, which is the shape a
    // branch with no open pull request produces.
    std::fs::write(
        dir.join("resp.last"),
        "HTTP/2 200\ncontent-type: application/json\n\n[]\n",
    )
    .expect("write the canned answer");
    let passes = gate(&dir, "passes.sh", 0);
    let (code, _, err) = lap(&dir, &passes);

    assert_eq!(code, 3);
    assert!(err.contains("cannot be asked"), "stderr: {err}");
    assert!(
        asked(&dir).is_empty(),
        "no gate should have been asked at all"
    );
}

/// **THE BRANCH-KEYED RECEIPTS GO WITH THE BRANCH (CLOUD-774), and the third
/// family is the one a literal port would have missed.**
///
/// The predecessor swept two stores by name. `Suppression::PerSet` writes a third
/// under the same key shape and landed after that cleanup was written, so a copy
/// of the two literals would leave one family accumulating forever — which is
/// what a named list in the engine exists to stop.
///
/// The remote half is not driven here: `retire_branch` reaches a remote, and this
/// case is about the sweep. It is stated rather than left implied — a reader
/// should not take this file as evidence that the delete or the tracking-ref
/// prune is covered.
#[test]
fn retiring_a_landed_branch_drops_every_branch_keyed_receipt() {
    let dir = common::scratch("land-retire-receipts");
    common::init_repo(&dir);
    let store = dir.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&store).expect("create the receipt store");

    // A branch whose name carries the separator the store flattens, because a
    // sweep spelling the slug differently would delete nothing and report a clean
    // count — the silent-empty-answer shape, one layer down.
    let branch = "claude/some-work";
    let families = ["board-writes", "filed-here-nudged", "filed-set-nudged"];
    for family in families {
        std::fs::write(store.join(format!("{family}.claude-some-work")), "x\n")
            .expect("write a receipt");
    }
    // One store this sweep must NOT touch: a sha-keyed receipt dies with its sha
    // and belongs to no branch. Without it, a sweep that removed the whole
    // directory would pass.
    std::fs::write(store.join("verify.deadbeef"), "x\n").expect("write a sha-keyed receipt");

    let retired = batten::land::retire_branch(&dir, "file:///nonexistent", branch);

    assert_eq!(retired.receipts, families.len());
    for family in families {
        assert!(
            !store.join(format!("{family}.claude-some-work")).exists(),
            "{family} should have gone with the branch"
        );
    }
    assert!(
        store.join("verify.deadbeef").exists(),
        "a sha-keyed receipt belongs to no branch and must survive"
    );
}
