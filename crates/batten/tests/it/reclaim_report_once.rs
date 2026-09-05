//! The reclaim verdict is reported once per BOOT, not once per session
//! (CLOUD-1301).
//!
//! # The defect
//!
//! `reclaim-census report` classifies the PREVIOUS boot, resolved as the newest
//! recorded boot that is not this one. That is immutable history: recording this
//! boot does not move it, and no landing completed here changes what the last
//! container was doing when it died. So on a container whose predecessor was
//! reclaimed mid-landing the verdict is TRUE and repeats at every session start
//! for the life of the container — and after the first read it is exactly the
//! noise CLOUD-891 removed. The session-start comment already made that argument
//! for the negative readings and did not apply it to the positive one.
//!
//! # Why the tier is here rather than in a `.bats`
//!
//! The case that WOULD have caught this died with its suite: `main` retired
//! `.claude/hooks/session-start.sh` into declared handler rows and took
//! `tests/session-start.bats` with it. A replacement `.bats` is refused by
//! `V-SHELL-RULE-ADDED`, and `tests/reclaim-census.bats` is governed at head so
//! it cannot be edited either. The fix therefore owes its own tier, and this is
//! it.
//!
//! # Why it drives the task body rather than a fabricated decision
//!
//! The suppression lives in `[tasks."session:census"]`'s body, because
//! `mise-tasks/reclaim-census.sh` is governed by `shell-retirement` and is not
//! this row's to edit. A test that re-implemented the decision in Rust would be
//! the `with input as` shape `.claude/rules/policy-modules.md` names one layer
//! down: it would pass over a body that never runs, reads the wrong store, or
//! writes the mark before the report instead of after.
//!
//! # The isolation, and why the census already affords it
//!
//! Both stores hang off the git directory and `git rev-parse` honours `GIT_DIR`,
//! and the boot time is `BATTEN_BOOT_TIME`-injectable — the census's own header
//! says why: "a suite that cannot vary the boot time cannot exercise a single
//! row of the table below". So a fixture git dir plus an injected boot drives
//! every verdict without touching the container's real record, which matters
//! more than usual here: this container's own store carries a live reclaim, and
//! a suite that read it would suppress the very verdict a human still needs.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
//
// UNIX-ONLY, for `session_provisioning.rs`'s reason one step over: the subject is
// a `mise` task body that runs under `sh`, and the fixture drives it through the
// task runner rather than through the engine.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The boot this fixture claims to be running under. Any value works; it only
/// has to differ from the recorded predecessor.
const NOW: &str = "9000";

/// The predecessor boot the seeded records belong to.
const BEFORE: &str = "500";

/// A git directory carrying nothing but the two census stores.
fn store(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-reclaim-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the fixture root");
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the fixture store must be a real git directory, because the census resolves it with `git rev-parse` and a hand-built `.git` would test a path the program never takes (CLOUD-1301)"
    )]
    let out = std::process::Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(&dir)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init: {out:?}");
    dir.join(".git")
}

/// Seed the two stores the census reads: the boots it has seen, and the beats
/// recorded under them.
///
/// `last` is the record that decides the verdict — `h` is a heartbeat, so the
/// predecessor was mid-landing when it went; `x` is an exit mark, so it stopped
/// on purpose.
fn seed(git_dir: &Path, last: &str) {
    std::fs::write(git_dir.join("batten-boots"), format!("{BEFORE}\n")).expect("seed the boots");
    std::fs::write(
        git_dir.join("batten-reclaim-log"),
        format!("h 1000 {BEFORE}\n{last} 2000 {BEFORE}\n"),
    )
    .expect("seed the log");
}

/// One session start, as the handler row invokes it.
fn session_start(git_dir: &Path) -> String {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the subject IS a task body, so the task runner is what has to invoke it — a spawn of the engine instead would assert over a decision this row deliberately does not put in the engine (CLOUD-1301)"
    )]
    let out = std::process::Command::new("mise")
        .args(["run", "session:census"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("GIT_DIR", git_dir)
        .env("BATTEN_BOOT_TIME", NOW)
        // THE SUBJECT IS A TASK BODY, SO NOTHING HERE NEEDS INSTALLING, and
        // saying so is what keeps this case from hanging on a network it does
        // not use. `session:census` runs shell; the runner resolves the whole
        // toolset first regardless, and behind an egress proxy that resolution
        // retries against a host answering 403 and never returns.
        //
        // Measured: without this the three cases in this file run FOREVER --
        // `timeout 180` returns 124 on a tree that contains none of the change
        // that was suspected -- and with it they pass in 10s. A test that hangs
        // indefinitely on an unrelated network condition reports nothing at all,
        // which is worse than failing: a suite nobody can finish is a suite
        // nobody runs.
        .env("MISE_AUTO_INSTALL", "0")
        .output()
        .expect("run the session-start census handler");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Does this session's output carry the reclaim verdict?
fn reported(output: &str) -> bool {
    output.contains("A LANDING WAS IN FLIGHT")
}

#[test]
fn a_reclaim_is_reported_once_and_the_repeat_is_silent() {
    let git_dir = store("reported-once");
    seed(&git_dir, "h");

    assert!(
        reported(&session_start(&git_dir)),
        "the first session on a container whose predecessor was reclaimed \
         mid-landing must still be told"
    );
    assert!(
        !reported(&session_start(&git_dir)),
        "the fact is once per boot, so every session after the first is noise"
    );
}

#[test]
fn a_predecessor_that_stopped_on_purpose_is_silent_throughout() {
    // The negative reading, unchanged by this row and asserted so it stays that
    // way: an ordinary stop is not news, and a fix that started announcing one
    // would be louder than the defect it replaced.
    let git_dir = store("intentional-stop");
    seed(&git_dir, "x");

    assert!(!reported(&session_start(&git_dir)), "first session");
    assert!(!reported(&session_start(&git_dir)), "second session");
}

#[test]
fn a_new_boot_is_reported_though_an_older_one_was_already_marked() {
    // THE VACUITY CASE. Suppression keyed to anything but the boot — a flag, a
    // once-per-clone marker — would silence the NEXT container's genuine reclaim
    // too, which deletes the instrument CLOUD-451 built rather than quietening
    // it. A mark left by another boot must not suppress this one's verdict.
    let git_dir = store("new-boot");
    seed(&git_dir, "h");
    std::fs::write(git_dir.join("batten-reclaim-log.reported"), "1\n")
        .expect("plant a mark from an older boot");

    assert!(
        reported(&session_start(&git_dir)),
        "a mark from a different boot says nothing about this one"
    );
    assert!(
        !reported(&session_start(&git_dir)),
        "and this boot's own mark then suppresses the repeat"
    );
}
