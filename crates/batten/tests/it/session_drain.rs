//! `batten doctor session` over the compiled binary (CLOUD-1376).
//!
//! # The defect this tier exists to keep closed
//!
//! Measured 2026-09-02: asked *"Done? Safe to archive?"*, the agent enumerated
//! the working tree, the stash, local branches and running processes, found all
//! four clean, and answered "yes — safe". The session's own task store held
//! `{"id": "21", "status": "pending"}` on disk at that moment. Every other
//! completion question resolves to a command — `verify` decides the tree, `land`
//! the PR, `done-check` the release — and nothing decided the SESSION, so the one
//! claim with no command behind it was the one that was wrong.
//!
//! # Why the could-not-look arms are half this file
//!
//! The failure being fixed is **an absent reading reported as a clean one**, so
//! the arms that assert `3` are not defensive extras — they are the row. A
//! version of this verb that answered `0` for an unreadable store would reproduce
//! the original defect exactly, with a command in front of it lending it
//! authority. `an_absent_store_is_could_not_look_and_never_clean` and
//! `an_undeclared_template_is_could_not_look_too` are the two ways to reach that
//! arm, kept apart because they have different remedies: mount the store, or
//! declare the template.
//!
//! # The mirror is what stops the vacuous pass
//!
//! `a_store_whose_tasks_are_all_completed_is_clean` is the anti-vacuity case
//! (CLOUD-418). Without it, every assertion here is satisfied by a verb that
//! refuses unconditionally, which is a gate that decides nothing while reading
//! green.
//!
//! The fixture writes a real directory where the engine parks a symlink.
//! `read_dir` follows a link, so the reading under test is identical, and a real
//! directory keeps the fixture from asserting a property of `symlink` on a
//! platform that spells it differently.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, stdout};

/// A repository declaring a transcript path and a task-store template.
///
/// The template is never resolved by these cases — `doctor session` reads the
/// link the hook parks, and the substitution is exercised where it lives. What
/// the key's PRESENCE decides here is could-not-look versus a real reading,
/// which is the distinction `an_undeclared_template_is_could_not_look_too` pins.
const DECLARED: &str = "version = 1\n\n[transcript]\npath = \".claude/.transcript.jsonl\"\ntasks = \"/nonexistent/{session}\"\n";

/// The same repository with the store undeclared.
const UNDECLARED: &str = "version = 1\n\n[transcript]\npath = \".claude/.transcript.jsonl\"\n";

fn scratch(name: &str, config: &str) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-session-e2e", name);
    common::git_in(&dir, &["init", "-q"]);
    common::write(&dir, "batten.toml", config);
    dir
}

/// Park one task file in the store the derived link names.
fn task(dir: &Path, id: &str, status: &str) {
    common::write(
        dir,
        &format!(".claude/.tasks/{id}.json"),
        &format!(
            "{{\n  \"id\": \"{id}\",\n  \"subject\": \"a declared unit of work\",\n  \"status\": \"{status}\"\n}}\n"
        ),
    );
}

fn session(dir: &Path, extra: &[&str]) -> Output {
    let mut command = batten();
    command.args(["doctor", "session"]);
    command.args(extra);
    command
        .current_dir(dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten doctor session")
}

#[test]
fn a_store_with_an_open_task_is_refused_and_names_its_id() {
    let dir = scratch("open-task", DECLARED);
    task(&dir, "21", "pending");
    task(&dir, "20", "completed");

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(1), "got: {}", stdout(&output));
    assert!(
        stdout(&output).contains("1 of 2 declared task(s) open"),
        "got: {}",
        stdout(&output)
    );
    // The POINTER, never the payload (rule 4): an id sends a reader to the task,
    // and the subject would hand the session its own prose back.
    assert!(stdout(&output).contains("21"), "got: {}", stdout(&output));
    assert!(
        !stdout(&output).contains("a declared unit of work"),
        "the subject line must not reach the channel: {}",
        stdout(&output)
    );
}

#[test]
fn a_store_whose_tasks_are_all_completed_is_clean() {
    // THE ANTI-VACUITY MIRROR. Every other case here asserts a refusal, and a
    // verb that refused unconditionally would satisfy all of them.
    let dir = scratch("all-done", DECLARED);
    task(&dir, "1", "completed");
    task(&dir, "2", "completed");

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "got: {}", stdout(&output));
    assert!(
        stdout(&output).contains("0 of 2 declared task(s) open"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn an_absent_store_is_could_not_look_and_never_clean() {
    // The whole row in one case: a store that is not there has told us NOTHING
    // about whether work remains, and `0` here would be the original defect with
    // a command in front of it.
    let dir = scratch("absent-store", DECLARED);

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(3), "got: {}", stdout(&output));
    assert!(
        stdout(&output).contains("could-not-look"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn an_undeclared_template_is_could_not_look_too() {
    // A DIFFERENT ROUTE TO THE SAME ARM, and kept separate because the remedies
    // differ: this one is "declare the store", the case above is "mount it". A
    // consumer that never declared a task store has not told us it has no work.
    let dir = scratch("undeclared", UNDECLARED);
    task(&dir, "7", "pending");

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(3), "got: {}", stdout(&output));
}

#[test]
fn one_malformed_member_poisons_the_whole_reading() {
    // A PARTIAL COUNT IS A NUMBER THAT LOOKS MEASURED AND IS NOT. Skipping the
    // unreadable member would report "1 of 1 open" over a store holding two, and
    // under-reporting is this verb's only failure mode that matters.
    let dir = scratch("malformed", DECLARED);
    task(&dir, "1", "pending");
    common::write(&dir, ".claude/.tasks/2.json", "{ this is not json\n");

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(3), "got: {}", stdout(&output));
}

#[test]
fn the_json_channel_carries_the_ids_and_no_subject() {
    let dir = scratch("json-shape", DECLARED);
    task(&dir, "3", "pending");
    task(&dir, "1", "in_progress");

    let output = session(&dir, &["-J"]);
    assert_eq!(output.status.code(), Some(1), "got: {}", stdout(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("parse -J");
    assert_eq!(report["open"], 2);
    assert_eq!(report["total"], 2);
    assert_eq!(report["ok"], false);
    // Sorted NUMERICALLY, not by directory order: §6 wants byte-stable output,
    // and the filesystem does not promise an order at all.
    assert_eq!(report["ids"][0], "1");
    assert_eq!(report["ids"][1], "3");
    assert!(
        !stdout(&output).contains("a declared unit of work"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn in_progress_counts_as_open() {
    // `completed` is the ONLY finished state, and the predicate says so by
    // naming it rather than by enumerating the unfinished ones — a status the
    // harness adds later must count as open, not slip through a list nobody
    // updated.
    let dir = scratch("in-progress", DECLARED);
    task(&dir, "4", "in_progress");

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(1), "got: {}", stdout(&output));
}
