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
//! Most fixtures write a real directory where the engine parks a symlink.
//! `read_dir` follows a link, so the reading under test is identical, and a real
//! directory keeps the fixture from asserting a property of `symlink` on a
//! platform that spells it differently.
//!
//! **Two cases must use a real symlink, and that is not a departure from the
//! paragraph above** (CLOUD-1435). `a_pointer_at_an_unwritten_store_is_zero…`
//! and its mirror turn on the pointer DANGLING, a condition a real directory
//! cannot express and `read_dir` cannot distinguish — an absent directory and an
//! absent link fail it identically, which is how `0` stayed unreachable for
//! every session on this host. Those two are `#[cfg(unix)]` for exactly the
//! reason the paragraph gives: the boundary's own write is too, so on a platform
//! that spells linking differently there is no pointer to have this property.

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

/// A store the host has not written yet reads as ZERO, not as a failure to look.
///
/// # The defect, and why the case above does not cover it
///
/// `an_absent_store_is_could_not_look_and_never_clean` is about no POINTER: the
/// engine was never told where to look, so it cannot answer. This is about a
/// pointer at nothing, which is a different fact and had the same answer.
///
/// Every host that keeps a per-session task store creates it LAZILY, on the first
/// task write. So a session that declares no work has a parked link and no
/// directory behind it — and that made `0` unreachable. Measured 2026-09-04 on
/// one container: with a task file already on disk the verb still answered `3`,
/// and one real `Stop` envelope driven through the hook was what finally made it
/// answer at all. A verb that abstains on the common case is a dead gate; its
/// answer stops carrying information and nothing reports that it has.
///
/// # Fails by
///
/// Restoring `refresh_tasks_link`'s `is_dir` early return, or dropping
/// `store_is_merely_unwritten`'s parent test — either sends this back to `3`.
///
/// A REAL SYMLINK rather than the real directory the other cases use, because the
/// pointer's danglingness IS the condition. `read_dir` cannot tell the two apart,
/// which is exactly why the reader follows the link instead.
#[cfg(unix)]
#[test]
fn a_pointer_at_an_unwritten_store_is_zero_and_never_could_not_look() {
    let dir = scratch("unwritten-store", DECLARED);
    // The parent exists — the declaration describes this machine — and only the
    // per-session leaf is missing, which is what "no tasks written yet" looks
    // like on every host that creates the store on demand.
    let root = dir.join("store-root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::os::unix::fs::symlink(root.join("s-1"), dir.join(".claude/.tasks")).unwrap();

    let output = session(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "got: {}", stdout(&output));
    assert!(
        stdout(&output).contains("0 of 0 declared task(s) open"),
        "got: {}",
        stdout(&output)
    );
}

/// And a pointer whose PARENT is absent too stays could-not-look.
///
/// THE DISCRIMINATING MIRROR of the case above, and the reason that one cannot be
/// satisfied by reading every absence as zero. A parent that is not there means
/// the declaration may not describe this machine at all — a template naming a
/// path this host has never had must never read as "no work left", which is the
/// false clean CLOUD-1376 exists to refuse.
///
/// This is also the bound the fix does not close: on a machine where the store
/// root has itself never existed, a genuinely empty session still reads `3`. That
/// is narrower than refusing every session and it fails in the safe direction.
///
/// Fails by: dropping the `parent().is_some_and(Path::is_dir)` conjunct, which
/// turns every dangling pointer into a clean answer.
#[cfg(unix)]
#[test]
fn a_pointer_whose_parent_is_absent_too_stays_could_not_look() {
    let dir = scratch("no-store-root", DECLARED);
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::os::unix::fs::symlink(dir.join("never-existed/s-1"), dir.join(".claude/.tasks")).unwrap();

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
