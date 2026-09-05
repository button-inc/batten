//! `mise run <task>` is refused at the boundary when a live process in this
//! clone already holds that task's singleton lock (CLOUD-438).
//!
//! # What this buys over the in-task lock, and what it does not replace
//!
//! The in-task lock (`batten task singleton`) is and stays the load-bearing
//! enforcement: a hook can be unwired, unloaded or bypassed, so this may never be
//! the only thing between a clone and a second landing loop. What the gate buys
//! is CLOUD-428 §3's *earliest computable moment* — the refusal arrives before a
//! process starts rather than ~200ms and one spawn later, and it arrives as a
//! denied tool call rather than buried in a task's output.
//!
//! # The lock is written directly, and that is deliberate
//!
//! A case that ran `batten task singleton` to take the lock would be testing the
//! acquiring path, which has its own suite. What this file needs is the four
//! STATES that path can leave behind, and writing them is the only way to get a
//! dead pid, an empty pid file and a live holder side by side without racing a
//! real process — the timer-standing-in-for-a-condition shape CLOUD-1177 refuses.
//!
//! `1` is the live holder throughout: pid 1 exists on every unix that can run
//! this suite, so the case needs no child to keep alive and no cleanup that could
//! leave one behind.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// The class the gate refuses under — the engine's own token.
const CLASS: &str = "task run twice";

/// A repository whose policy is adjudicable at all.
///
/// The `protected` set and the `[[verb]]` row are load-bearing and match nothing
/// here, for `Policy::is_empty`'s reason — the same trap `history_drop.rs` and
/// `mediated_admission.rs` both record at their own fixtures.
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
        .base_commit()
        .build()
}

/// Put the singleton lock for `task` into a named state.
///
/// `holder: None` writes the lock directory with no pid file — a holder caught
/// between its create and its write, which the acquiring path already reads as
/// held rather than as a corpse.
fn hold(dir: &Path, task: &str, holder: Option<&str>) {
    let lock = dir.join(".git/batten-singleton").join(task);
    std::fs::create_dir_all(&lock).expect("create the lock directory");
    if let Some(pid) = holder {
        std::fs::write(lock.join("pid"), format!("{pid}\n")).expect("write the holder");
    }
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

/// A live holder denies, and the refusal names both the task and the holder.
#[test]
fn a_live_holder_denies_the_second_start() {
    let dir = fixture("singleton-gate-live");
    hold(&dir, "land", Some("1"));
    let (code, cause) = adjudicate(&dir, "mise run land");
    assert_eq!(code, Some(2), "a live holder must refuse\n{cause}");
    assert!(cause.contains(CLASS), "under its own class\n{cause}");
    assert!(cause.contains("land"), "naming the task\n{cause}");
}

/// A DEAD holder allows, and this is the case that keeps the gate from becoming
/// a wall: a lock left behind by a crashed process must not make the task
/// permanently unstartable. The acquiring path reclaims it; this must not
/// pre-empt that with a refusal.
#[test]
fn a_dead_holder_allows() {
    let dir = fixture("singleton-gate-dead");
    // A pid that cannot be running: max_pid+1 on any Linux this suite runs on,
    // and `pid_exists` answers false for it rather than erroring.
    hold(&dir, "land", Some("4194305"));
    let (code, cause) = adjudicate(&dir, "mise run land");
    assert_eq!(
        code,
        Some(0),
        "a corpse holds nothing; the acquiring path reclaims it\n{cause}"
    );
}

/// AN EMPTY PID FILE DENIES. Absence of evidence is "held", never "free" — a
/// holder caught between its `create` and its `write` is a holder, and this is
/// the direction `singleton_acquire` already takes.
#[test]
fn a_lock_that_says_nothing_readable_denies() {
    let dir = fixture("singleton-gate-empty");
    hold(&dir, "land", None);
    let (code, cause) = adjudicate(&dir, "mise run land");
    assert_eq!(
        code,
        Some(2),
        "an unreadable lock is held, not free\n{cause}"
    );
    assert!(cause.contains(CLASS), "under its own class\n{cause}");
}

/// THE ANTI-VACUITY HALF. Without it, "refuse every `mise run`" passes the case
/// above — and the gate would stop a session doing anything at all.
#[test]
fn another_task_is_none_of_this_gates_business() {
    let dir = fixture("singleton-gate-other");
    hold(&dir, "land", Some("1"));
    for command in ["mise run verify", "mise run test", "mise x -- cargo build"] {
        let (code, cause) = adjudicate(&dir, command);
        assert_eq!(
            code,
            Some(0),
            "a task nothing holds must run: {command}\n{cause}"
        );
    }
}

/// No lock at all is the ordinary state, and it allows.
#[test]
fn an_unheld_task_starts() {
    let dir = fixture("singleton-gate-free");
    let (code, cause) = adjudicate(&dir, "mise run land");
    assert_eq!(code, Some(0), "nothing holds it\n{cause}");
}

/// A MENTION IS NOT AN INVOCATION (CLOUD-269), and shell grammar does not hide
/// the invocation either (CLOUD-1382). The gate reads `programs`, so both hold
/// for the same reason every other program anchor does.
#[test]
fn the_gate_reads_the_program_rather_than_the_line() {
    let dir = fixture("singleton-gate-anchor");
    hold(&dir, "land", Some("1"));
    for denied in [
        "cd /tmp && mise run land",
        "(mise run land)",
        "time mise run land",
    ] {
        let (code, cause) = adjudicate(&dir, denied);
        assert_eq!(code, Some(2), "must refuse: {denied}\n{cause}");
    }
    for allowed in ["echo mise run land", "echo \"mise run land\""] {
        let (code, cause) = adjudicate(&dir, allowed);
        assert_eq!(
            code,
            Some(0),
            "a mention is not an invocation: {allowed}\n{cause}"
        );
    }
}

/// A VALUE-TAKING OPTION DOES NOT MOVE THE TASK NAME, and this is the same miss
/// the git scan in `destructive_reset_target` declares its own option set for.
///
/// `mise run` takes options of its own before the task, and some consume the next
/// word. Reading the first non-flag word as the task therefore names the OPTION'S
/// VALUE — `mise run -E dev land` resolves to `dev` — and the gate then looks up
/// a lock nothing holds and allows the second `land`.
///
/// SHOWN ABLE TO FAIL: measured against the version this file first shipped with,
/// every command below exited `0` while the bare spelling exited 2.
#[test]
fn an_option_value_is_not_mistaken_for_the_task() {
    let dir = fixture("singleton-gate-options");
    hold(&dir, "land", Some("1"));
    for denied in [
        "mise run -E dev land",
        "mise run --env dev land",
        "mise run -j 4 land",
        "mise run -C /home/user/batten land",
    ] {
        let (code, cause) = adjudicate(&dir, denied);
        assert_eq!(code, Some(2), "must refuse: {denied}\n{cause}");
        assert!(cause.contains(CLASS), "under its own class\n{cause}");
    }
    // THE ANTI-VACUITY HALF: skipping mise's own options must not make every
    // `mise run` the held task. An option in front of another task is that task.
    for allowed in ["mise run -E dev verify", "mise run -j 4 test"] {
        let (code, cause) = adjudicate(&dir, allowed);
        assert_eq!(
            code,
            Some(0),
            "a task nothing holds must run: {allowed}\n{cause}"
        );
    }
}

/// The refusal is a pointer (rule 4): a task name and a holder, and the reader
/// that answers what the holder is doing. Never the holder's command line.
#[test]
fn the_refusal_points_at_the_reader_rather_than_the_lock() {
    let dir = fixture("singleton-gate-pointer");
    hold(&dir, "land", Some("1"));
    let (_, cause) = adjudicate(&dir, "mise run land");
    assert!(
        cause.contains("batten task alive"),
        "the remedy is the reader that answers without disturbing the holder\n{cause}"
    );
    assert!(
        !cause.contains("batten-singleton"),
        "the lock's path is not the caller's business\n{cause}"
    );
}
