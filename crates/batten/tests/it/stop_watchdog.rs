//! The Stop watchdog over the compiled binary (CLOUD-2370).
//!
//! A declared task whose registrant is gone forces one relaunch at `Stop`,
//! unless it crashed too fast; `stop.rs`'s own unit cases pin the predicate over
//! values, and these pin that the hook builds those values — the registry, the
//! boot second, the `[task]` table — and holds the bound across Stops.
//!
//! The crashed record is seeded under a pid the kernel never assigns, so it is a
//! genuine corpse rather than a race; off unix nothing reads as dead, so every
//! case whose subject is a crash says so (`task_registry.rs` states why).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, batten, scratch, stderr, stdout, unassignable_pid};

/// This container's boot second, as the fixture pins it.
const BOOT: u64 = 1_000_000;

const TABLE: &str = "\n[task]\nprogram_root = \"programs\"\nrelaunch = [\"land\"]\n";

/// A repository on its landing target, so no other Stop rung refuses, with
/// `config` as its committed authority. Returns `(repo, state home)`.
fn repo(name: &str, config: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(config)
        .git()
        .base_commit()
        .build();
    (repo, root.join("home"))
}

/// Seed one crashed record for `task`, registered at `started` and last stamped
/// at `last`, under a pid the kernel never assigns.
fn crash(repo: &Path, task: &str, started: u64, last: u64) {
    crash_as(repo, task, &unassignable_pid(), started, last);
}

/// [`crash`] under a named pid, for a case that needs two corpses.
fn crash_as(repo: &Path, task: &str, pid: &str, started: u64, last: u64) {
    let dir = repo.join(".git/batten-tasks");
    std::fs::create_dir_all(&dir).expect("a registry");
    std::fs::write(
        dir.join(pid),
        format!(
            "task: {task}\npid: {pid}\npgid: {pid}\nphase: verify\n\
             started_at: {started}\nphase_since: {last}\n\
             tick: \ntick_at: \nsig: \nsig_at: \n"
        ),
    )
    .expect("a record");
}

/// One Claude `Stop` through `batten adjudicate`, at the pinned boot.
fn stop(repo: &Path, home: &Path, active: bool) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "stop_hook_active": active,
        "last_assistant_message": "Done.",
    });
    hook(repo, home, &payload)
}

/// The call that starts a backgrounded `land`, as Claude Code reports it after
/// the fact: what writes the `land-dispatched` receipt.
fn dispatch_land(repo: &Path, home: &Path) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "s-1",
        "tool_name": "Bash",
        "tool_input": {"command": "mise run land", "run_in_background": true},
        "tool_response": {"backgroundTaskId": "b-1"},
    });
    let _ = hook(repo, home, &payload);
}

/// Where the `land-dispatched` receipt of `repo`'s current branch lives, by the
/// engine's own record path.
fn dispatch_receipt(repo: &Path) -> PathBuf {
    let branch = common::git_in(repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
    batten::recorder::record_path(&repo.join(".git"), "land-dispatched", branch.trim(), None)
}

/// One Claude hook payload through `batten adjudicate`, at the pinned boot.
fn hook(repo: &Path, home: &Path, payload: &serde_json::Value) -> Output {
    let mut command = batten();
    common::state_home(&mut command, home);
    command
        .current_dir(repo)
        .args(["adjudicate", "--harness", "claude-code"])
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env("BATTEN_BOOT_TIME", BOOT.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten adjudicate");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten adjudicate")
}

/// Now, as the epoch second a receipt written now carries.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

#[test]
fn a_crash_is_refused_once() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-once", &format!("version = 1\n{TABLE}"));
    crash(&repo, "land", BOOT + 10, BOOT + 7010);
    let first = stop(&repo, &home, false);
    assert_eq!(first.status.code(), Some(2), "{}", stderr(&first));
    assert!(
        stderr(&first).contains("task land crashed")
            && stderr(&first).contains("relaunch task land"),
        "naming the crash and the one relaunch: {}",
        stderr(&first)
    );
    let second = stop(&repo, &home, false);
    assert_eq!(
        second.status.code(),
        Some(0),
        "one refusal per crashed record, whatever stop_hook_active says: {}",
        stderr(&second)
    );
}

#[test]
fn a_crash_under_the_floor_is_advice() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-fast", &format!("version = 1\n{TABLE}"));
    crash(&repo, "land", BOOT + 10, BOOT + 130);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("lived 120s"),
        "the advice names the lifetime against the floor: {}",
        stdout(&output)
    );
}

#[test]
fn a_crash_before_this_boot_relaunches() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-reboot", &format!("version = 1\n{TABLE}"));
    crash(&repo, "land", BOOT - 100, BOOT - 40);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn a_continued_stop_is_never_refused() {
    let (repo, home) = repo("watchdog-continued", &format!("version = 1\n{TABLE}"));
    crash(&repo, "land", BOOT + 10, BOOT + 7010);
    let output = stop(&repo, &home, true);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn an_undeclared_crash_is_quiet() {
    let (repo, home) = repo("watchdog-undeclared", &format!("version = 1\n{TABLE}"));
    crash(&repo, "snapshots", BOOT + 10, BOOT + 7010);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stdout(&output).contains("crashed"), "{}", stdout(&output));
}

#[test]
fn without_a_task_table_the_watchdog_is_off() {
    let (repo, home) = repo("watchdog-off", "version = 1\n");
    crash(&repo, "land", BOOT + 10, BOOT + 7010);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stdout(&output).contains("crashed"), "{}", stdout(&output));
}

#[test]
fn a_live_land_lets_the_stop_pass() {
    let (repo, home) = repo("watchdog-landing", &format!("version = 1\n{TABLE}"));
    crash(&repo, "land", BOOT + 10, BOOT + 7010);
    let git_dir = repo.join(".git");
    let pid = std::process::id().to_string();
    let claim = batten::task::singleton_acquire(&git_dir, "land", &pid, std::time::Duration::ZERO);
    assert_eq!(
        claim,
        batten::task::Claim::Taken,
        "the fixture holds the lock"
    );
    let output = stop(&repo, &home, false);
    batten::task::singleton_release(&git_dir, "land");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a relaunched land holding the lock is the remedy running: {}",
        stderr(&output)
    );
}

/// A LAND STARTED SINCE THE CRASH IS THE REMEDY RUNNING: its dispatch receipt
/// postdates the crashed record, so the Stop passes.
#[test]
fn a_land_dispatched_after_the_crash_lets_the_stop_pass() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-dispatched", &format!("version = 1\n{TABLE}"));
    crash(&repo, "land", BOOT + 10, BOOT + 7010);
    dispatch_land(&repo, &home);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

/// A DISPATCH OLDER THAN THE CRASH IS THAT LAND'S OWN START, left behind when
/// no Stop saw it take the lock: a background deadline stop while the session
/// idled. It excuses nothing.
#[test]
fn a_land_dispatch_older_than_the_crash_excuses_nothing() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-stale-dispatch", &format!("version = 1\n{TABLE}"));
    dispatch_land(&repo, &home);
    let started = now() + 100;
    crash(&repo, "land", started, started + 7000);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// A DISPATCH IN THE CRASH'S OWN SECOND IS THAT LAND'S START: the receipt is
/// written as the call returns and the land registers within the second, so only
/// a STRICTLY later dispatch is a relaunch.
#[test]
fn a_land_dispatched_in_the_crash_second_excuses_nothing() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-same-second", &format!("version = 1\n{TABLE}"));
    dispatch_land(&repo, &home);
    let started = std::fs::metadata(dispatch_receipt(&repo))
        .and_then(|meta| meta.modified())
        .expect("the dispatch wrote its receipt")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    crash(&repo, "land", started, started + 7000);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// A LATER CRASH OF A TASK ALREADY SPOKEN FOR SPEAKS AGAIN: the receipt bounds
/// each record, never the task, so a relaunch that crashed is a new refusal.
#[test]
fn a_later_crash_of_a_spoken_task_speaks_again() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-again", &format!("version = 1\n{TABLE}"));
    let first: u64 = unassignable_pid().parse().expect("a number");
    crash_as(&repo, "land", &first.to_string(), BOOT + 10, BOOT + 7010);
    let spoken = stop(&repo, &home, false);
    assert_eq!(spoken.status.code(), Some(2), "{}", stderr(&spoken));
    crash_as(
        &repo,
        "land",
        &(first + 1).to_string(),
        BOOT + 8000,
        BOOT + 15000,
    );
    let again = stop(&repo, &home, false);
    assert_eq!(again.status.code(), Some(2), "{}", stderr(&again));
    assert!(
        stderr(&again).contains(&format!("--pid {}", first + 1)),
        "naming the new crash: {}",
        stderr(&again)
    );
}

/// TAKING THE LANDING LOCK CLEARS THE DISPATCH RECEIPT. The receipt means
/// "started, not yet locked"; left behind once this land holds the lock, it would
/// read here as a relaunch under way over this land's own later crash. A lap over
/// an origin nothing answers takes the lock before its first fetch fails, which
/// is all this needs.
#[test]
fn taking_the_landing_lock_clears_the_dispatch_receipt() {
    let (repo, home) = repo("watchdog-lock-clears-dispatch", "version = 1\n");
    common::git_in(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "http://127.0.0.1:9/unreachable.git",
        ],
    );
    let receipt = dispatch_receipt(&repo);
    std::fs::create_dir_all(receipt.parent().expect("a parent")).expect("a receipt dir");
    std::fs::write(&receipt, "land\n").expect("a receipt");
    // No entry gates: the developer's `mise.toml` exports some, and asking them
    // needs a forge this tier does not have, before the lock is ever reached.
    let mut command = batten();
    common::state_home(&mut command, &home);
    let output = command
        .args(["land", "lap", "refs/heads/main"])
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env("LAND_MAX_LAPS", "1")
        .env("LAND_VERIFY", "true")
        .env("LAND_WORKFLOW", "fast-forward.yml")
        .env_remove("LAND_ENTRY_GATES")
        .env_remove("LAND_BODY_GATES")
        .current_dir(&repo)
        .output()
        .expect("run batten land lap");
    assert!(
        !receipt.exists(),
        "the land that took the lock consumed its dispatch: {} {}",
        stdout(&output),
        stderr(&output)
    );
}

/// THE NEWEST CRASH SPEAKS, ONCE, FOR ITS TASK: a relaunch that crashed again
/// is one refusal naming the latest pid, and the superseded record goes quiet
/// with it.
#[test]
fn the_newest_crash_of_a_task_speaks_for_the_older_ones() {
    if !cfg!(unix) {
        return;
    }
    let (repo, home) = repo("watchdog-newest", &format!("version = 1\n{TABLE}"));
    let older: u64 = unassignable_pid().parse().expect("a number");
    let newer = older + 1;
    crash_as(&repo, "land", &older.to_string(), BOOT + 10, BOOT + 7010);
    crash_as(&repo, "land", &newer.to_string(), BOOT + 8000, BOOT + 15000);
    let first = stop(&repo, &home, false);
    assert_eq!(first.status.code(), Some(2), "{}", stderr(&first));
    assert!(
        stderr(&first).contains(&format!("--pid {newer}")),
        "naming the latest crash: {}",
        stderr(&first)
    );
    let second = stop(&repo, &home, false);
    assert_eq!(
        second.status.code(),
        Some(0),
        "the superseded record was spoken for: {}",
        stderr(&second)
    );
}
