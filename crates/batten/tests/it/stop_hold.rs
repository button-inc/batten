//! `[[stop.hold]]` over the compiled engine (CLOUD-2761).
//!
//! A row says: while a receipt of this name exists, this singleton lock must
//! have a live holder at the end of a turn. These cases drive Stop envelopes
//! through `batten adjudicate` as `stop_watchdog.rs` does, over a repository on
//! its landing target so no other rung refuses. The case that needs an unlanded
//! branch beside a hold lives in `stop_posture.rs`, beside its fixture.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, batten, scratch, stderr, stdout, unassignable_pid};

const HOLD: &str = "version = 1\n\n[[stop.hold]]\nid = \"children\"\nwhile_receipt = \"child\"\nunless_singleton = \"fleet-wait\"\nstart = [\"mise\", \"run\", \"fleet-wait\"]\n";

fn repo(name: &str, config: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(config)
        .git()
        .base_commit()
        .build();
    (repo, root.join("home"))
}

fn receipt(repo: &Path, suffix: &str) {
    let dir = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&dir).expect("a receipt store");
    std::fs::write(dir.join(format!("child.{suffix}")), "").expect("a receipt");
}

/// The `fleet-wait` lock, holding `pid`.
fn lock(repo: &Path, pid: &str) {
    let dir = repo.join(".git/batten-singleton/fleet-wait");
    std::fs::create_dir_all(&dir).expect("a lock");
    std::fs::write(dir.join("pid"), pid).expect("the holder");
}

fn unlock(repo: &Path) {
    let _ = std::fs::remove_dir_all(repo.join(".git/batten-singleton/fleet-wait"));
}

fn hook_at(cwd: &Path, home: &Path, payload: &serde_json::Value, harness: &str) -> Output {
    let mut command = batten();
    common::state_home(&mut command, home);
    command
        .current_dir(cwd)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env_remove("BATTEN_STOP_GUARD_BYPASS")
        .args(["adjudicate", "--harness", harness])
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

fn stop_payload(active: bool) -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "stop_hook_active": active,
        "last_assistant_message": "Done.",
    })
}

fn stop(repo: &Path, home: &Path, active: bool) -> Output {
    hook_at(repo, home, &stop_payload(active), "claude-code")
}

fn refused_by_hold(output: &Output) -> bool {
    output.status.code() == Some(2) && stderr(output).contains("hold children")
}

#[test]
fn a_receipt_with_no_holder_refuses_the_stop() {
    let (repo, home) = repo("hold-refuses", HOLD);
    receipt(&repo, "a");
    let output = stop(&repo, &home, false);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{said}");
    assert!(said.contains("hold children"), "the id: {said}");
    assert!(said.contains("lock fleet-wait"), "the lock: {said}");
    assert!(
        said.contains("while 1 child receipt(s)"),
        "the count: {said}"
    );
    assert!(
        said.contains("mise run fleet-wait"),
        "the start argv: {said}"
    );
    assert!(said.contains("backgrounded"), "{said}");
    assert!(said.contains(" in "), "the directory to run it in: {said}");
}

#[test]
fn a_live_holder_lets_the_stop_through() {
    let (repo, home) = repo("hold-live", HOLD);
    receipt(&repo, "a");
    lock(&repo, &std::process::id().to_string());
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn a_dead_holder_is_no_holder() {
    let (repo, home) = repo("hold-dead", HOLD);
    receipt(&repo, "a");
    lock(&repo, &unassignable_pid());
    assert!(refused_by_hold(&stop(&repo, &home, false)));
}

#[test]
fn an_empty_pid_lock_is_no_holder() {
    let (repo, home) = repo("hold-empty-pid", HOLD);
    receipt(&repo, "a");
    lock(&repo, "");
    assert!(refused_by_hold(&stop(&repo, &home, false)));
}

#[test]
fn no_receipt_no_hold() {
    let (repo, home) = repo("hold-no-receipt", HOLD);
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn a_continued_stop_is_refused_again_and_the_fourth_is_advice() {
    let (repo, home) = repo("hold-continued", HOLD);
    receipt(&repo, "a");
    assert!(
        refused_by_hold(&stop(&repo, &home, false)),
        "the first Stop"
    );
    assert!(refused_by_hold(&stop(&repo, &home, true)), "the second");
    assert!(refused_by_hold(&stop(&repo, &home, true)), "the third");
    let fourth = stop(&repo, &home, true);
    assert_eq!(fourth.status.code(), Some(0), "{}", stderr(&fourth));
    assert!(
        stdout(&fourth).contains("hold children"),
        "the line, as advice: {}",
        stdout(&fourth)
    );
}

#[test]
fn a_false_predicate_resets_the_count() {
    let (repo, home) = repo("hold-reset", HOLD);
    receipt(&repo, "a");
    assert!(refused_by_hold(&stop(&repo, &home, false)));
    assert!(refused_by_hold(&stop(&repo, &home, true)));
    lock(&repo, &std::process::id().to_string());
    assert_eq!(
        stop(&repo, &home, true).status.code(),
        Some(0),
        "a live holder"
    );
    unlock(&repo);
    assert!(
        refused_by_hold(&stop(&repo, &home, true)),
        "refused again from one"
    );
    assert!(refused_by_hold(&stop(&repo, &home, true)), "two");
    assert!(refused_by_hold(&stop(&repo, &home, true)), "three");
}

#[test]
fn a_host_that_cannot_block_gets_advice() {
    let (repo, home) = repo("hold-neutral", HOLD);
    receipt(&repo, "a");
    let output = hook_at(&repo, &home, &stop_payload(false), "exit-code");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let both = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        both.contains("hold children"),
        "the line, as advice: {both}"
    );
}

fn start(repo: &Path, home: &Path, background: bool) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "s-1",
        "tool_name": "Bash",
        "tool_input": {"command": "mise run fleet-wait", "run_in_background": background},
        "tool_response": {"backgroundTaskId": "b-1"},
    });
    let _ = hook_at(repo, home, &payload, "claude-code");
}

#[test]
fn starting_the_task_excuses_one_stop() {
    let (background, home) = repo("hold-dispatch", HOLD);
    receipt(&background, "a");
    start(&background, &home, true);
    let excused = stop(&background, &home, false);
    assert_eq!(excused.status.code(), Some(0), "{}", stderr(&excused));
    assert!(
        refused_by_hold(&stop(&background, &home, false)),
        "the next is refused"
    );
    // THE SAME ARGV IN THE FOREGROUND writes no note.
    let (foreground, home) = repo("hold-dispatch-foreground", HOLD);
    receipt(&foreground, "a");
    start(&foreground, &home, false);
    assert!(refused_by_hold(&stop(&foreground, &home, false)));
}

#[test]
fn an_unreadable_receipts_directory_fails_open() {
    let (repo, home) = repo("hold-unreadable", HOLD);
    std::fs::write(repo.join(".git/batten-receipts"), "not a directory").expect("a file");
    let output = stop(&repo, &home, false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stderr(&output).contains("hold children"));
}

#[test]
fn the_hold_reads_the_authority_root() {
    // OUTSIDE THIS CHECKOUT, so the parent is no repository at all and only the
    // recorded authority can name one.
    let root = common::scratch_outside_tree("batten-hold", "authority");
    let repo = Fixture::at(root.join("repo"))
        .config(HOLD)
        .git()
        .base_commit()
        .build();
    let home = root.join("home");
    // RECORDED FOR THE SESSION by a call made inside the repository.
    assert_eq!(
        stop(&repo, &home, false).status.code(),
        Some(0),
        "the premise"
    );
    receipt(&repo, "a");
    let output = hook_at(&root, &home, &stop_payload(false), "claude-code");
    assert!(refused_by_hold(&output), "{}", stderr(&output));
}

#[test]
fn the_bypass_and_plan_mode_silence_it() {
    let (repo, home) = repo("hold-bypass", HOLD);
    receipt(&repo, "a");
    let mut command = batten();
    common::state_home(&mut command, &home);
    command
        .current_dir(&repo)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env("BATTEN_STOP_GUARD_BYPASS", "1")
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stop_payload(false).to_string().as_bytes())
        .expect("write");
    let bypassed = child.wait_with_output().expect("run");
    assert_eq!(bypassed.status.code(), Some(0), "{}", stderr(&bypassed));
    let mut plan = stop_payload(false);
    plan["permission_mode"] = serde_json::json!("plan");
    let planned = hook_at(&repo, &home, &plan, "claude-code");
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    assert!(
        refused_by_hold(&stop(&repo, &home, false)),
        "the premise: it refuses"
    );
}

#[test]
fn removing_a_hold_row_is_a_weakening() {
    let (removed, _) = repo("hold-weakening", HOLD);
    common::git_in(&removed, &["checkout", "-q", "-b", "head"]);
    common::write(&removed, "batten.toml", "version = 1\n");
    let output = common::run(&removed, &["config", "lint", "--config-from", "main"]);
    assert!(
        format!("{}{}", stdout(&output), stderr(&output)).contains("stop-hold-removed"),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    let (added, _) = repo("hold-weakening-added", "version = 1\n");
    common::git_in(&added, &["checkout", "-q", "-b", "head"]);
    common::write(&added, "batten.toml", HOLD);
    let output = common::run(&added, &["config", "lint", "--config-from", "main"]);
    assert!(
        !format!("{}{}", stdout(&output), stderr(&output)).contains("stop-hold-removed"),
        "adding one reports nothing"
    );
}

#[test]
fn the_refusal_counts_and_does_not_name() {
    let (repo, home) = repo("hold-count", HOLD);
    for suffix in ["SUFFIX-ONE", "SUFFIX-TWO", "SUFFIX-THREE"] {
        receipt(&repo, suffix);
    }
    let output = stop(&repo, &home, false);
    let said = format!("{}{}", stdout(&output), stderr(&output));
    assert!(said.contains("while 3 child receipt(s)"), "{said}");
    assert!(
        !said.contains("SUFFIX-"),
        "no subject reaches the line: {said}"
    );
}
