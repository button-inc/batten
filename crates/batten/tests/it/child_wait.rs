//! A dispatcher may wait on its own open children, and nothing else may wait
//! (CLOUD-2889).
//!
//! `create_session` mints a `child-open` receipt keyed by the child's session id
//! and `archive_session` clears it. `policy/run-shape.rego` reads the ids back
//! as `input.facts.minted["children-open"]` and admits a `send_later`, a
//! `create_trigger` or a backgrounded wait only when the call's own arguments
//! name one of them. A PR heartbeat names none and is refused by construction.
//! These cases run the committed config and modules over the binary, so they
//! break if the mint pair, the minted row or an arm is edited away.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::Streamed as _;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

const CHILD: &str = "session_01ChildProbe";

/// Every spelling a host gives the timer tools: bare, the readable connector
/// name, and the session server's own name.
const SPELLINGS: &[&str] = &["", "mcp__Claude_Code_Remote__", "mcp__claude-code-remote__"];

/// This repository's own rows and modules, in a fresh checkout.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let path = entry.expect("a policy directory entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(path.file_name().expect("a file name")))
                .expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

fn receipts(dir: &Path) -> PathBuf {
    let output = common::git_command(dir, &["rev-parse", "--absolute-git-dir"])
        .streamed_output()
        .expect("resolve the git dir");
    PathBuf::from(String::from_utf8(output.stdout).expect("utf-8").trim()).join("batten-receipts")
}

fn receipt(dir: &Path, id: &str) -> PathBuf {
    receipts(dir).join(format!("child-open.{id}"))
}

fn adjudicate(dir: &Path, payload: &serde_json::Value) -> std::process::Output {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload.to_string(),
    )
}

/// A `create_session` that answered with `id`, as the host hands it back: one
/// text block carrying the JSON object.
fn create_child(dir: &Path, id: &str) {
    let _ = adjudicate(
        dir,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__claude-code-remote__create_session",
            "tool_input": {"prompt": "do the row"},
            "tool_response": [{
                "type": "text",
                "text": serde_json::json!({"ccr": {"id": id, "session_status": "SESSION_STATUS_RUNNING"}}).to_string(),
            }],
        }),
    );
}

fn archive_child(dir: &Path, id: &str) {
    let _ = adjudicate(
        dir,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__claude-code-remote__archive_session",
            "tool_input": {"session_id": id},
            "tool_response": [{"type": "text", "text": "archived"}],
        }),
    );
}

fn call(dir: &Path, tool: &str, input: serde_json::Value) -> std::process::Output {
    adjudicate(
        dir,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
        }),
    )
}

fn bash(dir: &Path, command: &str, background: bool) -> std::process::Output {
    call(
        dir,
        "Bash",
        serde_json::json!({"command": command, "run_in_background": background}),
    )
}

fn refused_by(output: &std::process::Output, rule: &str) {
    let text = stderr(output);
    assert_eq!(output.status.code(), Some(2), "refused: {text}");
    assert_eq!(
        common::refusing_rule(&text).as_deref(),
        Some(rule),
        "refused by {rule}: {text}"
    );
}

fn not_refused_by(output: &std::process::Output, rules: &[&str]) {
    let text = stderr(output);
    let by = common::refusing_rule(&text);
    assert!(
        by.as_deref().is_none_or(|rule| !rules.contains(&rule)),
        "admitted, yet refused by {by:?}: {text}"
    );
    assert_eq!(output.status.code(), Some(0), "admitted: {text}");
}

/// A created child mints its receipt and an archived one clears it.
///
/// MUTANT `child-open-clear-row-dropped`: a clear row keyed from a field the
/// input never carries leaves the receipt, and the second assertion fails.
#[test]
fn archiving_a_child_clears_its_receipt() {
    let dir = repo("child-wait-archive");
    create_child(&dir, CHILD);
    assert!(receipt(&dir, CHILD).exists(), "a created child mints");
    archive_child(&dir, CHILD);
    assert!(!receipt(&dir, CHILD).exists(), "an archived child clears");
}

/// An id outside a session id's shape mints nothing: the receipt's filename is
/// the id, so a separator would address a file outside the store.
#[test]
fn a_create_session_id_outside_the_session_shape_mints_nothing() {
    let dir = repo("child-wait-shape");
    create_child(&dir, "session_../escape");
    let store = receipts(&dir);
    let minted = std::fs::read_dir(&store)
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().starts_with("child-open."))
        })
        .unwrap_or(false);
    assert!(!minted, "no child-open receipt for a malformed id");
}

/// MUTANT `children-watch-unread` (no id ever matches) and
/// `timer-children-unread` (the timer arm ignores the command).
#[test]
fn a_backgrounded_wait_naming_an_open_child_is_admitted() {
    let dir = repo("child-wait-bash");
    create_child(&dir, CHILD);
    not_refused_by(
        &bash(&dir, &format!("sleep 30; echo {CHILD}"), true),
        &["timer run refused"],
    );
}

#[test]
fn a_bare_backgrounded_sleep_stays_refused_with_a_child_open() {
    let dir = repo("child-wait-bare");
    create_child(&dir, CHILD);
    refused_by(&bash(&dir, "sleep 600", true), "timer run refused");
}

#[test]
fn a_foreground_sleep_naming_an_open_child_stays_refused() {
    let dir = repo("child-wait-foreground");
    create_child(&dir, CHILD);
    refused_by(
        &bash(&dir, &format!("sleep 30; echo {CHILD}"), false),
        "sleep run blocked",
    );
}

/// MUTANT `send-later-children-unread`.
#[test]
fn send_later_naming_an_open_child_is_admitted_under_every_spelling() {
    let dir = repo("child-wait-send-later");
    create_child(&dir, CHILD);
    for prefix in SPELLINGS {
        not_refused_by(
            &call(
                &dir,
                &format!("{prefix}send_later"),
                serde_json::json!({"delay_minutes": 5, "message": format!("read {CHILD} again")}),
            ),
            &["timer mint refused"],
        );
    }
}

/// MUTANT `send-later-unrefused` and `connector-spelling-unread`: the bare and
/// prefixed spellings each carry the refusal.
#[test]
fn send_later_naming_no_open_child_is_refused() {
    let dir = repo("child-wait-send-later-pr");
    create_child(&dir, CHILD);
    for prefix in SPELLINGS {
        refused_by(
            &call(
                &dir,
                &format!("{prefix}send_later"),
                serde_json::json!({"delay_minutes": 5, "message": "check CI on PR #1282"}),
            ),
            "timer mint refused",
        );
    }
}

/// MUTANT `trigger-children-unread`.
#[test]
fn create_trigger_naming_an_open_child_is_admitted() {
    let dir = repo("child-wait-trigger");
    create_child(&dir, CHILD);
    not_refused_by(
        &call(
            &dir,
            "mcp__Claude_Code_Remote__create_trigger",
            serde_json::json!({"name": "watch", "prompt": format!("read {CHILD}"), "initiation": "own_followup"}),
        ),
        &["event mint refused"],
    );
}

/// MUTANT `trigger-unrefused`.
#[test]
fn create_trigger_naming_no_open_child_is_refused() {
    let dir = repo("child-wait-trigger-pr");
    create_child(&dir, CHILD);
    refused_by(
        &call(
            &dir,
            "mcp__Claude_Code_Remote__create_trigger",
            serde_json::json!({"name": "babysit", "prompt": "check PR #1282", "initiation": "own_followup"}),
        ),
        "event mint refused",
    );
}

/// A webhook is never a wait on a child, so an open child admits nothing here.
#[test]
fn subscribe_pr_activity_stays_refused_with_a_child_open() {
    let dir = repo("child-wait-subscribe");
    create_child(&dir, CHILD);
    refused_by(
        &call(
            &dir,
            "mcp__Claude_Code_Remote__subscribe_pr_activity",
            serde_json::json!({"owner": "o", "repo": "r", "pullNumber": 1}),
        ),
        "review watch refused",
    );
}

/// No store, an empty store, an archived child and a stale receipt each admit
/// nothing: every one of them is a timer naming no open child.
#[test]
fn a_missing_empty_archived_or_stale_store_admits_nothing() {
    let message = serde_json::json!({"delay_minutes": 5, "message": format!("read {CHILD}")});

    let missing = repo("child-wait-missing");
    refused_by(
        &call(&missing, "send_later", message.clone()),
        "timer mint refused",
    );

    let empty = repo("child-wait-empty");
    std::fs::create_dir_all(receipts(&empty)).expect("an empty receipt store");
    refused_by(
        &call(&empty, "send_later", message.clone()),
        "timer mint refused",
    );

    let archived = repo("child-wait-archived");
    create_child(&archived, CHILD);
    archive_child(&archived, CHILD);
    refused_by(
        &call(&archived, "send_later", message.clone()),
        "timer mint refused",
    );

    // Two days old against a one-day bound.
    let stale = repo("child-wait-stale");
    std::fs::create_dir_all(receipts(&stale)).expect("a receipt store");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    std::fs::write(
        receipt(&stale, CHILD),
        format!("{} open\n", now - 2 * 86_400),
    )
    .expect("plant a stale receipt");
    refused_by(&call(&stale, "send_later", message), "timer mint refused");
}
