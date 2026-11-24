//! `task watch pending` over this repository's own rows and module (CLOUD-2900).
//!
//! An `archive_session` is admitted only when `session watch`'s newest read of
//! that child, under a day old and not cleared by a message since, says `done`.
//! Each case writes the `child-state` receipt the watch would mint, then asks the
//! binary to adjudicate the archive under every spelling a host gives the tool.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

const CHILD: &str = "session_01ChildProbe";

const RULE: &str = "task watch pending";

/// Every spelling a host gives the session tools: bare, the readable connector
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
    PathBuf::from(common::git_in(dir, &["rev-parse", "--absolute-git-dir"]).trim())
        .join("batten-receipts")
}

fn receipt(dir: &Path) -> PathBuf {
    receipts(dir).join(format!("child-state.{CHILD}"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
}

/// The receipt `session watch` mints: `<at> <state> <open ids or ->`.
fn read_as(dir: &Path, at: u64, state: &str, open: &str) {
    let store = receipts(dir);
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    std::fs::write(receipt(dir), format!("{at} {state} {open}\n")).expect("write the receipt");
}

fn adjudicate(dir: &Path, payload: &serde_json::Value) -> std::process::Output {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload.to_string(),
    )
}

fn call(dir: &Path, tool: &str, input: &serde_json::Value) -> std::process::Output {
    adjudicate(
        dir,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
        }),
    )
}

fn archive(dir: &Path, prefix: &str) -> std::process::Output {
    call(
        dir,
        &format!("{prefix}archive_session"),
        &serde_json::json!({"session_id": CHILD}),
    )
}

fn refused_naming(output: &std::process::Output, names: &[&str]) {
    let text = stderr(output);
    assert_eq!(output.status.code(), Some(2), "refused: {text}");
    assert_eq!(
        common::refusing_rule(&text).as_deref(),
        Some(RULE),
        "refused by {RULE}: {text}"
    );
    for name in names {
        assert!(text.contains(name), "the refusal names {name}: {text}");
    }
}

fn not_refused_by_the_hold(output: &std::process::Output) {
    let text = stderr(output);
    assert_ne!(
        common::refusing_rule(&text).as_deref(),
        Some(RULE),
        "held, yet the read admits: {text}"
    );
    assert_eq!(output.status.code(), Some(0), "admitted: {text}");
}

/// Fails by: an archive admitted with no read of the child at all — the
/// incident, where silence was read as a dead machine.
///
/// MUTANT `archive-read-unchecked`.
#[test]
fn an_archive_with_no_read_of_the_child_is_refused() {
    let dir = repo("archive-held-unread");
    for prefix in SPELLINGS {
        refused_naming(&archive(&dir, prefix), &[CHILD]);
    }
}

/// Fails by: a refusal that names the child where the read named its open
/// runs, so the dispatcher cannot tell what it is waiting on.
///
/// MUTANT `archive-tasks-unnamed`.
#[test]
fn an_archive_whose_last_read_names_open_tasks_is_refused_naming_each() {
    let dir = repo("archive-held-waiting");
    read_as(&dir, now(), "waiting", "bgqosjroi,bwkc5djrv");
    for prefix in SPELLINGS {
        refused_naming(&archive(&dir, prefix), &["bgqosjroi", "bwkc5djrv"]);
    }
}

/// Fails by: a done read that still refuses, so no child could ever be
/// archived from a session.
///
/// MUTANT `archive-always-held`.
#[test]
fn an_archive_after_a_done_read_is_admitted() {
    let dir = repo("archive-held-done");
    read_as(&dir, now(), "done", "-");
    for prefix in SPELLINGS {
        not_refused_by_the_hold(&archive(&dir, prefix));
    }
}

/// Fails by: a message to the child leaving the read in place, so an archive
/// lands on a turn the read never saw.
///
/// MUTANT `child-state-clear-dropped`.
#[test]
fn a_message_to_the_child_after_its_read_holds_the_archive_again() {
    let dir = repo("archive-held-messaged");
    read_as(&dir, now(), "done", "-");
    not_refused_by_the_hold(&archive(&dir, ""));
    let _ = adjudicate(
        &dir,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__claude-code-remote__send_message",
            "tool_input": {"session_id": CHILD, "message": "are you stuck?"},
            "tool_response": [{"type": "text", "text": "sent"}],
        }),
    );
    assert!(!receipt(&dir).exists(), "the message cleared the read");
    for prefix in SPELLINGS {
        refused_naming(&archive(&dir, prefix), &[CHILD]);
    }
}

/// Fails by: a done read taken days ago still admitting.
#[test]
fn a_read_older_than_a_day_does_not_admit() {
    let dir = repo("archive-held-stale");
    read_as(&dir, now() - 2 * 86_400, "done", "-");
    refused_naming(&archive(&dir, ""), &[CHILD]);
}

/// Fails by: the hook minting a reading from one page of one transcript, which
/// shows only the launches on it.
#[test]
fn a_raw_list_events_result_mints_nothing() {
    let dir = repo("archive-held-raw");
    let _ = adjudicate(
        &dir,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__claude-code-remote__list_events",
            "tool_input": {"session_id": CHILD, "limit": 100},
            "tool_response": [{
                "type": "text",
                "text": format!(
                    "<other-session nonce=\"n1\">{}</other-session>",
                    serde_json::json!({"state": "done", "data": []})
                ),
            }],
        }),
    );
    assert!(!receipt(&dir).exists(), "a raw page minted child-state");
}

/// Fails by: the hold reaching a call that releases nothing.
#[test]
fn another_tool_naming_the_child_is_not_held() {
    let dir = repo("archive-held-other");
    for prefix in SPELLINGS {
        not_refused_by_the_hold(&call(
            &dir,
            &format!("{prefix}get_session"),
            &serde_json::json!({"session_id": CHILD}),
        ));
    }
}
