//! `on = "pull-request-ready"`: a row names the event, and the engine owns the
//! routes that raise it (CLOUD-2662).
//!
//! A receipt or shape row keyed on `pattern = "gh pr ready"` was due on that one
//! spelling: `gh pr ready --undo` owed it and the forge connector's undraft did
//! not. These cases run the compiled binary over a temp repository whose branch
//! names no key and holds no receipt, with one `on` row; every one failed at its
//! parent, where `on` was in no kind's permits.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, run_with_stdin, stderr};

/// A receipt row owing `verify` on the event.
const RECEIPT_ROW: &str = r#"[[rule]]
id = "ready-receipt"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
on = "pull-request-ready"
checks = ["verify"]
key = "head"
reason = "run verify before readying"
"#;

/// A shape row owing a tracker key on the event.
const SHAPE_ROW: &str = r#"[[rule]]
id = "ready-unkeyed"
kind = "shape"
scope = "mediated_call"
severity = "deny"
on = "pull-request-ready"
requires_key = '(?i)\bACME-[0-9]+\b'
base = "origin/main"
reason = "name the issue before readying"
"#;

/// A repository with `row`, on a branch whose one commit names no key.
fn repo(name: &str, row: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&format!("version = 1\n\n{row}"))
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", "user/some-slug"]);
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "chore: tidy"],
    );
    dir
}

/// The exit code the call earns: `2` refused, `0` allowed.
fn exit(dir: &Path, payload: &serde_json::Value) -> Option<i32> {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload.to_string(),
    )
    .status
    .code()
}

fn shell(command: &str) -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
}

fn connector(method: &str, input: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": format!("mcp__github__{method}"),
        "tool_input": input,
    })
}

fn refused(dir: &Path, payload: &serde_json::Value) {
    assert_eq!(exit(dir, payload), Some(2), "must be refused: {payload}");
}

fn allowed(dir: &Path, payload: &serde_json::Value) {
    assert_eq!(exit(dir, payload), Some(0), "must be allowed: {payload}");
}

#[test]
fn a_connector_undraft_owes_the_on_row_and_a_body_edit_does_not() {
    let dir = repo("ready-event-undraft", RECEIPT_ROW);
    for input in [
        serde_json::json!({"pullNumber": 1, "draft": false}),
        serde_json::json!({"pullNumber": 1, "draft": "false"}),
    ] {
        refused(&dir, &connector("update_pull_request", &input));
    }
    for input in [
        serde_json::json!({"pullNumber": 1, "body": "x"}),
        serde_json::json!({"pullNumber": 1, "draft": true}),
    ] {
        allowed(&dir, &connector("update_pull_request", &input));
    }
}

#[test]
fn a_ready_create_owes_the_on_row_on_both_routes() {
    let dir = repo("ready-event-create", RECEIPT_ROW);
    refused(
        &dir,
        &connector("create_pull_request", &serde_json::json!({})),
    );
    refused(
        &dir,
        &connector("create_pull_request", &serde_json::json!({"draft": false})),
    );
    allowed(
        &dir,
        &connector("create_pull_request", &serde_json::json!({"draft": true})),
    );
    // A quoted value is an operand, not a flag.
    refused(&dir, &shell("gh pr create --title t"));
    refused(&dir, &shell("gh pr create --title \"--draft\""));
    allowed(&dir, &shell("gh pr create --draft"));
    allowed(&dir, &shell("gh pr create -d"));
}

#[test]
fn ready_undo_owes_nothing_and_ready_owes_the_on_row() {
    let dir = repo("ready-event-undo", RECEIPT_ROW);
    refused(&dir, &shell("gh pr ready 1"));
    allowed(&dir, &shell("gh pr ready 1 --undo"));
    allowed(&dir, &shell("gh pr ready 1 --undo=true"));
}

#[test]
fn an_api_ready_owes_the_on_row_and_an_api_read_does_not() {
    let dir = repo("ready-event-api", RECEIPT_ROW);
    for command in [
        "gh api graphql -f query='mutation{markPullRequestReadyForReview(input:{pullRequestId:\"x\"}){clientMutationId}}'",
        "gh api -X POST repos/o/r/pulls/1/ccr/ready_for_review",
        "gh api graphql --input q.json",
    ] {
        refused(&dir, &shell(command));
    }
    for command in [
        "gh api repos/o/r/pulls/1",
        "gh api graphql -f query='{repository(owner:\"o\",name:\"r\"){pullRequest(number:1){timelineItems(itemTypes:[READY_FOR_REVIEW_EVENT],first:5){nodes{... on ReadyForReviewEvent{createdAt}}}}}}'",
    ] {
        allowed(&dir, &shell(command));
    }
}

#[test]
fn a_reopen_owes_the_on_row_on_both_routes() {
    let dir = repo("ready-event-reopen", RECEIPT_ROW);
    refused(&dir, &shell("gh pr reopen 1"));
    refused(
        &dir,
        &connector("update_pull_request", &serde_json::json!({"state": "open"})),
    );
    allowed(
        &dir,
        &connector(
            "update_pull_request",
            &serde_json::json!({"state": "open", "draft": true}),
        ),
    );
    allowed(
        &dir,
        &connector(
            "update_pull_request",
            &serde_json::json!({"state": "closed"}),
        ),
    );
}

#[test]
fn an_on_shape_row_refuses_an_unkeyed_ready_on_both_routes() {
    let dir = repo("ready-event-shape", SHAPE_ROW);
    let undraft = connector("update_pull_request", &serde_json::json!({"draft": false}));
    for payload in [&shell("gh pr ready 1"), &undraft] {
        let out = run_with_stdin(
            &dir,
            &["adjudicate", "--harness", "exit-code"],
            &payload.to_string(),
        );
        assert_eq!(out.status.code(), Some(2), "{payload}");
        assert_eq!(
            common::refusing_rule(&stderr(&out)).as_deref(),
            Some("ready-unkeyed"),
            "{payload}"
        );
    }
    allowed(&dir, &shell("gh pr ready 1 --undo"));
    // The row reads evidence rather than refusing blindly: a key in a commit
    // admits the connector undraft.
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "fix: ACME-1 x"],
    );
    allowed(&dir, &undraft);
}

/// Load-time refusals: what an `on` row cannot carry, and what it can.
#[test]
fn an_on_row_refuses_argv_and_projection_modifiers_at_load() {
    let refused_at_load = |name: &str, row: &str, column: &str| {
        let dir = repo(name, row);
        let out = run(&dir, &["check"]);
        assert_eq!(out.status.code(), Some(1), "{name}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(column),
            "{name} names {column}: {}",
            stderr(&out)
        );
    };
    refused_at_load(
        "on-shape-contains",
        &SHAPE_ROW.replace("reason =", "contains = \"x\"\nreason ="),
        "contains",
    );
    refused_at_load(
        "on-receipt-contains",
        &RECEIPT_ROW.replace("reason =", "contains = \"x\"\nreason ="),
        "contains",
    );
    refused_at_load(
        "on-when-present",
        &SHAPE_ROW.replace("reason =", "when_present = \"input-draft\"\nreason ="),
        "when_present",
    );
    refused_at_load(
        "on-with-pattern",
        &SHAPE_ROW.replace("reason =", "pattern = \"gh pr ready\"\nreason ="),
        "pattern",
    );
    refused_at_load(
        "on-unknown-event",
        &SHAPE_ROW.replace("pull-request-ready", "pull-request-merged"),
        "on",
    );
    refused_at_load(
        "on-receipt-write",
        &RECEIPT_ROW.replace("reason =", "trigger = \"write\"\nreason ="),
        "on",
    );
    let loads = repo("on-shape-loads", SHAPE_ROW);
    let out = run(&loads, &["check"]);
    assert_ne!(out.status.code(), Some(1), "{}", stderr(&out));
}
