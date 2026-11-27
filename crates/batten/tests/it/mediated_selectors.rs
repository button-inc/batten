//! ONE CALL, EVERY SURFACE (CLOUD-2789): a connector call made through
//! `batten mcp call <server> <method> <params>` on a shell is selected by every
//! selector exactly as the direct `mcp__<server>__<method>` call is.
//!
//! One case per selector kind — a `[[rule]]`'s `tool` (and the modifier that
//! reads the call's arguments), the call event an `on` row keys on, and a
//! `[[mint]]` row's `selects_at` (the `[[hook.handler]]` matcher's case is in
//! `handler_dispatch.rs`, whose stub needs a unix shell) — each asserting the
//! mediated route earns what the direct route earns, and each with a negative
//! control so a selector that fires on every shell call cannot pass.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run_with_stdin, stderr};

/// A repository on a work branch carrying `config`.
fn repo(name: &str, config: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(config)
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    dir
}

/// The direct connector call, as the host sends it.
fn direct(event: &str, method: &str, input: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": event,
        "tool_name": format!("mcp__github__{method}"),
        "tool_input": input,
    })
}

/// The same call MEDIATED: a shell running `batten mcp call`.
fn mediated(event: &str, method: &str, input: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": format!("batten mcp call github {method} '{input}'")},
    })
}

/// The exit code and the refusing row the call earns.
fn verdict(dir: &Path, payload: &serde_json::Value) -> (Option<i32>, Option<String>) {
    let out = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload.to_string(),
    );
    (out.status.code(), common::refusing_rule(&stderr(&out)))
}

/// Both routes of one call earn one verdict, and it is `expected`.
fn alike(dir: &Path, method: &str, input: &serde_json::Value, expected: Option<&str>) {
    let direct = verdict(dir, &direct("PreToolUse", method, input));
    let mediated = verdict(dir, &mediated("PreToolUse", method, input));
    assert_eq!(
        direct.1.as_deref(),
        expected,
        "direct {method} {input}: {direct:?}"
    );
    assert_eq!(mediated, direct, "mediated {method} {input}");
}

const SHAPE_ROWS: &str = r#"version = 1

[[rule]]
id = "timer refused"
kind = "shape"
scope = "mediated_call"
severity = "deny"
tool = "send_later"
reason = "no timers here"

[[rule]]
id = "close refused"
kind = "shape"
scope = "mediated_call"
severity = "deny"
tool = "update_pull_request"
when_present = "input-state"
when_value = "closed"
reason = "do not close pull requests here"
"#;

/// A `[[rule]]` keyed on a `tool` refuses the mediated call as it refuses the
/// direct one, and its modifier reads the mediated call's params.
///
/// Fails by: a selector reading only `raw_tool`, which is `Bash` on the
/// mediated route; or a modifier reading the shell's own input.
#[test]
fn a_tool_keyed_rule_refuses_the_mediated_call_as_the_direct_one() {
    let dir = repo("mediated-shape", SHAPE_ROWS);
    alike(
        &dir,
        "send_later",
        &serde_json::json!({}),
        Some("timer refused"),
    );
    alike(
        &dir,
        "update_pull_request",
        &serde_json::json!({"pullNumber": 1, "state": "closed"}),
        Some("close refused"),
    );
    // NEGATIVE CONTROLS: the modifier excludes a call the selector selects,
    // and a method no row names is allowed, on both routes.
    alike(
        &dir,
        "update_pull_request",
        &serde_json::json!({"pullNumber": 1, "state": "open"}),
        None,
    );
    alike(&dir, "list_triggers", &serde_json::json!({}), None);
}

const ON_ROW: &str = r#"version = 1

[[rule]]
id = "ready-receipt"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
on = "pull-request-ready"
checks = ["verify"]
key = "head"
reason = "run verify before readying"
"#;

/// The call event an `on` row keys on is raised by the mediated call exactly
/// as by the direct one, read from the mediated params.
///
/// Fails by: `call_event` reading a shell command only as a `gh` line, or
/// `connector_event` reading the shell's name and input.
#[test]
fn the_mediated_call_raises_the_direct_calls_event() {
    let dir = repo("mediated-event", ON_ROW);
    alike(
        &dir,
        "update_pull_request",
        &serde_json::json!({"pullNumber": 1, "draft": false}),
        Some("ready-receipt"),
    );
    alike(
        &dir,
        "create_pull_request",
        &serde_json::json!({"title": "t"}),
        Some("ready-receipt"),
    );
    // NEGATIVE CONTROLS: a draft create and a body edit raise nothing.
    alike(
        &dir,
        "create_pull_request",
        &serde_json::json!({"title": "t", "draft": true}),
        None,
    );
    alike(
        &dir,
        "update_pull_request",
        &serde_json::json!({"pullNumber": 1, "body": "x"}),
        None,
    );
}

const MINT_ROW: &str = r#"version = 1

[[mint]]
name = "pr-closed"
tool = "update_pull_request"
key = "branch"
selects_at = "state"
selects = "closed"
requires = ["url"]
mode = "replace"
body = "{now} {url}"
"#;

/// The receipts `dir` holds, by file name.
fn receipts(dir: &Path) -> Vec<String> {
    let git_dir = git_in(dir, &["rev-parse", "--absolute-git-dir"]);
    let store = Path::new(git_dir.trim()).join("batten-receipts");
    let mut names: Vec<String> = walk(&store)
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(&store)
                .ok()
                .map(|rel| rel.display().to_string())
        })
        .collect();
    names.sort();
    names
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .flat_map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                walk(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

/// A `[[mint]]` row's `selects_at` selects the mediated call — minted by the
/// `mcp call` verb, which holds the params — as the hook selects the direct
/// call.
///
/// Fails by: the verb minting with a `null` input, under which a `selects_at`
/// row selects nothing.
#[test]
fn a_selecting_mint_mints_for_the_mediated_call_as_for_the_direct_one() {
    let answer = serde_json::json!({"url": "https://github.com/o/r/pull/7"});
    let closing = serde_json::json!({"pullNumber": 7, "state": "closed"});

    let by_hook = repo("mediated-mint-direct", MINT_ROW);
    let mut post = direct("PostToolUse", "update_pull_request", &closing);
    post["tool_response"] = answer.clone();
    let _ = run_with_stdin(
        &by_hook,
        &["adjudicate", "--harness", "exit-code"],
        &post.to_string(),
    );
    let direct_receipts = receipts(&by_hook);
    assert_eq!(direct_receipts.len(), 1, "{direct_receipts:?}");

    let by_verb = repo("mediated-mint-verb", MINT_ROW);
    batten::mint_dispatched_for_test(&by_verb, "update_pull_request", &closing, &answer)
        .expect("the fixture config resolves");
    assert_eq!(receipts(&by_verb), direct_receipts, "one call, one receipt");

    // NEGATIVE CONTROL: params the row does not select mint nothing.
    let unselected = repo("mediated-mint-unselected", MINT_ROW);
    batten::mint_dispatched_for_test(
        &unselected,
        "update_pull_request",
        &serde_json::json!({"pullNumber": 7, "state": "open"}),
        &answer,
    )
    .expect("the fixture config resolves");
    assert!(receipts(&unselected).is_empty());
}

/// The mediated call's receipt lands in the LINKED WORKTREE the call stands in,
/// where that checkout's gates read it, as the direct call's does — never in
/// the main checkout's git dir.
///
/// Fails by: the verb minting at `git::repo_root`, which from a linked worktree
/// is the main checkout, so the worktree's gate denied over a call that minted.
#[test]
fn a_mediated_mint_from_a_linked_worktree_lands_in_that_worktree() {
    let answer = serde_json::json!({"url": "https://github.com/o/r/pull/7"});
    let closing = serde_json::json!({"pullNumber": 7, "state": "closed"});
    let main = repo("mediated-mint-worktree", MINT_ROW);
    let linked = common::scratch("mediated-mint-worktree-linked");
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "linked-work",
            linked.to_str().unwrap_or_default(),
        ],
    );
    assert!(
        linked.join("batten.toml").is_file(),
        "the linked worktree carries the committed authority"
    );
    batten::mint_dispatched_for_test(&linked, "update_pull_request", &closing, &answer)
        .expect("the worktree's config resolves");
    assert_eq!(receipts(&linked).len(), 1, "{:?}", receipts(&linked));
    assert!(receipts(&main).is_empty(), "{:?}", receipts(&main));
}
