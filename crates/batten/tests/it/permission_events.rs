//! The two permission events Claude Code sends after pre-tool, answered with
//! the grant the call already had and counted (CLOUD-2768), driven through
//! `batten adjudicate --harness claude-code` over fixture envelopes.
//!
//! **THE OWNER'S RULING (2026-11-23).** Batten grants every call the engine
//! allows at pre-tool, at `PermissionRequest` (`decision.behavior = "allow"`)
//! and at `PermissionDenied` (`retry: true`), in every permission mode but plan.
//! Plan mode is read-only, so there only a read-only call is granted. Each
//! event in that scope leaves one line in `batten doctor gaps`, naming the
//! event and the call's tool or program, never an argument.
//!
//! Each case runs in its own committed fixture, so one case's gap lines never
//! reach another's count.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use common::stdout;
use std::path::{Path, PathBuf};

/// A fixture carrying this repository's committed rows, which enable the
/// `claude-code-cloud` preset.
fn root(case: &str) -> PathBuf {
    common::committed_fixture_with_substitution(&format!(
        "permission-events-{case}-{}",
        std::process::id()
    ))
}

/// A permission event's envelope: `event` is the host's name for it, and
/// `mode` the `permission_mode` field, absent where `None`.
fn envelope(event: &str, mode: Option<&str>, tool: &str, input: &serde_json::Value) -> String {
    let mut payload = serde_json::json!({
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": input,
    });
    if let Some(mode) = mode {
        payload["permission_mode"] = serde_json::Value::from(mode);
    }
    if event == "PermissionDenied" {
        payload["reason"] = serde_json::Value::from("the classifier's text");
    }
    payload.to_string()
}

fn shell(event: &str, mode: Option<&str>, command: &str) -> String {
    envelope(
        event,
        mode,
        "Bash",
        &serde_json::json!({ "command": command }),
    )
}

/// The hook's exit, and every document it put on stdout, parsed.
fn adjudicate(root: &Path, payload: &str) -> (Option<i32>, Vec<serde_json::Value>) {
    let outcome = common::stdin_run(
        &mut common::batten(),
        root,
        &["adjudicate", "--harness", "claude-code"],
        payload,
    );
    let documents = stdout(&outcome)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("the host reads JSON"))
        .collect();
    (outcome.status.code(), documents)
}

/// `batten doctor gaps` in `root`, one entry per line.
fn gaps(root: &Path) -> Vec<String> {
    let outcome = common::batten()
        .args(["doctor", "gaps"])
        .current_dir(root)
        .streamed_output()
        .expect("run doctor gaps");
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "{}",
        common::stderr(&outcome)
    );
    stdout(&outcome).lines().map(str::to_owned).collect()
}

/// Whether `documents` holds the `PermissionRequest` allow.
fn allowed(documents: &[serde_json::Value]) -> bool {
    documents.iter().any(|document| {
        document["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
            && document["hookSpecificOutput"]["decision"]["behavior"] == "allow"
    })
}

/// Whether `documents` holds the `PermissionDenied` retry.
fn retried(documents: &[serde_json::Value]) -> bool {
    documents.iter().any(|document| {
        document["hookSpecificOutput"]["hookEventName"] == "PermissionDenied"
            && document["hookSpecificOutput"]["retry"] == true
    })
}

/// Whether one gap line counts `event` at `subject`, once.
fn counted_once(gaps: &[String], event: &str, subject: &str) -> bool {
    let prefix = format!("{event} at {subject} 1 last ");
    gaps.iter().filter(|line| line.starts_with(&prefix)).count() == 1
}

/// Fails by: the denial left unanswered (`denial-unanswered`) or uncounted
/// (`denial-uncounted`), or the denial grant moved back to pre-tool
/// (`auto-grant-pre-tool-only`).
#[test]
fn a_denial_in_auto_is_answered_with_retry_and_counted() {
    let root = root("denial-auto");
    // A WRITE, so the mode grant alone answers it: the read-only grant answers
    // a read at the denial too.
    let (code, documents) = adjudicate(
        &root,
        &shell("PermissionDenied", Some("auto"), "touch made"),
    );
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(retried(&documents), "{documents:?}");
    let gaps = gaps(&root);
    assert!(
        counted_once(&gaps, "permission-denied", "touch"),
        "{gaps:?}"
    );
}

/// Fails by: the prompt left unanswered (`prompt-unanswered`) or uncounted
/// (`prompt-uncounted`), or the mode grant held at pre-tool alone
/// (`prompt-grant-pre-tool-only`).
#[test]
fn a_prompt_in_auto_is_answered_with_allow_and_counted() {
    let root = root("prompt-auto");
    // A WRITE, so the mode grant alone answers it: the read-only grant answers
    // a read at the prompt too.
    let (code, documents) = adjudicate(
        &root,
        &shell("PermissionRequest", Some("auto"), "touch made"),
    );
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(allowed(&documents), "{documents:?}");
    let gaps = gaps(&root);
    assert!(
        counted_once(&gaps, "permission-request", "touch"),
        "{gaps:?}"
    );
}

/// THE RULING'S WIDENING: a prompt in `default` mode is the owner's prompt for
/// a call the engine already allowed, so it is answered and counted as in
/// `auto`. Fails by: the old auto-only grant (`grant-auto-only`), which reached
/// the owner as a prompt (`hook.rs` once listed `PermissionRequest` among the
/// events no rule selects).
#[test]
fn a_prompt_in_default_mode_is_answered_with_allow() {
    let root = root("prompt-default");
    let (code, documents) = adjudicate(
        &root,
        &shell("PermissionRequest", Some("default"), "touch made"),
    );
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(allowed(&documents), "{documents:?}");
    let gaps = gaps(&root);
    assert!(
        counted_once(&gaps, "permission-request", "touch"),
        "{gaps:?}"
    );
}

/// PLAN MODE IS READ-ONLY: a write prompt there is the person's. No answer
/// document, exit 0, and no gap line, because it is outside the grant's scope.
/// Fails by: the plan test removed from the grant (`plan-mode-write-granted`)
/// or from in front of the request recorder (`plan-mode-write-counted`).
#[test]
fn a_write_prompt_in_plan_mode_is_not_granted() {
    let root = root("prompt-plan-write");
    let (code, documents) = adjudicate(
        &root,
        &shell("PermissionRequest", Some("plan"), "touch made"),
    );
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(documents.is_empty(), "{documents:?}");
    assert!(gaps(&root).is_empty());
}

/// A read-only call in plan mode is granted there, by the read-only grant at the
/// prompt. Fails by: that grant held at pre-tool alone (`plan-mode-reads-refused`).
#[test]
fn a_read_prompt_in_plan_mode_is_granted() {
    let root = root("prompt-plan-read");
    let payload = envelope(
        "PermissionRequest",
        Some("plan"),
        "Read",
        &serde_json::json!({ "file_path": "README.md" }),
    );
    let (code, documents) = adjudicate(&root, &payload);
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(allowed(&documents), "{documents:?}");
    let gaps = gaps(&root);
    assert!(
        counted_once(&gaps, "permission-request", "Read"),
        "{gaps:?}"
    );
}

/// The host documents the denial as firing only in auto mode, so an envelope
/// with no mode field is still answered and counted. Fails by: the denial clause
/// keyed on the mode (`denial-needs-the-mode-field`).
#[test]
fn a_denial_with_no_mode_field_is_still_answered_and_counted() {
    let root = root("denial-no-mode");
    let (code, documents) = adjudicate(&root, &shell("PermissionDenied", None, "touch made"));
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(retried(&documents), "{documents:?}");
    let gaps = gaps(&root);
    assert!(
        counted_once(&gaps, "permission-denied", "touch"),
        "{gaps:?}"
    );
}

/// A call with no command still loads the config at a permission event. Fails
/// by: the `is_adjudicable` widening removed (`permission-event-loads-no-config`),
/// which leaves no module and no grant.
#[test]
fn a_tool_with_no_command_is_answered_too() {
    let root = root("prompt-read-tool");
    let payload = envelope(
        "PermissionRequest",
        Some("auto"),
        "Read",
        &serde_json::json!({ "file_path": "README.md" }),
    );
    let (code, documents) = adjudicate(&root, &payload);
    assert_eq!(code, Some(0), "{documents:?}");
    assert!(allowed(&documents), "{documents:?}");
    let gaps = gaps(&root);
    assert!(
        counted_once(&gaps, "permission-request", "Read"),
        "{gaps:?}"
    );
}

/// POINTER-ONLY (rule 4): neither the call's argument nor the host's `reason`
/// reaches the gap list or the answer. Fails by: a subject built from the whole
/// command (`gap-subject-carries-arguments`).
#[test]
fn no_argument_reaches_the_gap_list() {
    let root = root("no-argument");
    let mut payload: serde_json::Value = serde_json::from_str(&shell(
        "PermissionDenied",
        Some("auto"),
        "ls argument-marker-0b7c",
    ))
    .expect("the envelope parses");
    payload["reason"] = serde_json::Value::from("reason-marker-3f1a");
    let (_, documents) = adjudicate(&root, &payload.to_string());
    let gaps = gaps(&root);
    let seen = format!("{documents:?}{gaps:?}");
    assert!(!seen.contains("argument-marker-0b7c"), "{seen}");
    assert!(!seen.contains("reason-marker-3f1a"), "{seen}");
    assert!(counted_once(&gaps, "permission-denied", "ls"), "{gaps:?}");
}

/// THE BRANCH RETURNS BEFORE THE HANDLERS: a permission event is answered with
/// the grant the call already had, and is not adjudicated again. Fails by: the
/// branch moved below `dispatch_handlers` (`permission-event-readjudicates`).
#[test]
fn no_handler_runs_at_a_permission_event() {
    let root = root("no-handler");
    common::write(&root, "mark.sh", "#!/bin/sh\ntouch handler-ran\n");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.join("mark.sh"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
    }
    let config = root.join("batten.toml");
    let mut text = std::fs::read_to_string(&config).expect("read the fixture config");
    for event in ["permission-request", "permission-denied"] {
        use std::fmt::Write as _;
        write!(
            text,
            "\n[[hook.handler]]\nid = \"mark-{event}\"\non = \"{event}\"\nrun = [\"./mark.sh\"]\n\
             timeout_ms = 5000\nowner = \"CLOUD-2768\"\n"
        )
        .expect("append to a String");
    }
    std::fs::write(&config, text).expect("write the fixture config");
    common::git_in(&root, &["add", "mark.sh", "batten.toml"]);
    common::git_in(
        &root,
        &[
            "commit",
            "-qm",
            "declare a handler on each permission event",
        ],
    );
    let (_, documents) = adjudicate(&root, &shell("PermissionRequest", Some("auto"), "ls -la"));
    assert!(allowed(&documents), "{documents:?}");
    assert!(!root.join("handler-ran").exists(), "a handler ran");
}
