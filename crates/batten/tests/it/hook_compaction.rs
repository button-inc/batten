//! Operator directives survive a compaction (CLOUD-2811), over the compiled
//! binary: each operator message is journaled verbatim as it is given, and a
//! `SessionStart` whose source is `compact` points the new window at the
//! journal — a pointer, never the payload (house style §6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{run_with_stdin, stderr};

fn fixture(name: &str) -> PathBuf {
    common::adjudicable_with(name, "")
}

/// What the hook said about one host event, stdout and stderr together.
fn said(repo: &Path, event: &serde_json::Value) -> String {
    let output = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "claude-code"],
        &event.to_string(),
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    )
}

fn prompt(repo: &Path, text: &str) {
    let _ = said(
        repo,
        &serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s1",
            "prompt": text,
        }),
    );
}

fn start(repo: &Path, source: &str) -> String {
    said(
        repo,
        &serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "s1",
            "source": source,
        }),
    )
}

/// The branch's journal, wherever the receipt store keys it: the one file under
/// the git directory whose name begins with the family.
fn journal(repo: &Path) -> String {
    let git_dir = repo.join(".git");
    let mut found = Vec::new();
    let mut queue = vec![git_dir];
    while let Some(dir) = queue.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                queue.push(path);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("directives"))
            {
                found.push(path);
            }
        }
    }
    assert_eq!(found.len(), 1, "exactly one directives journal: {found:?}");
    std::fs::read_to_string(&found[0]).expect("the journal reads")
}

/// Fails by: a prompt not journaled, a compaction that names nothing, the
/// journal's text emitted as payload, or a resume (whose window kept every
/// message) pointed at the journal anyway.
#[test]
fn directives_survive_a_compaction() {
    let repo = fixture("directives-compaction");
    prompt(&repo, "never merge; rebase and push with a lease");
    prompt(
        &repo,
        "rules ship with their mechanism\nand presets are Rego",
    );

    let text = journal(&repo);
    assert!(
        text.contains("never merge; rebase and push with a lease"),
        "{text}"
    );
    assert!(
        text.contains("rules ship with their mechanism\\nand presets are Rego"),
        "a multi-line prompt is one entry, verbatim: {text}"
    );

    let compacted = start(&repo, "compact");
    assert!(compacted.contains("directive read missing"), "{compacted}");
    assert!(compacted.contains("2 operator message(s)"), "{compacted}");
    assert!(
        !compacted.contains("never merge"),
        "a pointer, never the payload: {compacted}"
    );

    let resumed = start(&repo, "resume");
    assert!(
        !resumed.contains("directive read missing"),
        "a resume replays the window, so nothing was dropped: {resumed}"
    );
}

/// Fails by: a hook's own notice journaled as if the operator had said it.
#[test]
fn only_the_operator_is_journaled() {
    let repo = fixture("directives-operator-only");
    let _ = said(
        &repo,
        &serde_json::json!({
            "hook_event_name": "Stop",
            "session_id": "s1",
            "last_assistant_message": "done",
        }),
    );
    let compacted = start(&repo, "compact");
    assert!(
        !compacted.contains("directive read missing"),
        "nothing the operator said, so nothing to point at: {compacted}"
    );
}

/// Fails by: the branch's design corrections, recorded through the verb, left
/// out of the compacted window's pointer, or their text emitted as payload.
#[test]
fn design_corrections_survive_a_compaction() {
    let repo = fixture("corrections-compaction");
    let recorded = run_with_stdin(
        &repo,
        &["record", "named", "corrections"],
        "a rename is a codemod, never a text replace\njudgement lives in Rego presets\n",
    );
    assert!(recorded.status.success(), "{}", stderr(&recorded));
    let compacted = start(&repo, "compact");
    assert!(compacted.contains("directive read missing"), "{compacted}");
    assert!(
        compacted.contains("2 design correction line(s)"),
        "{compacted}"
    );
    assert!(
        !compacted.contains("codemod"),
        "a pointer, never the payload: {compacted}"
    );
}
