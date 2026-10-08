//! A config row changed by a context that has not read its history is refused
//! (CLOUD-2144), over the compiled binary and a fixture carrying this
//! repository's committed `batten.toml` at `HEAD`.
//!
//! Every case drives the hook the way a host does: a PreToolUse `Edit` of the
//! authority, a PostToolUse `Bash` of `batten policy explain … --history` for the
//! read, and a `SessionStart` for the compaction. The receipt store is the
//! fixture's own `$GIT_DIR`, so no case reads or writes the tree under test.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run_with_stdin, stderr};

/// The row every case edits, and a line only it carries.
const ROW: &str = "tool select other";
const ROW_LINE: &str = "id = \"tool select other\"";

/// A fixture whose `HEAD` carries the committed authority AND its policy
/// modules: without the modules the config does not load, and the landed floor
/// admits any edit of the authority — which would pass every case vacuously.
fn fixture(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy");
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

/// A PreToolUse `Edit` of the authority in `session`, replacing `old` with `new`.
fn edit(repo: &Path, session: &str, old: &str, new: &str) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "tool_name": "Edit",
        "tool_input": {
            "file_path": repo.join("batten.toml").display().to_string(),
            "old_string": old,
            "new_string": new,
        },
    });
    // Claude Code's adapter, whose tool vocabulary names `Edit` as a write; the
    // refusal travels in its decision document on stdout.
    let run = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload.to_string(),
    );
    format!("{}{}", common::stdout(&run), stderr(&run))
}

/// The row's own line, edited in place.
fn edit_row(repo: &Path, session: &str) -> String {
    edit(repo, session, ROW_LINE, &format!("{ROW_LINE}\n# touched"))
}

/// The PostToolUse a `--history` read of `ROW` produces, in `session`.
fn read_history(repo: &Path, session: &str) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": session,
        "tool_name": "Bash",
        "tool_input": { "command": format!("batten policy explain '{ROW}' --history") },
        "tool_response": { "stdout": "the history", "stderr": "", "interrupted": false },
    });
    let _ = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload.to_string(),
    );
}

fn refused(line: &str) -> bool {
    line.contains("rule read missing") && line.contains(ROW)
}

#[test]
fn an_edit_to_a_rule_row_without_its_history_read_is_refused() {
    let repo = fixture("history-unread");
    let line = edit_row(&repo, "s1");
    assert!(
        refused(&line),
        "an unread row is refused, naming it: {line}"
    );
    assert!(
        line.contains("--history"),
        "and the line names the read that admits: {line}"
    );
    read_history(&repo, "s1");
    let line = edit_row(&repo, "s1");
    assert!(!refused(&line), "the same edit after the read: {line}");
}

#[test]
fn another_contexts_receipt_does_not_admit() {
    let repo = fixture("history-other-context");
    read_history(&repo, "s2");
    let line = edit_row(&repo, "s1");
    assert!(refused(&line), "s2's read is not s1's: {line}");
}

#[test]
fn a_new_commit_to_the_rule_invalidates_the_history_receipt() {
    let repo = fixture("history-new-commit");
    read_history(&repo, "s1");
    assert!(!refused(&edit_row(&repo, "s1")), "read, so admitted");
    // A commit that changes the row: the old receipt file stays in place, and
    // only its digest no longer matches.
    let path = repo.join("batten.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replacen(ROW_LINE, &format!("# changed upstream\n{ROW_LINE}"), 1),
    )
    .unwrap();
    git_in(&repo, &["commit", "-q", "-am", "change the row"]);
    let line = edit_row(&repo, "s1");
    assert!(refused(&line), "the row changed since it was read: {line}");
}

#[test]
fn a_compaction_drops_the_history_receipt() {
    let repo = fixture("history-compaction");
    read_history(&repo, "s1");
    assert!(!refused(&edit_row(&repo, "s1")), "read, so admitted");
    let start = serde_json::json!({
        "hook_event_name": "SessionStart",
        "session_id": "s1",
        "source": "compact",
    });
    let _ = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        &start.to_string(),
    );
    let line = edit_row(&repo, "s1");
    assert!(refused(&line), "what was read left the window: {line}");
    // RESUME KEEPS IT: the window carried over.
    read_history(&repo, "s1");
    let resume = serde_json::json!({
        "hook_event_name": "SessionStart",
        "session_id": "s1",
        "source": "resume",
    });
    let _ = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        &resume.to_string(),
    );
    assert!(!refused(&edit_row(&repo, "s1")), "a resume keeps the read");
}

#[test]
fn a_new_row_is_admitted_and_an_existing_one_is_not() {
    let repo = fixture("history-new-row");
    // Inserted beside an id-less row, so the edit touches no gated row.
    let anchor = "[[mint]]\nname = \"issue-read\"";
    let new_row = format!("[[rule]]\nid = \"brand new row\"\nkind = \"x\"\n\n{anchor}");
    let line = edit(&repo, "s1", anchor, &new_row);
    assert!(
        !line.contains("rule read missing"),
        "a new row owes no history: {line}"
    );
    let line = edit_row(&repo, "s1");
    assert!(refused(&line), "an existing row does: {line}");
}
