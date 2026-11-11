//! A `ratchet` row judged at the write that would move it (CLOUD-2692).
//!
//! `batten check` reported a ratchet only after the edit landed. These cases
//! drive the compiled binary's `adjudicate` over a fixture repository whose
//! branch sits ahead of `main`, so the committed half of the sum is real: each
//! refusal is a write that moves the row the banned way past its merge base,
//! and each admission is one that does not.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// A non-increasing aggregate row over `docs/*.md` counting `TODO`, plus a
/// per-file non-decreasing row over `tests/*.txt` counting `case`.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "todo count ahead"
kind = "ratchet"
glob = "docs/*.md"
pattern = "TODO"
direction = "non_increasing"
base = "main"
severity = "deny"
scope = "tree"
admits_with = "todo-admits:"
no_fix_reason = "class 3 (test): fixture"

[[rule]]
id = "case count dropped"
kind = "ratchet"
glob = "tests/*.txt"
pattern = "case"
direction = "non_decreasing"
base = "main"
per_file = true
severity = "deny"
scope = "tree"
no_fix_reason = "class 3 (test): fixture"
"#;

/// `files` committed on `main`, then `branch` committed on a feature branch.
fn fixture(name: &str, files: &[(&str, &str)], branch: &[(&str, &str)]) -> PathBuf {
    let dir = scratch(name);
    std::fs::write(dir.join("batten.toml"), CONFIG).unwrap();
    let write = |files: &[(&str, &str)]| {
        for (path, text) in files {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
    };
    write(files);
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    common::git_in(&dir, &["branch", "-M", "main"]);
    common::git_in(&dir, &["checkout", "-qb", "feature"]);
    if !branch.is_empty() {
        write(branch);
        common::git_in(&dir, &["add", "-A"]);
        common::git_in(&dir, &["commit", "-qm", "branch"]);
    }
    dir
}

fn hook(dir: &Path, tool: &str, input: &serde_json::Value) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string();
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

/// The deny reason, or `None` when the call is not refused.
fn denied(output: &Output) -> Option<String> {
    let raw = common::stdout(output);
    let document: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    let inner = &document["hookSpecificOutput"];
    (inner["permissionDecision"] == "deny").then(|| {
        inner["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    })
}

fn edit(dir: &Path, path: &str, old: &str, new: &str) -> Output {
    hook(
        dir,
        "Edit",
        &serde_json::json!({"file_path": dir.join(path), "old_string": old, "new_string": new}),
    )
}

fn write(dir: &Path, path: &str, content: &str) -> Output {
    hook(
        dir,
        "Write",
        &serde_json::json!({"file_path": dir.join(path), "content": content}),
    )
}

#[test]
fn a_write_growing_an_aggregate_past_its_base_is_refused_at_the_call() {
    let dir = fixture("ratchet-call-grow", &[("docs/a.md", "TODO one\n")], &[]);
    let output = edit(&dir, "docs/a.md", "TODO one", "TODO one\nTODO two");
    let reason = denied(&output).unwrap_or_else(|| panic!("{}", common::stderr(&output)));
    assert!(reason.contains("todo count ahead"), "{reason}");
    assert!(
        reason.contains("docs/a.md"),
        "the written path is the pointer: {reason}"
    );
}

#[test]
fn a_write_the_ratchet_allows_is_admitted() {
    let dir = fixture(
        "ratchet-call-allowed",
        &[("docs/a.md", "TODO one\nTODO two\n")],
        &[],
    );
    // Shrinking a non-increasing count, and touching no counted token.
    assert_eq!(denied(&edit(&dir, "docs/a.md", "TODO two\n", "")), None);
    assert_eq!(denied(&edit(&dir, "docs/a.md", "one", "uno")), None);
    // A path no row's glob covers reads nothing.
    assert_eq!(denied(&write(&dir, "notes/b.md", "TODO TODO\n")), None);
}

#[test]
fn the_branch_committed_movement_is_part_of_the_sum() {
    // The branch already removed a TODO in b.md, so adding one in a.md leaves
    // the sum at its base: admitted. A second one moves it past: refused.
    let dir = fixture(
        "ratchet-call-committed",
        &[("docs/a.md", "TODO one\n"), ("docs/b.md", "TODO gone\n")],
        &[("docs/b.md", "done\n")],
    );
    assert_eq!(
        denied(&edit(&dir, "docs/a.md", "TODO one", "TODO one\nTODO two")),
        None
    );
    let output = edit(
        &dir,
        "docs/a.md",
        "TODO one",
        "TODO one\nTODO two\nTODO three",
    );
    assert!(denied(&output).is_some(), "{}", common::stdout(&output));
}

#[test]
fn a_declared_rise_is_admitted() {
    let dir = fixture("ratchet-call-admits", &[("docs/a.md", "TODO one\n")], &[]);
    let output = edit(
        &dir,
        "docs/a.md",
        "TODO one",
        "TODO one\nTODO two\ntodo-admits: CLOUD-1",
    );
    assert_eq!(denied(&output), None);
}

#[test]
fn a_per_file_row_judges_the_file_against_its_own_base() {
    let dir = fixture(
        "ratchet-call-per-file",
        &[
            ("tests/a.txt", "case one\ncase two\n"),
            ("tests/b.txt", "case\n"),
        ],
        &[],
    );
    // Dropping a case in a.txt is refused, though b.txt could have paid for it
    // in an aggregate.
    let output = edit(&dir, "tests/a.txt", "case two\n", "");
    assert!(denied(&output).is_some(), "{}", common::stdout(&output));
    // A file absent at the base has no ceiling.
    assert_eq!(
        denied(&write(&dir, "tests/new.txt", "nothing here\n")),
        None
    );
}
