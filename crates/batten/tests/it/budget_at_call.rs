//! A `[budget.*]` set judged at the write that would breach it (CLOUD-2661).
//!
//! `batten check` reported a set over its ceiling only after the edit landed;
//! the mediated path had no budget arm at all. These cases drive the compiled
//! binary's `adjudicate` over a fixture repository, the way
//! `prospective_facts.rs` does. Each refusal case was allowed at its parent.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// A repository with `config` and `files`, committed.
fn fixture(name: &str, config: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = scratch(name);
    std::fs::write(dir.join("batten.toml"), config).unwrap();
    for (path, text) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
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

/// `[budget.always]` over `CLAUDE.md`, at exactly its current token count.
fn always(name: &str, text: &str) -> PathBuf {
    let tokens = batten::budget::estimate_tokens(&batten::budget::loaded(text));
    fixture(
        name,
        &format!(
            "version = 1\n\n[budget.always]\nfiles = [\"CLAUDE.md\"]\nmax_tokens = {tokens}\n"
        ),
        &[("CLAUDE.md", text)],
    )
}

const CONTRACT: &str = "# The contract\n\nOne line of rules.\n";

#[test]
fn an_edit_that_pushes_a_literal_set_over_its_ceiling_is_refused_at_the_call() {
    let dir = always("budget-call-refused", CONTRACT);
    let grown = format!("One line of rules.{}", " more words".repeat(4));
    let reason = denied(&edit(&dir, "CLAUDE.md", "One line of rules.", &grown))
        .expect("the edit is refused at the call");
    assert!(reason.contains("budget.always"), "{reason}");
    assert!(!reason.contains("more words"), "pointer-only: {reason}");
}

#[test]
fn the_projection_not_the_disk_is_what_is_counted() {
    let dir = always("budget-projection", CONTRACT);
    let batch = serde_json::json!({
        "file_path": dir.join("CLAUDE.md"),
        "edits": [
            {"old_string": "# The contract", "new_string": "# The contract"},
            {"old_string": "One line of rules.", "new_string": format!("One line of rules.{}", " more words".repeat(4))},
        ],
    });
    assert!(
        denied(&hook(&dir, "MultiEdit", &batch)).is_some(),
        "the second span grows it"
    );
    assert!(
        denied(&edit(&dir, "CLAUDE.md", "One line", "One")).is_none(),
        "a shrink stays under"
    );
}

#[test]
fn an_edit_that_shrinks_an_over_budget_set_is_admitted() {
    let dir = fixture(
        "budget-repair",
        "version = 1\n\n[budget.always]\nfiles = [\"CLAUDE.md\"]\nmax_tokens = 1\n",
        &[("CLAUDE.md", CONTRACT)],
    );
    assert!(
        denied(&edit(&dir, "CLAUDE.md", "One line of rules.", "Rules.")).is_none(),
        "the repair of a standing breach is admitted"
    );
}

#[test]
fn a_write_creating_a_file_over_its_per_file_ceiling_is_refused() {
    let dir = fixture(
        "budget-new-file",
        "version = 1\n\n[budget.review]\nfiles = [\"REVIEW.md\"]\nmax_tokens = 1000000\nmax_bytes_per_file = 6000\n",
        &[("README.md", "seed\n")],
    );
    let write = |bytes: usize| {
        hook(
            &dir,
            "Write",
            &serde_json::json!({"file_path": dir.join("REVIEW.md"), "content": "a".repeat(bytes)}),
        )
    };
    let reason = denied(&write(6001)).expect("6001 bytes is over the per-file ceiling");
    assert!(reason.contains("budget.review"), "{reason}");
    assert!(denied(&write(6000)).is_none(), "6000 bytes is at it");
}

#[test]
fn a_glob_set_judges_bytes_but_not_totals_at_the_call() {
    let dir = fixture(
        "budget-glob",
        "version = 1\n\n[budget.docs]\nfiles = [\"docs/*.md\"]\nmax_tokens = 1\nmax_bytes_per_file = 100\n",
        &[("docs/a.md", "a\n")],
    );
    assert!(
        denied(&edit(&dir, "docs/a.md", "a", "abc")).is_none(),
        "a glob set's totals are not judged at the call"
    );
    let big = "b".repeat(200);
    assert!(
        denied(&edit(&dir, "docs/a.md", "a", &big)).is_some(),
        "but its per-file bytes are"
    );
}

#[test]
fn a_missing_literal_member_leaves_the_totals_unjudged() {
    let dir = fixture(
        "budget-missing-member",
        "version = 1\n\n[budget.pair]\nfiles = [\"CLAUDE.md\", \"AGENTS.md\"]\nmax_tokens = 1\n",
        &[("CLAUDE.md", CONTRACT)],
    );
    let grown = format!("One line of rules.{}", " more words".repeat(4));
    assert!(denied(&edit(&dir, "CLAUDE.md", "One line of rules.", &grown)).is_none());
}

#[test]
fn a_repository_with_no_budget_reads_no_file_and_allows() {
    let dir = fixture("budget-none", "version = 1\n", &[("CLAUDE.md", CONTRACT)]);
    let grown = format!("One line of rules.{}", " more words".repeat(40));
    assert!(denied(&edit(&dir, "CLAUDE.md", "One line of rules.", &grown)).is_none());
}

#[test]
fn literal_entry_reads_glob_syntax() {
    for entry in ["a*", "a?", "a[b]", "{a,b}", "a\\b"] {
        assert!(!batten::budget::literal_entry(entry), "{entry}");
    }
    assert!(batten::budget::literal_entry(".claude/CLAUDE.md"));
}
