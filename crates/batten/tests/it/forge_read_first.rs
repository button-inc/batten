//! The compiled-binary tier for `policy/forge-read-first.rego` (CLOUD-1470).
//!
//! The module's own `test_` rules pin the predicate against a hand-written
//! `programs` list; only this tier shows the ENGINE resolves the program the
//! predicate reads, and that the class's document route reaches the reader on an
//! ALLOWED call. The bench registers only this module, with the committed module
//! bytes, so nothing else in the repository's config can refuse the call first.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stderr, stdout};

const POINTER: &str = "read .serena/memories/github-access.md";

/// The repository root, whose committed `batten.toml` registers the module.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A fixture copy of the committed row and class, over the committed module.
fn bench(name: &str) -> PathBuf {
    let module = std::fs::read_to_string(root().join("policy/forge-read-first.rego"))
        .expect("the module is readable");
    Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\nid = \"forge read first\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"policy/forge-read-first.rego\"\n\
             severity = \"warn\"\n\n\
             [[verdict]]\nid = \"forge read first\"\n\
             gloss = \"a code-host call; read the memory documenting this host's GitHub access first\"\n\
             class = \"A fixture copy of the committed class.\"\n\n\
             [[verdict.route]]\nid = \"memory read first\"\nkind = \"document\"\n\
             target = \".serena/memories/github-access.md\"\n",
        )
        .file("policy/forge-read-first.rego", &module)
        .git()
        .base_commit()
        .build()
}

fn bash(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

fn tool(name: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": name,
        "tool_input": {},
    })
    .to_string()
}

/// Everything the door said on either stream, and its exit code.
fn adjudicate(dir: &Path, payload: &str) -> (Option<i32>, String) {
    let answer = run_with_stdin(dir, &["adjudicate", "--harness", "claude-code"], payload);
    (
        answer.status.code(),
        format!("{}{}", stdout(&answer), stderr(&answer)),
    )
}

#[test]
fn a_forge_call_is_handed_its_memory() {
    let dir = bench("forge-read-first-selected");
    for payload in [
        bash("gh pr view 1"),
        bash("cd /tmp && mise exec -- gh api repos/o/r"),
        bash("git push origin HEAD"),
        bash("mise run land"),
        tool("mcp__github__get_me"),
        tool("mcp__claude-code-remote__add_repo"),
    ] {
        let (code, said) = adjudicate(&dir, &payload);
        assert_eq!(
            code,
            Some(0),
            "an advisory refuses nothing: {payload} {said}"
        );
        assert!(!said.contains("permissionDecision"), "{payload}: {said}");
        assert!(
            said.contains(POINTER),
            "{payload} carries no pointer: {said}"
        );
    }
}

#[test]
fn a_non_forge_call_hears_nothing() {
    let dir = bench("forge-read-first-unselected");
    for command in [
        "ls -la",
        "git status",
        "git commit -m push",
        "cd /tmp && echo gh",
    ] {
        let (_, said) = adjudicate(&dir, &bash(command));
        assert!(!said.contains("forge read first"), "{command}: {said}");
    }
}

/// The COMMITTED table, which the bench cannot pin: the row, the class and its
/// route, and no doubled verb on any co-firing route.
#[test]
fn the_committed_policy_hands_a_gh_read_its_memory() {
    let explained = run(&root(), &["policy", "explain", "forge read first"]);
    let table = stdout(&explained);
    assert!(
        table.contains("memory read first")
            && table.contains("document")
            && table.contains(".serena/memories/github-access.md"),
        "the class declares the memory route: {table}"
    );
    let (code, said) = adjudicate(&root(), &bash("gh pr view 1"));
    assert_eq!(code, Some(0), "a gh read is allowed here: {said}");
    assert!(said.contains(POINTER), "{said}");
    assert!(
        !said.contains("run run "),
        "no route repeats its verb: {said}"
    );
}
