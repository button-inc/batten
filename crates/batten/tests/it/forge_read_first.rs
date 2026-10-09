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
    bench_with(name, "")
}

/// [`bench`] with `extra` appended to the fixture's config.
fn bench_with(name: &str, extra: &str) -> PathBuf {
    let module = std::fs::read_to_string(root().join("policy/forge-read-first.rego"))
        .expect("the module is readable");
    Fixture::new(name)
        .config(
            &("version = 1\n\n\
             [[rule]]\nid = \"forge read first\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"policy/forge-read-first.rego\"\n\
             severity = \"warn\"\n\n\
             [[verdict]]\nid = \"forge read first\"\n\
             gloss = \"a code-host call; read the memory documenting this host's GitHub access first\"\n\
             class = \"A fixture copy of the committed class.\"\n\n\
             [[verdict.route]]\nid = \"memory read first\"\nkind = \"document\"\n\
             target = \".serena/memories/github-access.md\"\n"
                .to_owned()
                + extra),
        )
        .file("policy/forge-read-first.rego", &module)
        .git()
        .base_commit()
        .build()
}

fn bash(command: &str) -> String {
    bash_in("s1", command)
}

/// A Bash call in `session` (CLOUD-2075: the lifecycle is per context).
fn bash_in(session: &str, command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

fn tool(name: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
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
    // One session: the first call is handed the memory, and every later one is
    // addressed by the rule's name, the memory being already in its context
    // (CLOUD-2145).
    for (index, payload) in [
        bash("gh pr view 1"),
        bash("cd /tmp && mise exec -- gh api repos/o/r"),
        bash("git push origin HEAD"),
        bash("mise run land"),
        tool("mcp__github__get_me"),
        tool("mcp__claude-code-remote__add_repo"),
    ]
    .into_iter()
    .enumerate()
    {
        let (code, said) = adjudicate(&dir, &payload);
        assert_eq!(
            code,
            Some(0),
            "an advisory refuses nothing: {payload} {said}"
        );
        assert!(!said.contains("permissionDecision"), "{payload}: {said}");
        assert!(
            said.contains("rule 'forge read first'"),
            "{payload} is not addressed: {said}"
        );
        if index == 0 {
            assert!(
                said.contains(POINTER),
                "the first carries the memory: {said}"
            );
        }
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
    // A session no earlier run used: the checkout's sighting store persists,
    // and a context that already held the memory would get only the address.
    let session = format!(
        "committed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    );
    let (code, said) = adjudicate(&root(), &bash_in(&session, "gh pr view 1"));
    assert_eq!(code, Some(0), "a gh read is allowed here: {said}");
    assert!(said.contains(POINTER), "{said}");
    assert!(
        !said.contains("run run "),
        "no route repeats its verb: {said}"
    );
}

/// A warn advisory is the full arm once per context, then the pointer
/// (CLOUD-2075 §7 case 10).
#[test]
fn a_warn_advisory_is_full_once_then_a_pointer() {
    let dir = bench("forge-read-first-lifecycle");
    let (first_code, first) = adjudicate(&dir, &bash_in("s1", "gh pr view 1"));
    let (second_code, second) = adjudicate(&dir, &bash_in("s1", "gh pr view 1"));
    assert_eq!((first_code, second_code), (Some(0), Some(0)));
    let address = "rule 'forge read first'";
    assert!(
        first.contains(address) && first.contains(POINTER) && first.contains(" —"),
        "{first}"
    );
    assert!(
        first.contains("code-host call"),
        "the gloss rides the full arm: {first}"
    );
    assert!(
        second.contains(&format!("\"{address}\"")),
        "the second is the address alone: {second}"
    );
    assert!(
        !second.contains(" —"),
        "the second is the pointer: {second}"
    );
}

/// A document route into a read-redirected path names its reader (CLOUD-2075
/// §7 case 11), and only where the consumer declares one.
#[test]
fn a_document_route_into_a_read_redirected_path_names_its_reader() {
    let redirected = bench_with(
        "forge-read-first-reader",
        "\n[[redirect]]\nglob = \".serena/memories/**\"\n\
         mutation = \"use the memory tools\"\nread = \"read_memory\"\n",
    );
    let (_, said) = adjudicate(&redirected, &bash("gh pr view 1"));
    assert!(
        said.contains(&format!("{POINTER} via read_memory")),
        "{said}"
    );
    let plain = bench("forge-read-first-no-reader");
    let (_, said) = adjudicate(&plain, &bash("gh pr view 1"));
    assert!(!said.contains(" via "), "{said}");
}
