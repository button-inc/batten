//! The local MCP server health gate (CLOUD-2398), driven through
//! `batten adjudicate --harness claude-code` over stub stdio servers.
//!
//! A host connects a local server once, at session start, and never retries,
//! so a server whose tools were still installing was dead for the whole
//! session. Batten probes each `[[mcp.local]]` row as an MCP client — spawn,
//! `initialize`, read the answer — and refuses the calls that would reach it
//! until it answers. These cases prove the probe against a stub that answers
//! and one that does not, and that a server dying mid-session is caught on the
//! next turn.
//!
//! # UNIX ONLY, for `session_provisioning.rs`'s reason
//!
//! Every stub is a `#!/bin/sh` program. On Windows the spawn ladder cannot start
//! the interpreter its shebang names, so every probe would fail, and the cases
//! asserting a refusal would pass for the wrong reason.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, stdout, write};

/// A stub stdio server that answers `initialize` once and exits on end of input.
const ANSWERS: &str =
    "read line\nprintf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}'\n";

/// A stub stdio server that cannot start.
const DIES: &str = "exit 1\n";

/// A fixture repository declaring one local server, `stub`, whose launch line
/// is `./stub-server` and whose memory tree is `memo/**`.
fn fixture(name: &str, server: &str) -> PathBuf {
    let repo = Fixture::new(name)
        .config(
            "version = 1\n\
             \n\
             [[mcp.local]]\n\
             server = \"stub\"\n\
             install = [[\"steps/install\"]]\n\
             routes = [\"memo/**\"]\n",
        )
        .file(
            ".mcp.json",
            r#"{"mcpServers":{"stub":{"command":"./stub-server","args":[]}}}"#,
        )
        .file("memo/a.md", "a memory\n")
        .file("notes.md", "not routed\n")
        .build();
    stub(&repo, server);
    repo
}

fn stub(repo: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    write(repo, "stub-server", &format!("#!/bin/sh\n{body}"));
    let path = repo.join("stub-server");
    let mut mode = std::fs::metadata(&path)
        .expect("the stub exists")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&path, mode).expect("the stub is runnable");
}

/// What the hook answered `envelope` with, on stdout.
fn send(repo: &Path, envelope: &serde_json::Value) -> String {
    let outcome = common::run_with_stdin(
        repo,
        &["adjudicate", "--harness", "claude-code"],
        &envelope.to_string(),
    );
    stdout(&outcome)
}

fn pre_tool(repo: &Path, tool: &str, input: &serde_json::Value) -> String {
    send(
        repo,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "session_id": "mcp-health-fixture",
            "permission_mode": "default",
            "tool_name": tool,
            "tool_input": input,
        }),
    )
}

fn next_turn(repo: &Path) {
    send(
        repo,
        &serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "mcp-health-fixture",
            "prompt": "go on",
        }),
    );
}

fn refused_by_the_probe(said: &str) -> bool {
    said.contains("\"deny\"") && said.contains("server probe failed")
}

#[test]
fn an_unhealthy_server_refuses_its_tools_and_routed_paths() {
    let repo = fixture("mcp-health-dead", DIES);

    let tool = pre_tool(&repo, "mcp__stub__get_x", &serde_json::json!({}));
    assert!(
        refused_by_the_probe(&tool),
        "a tool of a server that does not answer is refused: {tool}"
    );
    assert!(
        tool.contains("steps/install"),
        "the refusal names the install command to launch: {tool}"
    );

    let routed = pre_tool(
        &repo,
        "Read",
        &serde_json::json!({ "file_path": repo.join("memo/a.md") }),
    );
    assert!(
        refused_by_the_probe(&routed),
        "a path routed to the dead server is refused too: {routed}"
    );

    let unrouted = pre_tool(
        &repo,
        "Read",
        &serde_json::json!({ "file_path": repo.join("notes.md") }),
    );
    assert!(
        !refused_by_the_probe(&unrouted),
        "a path nothing routes is not this gate's: {unrouted}"
    );

    let install = pre_tool(
        &repo,
        "Bash",
        &serde_json::json!({ "command": "steps/install", "run_in_background": true }),
    );
    assert!(
        !refused_by_the_probe(&install),
        "the install the refusal names is never refused by it: {install}"
    );
}

#[test]
fn a_healthy_server_passes_and_one_that_dies_is_refused_next_turn() {
    let repo = fixture("mcp-health-alive", ANSWERS);

    let first = pre_tool(&repo, "mcp__stub__get_x", &serde_json::json!({}));
    assert!(
        !refused_by_the_probe(&first),
        "a server answering `initialize` passes: {first}"
    );

    // The server dies mid-session: its executable is gone.
    std::fs::remove_file(repo.join("stub-server")).expect("remove the stub");

    let same_turn = pre_tool(&repo, "mcp__stub__get_x", &serde_json::json!({}));
    assert!(
        !refused_by_the_probe(&same_turn),
        "the probe is held for the turn, not repeated per call: {same_turn}"
    );

    next_turn(&repo);
    let later = pre_tool(&repo, "mcp__stub__get_x", &serde_json::json!({}));
    assert!(
        refused_by_the_probe(&later),
        "the next turn probes again and finds it gone: {later}"
    );
}
