//! The state-repository gate (CLOUD-2939), over the compiled binary. A session
//! whose `BATTEN_STATE_REPO` answered 401/403/404 is held but for a read and the
//! host's attach call, and the refusal names the repository, the status and the
//! attach; a later `200` lifts the hold with no command; unset is inert and an
//! opt-out holds nothing.
//!
//! The probe's answer is the record the engine keeps under the git dir, written
//! here as the engine writes it: a refusal inside the re-probe window is
//! answered from it, so no case touches the network.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use std::path::{Path, PathBuf};

const CONFIG: &str = "version = 1\n\n\
     [[rule]]\nid = \"lease carry blocked\"\nkind = \"policy\"\n\
     scope = \"mediated_call\"\npreset = \"claude-code-state\"\nseverity = \"deny\"\n";

/// A bench enabling the `claude-code-state` preset, its origin on a forge, and
/// `extra` appended to its authority.
fn bench(name: &str, extra: &str) -> PathBuf {
    let dir = common::Fixture::new(name)
        .config(&format!("{CONFIG}{extra}"))
        .git()
        .base_commit()
        .build();
    common::git_in(
        &dir,
        &["remote", "add", "origin", "https://github.com/acme/app.git"],
    );
    dir
}

/// Record the probe's answer as the engine records it, stamped now.
fn record(dir: &Path, answer: &str) {
    let git_dir = batten::git::git_dir(dir).expect("the bench has a git dir");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let body = match answer {
        "granted" => String::from("granted\n"),
        status => format!("refused {status} {now}\n"),
    };
    std::fs::write(git_dir.join("batten-state-repo"), body).expect("the record");
}

/// A `PreToolUse` call to `tool` with `input`, `BATTEN_STATE_REPO` set to
/// `state` or unset: what the door said.
fn call(dir: &Path, tool: &str, input: &serde_json::Value, state: Option<&str>) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": dir,
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string();
    let mut command = common::batten();
    match state {
        Some(value) => command.env("BATTEN_STATE_REPO", value),
        None => command.env_remove("BATTEN_STATE_REPO"),
    };
    let answer = common::stdin_run(
        &mut command,
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    format!("{}{}", common::stdout(&answer), common::stderr(&answer))
}

fn edit(dir: &Path, state: Option<&str>) -> String {
    call(
        dir,
        "Edit",
        &serde_json::json!({"file_path": dir.join("a.txt"), "old_string": "a", "new_string": "b"}),
        state,
    )
}

fn held(said: &str) -> bool {
    said.contains("lease carry blocked")
}

/// Fails by: the gate left open while the repository is unattached — mutant
/// `state-hold-open` — or a refusal that does not name the repository, its
/// status and the attach.
#[test]
fn an_unattached_state_repo_holds_a_write_and_names_the_attach() {
    let dir = bench("state-repo-held", "");
    record(&dir, "404");
    let said = edit(&dir, Some("acme/state"));
    assert!(held(&said), "{said}");
    assert!(said.contains("acme/state 404"), "{said}");
    assert!(said.contains("add_repo"), "{said}");
}

/// Fails by: the attach or a read held — mutant `attach-held` — which leaves a
/// held session no call that lifts the hold.
#[test]
fn the_attach_and_the_reads_are_admitted_while_held() {
    let dir = bench("state-repo-admits", "");
    record(&dir, "403");
    let attach = call(
        &dir,
        "mcp__claude-code-remote__add_repo",
        &serde_json::json!({"owner": "acme", "repo": "state", "access": "push"}),
        Some("acme/state"),
    );
    assert!(!held(&attach), "{attach}");
    let read = call(
        &dir,
        "Read",
        &serde_json::json!({"file_path": dir.join("batten.toml")}),
        Some("acme/state"),
    );
    assert!(!held(&read), "{read}");
    let notes = call(
        &dir,
        "ReadNotifications",
        &serde_json::json!({}),
        Some("acme/state"),
    );
    assert!(!held(&notes), "{notes}");
}

/// Fails by: a granted record still holding, so the hold outlives the attach.
#[test]
fn a_granted_state_repo_holds_nothing() {
    let dir = bench("state-repo-granted", "");
    record(&dir, "granted");
    let said = edit(&dir, Some("acme/state"));
    assert!(!held(&said), "{said}");
}

/// Fails by: a session with no state repository judged at all.
#[test]
fn an_unset_state_repo_is_inert() {
    let dir = bench("state-repo-unset", "");
    record(&dir, "404");
    let said = edit(&dir, None);
    assert!(!held(&said), "{said}");
}

/// Fails by: a declared opt-out still holding the session.
#[test]
fn a_declared_opt_out_holds_nothing() {
    let dir = bench(
        "state-repo-optional",
        "\n[receipt]\nstate_repo_optional = true\n",
    );
    record(&dir, "404");
    let said = edit(&dir, Some("acme/state"));
    assert!(!held(&said), "{said}");
}

/// Fails by: a shell read held — mutant `shell-read-held` — so a held session
/// cannot look at its tree before it attaches; or a redirect read as a read.
#[test]
fn a_shell_read_is_admitted_while_held() {
    let dir = bench("state-repo-shell-read", "");
    record(&dir, "401");
    let read = call(
        &dir,
        "Bash",
        &serde_json::json!({"command": "cat batten.toml"}),
        Some("acme/state"),
    );
    assert!(!held(&read), "{read}");
    let write = call(
        &dir,
        "Bash",
        &serde_json::json!({"command": "cat batten.toml > copy.toml"}),
        Some("acme/state"),
    );
    assert!(held(&write), "{write}");
}
