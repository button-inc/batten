//! The `detach` native gate (CLOUD-2667): a `&` job the call does not wait on
//! is refused wherever the harness has a supported background option, whatever
//! program it runs.
//!
//! The pipeline row refused a detach only for a program it declared as
//! verdict-bearing, so `true &` and `sleep 30 &` were allowed. Every case here
//! runs the compiled binary over a temp repository that declares no `pipeline`
//! row unless the case adds one.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr, stdout};

/// A repository whose config carries `rows` after the version line.
///
/// Always one unrelated row as well: a config with none skips the mediated
/// chain outright, so the gate under test would never be asked. The `singleton`
/// row grades only its own gate, so `detach` stays at its no-row default.
fn repo(name: &str, rows: &str) -> PathBuf {
    let anchor = common::native_row("singleton", "deny");
    Fixture::new(name)
        .config(&format!("version = 1\n\n{anchor}{rows}"))
        .git()
        .base_commit()
        .build()
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"s1\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// The host's rendered verdict for `command`, stdout and stderr together.
fn judged(dir: &Path, harness: &str, command: &str) -> String {
    let out = run_with_stdin(
        dir,
        &["adjudicate", "--harness", harness],
        &payload(command),
    );
    format!(
        "exit {:?}\n{}\n{}",
        out.status.code(),
        stdout(&out),
        stderr(&out)
    )
}

fn refused(dir: &Path, command: &str) -> bool {
    judged(dir, "claude-code", command).contains("\"deny\"")
}

fn assert_detached(dir: &Path, command: &str) {
    let out = judged(dir, "claude-code", command);
    assert!(
        out.contains("\"deny\""),
        "`{command}` must be refused\n{out}"
    );
    // The class, which is what a refusal renders. No fixture here carries a
    // row that could deny under it, so it is the detach gate's.
    assert!(
        out.contains("turn watch dropped"),
        "by the detach gate\n{out}"
    );
}

fn assert_allowed(dir: &Path, command: &str) {
    let out = judged(dir, "claude-code", command);
    assert!(
        !out.contains("\"deny\""),
        "`{command}` must be allowed\n{out}"
    );
}

/// A bare `&` on a program no pipeline row declares is refused, by the gate's
/// own class and never by echoing the command; and a pipeline row graded
/// `warn` does not lower a gate it does not name.
#[test]
fn a_bare_ampersand_on_any_program_is_refused() {
    let dir = repo("detach-bare", "");
    assert_detached(&dir, "true &");
    assert_detached(&dir, "sleep 30 &");
    let out = judged(&dir, "claude-code", "sleep 30 &");
    assert!(!out.contains("sleep 30"), "pointer-only\n{out}");
    assert_allowed(&dir, "true");
    assert_allowed(&dir, "nohup true");

    let warned = repo(
        "detach-pipeline-warn",
        "[[rule]]\nid = \"read-the-verdict\"\nkind = \"pipeline\"\n\
         scope = \"mediated_call\"\nseverity = \"warn\"\nfilters = [\"tail\"]\n\
         reason = \"read the status\"\n\
         verdict = [{ program = \"git\", subcommands = [\"push\"] }]\n",
    );
    assert_detached(&warned, "git push origin x &");
}

/// A `native` row naming `detach` grades it: `allow` switches it off, `warn`
/// lets the call run and says what it would have refused.
#[test]
fn a_native_detach_row_grades_the_gate() {
    let off = repo("detach-allow", &common::native_row("detach", "allow"));
    assert_allowed(&off, "true &");
    let warned = repo("detach-warn", &common::native_row("detach", "warn"));
    let out = judged(&warned, "claude-code", "true &");
    assert!(!out.contains("\"deny\""), "a warn grade allows\n{out}");
    assert!(out.contains("turn watch dropped"), "and advises\n{out}");
}

/// A harness with no supported background option has no better shape to name.
#[test]
fn a_harness_without_a_background_option_is_not_refused() {
    let dir = repo("detach-exit-code", "");
    let out = judged(&dir, "exit-code", "true &");
    assert!(out.starts_with("exit Some(0)"), "{out}");
}

/// Waiting in the same call is not detaching.
#[test]
fn waiting_in_the_same_call_is_not_detached() {
    let dir = repo("detach-waited", "");
    for command in [
        "true & true & wait",
        "true & true; wait",
        "sleep 1 & wait $!",
        "sleep 1 & wait %1",
        "sleep 1 & wait -n",
        "(true & wait)",
        "true && true",
    ] {
        assert_allowed(&dir, command);
    }
}

/// A wait that names another job, or a literal pid, leaves this one detached.
#[test]
fn a_wait_on_another_job_is_detached() {
    let dir = repo("detach-foreign-wait", "");
    for command in [
        "sleep 30 & sleep 40 & wait $!",
        "pnpm dev & wait 1",
        "true & wait 123",
    ] {
        assert_detached(&dir, command);
    }
}

/// A wait outside the subshell or substitution that started the job cannot
/// wait on it.
#[test]
fn a_wait_outside_the_subshell_is_detached() {
    let dir = repo("detach-subshell", "");
    assert!(refused(&dir, "(true &); wait"));
    assert!(refused(&dir, "echo $(true &); wait"));
}
