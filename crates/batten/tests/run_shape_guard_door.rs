//! `run-shape-guard` driven THROUGH the door, over the compiled binary.
//!
//! **The second tier for CLOUD-312 row 11, and CLOUD-312's own differential
//! obligation**: the retiring registration's fixtures replay through
//! `batten hook` before the registration is deleted. `tests/run-shape-guard.bats`
//! runs the script directly, which cannot answer the question that actually
//! broke the previous migration — whether the ENGINE can consume what this
//! script produces.
//!
//! It broke exactly once and silently: `connector-allow-guard` went behind the
//! door still writing `hookSpecificOutput` on stdout, which is
//! `Violation::ImpersonatedHost` — reported and never forwarded — so every
//! verdict it produced was discarded for the life of the migration and no suite
//! noticed. This file is the row that would have.
//!
//! **THE FIXTURE REPOSITORY CARRIES ONE HANDLER ROW AND NO `[[rule]]` AT ALL.**
//! That isolation is the whole design: `verdict-not-discarded` and the other
//! mediated rows in the real `batten.toml` refuse commands in this same family,
//! so driving the real config would let an engine row's verdict stand in for the
//! handler's — the substitution that hid the defect the first time.
//!
//! **Rust rather than a `.bats` suite** (CLOUD-843). `shell-retirement` refuses
//! a new `tests/*.bats`, and it is right to: the campaign's corpus has to shrink
//! rather than stay level while the census reports movement. Writing the
//! door tier here costs nothing it would have had in bash — the fixture is the
//! same fixture and the binary is the same binary — and `.claude/rules/rust.md`
//! already prefers an end-to-end test over the compiled binary for anything a
//! consumer depends on.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{run_with_stdin, scratch, stderr, stdout, write};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A fixture repository carrying exactly one `[[hook.handler]]` row.
///
/// The guard and its `payload-field` helper are COPIED from this tree rather
/// than written here, so `mise run mutant` reaches this tier: under `mutant`
/// that tree is the mutated one, and a fixture with its own inlined copy would
/// be green over every mutation.
fn fixture(name: &str) -> PathBuf {
    let dir = scratch(name);
    std::fs::create_dir_all(dir.join("mise-tasks")).expect("the fixture's task dir");
    for task in ["run-shape-guard.sh", "payload-field.sh"] {
        let from = repo_root().join("mise-tasks").join(task);
        let to = dir.join("mise-tasks").join(task);
        std::fs::copy(&from, &to).expect("the guard is copied from this tree");
        make_executable(&to);
    }
    // The guard resolves `mise.toml` beside itself for the cargo family. An
    // empty one keeps that arm defined and silent; the cargo family's own corpus
    // stays in the direct suite, where a fixture `mise.toml` is what it tests.
    write(&dir, "mise.toml", "[tools]\n");
    write(
        &dir,
        "batten.toml",
        r#"version = 1

[[hook.handler]]
id = "run-shape-guard"
on = "pre-tool"
run = ["mise-tasks/run-shape-guard.sh"]
matcher = "Bash"
timeout_ms = 8000
owner = "CLOUD-613"
expires = "2027-02-28"
"#,
    );
    dir
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut mode = std::fs::metadata(path)
            .expect("the copy exists")
            .permissions();
        mode.set_mode(0o755);
        std::fs::set_permissions(path, mode).expect("the copy is runnable");
    }
}

/// What the door said to the host, and what it said about the handler.
struct Door {
    out: String,
    err: String,
}

impl Door {
    fn denied(&self) -> bool {
        self.out.contains(r#""permissionDecision":"deny""#)
    }

    fn allowed(&self) -> bool {
        !self.out.contains(r#""deny""#)
    }

    /// Nothing the door reports about the handler ITSELF — which is different
    /// from "the handler said nothing", and is the distinction this file exists
    /// for.
    fn unbroken(&self) -> bool {
        !self.err.contains("hook.handler run-shape-guard:")
    }
}

fn envelope(command: &str, background: bool) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    let extra = if background {
        r#","run_in_background":true"#
    } else {
        ""
    };
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}{extra}}}}}"
    )
}

fn door(dir: &Path, command: &str) -> Door {
    door_envelope(dir, &envelope(command, false))
}

fn door_bg(dir: &Path, command: &str) -> Door {
    door_envelope(dir, &envelope(command, true))
}

fn door_envelope(dir: &Path, payload: &str) -> Door {
    let outcome = run_with_stdin(dir, &["hook", "--harness", "claude-code"], payload);
    Door {
        out: stdout(&outcome),
        err: stderr(&outcome),
    }
}

#[test]
fn the_measured_defect_no_host_document_the_handler_wrote_is_forwarded() {
    let dir = fixture("door-no-host-document");
    let answer = door(&dir, "cd /tmp; sleep 90; git log --oneline -1");
    assert!(
        !answer.err.contains("wrote a host decision document"),
        "{}",
        answer.err
    );
    assert!(answer.unbroken(), "{}", answer.err);
}

#[test]
fn a_foreground_sleep_is_refused_through_the_door_and_the_reason_travels() {
    let dir = fixture("door-foreground-sleep");
    let answer = door(&dir, "cd /tmp; sleep 90; git log --oneline -1");
    assert!(answer.denied(), "{}", answer.out);
    // Attributed to the handler BY THE ENGINE, which is the difference between a
    // verdict that travelled and one the script printed to itself.
    assert!(
        answer.out.contains("hook.handler.run-shape-guard"),
        "{}",
        answer.out
    );
    assert!(answer.out.contains("foreground"), "{}", answer.out);
}

#[test]
fn a_backgrounded_timer_is_refused_so_the_calls_own_fact_reached_it() {
    // THE LOAD-BEARING CASE for the migration. This predicate is over
    // `run_in_background`, a property of the CALL rather than of the command
    // string, and it is the one thing a reader would reasonably fear the extra
    // hop loses. It does not: a handler receives the host's own payload.
    let dir = fixture("door-background-timer");
    let answer = door_bg(&dir, "sleep 590; tail -6 /tmp/land.log");
    assert!(answer.denied(), "{}", answer.out);
    assert!(answer.out.contains("TIMER"), "{}", answer.out);
}

#[test]
fn a_backgrounded_wait_on_a_condition_stays_allowed() {
    // The half without which the case above proves nothing: a guard refusing
    // every backgrounded sleep would satisfy it and be the false positive that
    // gets a guard switched off (CLOUD-418).
    let dir = fixture("door-background-wait");
    let answer = door_bg(&dir, "until [ -f /tmp/done ]; do sleep 1; done");
    assert!(answer.allowed(), "{}", answer.out);
    assert!(answer.unbroken(), "{}", answer.err);
}

#[test]
fn a_commit_that_can_never_obtain_a_message_is_refused_through_the_door() {
    let dir = fixture("door-unsatisfiable-commit");
    let answer = door(
        &dir,
        "git add -A && git commit -F - >log 2>&1 && mise run land >l2 2>&1 <<'EOF'\nmsg\nEOF\n",
    );
    assert!(answer.denied(), "{}", answer.out);
    assert!(answer.out.contains("-F <path>"), "{}", answer.out);
}

#[test]
fn an_ordinary_command_is_none_of_this_guards_business() {
    let dir = fixture("door-ordinary");
    let answer = door(&dir, "ls -la");
    assert!(answer.allowed(), "{}", answer.out);
    assert!(answer.err.is_empty(), "{}", answer.err);
}

#[test]
fn a_non_bash_tool_never_reaches_the_handler_at_all() {
    // `matcher` is the ENGINE's narrowing, not the script's, so it is only
    // assertable here. Without it this row costs a spawn on every mediated call.
    let dir = fixture("door-non-bash");
    let answer = door_envelope(
        &dir,
        r#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}"#,
    );
    assert!(answer.allowed(), "{}", answer.out);
    assert!(answer.err.is_empty(), "{}", answer.err);
}

#[test]
fn the_impersonation_detector_is_live_behind_this_row() {
    // THE POSITIVE CONTROL. Every negative case above is also satisfied by a
    // handler that never ran, so this one makes the guard write the host
    // document on purpose and requires the door to name it.
    let dir = fixture("door-impersonation");
    write(
        &dir,
        "mise-tasks/run-shape-guard.sh",
        "#!/usr/bin/env bash\nprintf '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"x\"}}\\n'\n",
    );
    make_executable(&dir.join("mise-tasks/run-shape-guard.sh"));
    let answer = door(&dir, "ls -la");
    assert!(
        answer
            .err
            .contains("hook.handler run-shape-guard: wrote a host decision document"),
        "{}",
        answer.err
    );
    assert!(answer.allowed(), "{}", answer.out);
}

#[test]
fn the_bypass_reaches_the_handler_through_the_door() {
    // A refusal whose bypass cannot be reached is not a remedy (§5). The engine
    // passes the environment through, so the guard's own hatch still works from
    // behind the door — which is not automatic and is worth one case.
    let dir = fixture("door-bypass");
    let payload = envelope("cd /tmp; sleep 90; echo done", false);
    let outcome = common::batten()
        .current_dir(&dir)
        .args(["hook", "--harness", "claude-code"])
        .env("BATTEN_RUN_SHAPE_BYPASS", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin is piped")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .expect("the binary runs");
    let answer = Door {
        out: stdout(&outcome),
        err: stderr(&outcome),
    };
    assert!(answer.allowed(), "{}", answer.out);
    assert!(answer.unbroken(), "{}", answer.err);
}
