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

//! **UNIX ONLY, and the gate is load-bearing rather than tidy.** Every case here
//! dispatches a `#!/usr/bin/env bash` program as a `[[hook.handler]]` row. On a
//! Windows runner the spawn ladder resolves the interpreter the shebang names
//! and cannot start it, so the door reports a could-not-run and forwards
//! nothing. The cases that assert an ABSENCE — an allowed command, a dropped
//! verdict — therefore passed there for the wrong reason, while the ones that
//! assert a handler's refusal REACHING the host failed outright. Half a suite
//! green over a mechanism that never ran is the vacuous-pass class this file was
//! written to expose, so it is gated rather than split.
//!
//! `board_record.rs` gates its whole suite on the same rung of the same ladder,
//! and `tests/run-shape-guard.bats` — the tier this one is the second half of —
//! never ran on Windows either, so nothing is narrowed that was covered.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{at_root, run_with_stdin, scratch, stderr, stdout, write};

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
        let from = at_root("mise-tasks").join(task);
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

// No `#[cfg(unix)]` pair here: the module gate above already decides the target,
// so a `#[cfg(not(unix))]` twin would be a definition nothing can reach.
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("the copy exists")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("the copy is runnable");
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

/// Replace the copied guard with a stub that answers on the handler contract.
///
/// **The door's own claims are asserted through this rather than through the
/// committed guard**, because that guard cannot answer on the contract today —
/// see `the_committed_guard_writes_a_host_document_so_its_verdict_is_dropped`.
/// Driven against it, every case below would fail for the guard's reason instead
/// of for its own.
fn stub_guard(dir: &Path, body: &str) {
    write(
        dir,
        "mise-tasks/run-shape-guard.sh",
        &format!("#!/usr/bin/env bash\n{body}\n"),
    );
    make_executable(&dir.join("mise-tasks/run-shape-guard.sh"));
}

#[test]
fn the_committed_guard_writes_a_host_document_so_its_verdict_is_dropped() {
    // THE MEASURED DEFECT, asserted rather than described. The committed guard
    // denies by printing `hookSpecificOutput` on stdout and exiting 0; behind the
    // door `impersonates_host` reads that shape BEFORE the exit code, so the
    // outcome is `Broke(ImpersonatedHost)` — and every `Broke` variant ALLOWS.
    //
    // It is the same class `connector-allow-guard` was measured in on 2026-08-26,
    // and the same reason it is asserted rather than fixed: the repair is an edit
    // to a governed shell file, which `shell-retirement` admits only for a file
    // being retired, and this one cannot retire while its cargo family has no
    // surface (CLOUD-856).
    //
    // So the guard stays natively registered rather than dispatched, and this
    // case is the record of why. It FLIPS the day the guard is repaired.
    let dir = fixture("door-no-host-document");
    let answer = door(&dir, "cd /tmp; sleep 90; git log --oneline -1");
    assert!(
        answer
            .err
            .contains("hook.handler run-shape-guard: wrote a host decision document"),
        "the committed guard still impersonates the host; if this now fails, the \
         guard was repaired and the stubbed cases below should be restored to \
         driving it: {}",
        answer.err
    );
    // And what it tried to write did not become a verdict.
    assert!(answer.allowed(), "{}", answer.out);
}

#[test]
fn a_handler_deny_reaches_the_host_with_its_reason_attributed() {
    // Exit 2 with the reason on stderr is the contract, and this is the door
    // rendering it — attributed to the handler BY THE ENGINE, which is the
    // difference between a verdict that travelled and one a script printed to
    // itself.
    let dir = fixture("door-handler-deny");
    stub_guard(
        &dir,
        "printf 'a foreground sleep spends the turn\\n' >&2\nexit 2",
    );

    let answer = door(&dir, "cd /tmp; sleep 90; git log --oneline -1");
    assert!(answer.denied(), "{}", answer.out);
    assert!(
        answer.out.contains("hook.handler.run-shape-guard"),
        "{}",
        answer.out
    );
    assert!(answer.out.contains("foreground"), "{}", answer.out);
}

#[test]
fn the_handler_receives_the_hosts_own_payload_including_the_calls_background_flag() {
    // THE LOAD-BEARING CASE for the migration, and the one thing a reader would
    // reasonably fear the extra hop loses: `run_in_background` is a property of
    // the CALL rather than of the command string, and it is what tells a timer
    // from a wait. It survives, because a handler is handed the host's own raw
    // payload rather than the engine's normalized envelope.
    //
    // The stub decides on nothing else, so this asserts the HOP rather than any
    // predicate: it denies iff the flag arrived.
    let dir = fixture("door-background-flag");
    stub_guard(
        &dir,
        "raw=$(cat)\ncase \"$raw\" in\n*'\"run_in_background\":true'*)\n  printf 'the flag arrived\\n' >&2; exit 2 ;;\nesac\nexit 0",
    );

    let backgrounded = door_bg(&dir, "sleep 590; tail -6 /tmp/land.log");
    assert!(backgrounded.denied(), "{}", backgrounded.out);
    assert!(
        backgrounded.out.contains("the flag arrived"),
        "{}",
        backgrounded.out
    );

    // The discrimination, without which a stub that denied everything would
    // satisfy the half above (CLOUD-418): the same command with no flag on the
    // call is allowed, so it is the FACT being read and not the command string.
    let foreground = door(&dir, "sleep 590; tail -6 /tmp/land.log");
    assert!(foreground.allowed(), "{}", foreground.out);
}

#[test]
fn a_backgrounded_wait_on_a_condition_stays_allowed() {
    // Driven against the COMMITTED guard deliberately, because this is its allow
    // path and the allow path is not broken: the guard prints a document only
    // when it denies, so a command it passes leaves the door silent either way.
    // A guard refusing every backgrounded sleep would fail this and be the false
    // positive that gets a guard switched off (CLOUD-418).
    let dir = fixture("door-background-wait");
    let answer = door_bg(&dir, "until [ -f /tmp/done ]; do sleep 1; done");
    assert!(answer.allowed(), "{}", answer.out);
    assert!(answer.unbroken(), "{}", answer.err);
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
