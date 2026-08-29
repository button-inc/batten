//! The compiled-binary tier for `policy/shell-write-advisory.rego` (CLOUD-1131).
//!
//! # Why this file exists rather than a `with input as` case
//!
//! The module's own `test_` rules are the load-time tier and they pin the
//! PREDICATE. They cannot pin that the ENGINE builds the input the predicate
//! reads: a fabricated envelope is exactly the shape the engine may be unable to
//! produce, so a suite made only of them passes over a key nothing fills. Both
//! live instances of that class in this repository were found by adding this
//! tier, never by reading — `.claude/rules/policy-modules.md` records them.
//!
//! It matters more than usual here. The module reads `input.call.writes`, and
//! that key CHANGED MEANING under this row's feet: CLOUD-1133 found it carried
//! the host's `file_path` verbatim, which Claude Code sends absolute, so every
//! repo-relative comparison silently missed. A `with input as` case written
//! against the fixed shape would have passed against the broken engine.
//!
//! # The drift gate
//!
//! [`the_two_authorities_agree_on_what_is_governed`] is the mechanism the module
//! header promises. §1 asks that `shell-retirement` and this advisory never
//! disagree about the governed set, and the clean way to guarantee it — calling
//! the owning module's predicate — does not compile in this engine. So the
//! predicate is restated, and restatement without a gate is how two authorities
//! drift while both keep passing their own suites.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{run_with_stdin, stderr, stdout};

/// The repository root, whose committed `batten.toml` registers both modules.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A Claude Code `PreToolUse` envelope for a write tool.
fn write_payload(tool: &str, path: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": path, "content": "x\n"},
    })
    .to_string()
}

/// A Claude Code `PreToolUse` envelope for a shell command.
fn bash_payload(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

/// Everything the door said, on either stream.
///
/// BOTH, because which one carries the advisory is a property of the event
/// rather than of the message: `emit_advisory` uses stdout wherever the channel
/// is reachable and the operator's stream only as the unreachable fallback. A
/// case reading one stream would pass against a build that silently stopped
/// delivering, which is the thing this file is here to catch.
fn reported(payload: &str) -> String {
    let answer = run_with_stdin(&root(), &["hook", "--harness", "claude-code"], payload);
    format!("{}{}", stdout(&answer), stderr(&answer))
}

fn signals(payload: &str) -> bool {
    reported(payload).contains("V-SHELL-EDIT-BEFORE-RETIREMENT")
}

/// A write to an authored shell gate is told at the write.
///
/// The exit code is asserted alongside, because a `warn` that moved the status
/// would be the deny this row refuses — and a deny at write time refuses the one
/// disposition `shell-retirement` admits.
#[test]
fn a_write_to_a_governed_shell_path_signals_without_refusing() {
    let payload = write_payload("Write", "mise-tasks/ready-lint.sh");
    let answer = run_with_stdin(&root(), &["hook", "--harness", "exit-code"], &payload);
    assert_eq!(
        answer.status.code(),
        Some(0),
        "an advisory must not move the exit code"
    );
    assert!(signals(&payload), "{}", reported(&payload));
}

/// And in the spelling the host actually sends.
///
/// CLOUD-1133's normalisation is what makes this pass; before it the absolute
/// spelling missed every repo-relative comparison. Asserted here rather than
/// assumed, because this module is a consumer of that fix and would fail
/// silently — no advisory looks exactly like a clean path.
#[test]
fn the_absolute_spelling_the_host_sends_signals_too() {
    let absolute = root()
        .canonicalize()
        .expect("the repository root resolves")
        .join("mise-tasks/ready-lint.sh")
        .display()
        .to_string();
    let payload = write_payload("Write", &absolute);
    assert!(signals(&payload), "{}", reported(&payload));
}

/// A bats suite is governed too.
#[test]
fn a_write_to_a_bats_suite_signals() {
    let payload = write_payload("Write", "tests/land.bats");
    assert!(signals(&payload), "{}", reported(&payload));
}

/// THE DISCRIMINATING CASE, asserted over the REAL deletion shape.
///
/// A retirement deletes the governed path, and the row's acceptance requires
/// this be asserted over what a deletion actually is — a Bash `git rm` — rather
/// than over a fabricated `Write` event, which would prove nothing about the
/// shape that occurs. A module keyed on the path alone passes every positive
/// case above and impedes every retirement; this is what tells the two apart.
#[test]
fn the_deletion_a_retirement_performs_is_not_impeded() {
    let payload = bash_payload("git rm mise-tasks/ready-lint.sh");
    assert!(!signals(&payload), "{}", reported(&payload));
}

/// The compound deletion, which is what a retirement actually looks like: a
/// program and its suite are two paths, so the real shape is one list.
#[test]
fn a_compound_retirement_deletion_is_not_impeded() {
    let payload = bash_payload("git rm mise-tasks/ready-lint.sh && git rm tests/ready-lint.bats");
    assert!(!signals(&payload), "{}", reported(&payload));
}

/// An ungoverned write is silent, which keeps the governed set a SET.
#[test]
fn an_ungoverned_write_is_silent() {
    let payload = write_payload("Write", "crates/batten/src/hook.rs");
    assert!(!signals(&payload), "{}", reported(&payload));
}

/// The vacuity case the surface makes easy to get wrong.
///
/// A call carrying no write target must resolve to SILENCE rather than to a
/// match or a fault. `writes` is `null` on every non-write call, and the
/// module's `is_string` guard is what makes that a non-answer instead of an
/// evaluation error — asserted over the engine, because whether the key arrives
/// as `null` or absent is the engine's business and not the module's.
#[test]
fn a_call_carrying_no_write_target_is_silent() {
    let payload = bash_payload("ls -la");
    assert!(!signals(&payload), "{}", reported(&payload));
}

/// THE DRIFT GATE. The two authorities agree about what is governed.
///
/// The advisory restates `shell-retirement`'s path predicate because calling it
/// does not compile — a FUNCTION rule in another package is not reachable even
/// though the bundle shares one engine. Restating creates two authorities that
/// can disagree, and the disagreement would be invisible: each module keeps
/// passing its own suite.
///
/// So this drives one corpus through both surfaces and requires the same answer.
/// `batten check --rule shell-retirement` is the tree authority; the advisory is
/// the mediated one. The corpus deliberately includes the paths where the two
/// predicates are known to differ for a REASON — a `mise-tasks/` file with no
/// shebang is governed for deletion and not for edit — so the assertion is over
/// the PATH-ONLY classification both can compute, which is the only thing the
/// mediated surface has.
///
/// Fails by: editing either module's prefix test or its two suffix exclusions
/// without editing the other.
#[test]
fn the_two_authorities_agree_on_what_is_governed() {
    // Read the tree module's own predicate out of its source rather than
    // restating it a THIRD time here, which would make this gate part of the
    // drift it exists to catch.
    let owner = std::fs::read_to_string(root().join("policy/shell-retirement.rego"))
        .expect("the tree module is readable");
    let mirror = std::fs::read_to_string(root().join("policy/shell-write-advisory.rego"))
        .expect("the advisory module is readable");

    for clause in [
        r#"startswith(path, "mise-tasks/")"#,
        r#"not endswith(path, ".py")"#,
        r#"not endswith(path, ".tsv")"#,
        r#"startswith(path, "tests/")"#,
        r#"endswith(path, ".bats")"#,
    ] {
        assert!(
            owner.contains(clause),
            "shell-retirement no longer carries `{clause}` — the advisory mirrors a \
             predicate that moved, so update both or make the call compile"
        );
        assert!(
            mirror.contains(clause),
            "shell-write-advisory no longer carries `{clause}` — it has drifted from \
             the gate it advertises"
        );
    }
}
