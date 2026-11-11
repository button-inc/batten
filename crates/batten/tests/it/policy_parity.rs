//! `policy test` and live adjudication decide alike (CLOUD-2696).
//!
//! Measured on a consumer: a module whose helper is undefined for a call
//! (`subject(args)` with no `-m`) passed its own `with input as` case under
//! `policy test`, while the same call was refused live. Either the live input
//! differs from the documented shape or live evaluation reads undefined
//! differently, and a consumer cannot tell which. Each case here drives ONE
//! module through both, so a divergence fails by name.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

const CONFIG: &str = r#"version = 1

[[rule]]
id = "commit name refused"
kind = "policy"
scope = "mediated_call"
module = "policy/probe.rego"
severity = "deny"

[[pattern]]
id = "probe-subject"
regex = '^feat'

[[verdict]]
id = "commit name refused"
gloss = "the commit subject does not match"
class = """
A probe verdict for CLOUD-2696's parity cases.
"""
[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/probe.rego"
"#;

/// The consumer's shape: a helper undefined when there is no `-m`.
const MODULE: &str = r#"# METADATA
# description: CLOUD-2696's probe.
package batten.probe

import rego.v1

rules contains "commit name refused"

commit_args contains args if {
	some program in input.call.programs
	program.name == "git"
	program.subcommand == "commit"
	args := program.arguments
}

subject(args) := message if {
	some i, word in args
	word == "-m"
	message := args[i + 1]
}

violation contains {"rule": "commit name refused", "verdict": "commit name refused", "subjects": []} if {
	some args in commit_args
	message := subject(args)
	not regex.match(data.batten.patterns["probe-subject"], message)
}

test_no_message_is_clean if {
	count(violation) == 0 with input as {"call": {"programs": [{
		"name": "git",
		"subcommand": "commit",
		"arguments": ["commit", "--amend", "--no-edit"],
	}]}}
}

test_a_wrong_subject_is_refused if {
	count(violation) == 1 with input as {"call": {"programs": [{
		"name": "git",
		"subcommand": "commit",
		"arguments": ["commit", "-m", "fix: x"],
	}]}}
}
"#;

fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let dir = common::scratch(name);
    let home = common::scratch(&format!("{name}-home"));
    common::write(&dir, "batten.toml", CONFIG);
    common::write(&dir, "policy/probe.rego", MODULE);
    common::init_repo(&dir);
    (dir, home)
}

/// Whether the live hook refused `command` with the probe's verdict.
fn refused_live(dir: &Path, home: &Path, command: &str) -> bool {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "parity",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let mut invocation = common::batten();
    common::state_home(&mut invocation, home);
    let outcome = common::stdin_run(
        &mut invocation,
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &envelope,
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    );
    said.contains("commit name refused")
}

#[test]
fn a_module_decides_live_as_its_own_cases_say() {
    let (dir, home) = fixture("policy-parity");
    let tested = common::batten()
        .current_dir(&dir)
        .args(["policy", "test"])
        .output()
        .expect("run policy test");
    assert!(
        String::from_utf8_lossy(&tested.stdout).contains("2 passed, 0 failed"),
        "{}{}",
        String::from_utf8_lossy(&tested.stdout),
        String::from_utf8_lossy(&tested.stderr)
    );
    // The module's own cases, decided live: what `policy test` passed as clean
    // is clean, and what it passed as refused is refused.
    assert!(
        !refused_live(&dir, &home, "git commit --amend --no-edit"),
        "live refused a call whose helper is undefined, which `policy test` passed as clean"
    );
    assert!(
        !refused_live(&dir, &home, "git commit -F msg.txt"),
        "live refused a call with no `-m`"
    );
    assert!(
        refused_live(&dir, &home, "git commit -m \"fix: x\""),
        "live allowed the subject `policy test` refuses"
    );
    assert!(!refused_live(&dir, &home, "git commit -m \"feat: x\""));
}

/// A MODULE THE GATE CANNOT REACH IS REFUSED WHERE IT IS TESTED (CLOUD-2696). A
/// package outside `data.batten` passed its own cases under `policy test` and
/// decided nothing live, which allowed every call. Fails by: `policy test`
/// passing it, so the module reads green while the gate ignores it.
#[test]
fn a_module_outside_the_batten_namespace_is_refused_where_it_is_tested() {
    let (dir, _home) = fixture("policy-parity-namespace");
    common::write(
        &dir,
        "policy/probe.rego",
        &MODULE.replace("package batten.probe", "package probe"),
    );
    let tested = common::batten()
        .current_dir(&dir)
        .args(["policy", "test"])
        .output()
        .expect("run policy test");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&tested.stdout),
        String::from_utf8_lossy(&tested.stderr)
    );
    assert_ne!(tested.status.code(), Some(0), "{said}");
    assert!(said.contains("outside `data.batten`"), "{said}");
}

/// `--show-input` STORES THE INPUT THE MODULE WAS HANDED (CLOUD-2696), and the
/// stored view carries the fields the module reads. Fails by: no pointer, or a
/// view whose `programs` is not the call's.
#[test]
fn the_policy_input_is_stored_and_pointed_at() {
    let (dir, home) = fixture("policy-parity-input");
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "parity",
        "tool_name": "Bash",
        "tool_input": { "command": "git commit -m \"fix: x\"" },
    })
    .to_string();
    let mut invocation = common::batten();
    common::state_home(&mut invocation, &home);
    let outcome = common::stdin_run(
        &mut invocation,
        &dir,
        &["adjudicate", "--harness", "claude-code", "--show-input"],
        &envelope,
    );
    let said = String::from_utf8_lossy(&outcome.stderr);
    let view = said
        .split("; read ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no pointer: {said}"));
    let text = std::fs::read_to_string(view).expect("the view reads");
    assert!(
        text.contains("## /call/programs/0/subcommand\ncommit"),
        "{text}"
    );
    assert!(
        text.contains("## /call/programs/0/arguments/2\nfix: x"),
        "{text}"
    );
}
