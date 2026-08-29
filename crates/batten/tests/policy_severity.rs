//! A `mediated_call` policy row's `severity` column reaches the surface it is
//! declared on (CLOUD-1131).
//!
//! # The defect, measured before anything was built
//!
//! CLOUD-1131 asked one question first: does a `warn` at `PreToolUse` reach the
//! agent, or is it swallowed? The answer was worse than the row expected, and one
//! layer lower. `hook::policy_rules` turned EVERY module violation into a
//! `Decision::Deny` and never consulted the enabling row's severity —
//! `policy::Bundle` carried none, and `hook::blocks`, which every typed rule kind
//! asks, was never asked here. So `severity = "warn"` on a `scope =
//! "mediated_call"` policy row **denied exactly as `deny` did**, silently, which
//! is the one direction a severity column must never fail in.
//!
//! `pinned-toolchain-preset` was live in that state: `batten.toml` declares it
//! `warn` — with a comment explaining that the first landing must not refuse —
//! and it refused.
//!
//! # Why the two arms are one test
//!
//! "The advisory does not block" is satisfied by a module that has simply stopped
//! firing, and a demotion implemented as a silent skip looks identical from
//! outside. So both arms run the SAME module over the SAME call with one column
//! different: at `deny` it refuses, at `warn` it allows — and the class still
//! travels where the host declares a channel. (The refusal is a verdict BODY
//! rather than exit 2 on this host: `reason_travels_in_band` is `true` for Claude
//! Code because exit 2 discards its stdout JSON, so the two channels are
//! exclusive and the richer one wins.)
//!
//! # What this file does not hold
//!
//! Which events a host can be advised on. That is the capability table's answer
//! (`Harness::capabilities`), it is evidence-backed per surface, and this file
//! reads it rather than restating it: `PostToolBatch` is one Claude Code declares
//! and has been probed on, `PreToolUse` is not one at all.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// A fixture module, deliberately not one of the committed ones.
///
/// The property under test is the ENGINE's reading of the severity column, so the
/// predicate wants to be as small as a predicate can be — and anchoring a real
/// module here would tie this file to that module's own subject.
///
/// Anchored on `segments` rather than on `command`, which is the standing rule
/// for a mediated module (CLOUD-857): the first word of the whole LINE is not the
/// first word of the call, and a real agent command is compound most of the time.
const MODULE: &str = r#"package batten.fixture_severity

import rego.v1

rules contains "fixture-severity"

violation contains {
	"rule": "fixture-severity",
	"verdict": "V-FIXTURE-SEVERITY",
	"subjects": [{"path": "fixture"}],
} if {
	some segment in input.call.segments
	segment.words[0] == "forbidden"
}
"#;

fn config(severity: &str) -> String {
    format!(
        r#"version = 1

[[verdict]]
id = "V-FIXTURE-SEVERITY"
gloss = "the fixture predicate matched"
class = """
A fixture class, carrying one route so the registry's own shape rules are met.
"""

[[verdict.route]]
id = "R-FIXTURE"
kind = "command"
target = "stop running the fixture command"

[[rule]]
id = "fixture-severity"
kind = "policy"
scope = "mediated_call"
module = "policy/fixture-severity.rego"
severity = "{severity}"
"#
    )
}

fn repo(name: &str, severity: &str) -> PathBuf {
    let dir = scratch(name);
    fs::write(dir.join("batten.toml"), config(severity)).expect("write config");
    fs::create_dir_all(dir.join("policy")).expect("policy dir");
    fs::write(dir.join("policy/fixture-severity.rego"), MODULE).expect("write module");
    dir
}

/// A compound command, because that is what a real call looks like and what the
/// module is anchored to read.
fn command_payload(event: &str, command: &str) -> String {
    serde_json::json!({
        "hook_event_name": event,
        "session_id": "s-1",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

fn hook(dir: &Path, payload: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .env_remove("BATTEN_HOOK_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

const CALL: &str = "cd /tmp && forbidden --now";

#[test]
fn a_deny_row_refuses_the_call() {
    let dir = repo("policy-severity-deny", "deny");
    let output = hook(&dir, &command_payload("PreToolUse", CALL));
    let stdout = stdout_of(&output);
    // EXIT 0 WITH A VERDICT BODY IS THIS HOST'S REFUSAL, not an allow: Claude
    // Code's `reason_travels_in_band` row is `true` because exit 2 discards its
    // stdout JSON, so the two channels are exclusive and the richer one wins. The
    // discriminator is therefore the body rather than the code, which is also why
    // the warn arm below asserts the body's ABSENCE.
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#),
        "a `deny` module violation is the policy verdict: {stdout}"
    );
    assert!(
        stdout.contains("V-FIXTURE-SEVERITY"),
        "and it names the class it refused under: {stdout}"
    );
}

/// THE DISCRIMINATING HALF. The same module, the same call, one column different.
#[test]
fn a_warn_row_allows_the_same_call() {
    let dir = repo("policy-severity-warn", "warn");
    let output = hook(&dir, &command_payload("PreToolUse", CALL));
    let stdout = stdout_of(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a `warn` module violation refuses nothing: {stdout}"
    );
    assert!(
        !stdout.contains("permissionDecision"),
        "and it emits no verdict a host could act on — the same violation, one \
         column different: {stdout}"
    );
}

/// The demotion is not a discard: where the host declares an advisory channel,
/// the same violation arrives as context.
///
/// `PostToolBatch` is the event chosen because the capability table already
/// carries it as probed for Claude Code. `PreToolUse` is not an advisory surface
/// on this host at all, which is the finding CLOUD-1131 recorded rather than the
/// gap this test papers over: a `warn` module has a reader at the batch boundary
/// and none at the tool call.
#[test]
fn a_warn_violation_reaches_the_advisory_channel_where_the_host_has_one() {
    let dir = repo("policy-severity-advisory", "warn");
    let output = hook(&dir, &command_payload("PostToolBatch", CALL));
    let stdout = stdout_of(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an advisory refuses nothing: {stdout}"
    );
    assert!(
        stdout.contains("additionalContext"),
        "the demoted violation travels on the advisory channel: {stdout}"
    );
    assert!(
        stdout.contains("V-FIXTURE-SEVERITY"),
        "carrying the class, so the reader can look it up: {stdout}"
    );
    assert!(
        !stdout.contains("permissionDecision"),
        "an advisory body has no field a verdict could occupy: {stdout}"
    );
}

/// And a `deny` row is NOT demoted at the same event: it is the decision, and
/// `adjudicated` allows at a post-tool event for its own reason, so nothing is
/// emitted twice.
///
/// Without this, the case above would be satisfied by a build that put every
/// violation on the advisory channel regardless of severity — which is the
/// mirror of the defect this row fixed.
#[test]
fn a_deny_row_is_not_also_advised_at_the_batch_boundary() {
    let dir = repo("policy-severity-deny-batch", "deny");
    let output = hook(&dir, &command_payload("PostToolBatch", CALL));
    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains("V-FIXTURE-SEVERITY"),
        "a blocking row's violation is its decision's, not the advisory channel's: {stdout}"
    );
}
