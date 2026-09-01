//! `input.facts.tasks`, over the compiled binary (CLOUD-856).
//!
//! **The row's whole answer is WHERE the parse happens**, so the cases that
//! matter are about the boundary rather than about the predicate.
//! `the_mediated_call_parses_no_manifest` is the instrumentation case its
//! acceptance names: the manifest is deleted after minting, and the call still
//! answers — which is only possible if that path reads the record and nothing
//! else. A timing assertion could not discriminate this and a read counter over
//! a file that still exists could not either.
//!
//! `a_moved_manifest_does_not_answer` is the other half and the one the family
//! lives on. A receipt about a manifest that has since changed is not a stale
//! answer to be trusted a little; it is an answer about a different toolchain,
//! and reading it would be the could-not-look-as-a-pass failure the whole fact
//! model refuses.
//!
//! A `with input as` case can do neither: it fabricates the shape the engine may
//! be unable to produce (CLOUD-845, CLOUD-857), and here it would fabricate the
//! entire acquisition this row moved.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{StateHome as _, batten, git_in, scratch, write};

/// A manifest whose one task wraps a tool a call might reach for directly.
const MANIFEST: &str = r#"[tasks]
lint = "probe-tool --strict"
ship = "probe-tool build && probe-tool push"
"#;

/// The same manifest with the task's argv changed — a different toolchain, and
/// the receipt taken over the first must not answer for it.
const MOVED: &str = r#"[tasks]
lint = "probe-tool --lenient"
"#;

/// A manifest carrying ONLY the compound task.
///
/// Its own fixture because a mediated call yields ONE decision: with `lint`
/// present, `probe-argv` refuses first and `probe-compound` is never reported,
/// so a single fixture could not show the second class exists.
const COMPOUND_ONLY: &str = r#"[tasks]
ship = "probe-tool build && probe-tool push"
"#;

fn config() -> String {
    String::from(
        r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "mediated_call"
module = "probe.rego"
severity = "deny"

[[rule.tasks]]
manifest = "manifest.toml"
node = "tasks"

[[verdict]]
id = "task argv probe"
gloss = "the receipt carried a task's argv"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe argv probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "task compound probe"
gloss = "the receipt carried a task with no single argv"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe compound probe"
kind = "document"
target = "probe.rego"
"#,
    )
}

/// Three predicates, and the set is what discriminates.
///
/// `probe-argv` fires on the recorded argv EXACTLY, so a projection that emitted
/// a constant or carried the moved manifest's body fails it. `probe-compound`
/// fires on a task recorded with no single argv, which no fabricated empty table
/// could produce.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-argv"

rules contains "probe-compound"

violation contains {
	"rule": "probe-argv",
	"verdict": "task argv probe",
} if {
	is_object(input.facts.tasks)
	input.facts.tasks.lint == ["probe-tool", "--strict"]
}

violation contains {
	"rule": "probe-compound",
	"verdict": "task compound probe",
} if {
	is_object(input.facts.tasks)
	input.facts.tasks.ship == null
}

test_a_recorded_argv_fires if {
	some v in violation with input as {"facts": {"tasks": {"lint": ["probe-tool", "--strict"]}}}
	v.rule == "probe-argv"
}

test_a_compound_task_fires_the_other_class if {
	some v in violation with input as {"facts": {"tasks": {"ship": null}}}
	v.rule == "probe-compound"
}

test_could_not_look_fires_neither if {
	count(violation) == 0 with input as {"call": {"command": "a && b"}, "facts": {"tasks": null}}
}
"#;

/// The same manifest, plus a HAND-WRITTEN row selecting the very call the module
/// selects — the pair CLOUD-1050's class needs and the committed tree cannot
/// supply as evidence (see `a_hand_written_row_outranks_a_module`).
fn contested_config() -> String {
    format!(
        "{}\n{}",
        config(),
        r#"[[rule]]
id = "probe-pinned"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "probe-tool"
require_via = "mise"
reason = "reach it through the runner: mise exec -- probe-tool"
"#
    )
}

/// [`with_manifest`], with the contested config.
fn contested(name: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("task-receipt-{name}"));
    let home = scratch(&format!("task-receipt-home-{name}"));
    write(&dir, "batten.toml", &contested_config());
    write(&dir, "probe.rego", PROBE);
    write(&dir, "manifest.toml", MANIFEST);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    (dir, home)
}

/// A repository declaring one manifest, plus a scrubbed state home.
fn fixture(name: &str) -> (PathBuf, PathBuf) {
    with_manifest(name, MANIFEST)
}

/// [`fixture`] over a named manifest body.
fn with_manifest(name: &str, manifest: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("task-receipt-{name}"));
    let home = scratch(&format!("task-receipt-home-{name}"));
    write(&dir, "batten.toml", &config());
    write(&dir, "probe.rego", PROBE);
    write(&dir, "manifest.toml", manifest);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    (dir, home)
}

/// The envelope a host sends for one event.
fn envelope(event: &str, command: &str) -> String {
    serde_json::json!({
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

/// Drive `batten hook` for one event, with the state root contained.
///
/// Spelled here rather than through `common::run_with_stdin`, which takes a
/// directory and builds its own command: this suite needs the state home
/// CONTAINED, or the receipt lands in the developer's real state root and the
/// cases read each other's records.
fn hook(dir: &Path, home: &Path, event: &str, command: &str) -> std::process::Output {
    let mut invocation = batten();
    invocation
        .current_dir(dir)
        .state_home(home)
        .args(["hook", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = invocation.spawn().expect("spawn batten hook");
    {
        use std::io::Write as _;
        let mut sink = child.stdin.take().expect("the child's stdin");
        sink.write_all(envelope(event, command).as_bytes())
            .expect("write the envelope");
    }
    child.wait_with_output().expect("run batten hook")
}

/// Mint the receipt the way a session does, then return the fixture.
fn minted(name: &str) -> (PathBuf, PathBuf) {
    let (dir, home) = fixture(name);
    let started = hook(&dir, &home, "SessionStart", "");
    assert!(
        started.status.success(),
        "session start must not fail: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    (dir, home)
}

#[test]
fn a_session_start_mints_a_receipt_a_call_can_read() {
    // THE POSITIVE, and it is a statement about two events rather than one: the
    // parse happens at session start and the answer survives to the call. Before
    // this family the mediated path had no way to reach a manifest at all, so
    // `cargo-substitutes-for-a-task` stayed in bash while the rest of its guard
    // moved.
    let (dir, home) = minted("positive");
    let outcome = hook(&dir, &home, "PreToolUse", "probe-tool --lenient");
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let cause = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        answer.contains("probe-argv") || cause.contains("probe-argv"),
        "the receipt's argv must reach the module\n{answer}{cause}"
    );
}

#[test]
fn a_compound_task_is_recorded_with_no_argv() {
    // THE POSITIVE CONTROL (CLOUD-418), and a real distinction rather than a
    // second spelling of the first: `ship` is recorded because the task EXISTS,
    // and its argv is null because the body is not a single command. A projection
    // that dropped such a task would make it indistinguishable from one the
    // manifest never defined, and a projection that reduced it to a word list
    // would let a guard refuse a call by naming a command the task never runs.
    let (dir, home) = with_manifest("compound", COMPOUND_ONLY);
    let started = hook(&dir, &home, "SessionStart", "");
    assert!(started.status.success(), "session start must not fail");
    let outcome = hook(&dir, &home, "PreToolUse", "probe-tool --lenient");
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let cause = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        answer.contains("probe-compound") || cause.contains("probe-compound"),
        "a task with no single argv must be present and null\n{answer}{cause}"
    );
}

#[test]
fn the_mediated_call_digests_the_manifest_and_never_parses_it() {
    // THE INSTRUMENTATION CASE the row's acceptance names, and it took a
    // correction to state honestly. The first draft deleted the manifest and
    // expected the call to answer — but the receipt's key is RECOMPUTED from the
    // manifest's bytes at read time, which is exactly what makes staleness
    // structural, so a deleted manifest is could-not-look by design.
    //
    // The guarantee is therefore "reads bytes, parses nothing", and this is what
    // discriminates the two: a manifest that is NOT valid TOML, with a record
    // written over it through the module's own public writer. A read that parsed
    // would answer could-not-look here; a read that digests answers.
    //
    // The record is written by `taskset::record` rather than hand-spelled,
    // because a fixture that spells the bytes itself passes while the real writer
    // and the real reader disagree (CLOUD-1093).
    let (dir, home) = with_manifest("no-parse", "this is not TOML at all {{{\n");
    let mut tasks = std::collections::BTreeMap::new();
    tasks.insert(
        String::from("lint"),
        Some(vec![String::from("probe-tool"), String::from("--strict")]),
    );
    assert!(
        batten::taskset::record(&dir, &[dir.join("manifest.toml")], &tasks),
        "the module's own writer must be able to record"
    );

    let outcome = hook(&dir, &home, "PreToolUse", "probe-tool --lenient");
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let cause = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        answer.contains("probe-argv") || cause.contains("probe-argv"),
        "the call must digest the manifest, never parse it\n{answer}{cause}"
    );
}

#[test]
fn a_moved_manifest_does_not_answer() {
    // THE ANTI-STALENESS CASE, and the one the family lives on. The receipt is
    // readable and says `--strict`; the manifest now says `--lenient`. That is
    // not a stale answer to be trusted a little, it is an answer about a
    // different toolchain — so the key recomputed at read time does not match and
    // the whole fact is could-not-look.
    //
    // Distinguishable from the positive by the only means that discriminates: the
    // same fixture, the same module, one file's bytes changed.
    let (dir, home) = minted("moved");
    write(&dir, "manifest.toml", MOVED);
    let outcome = hook(&dir, &home, "PreToolUse", "probe-tool --lenient");
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let cause = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        !answer.contains("probe-argv") && !cause.contains("probe-argv"),
        "a receipt about a manifest that moved must not answer\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-compound") && !cause.contains("probe-compound"),
        "the WHOLE fact is could-not-look, not the changed half\n{answer}{cause}"
    );
}

#[test]
fn a_call_with_no_receipt_is_could_not_look() {
    // NEVER AN EMPTY TASK TABLE, which is the direction this fact must fail in: a
    // guard comparing a call against an empty table would refuse every command
    // the project runs. Distinguishable from the positive by the only means that
    // discriminates — the same fixture with session start never having run.
    let (dir, home) = fixture("unminted");
    let outcome = hook(&dir, &home, "PreToolUse", "probe-tool --lenient");
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let cause = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        !answer.contains("probe-argv") && !cause.contains("probe-argv"),
        "an unminted receipt must not answer\n{answer}{cause}"
    );
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "and must never be a refusal\n{answer}{cause}"
    );
}

/// A hand-written row outranks a module over a call BOTH select.
///
/// # The defect, and why nothing caught it
///
/// `adjudicate` ran `policy_rules` before `shape_rules`, while the comment
/// beside it said the opposite — "a row a reviewer wrote by hand is the one they
/// should see quoted back, and its reason is more specific than a module's". So
/// for every call both select, the module won and the reviewer's own remedy was
/// never rendered.
///
/// Measured on this repository's own policy: `cargo test -p batten` selects
/// `no-bare-cargo`, whose reason names both sanctioned routes, and
/// `task-substitution`, whose subject is whichever declared task leads with
/// `cargo` — 13 do. The reader was told to run `attribution-identity`, a task
/// that has nothing to do with running tests: a remedy that does not do the job,
/// which is the class CLOUD-1050 made unrepresentable in a verdict's own prose
/// and the gate ordering put back.
///
/// **CI could never have seen it.** A module reading `input.facts.tasks` is
/// could-not-look until a session-start receipt exists, so `task-substitution`
/// is live in an agent session and inert on a runner — which is exactly why this
/// case mints the receipt itself rather than asserting over the committed tree.
/// A case over the committed tree passes on a runner whichever way the gates are
/// ordered, and is therefore no evidence at all.
#[test]
fn a_hand_written_row_outranks_a_module() {
    let (dir, home) = contested("precedence");
    let started = hook(&dir, &home, "SessionStart", "");
    assert!(
        started.status.success(),
        "session start must not fail: {}",
        String::from_utf8_lossy(&started.stderr)
    );

    // Both rows select this call: the module fires on the recorded argv, and the
    // shape row refuses the program for having been reached without the pin.
    let outcome = hook(&dir, &home, "PreToolUse", "probe-tool --strict");
    let cause = String::from_utf8_lossy(&outcome.stderr);
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let said = format!("{answer}{cause}");

    // CLOUD-1286: WHICH row answered is read off the id on the line rather than
    // off its remedy, and that is the stricter test of precedence anyway — a
    // remedy is prose two rows could share, an id is not.
    assert!(
        said.contains("probe-pinned"),
        "the hand-written row is what answered: {said}"
    );
    assert!(
        !said.contains("task argv probe"),
        "and the module must not have answered first: {said}"
    );
}

/// The module still answers where NO hand-written row selects the call.
///
/// Without this the fix above is indistinguishable from disabling modules on the
/// command path: hoisting `shape_rules` would pass the case above by making
/// `policy_rules` unreachable, and a gate that stopped deciding reads exactly
/// like one that lost a race it should lose.
#[test]
fn the_module_still_answers_where_no_hand_written_row_selects() {
    let (dir, home) = contested("precedence-uncontested");
    let started = hook(&dir, &home, "SessionStart", "");
    assert!(started.status.success(), "session start must not fail");

    // `probe-argv` fires on the RECORDED argv rather than on this command line,
    // so it answers here too — and `probe-pinned` selects `probe-tool`, which
    // this call is not.
    let outcome = hook(&dir, &home, "PreToolUse", "some-other-tool --strict");
    let cause = String::from_utf8_lossy(&outcome.stderr);
    let answer = String::from_utf8_lossy(&outcome.stdout);
    let said = format!("{answer}{cause}");

    assert!(
        said.contains("task argv probe") || said.contains("probe-argv"),
        "the module is still on the command path: {said}"
    );
}
