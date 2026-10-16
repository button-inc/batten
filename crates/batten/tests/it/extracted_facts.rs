//! `input.facts.extracted`, over the compiled binary (CLOUD-1172).
//!
//! **This is the family where rule 4 is most at risk, so it is asserted twice
//! and in two different ways.** `no_transcript_text_reaches_any_output` searches
//! both channels for prose that is in the fixture transcript, and the projection
//! itself can carry nothing else: the extractor set is closed and every member
//! resolves to an integer, so a span of session text has no shape to travel in.
//! A transcript holds every command, every file body and every prompt the session
//! touched — worse than the commit body CLOUD-1168 declines to carry, because a
//! body is authored and a transcript is captured.
//!
//! **Could-not-look is the COMMON case, not the edge one** (CLOUD-388:
//! transcripts die with their container), which is why
//! `a_missing_transcript_is_not_a_clean_session` is the case the row's acceptance
//! says it fails its own review without. A gate that read "no transcript" as
//! "nothing was stranded" would report clean on every host that never had one —
//! the false green CLOUD-990 measured costing a session an hour.
//!
//! A `with input as` case can assert none of this: it fabricates the shape the
//! engine may be unable to produce (CLOUD-845, CLOUD-857), and here it would
//! fabricate the transcript read itself.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{StateHome as _, batten, scratch, write};

/// Prose distinctive enough that finding it anywhere is unambiguous — standing in
/// for everything a real transcript carries.
const PROSE: &str = "TRANSCRIPT-PROSE-THAT-MUST-NOT-REACH-ANY-OUTPUT";

fn config() -> String {
    String::from(
        r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "mediated_call"
module = "probe.rego"
severity = "deny"

[[rule.extract]]
id = "denials"
count = "hook-denials"

[[rule.extract]]
id = "calls"
count = "tool-calls"

[[verdict]]
id = "extract denials probe"
gloss = "the declared extractor counted a denial"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe denials probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "extract calls probe"
gloss = "the declared extractor counted the tool calls"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe calls probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "extract undeclared probe"
gloss = "an extractor no row declared answered anyway"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe undeclared probe"
kind = "document"
target = "probe.rego"
"#,
    )
}

/// Three predicates, and the set is what discriminates.
///
/// `probe-calls` fires on an EXACT count, so a projection emitting a constant
/// fails it. `probe-undeclared` must never fire: `turns` is a real member of the
/// extraction set that this config does not declare, so its absence is what makes
/// the declaration the bound.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-denials"

rules contains "probe-calls"

rules contains "probe-undeclared"

violation contains {
	"rule": "probe-denials",
	"verdict": "extract denials probe",
} if {
	is_object(input.facts.extracted)
	input.facts.extracted.denials == 1
}

violation contains {
	"rule": "probe-calls",
	"verdict": "extract calls probe",
} if {
	is_object(input.facts.extracted)
	input.facts.extracted.calls == 2
}

violation contains {
	"rule": "probe-undeclared",
	"verdict": "extract undeclared probe",
} if {
	is_object(input.facts.extracted)
	input.facts.extracted.turns
}

test_a_declared_count_fires if {
	some v in violation with input as {"call": {"command": "a && b"}, "facts": {"extracted": {"denials": 1}}}
	v.rule == "probe-denials"
}

test_another_declared_count_fires_its_own_class if {
	some v in violation with input as {"call": {"command": "a && b"}, "facts": {"extracted": {"calls": 2}}}
	v.rule == "probe-calls"
}

test_could_not_look_fires_nothing if {
	count(violation) == 0 with input as {"call": {"command": "a && b"}, "facts": {"extracted": null}}
}
"#;

/// A session record with `tool_calls` calls and, optionally, one denied hook run.
///
/// Written in the host's own shape so `transcript::parse` reads it the way it
/// reads a real one — and carrying [`PROSE`], because a fixture with nothing
/// secret in it could not show that nothing secret escapes.
fn session_with(tool_calls: usize, denied: bool) -> String {
    // THE HOST'S REAL SHAPE, taken from `transcript.rs`'s own corpus rather than
    // invented: a hook record is an `attachment` carrying `hookEvent` and
    // `exitCode`, not a `system` line. A fixture in a shape the parser does not
    // read would count zero and this suite would assert over a transcript nobody
    // parsed — the fabrication CLOUD-845 is about, one layer down.
    let mut lines: Vec<serde_json::Value> = Vec::new();
    for index in 0..tool_calls {
        lines.push(serde_json::json!({
            "type": "assistant",
            "sessionId": "s-1",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": format!("t{index}"), "name": "Bash",
                 "input": {"command": PROSE}}
            ]},
        }));
    }
    if denied {
        lines.push(serde_json::json!({
            "type": "attachment",
            "sessionId": "s-1",
            "attachment": {
                "type": "hook_success",
                "hookEvent": "PreToolUse",
                "hookName": "PreToolUse:Bash",
                "toolUseID": "t0",
                "exitCode": 2,
                "stderr": PROSE,
            },
        }));
    }
    lines.push(serde_json::json!({
        "type": "user",
        "sessionId": "s-1",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t0", "is_error": true, "content": PROSE}
        ]},
    }));
    lines.push(serde_json::json!({
        "type": "user",
        "sessionId": "s-1",
        "message": {"role": "user", "content": PROSE},
    }));
    lines
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A repository declaring two extractors, plus a scrubbed state home.
///
/// `transcript` is `None` for the host that hands over no path — the common case
/// (CLOUD-388), and the one that must not read as a clean session.
fn fixture(name: &str, transcript: Option<&str>) -> (PathBuf, PathBuf, Option<PathBuf>) {
    let fixture = fixture_with(&format!("extracted-{name}"), &config(), transcript);
    write(&fixture.0, "probe.rego", PROBE);
    fixture
}

/// A repository under `name` carrying `config`, a scrubbed state home, and the
/// session record `transcript`, if any.
fn fixture_with(
    name: &str,
    config: &str,
    transcript: Option<&str>,
) -> (PathBuf, PathBuf, Option<PathBuf>) {
    let dir = scratch(name);
    let home = scratch(&format!("{name}-home"));
    write(&dir, "batten.toml", config);
    common::init_repo(&dir);
    let path = transcript.map(|body| {
        write(&dir, "session.jsonl", body);
        dir.join("session.jsonl")
    });
    (dir, home, path)
}

/// Drive `batten hook` for one call, with the state root contained.
fn hook(dir: &Path, home: &Path, transcript: Option<&Path>) -> std::process::Output {
    adjudicate(
        dir,
        home,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "probe-command"},
            "transcript_path": transcript.map(|path| path.display().to_string()),
        }),
    )
}

/// Hand `envelope` to `batten adjudicate`, with the state root contained.
fn adjudicate(dir: &Path, home: &Path, envelope: &serde_json::Value) -> std::process::Output {
    let envelope = envelope.to_string();
    let mut invocation = batten();
    invocation
        .current_dir(dir)
        .state_home(home)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = invocation.spawn().expect("spawn batten hook");
    {
        use std::io::Write as _;
        let mut sink = child.stdin.take().expect("the child's stdin");
        sink.write_all(envelope.as_bytes())
            .expect("write the envelope");
    }
    child.wait_with_output().expect("run batten hook")
}

/// Both channels of one run, as one pair.
fn channels(outcome: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&outcome.stdout).into_owned(),
        String::from_utf8_lossy(&outcome.stderr).into_owned(),
    )
}

#[test]
fn a_declared_extractor_reaches_the_module() {
    // THE POSITIVE. Before this family `input.call.transcript` was the path and
    // nothing could read past it, so `finding-sink-check` and `board-payloads`
    // had no expressible successor at all.
    let (dir, home, transcript) = fixture("positive", Some(&session_with(3, true)));
    let outcome = hook(&dir, &home, transcript.as_deref());
    let (answer, cause) = channels(&outcome);
    assert!(
        answer.contains("probe-denials") || cause.contains("probe-denials"),
        "a declared extractor's count must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_projection_carries_each_extractor_s_own_count() {
    // THE POSITIVE CONTROL (CLOUD-418), and a genuine second measurement rather
    // than a restatement of the first. This session has TWO tool calls and NO
    // denial, so `probe-denials` cannot fire and `probe-calls` fires on an exact
    // count — where the case above has three calls and one denial, so only
    // `probe-denials` can. Each positive excludes the other's predicate, which is
    // what a single decision per mediated call forces and what makes either
    // observation unambiguous.
    //
    // A projection emitting a constant, or one counting the wrong typed event,
    // fails one of the two.
    let (dir, home, transcript) = fixture("control", Some(&session_with(2, false)));
    let outcome = hook(&dir, &home, transcript.as_deref());
    let (answer, cause) = channels(&outcome);
    assert!(
        answer.contains("probe-calls") || cause.contains("probe-calls"),
        "an exact count of a different typed event must decide\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-denials") && !cause.contains("probe-denials"),
        "a session with no denial must not report one\n{answer}{cause}"
    );
}

#[test]
fn no_transcript_text_reaches_any_output() {
    // NON-NEGOTIABLE RULE 4, and this family is where it is most at risk. The
    // fixture's every field carries the same distinctive prose — a user message,
    // a tool call's command, a tool result's body — so if any of it travelled,
    // it would appear here.
    //
    // The projection could not carry it in any case: the extraction set is closed
    // and every member resolves to an integer, so a span has no shape to travel
    // in. This asserts the guarantee rather than trusting the type.
    let (dir, home, transcript) = fixture("prose", Some(&session_with(2, true)));
    let outcome = hook(&dir, &home, transcript.as_deref());
    let (answer, cause) = channels(&outcome);
    for channel in [&answer, &cause] {
        assert!(
            !channel.contains(PROSE),
            "no byte of the session may reach an output channel\n{channel}"
        );
    }
}

#[test]
fn an_undeclared_extractor_yields_nothing() {
    // THE DECLARATION IS THE BOUND. `turns` is a real member of the extraction
    // set that this config does not declare, and the session plainly has turns —
    // so its absence is the projection honouring the declaration rather than the
    // transcript being empty.
    let (dir, home, transcript) = fixture("undeclared", Some(&session_with(2, true)));
    let outcome = hook(&dir, &home, transcript.as_deref());
    let (answer, cause) = channels(&outcome);
    assert!(
        !answer.contains("probe-undeclared") && !cause.contains("probe-undeclared"),
        "an extractor no row declared must not answer\n{answer}{cause}"
    );
}

#[test]
fn a_missing_transcript_is_not_a_clean_session() {
    // THE CASE THE ROW SAYS IT FAILS ITS OWN REVIEW WITHOUT, and the common state
    // rather than the edge one: transcripts die with their container (CLOUD-388),
    // so most hosts most of the time hand over nothing.
    //
    // Distinguishable from a real negative by the only means that discriminates:
    // the same fixture and the same module, with and without a transcript. The
    // positive above fires; this fires nothing AND never refuses — because a gate
    // that read this as "nothing was stranded" would report clean on every host
    // that never had a transcript, which is the false green CLOUD-990 measured
    // costing a session an hour.
    let (dir, home, _) = fixture("no-transcript", None);
    let outcome = hook(&dir, &home, None);
    let (answer, cause) = channels(&outcome);
    assert!(
        !answer.contains("probe-denials") && !cause.contains("probe-denials"),
        "a missing transcript must not answer\n{answer}{cause}"
    );
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "and must never be a refusal\n{answer}{cause}"
    );
}

#[test]
fn an_unreadable_transcript_is_could_not_look() {
    // The fourth non-answer, and the one that is DATA damaged rather than a seam
    // never wired. Operationally it agrees with the case above — nothing answers
    // — and it is a different fact about the world, which is why
    // `transcript::Capability` keeps them apart rather than collapsing them.
    let (dir, home, transcript) = fixture("unreadable", Some("{ this is not JSONL\n"));
    let outcome = hook(&dir, &home, transcript.as_deref());
    let (answer, cause) = channels(&outcome);
    assert!(
        !answer.contains("probe-denials") && !cause.contains("probe-denials"),
        "a torn transcript must not answer\n{answer}{cause}"
    );
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "and must never be a refusal\n{answer}{cause}"
    );
}

// ---------------------------------------------------------------------------
// `plan-exits` and the vendored first-plan refusal (CLOUD-2383)
// ---------------------------------------------------------------------------

/// The operator's correction, which the refusal must carry verbatim.
const PLAN_SENTENCE: &str = "verify, pressure test, validate; present corrected plan";

/// A repository enabling the vendored preset with the count it reads, as the
/// committed authority enables it: one preset row, the extract on that row.
fn plan_fixture(name: &str, transcript: Option<&str>) -> (PathBuf, PathBuf, Option<PathBuf>) {
    fixture_with(
        &format!("plan-exits-{name}"),
        r#"version = 1

[[rule]]
id = "plan check first"
kind = "policy"
scope = "mediated_call"
preset = "claude-code-plan"
severity = "deny"

[[rule.extract]]
id = "plan-exits"
count = "plan-exits"
"#,
        transcript,
    )
}

/// A session whose assistant turns call `tools`, in order, in the host's shape.
/// The last entry stands for the call in flight: the host has written it by the
/// time the pre-tool hook reads the file.
fn calls(tools: &[&str]) -> String {
    tools
        .iter()
        .enumerate()
        .map(|(index, name)| {
            serde_json::json!({
                "type": "assistant",
                "sessionId": "s-1",
                "message": {"role": "assistant", "content": [
                    {"type": "tool_use", "id": format!("t{index}"), "name": name, "input": {}}
                ]},
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Drive one plan-mode presentation through `batten adjudicate`.
fn present(dir: &Path, home: &Path, transcript: Option<&Path>) -> String {
    let outcome = adjudicate(
        dir,
        home,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "permission_mode": "plan",
            "tool_name": "ExitPlanMode",
            "tool_input": {},
            "transcript_path": transcript.map(|path| path.display().to_string()),
        }),
    );
    let (answer, cause) = channels(&outcome);
    format!("{answer}{cause}")
}

#[test]
fn the_first_plan_exit_of_a_session_is_refused_with_the_operator_sentence() {
    let (dir, home, transcript) = plan_fixture("first", Some(&calls(&["ExitPlanMode"])));
    let said = present(&dir, &home, transcript.as_deref());
    assert!(
        said.contains("plan check first") && said.contains("\"deny\""),
        "a session's first presentation must be refused by the vendored class\n{said}"
    );
    assert!(
        said.contains(PLAN_SENTENCE),
        "and the refusal must carry the operator's sentence verbatim\n{said}"
    );
}

#[test]
fn a_second_plan_exit_is_admitted() {
    // The first presentation was refused and stays recorded, so the retry reads 2.
    let (dir, home, transcript) = plan_fixture(
        "second",
        Some(&calls(&["ExitPlanMode", "Read", "ExitPlanMode"])),
    );
    let said = present(&dir, &home, transcript.as_deref());
    assert!(
        !said.contains("plan check first"),
        "a later presentation must not be refused again\n{said}"
    );
}

#[test]
fn a_plan_exit_with_no_transcript_is_admitted() {
    // Could-not-look, the common case (CLOUD-388): an unread count asks nothing.
    let (dir, home, transcript) = plan_fixture("unread", None);
    let said = present(&dir, &home, transcript.as_deref());
    assert!(
        !said.contains("plan check first"),
        "no transcript must never read as a first presentation\n{said}"
    );
}

#[test]
fn plan_exits_counts_only_exit_plan_mode_calls() {
    // Two calls of other tools before the in-flight presentation: a count over
    // every call would read 3 and admit it.
    let (dir, home, transcript) =
        plan_fixture("only", Some(&calls(&["Bash", "Read", "ExitPlanMode"])));
    let said = present(&dir, &home, transcript.as_deref());
    assert!(
        said.contains("plan check first"),
        "calls to other tools must not move the count\n{said}"
    );
}
