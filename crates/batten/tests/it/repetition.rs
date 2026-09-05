//! `policy/repetition-without-progress.rego` over the compiled engine (CLOUD-1344).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `facts.extracted` object, so
//! they are green over a shape the engine may never build. Two things here can
//! only be proved against the real boundary, and both are this row's whole point:
//!
//! * that `agent-turn-run` is the RUN the engine computes, not the author's
//!   arithmetic — a fabricated `{"agent-turn-run": 3}` asserts the latter;
//! * that an extraction this host cannot answer is **absent** from the map rather
//!   than reported as `0`. A `with input as` case cannot distinguish those at all,
//!   because it writes the map itself.
//!
//! # The probe, and why the shipped module cannot do this alone
//!
//! Absent and zero are both SILENT under a `>= 3` predicate, so the shipped module
//! cannot tell them apart and neither can a test over it. [`PROBE`] carries two
//! predicates that can: one fires only where the key is undefined, the other only
//! where it is present and zero. In Rego `not x` succeeds on undefined and fails
//! on `0`, because `0` is a value — that asymmetry is the whole discriminator.
//!
//! # Confirming the channel
//!
//! `the_module_channel_is_live` carries an UNCONDITIONAL `violation` body. A probe
//! whose only clause reads the thing under test cannot tell an empty answer from a
//! module that never ran, which is exactly how CLOUD-1049's dead channel survived
//! two measurements.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{StateHome as _, at_root, batten, git_in, scratch, write};

/// Prose distinctive enough that finding it anywhere is unambiguous.
const PROSE: &str = "REPETITION-PROSE-THAT-MUST-NOT-REACH-ANY-OUTPUT";

/// The SHIPPED module's registration, so a mutation of it reddens these cases.
///
/// **`deny` here where the repository ships `warn`, deliberately.** This fixture
/// pins the PREDICATE; the severity the row ships at is CLOUD-1352's decision.
///
/// **No `[[pattern]]` rows**, so the tier gets the same empty vocabulary a
/// consumer has: declaring pattern ids would supply input no consumer supplies.
fn config(module: &str, extra: &str) -> String {
    format!(
        r#"version = 1

[[rule]]
id = "repetition-without-progress"
kind = "policy"
scope = "mediated_call"
module = "{module}"
severity = "deny"

[[rule.extract]]
id = "agent-turn-run"
count = "agent-turn-run"
{extra}
[[verdict]]
id = "turn run loose"
gloss = "this session has taken several turns in a row without doing anything"
class = "Several turns in a row with no tool call between them."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "{module}"
"#
    )
}

/// Two predicates that separate an ABSENT key from a present zero.
///
/// `not input.facts.extracted["agent-turn-run"]` succeeds only where the key is
/// undefined: `0` is a value in Rego, so `not 0` fails. That is the discriminator
/// the shipped module cannot express, because both are silent under `>= 3`.
const PROBE: &str = r#"package batten.repetition_without_progress

import rego.v1

rules contains "run-absent"

rules contains "run-zero"

violation contains {
	"rule": "run-absent",
	"verdict": "extract absent probe",
} if {
	is_object(input.facts.extracted)
	not input.facts.extracted["agent-turn-run"]
}

violation contains {
	"rule": "run-zero",
	"verdict": "extract zero probe",
} if {
	is_object(input.facts.extracted)
	input.facts.extracted["agent-turn-run"] == 0
}

test_absent_fires_on_an_undeclared_key if {
	some v in violation with input as {"call": {"command": "a && b"}, "facts": {"extracted": {}}}
	v.rule == "run-absent"
}

test_zero_fires_on_a_real_zero if {
	some v in violation with input as {"call": {"command": "a && b"}, "facts": {"extracted": {"agent-turn-run": 0}}}
	v.rule == "run-zero"
}
"#;

/// The probe's own verdict rows, appended to the fixture config.
const PROBE_VERDICTS: &str = r#"
[[verdict]]
id = "extract absent probe"
gloss = "the extraction answered could-not-look"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe absent probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "extract zero probe"
gloss = "the extraction answered a real zero"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe zero probe"
kind = "document"
target = "probe.rego"
"#;

/// An assistant turn carrying only text — a monologue step, no action.
fn thinking(index: usize) -> serde_json::Value {
    serde_json::json!({
        "type": "assistant",
        "sessionId": "s-1",
        "message": {"role": "assistant", "content": [
            {"type": "text", "text": format!("{PROSE}-{index}")}
        ]},
    })
}

/// An assistant turn that calls a tool — an action, which breaks any run.
fn acting(index: usize) -> serde_json::Value {
    serde_json::json!({
        "type": "assistant",
        "sessionId": "s-1",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": format!("t{index}"), "name": "Bash",
             "input": {"command": PROSE}}
        ]},
    })
}

fn jsonl(records: &[serde_json::Value]) -> String {
    records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn fixture(name: &str, module_body: &str, transcript: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = scratch(&format!("repetition-{name}"));
    let home = scratch(&format!("repetition-home-{name}"));
    let shipped = module_body.is_empty();
    let (module_name, extra) = if shipped {
        ("repetition-without-progress.rego", "")
    } else {
        ("probe.rego", PROBE_VERDICTS)
    };
    write(&dir, "batten.toml", &config(module_name, extra));
    if shipped {
        let body = std::fs::read_to_string(at_root("policy/repetition-without-progress.rego"))
            .expect("the shipped module is committed");
        write(&dir, module_name, &body);
    } else {
        write(&dir, module_name, module_body);
    }
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "session.jsonl", transcript);
    let path = dir.join("session.jsonl");
    (dir, home, path)
}

fn channels(dir: &Path, home: &Path, transcript: Option<&Path>) -> (String, String) {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "probe-command"},
        "transcript_path": transcript.map(|path| path.display().to_string()),
    })
    .to_string();
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
    let outcome = child.wait_with_output().expect("run batten hook");
    (
        String::from_utf8_lossy(&outcome.stdout).into_owned(),
        String::from_utf8_lossy(&outcome.stderr).into_owned(),
    )
}

fn says(dir: &Path, home: &Path, transcript: &Path, token: &str) -> bool {
    let (answer, cause) = channels(dir, home, Some(transcript));
    answer.contains(token) || cause.contains(token)
}

// --- (a) the member decides -------------------------------------------------

#[test]
fn a_monologue_run_is_reported() {
    // The case `#MUTANT run-may-go-unbounded` names. Three assistant turns with no
    // tool call between them is a run of 3 — OpenHands' monologue threshold.
    let records: Vec<_> = (0..3).map(thinking).collect();
    let (dir, home, transcript) = fixture("monologue", "", &jsonl(&records));
    assert!(
        says(&dir, &home, &transcript, "turn run loose"),
        "three turns in a row with no action must reach the threshold"
    );
}

#[test]
fn an_action_between_turns_clears_the_run() {
    // ADJACENCY IS WHAT DOES THE FALSE-POSITIVE WORK, and this is the arm that
    // says so. The same turns, with the session acting last: the run is broken, so
    // a session thinking between actions never reaches the threshold.
    let records = vec![thinking(0), thinking(1), thinking(2), acting(3)];
    let (dir, home, transcript) = fixture("acted", "", &jsonl(&records));
    assert!(
        !says(&dir, &home, &transcript, "turn run loose"),
        "a session that acts has no trailing monologue run"
    );
}

#[test]
fn two_turns_in_a_row_is_not_a_run() {
    // The boundary from below, decided by the ENGINE rather than by a fabricated
    // count: a run counts TURNS, so two is two and is below the threshold.
    let records: Vec<_> = (0..2).map(thinking).collect();
    let (dir, home, transcript) = fixture("two", "", &jsonl(&records));
    assert!(
        !says(&dir, &home, &transcript, "turn run loose"),
        "two turns are below the threshold"
    );
}

// --- (b) and (c) could-not-look is not zero ---------------------------------

#[test]
fn a_host_that_records_no_turns_answers_could_not_look() {
    // THE CROSS-COMPATIBILITY CASE, and the only one distinguishing this row from
    // an absent gate. A transcript the parser reads but which carries no turn
    // boundaries at all must leave the key ABSENT — never `0`, which is a real
    // count meaning the extractor ran.
    //
    // A HOOK RUN AND NOTHING ELSE. A `user` record will not do: the parser reads
    // one as a turn, so a transcript built from those records turns after all and
    // the answer is a real zero. This host records hook decisions and no turn
    // boundaries at all, which is the shape the claim is actually about.
    let records = vec![serde_json::json!({
        "type": "attachment",
        "sessionId": "s-1",
        "attachment": {
            "type": "hook_success",
            "hookEvent": "PreToolUse",
            "hookName": "PreToolUse:Bash",
            "toolUseID": "t0",
            "exitCode": 0,
            "stderr": PROSE,
        },
    })];
    let (dir, home, transcript) = fixture("no-turns", PROBE, &jsonl(&records));
    assert!(
        says(&dir, &home, &transcript, "extract absent probe"),
        "a host recording no turns must answer could-not-look for this extraction"
    );
    assert!(
        !says(&dir, &home, &transcript, "extract zero probe"),
        "could-not-look must not be reported as a zero"
    );
}

#[test]
fn a_session_with_no_run_is_a_real_zero() {
    // DISTINCT FROM THE CASE ABOVE, and the pair is what makes either meaningful.
    // Turns ARE recorded here and the trailing run is genuinely zero, so the key is
    // present and the answer is a real count.
    let records = vec![thinking(0), acting(1)];
    let (dir, home, transcript) = fixture("real-zero", PROBE, &jsonl(&records));
    assert!(
        says(&dir, &home, &transcript, "extract zero probe"),
        "a recorded session with no trailing run answers a real zero"
    );
    assert!(
        !says(&dir, &home, &transcript, "extract absent probe"),
        "a real zero must not read as could-not-look"
    );
}

// --- the channel, and rule 4 ------------------------------------------------

#[test]
fn a_missing_transcript_is_not_a_clean_session() {
    // COULD NOT LOOK IS NOT INNOCENCE. A host that hands over no path is the common
    // case, and reading it as "nothing happened" is the false green.
    let records: Vec<_> = (0..9).map(thinking).collect();
    let (dir, home, _transcript) = fixture("absent", "", &jsonl(&records));
    let (answer, cause) = channels(&dir, &home, None);
    assert!(
        !answer.contains("turn run loose") && !cause.contains("turn run loose"),
        "an unlooked-at session is not a finding\n{answer}{cause}"
    );
}

#[test]
fn no_transcript_text_reaches_any_output() {
    // RULE 4, as a standing guarantee. Only a count is projected, so finding the
    // fixture's prose in either channel is the leak.
    let records: Vec<_> = (0..9).map(thinking).collect();
    let (dir, home, transcript) = fixture("scrub", "", &jsonl(&records));
    let (answer, cause) = channels(&dir, &home, Some(&transcript));
    assert!(
        !answer.contains(PROSE) && !cause.contains(PROSE),
        "no session text may reach any output\n{answer}{cause}"
    );
}
