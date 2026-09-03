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

use common::{StateHome as _, at_root, batten, git_in, scratch, write};

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

/// The SHIPPED module's own registration, so a mutation of `policy/
/// a-repeated-call-is-not-progress.rego` reddens the cases below.
///
/// **`deny` here where the repository ships `warn`, deliberately.** This fixture
/// pins the PREDICATE — whether the engine builds the count the module reads —
/// and a refusal is the unambiguous observable for that. The severity the row
/// actually ships at is a separate decision, recorded in `batten.toml` beside the
/// row: a `mediated_call` deny refuses every later tool call and no admission can
/// clear it, so it is promoted only once shown silent against a real transcript.
///
/// **No `[[pattern]]` rows, and that is the point.** A harness declaring pattern
/// ids supplies input no consumer supplies, and the deny cases then pass for the
/// wrong reason (`.claude/rules/policy-modules.md`).
fn shipped_config() -> String {
    String::from(
        r#"version = 1

[[rule]]
id = "a-repeated-call-is-not-progress"
kind = "policy"
scope = "mediated_call"
module = "a-repeated-call-is-not-progress.rego"
severity = "deny"

[[rule.extract]]
id = "repeats"
count = "repeated-calls"

[[verdict]]
id = "turn ask twice"
gloss = "this session has already made this call, with these arguments, many times over"
class = "A call you have already made, with the same arguments, told you what it told you the first time."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "a-repeated-call-is-not-progress.rego"
"#,
    )
}

/// `calls` tool calls, each carrying `arguments` for its index.
///
/// The id is always distinct unless `replayed` is set, which re-emits ONE id for
/// every record — the compaction shape whose whole point is that it is not a
/// second call.
fn calls_session(calls: usize, replayed: bool, arguments: &dyn Fn(usize) -> String) -> String {
    let mut lines: Vec<serde_json::Value> = Vec::new();
    for index in 0..calls {
        let id = if replayed {
            String::from("t0")
        } else {
            format!("t{index}")
        };
        lines.push(serde_json::json!({
            "type": "assistant",
            "sessionId": "s-1",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": id, "name": "ReadNotifications",
                 "input": {"command": arguments(index)}}
            ]},
        }));
    }
    lines
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every call identical — one identity recurring `calls - 1` times.
fn repeated_session(calls: usize) -> String {
    calls_session(calls, false, &|_| String::from(PROSE))
}

/// A repository registering the SHIPPED module over a given transcript.
fn shipped_fixture(name: &str, transcript: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = scratch(&format!("repeats-{name}"));
    let home = scratch(&format!("repeats-home-{name}"));
    write(&dir, "batten.toml", &shipped_config());
    let module = std::fs::read_to_string(at_root("policy/a-repeated-call-is-not-progress.rego"))
        .expect("the shipped module is committed");
    write(&dir, "a-repeated-call-is-not-progress.rego", &module);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "session.jsonl", transcript);
    let path = dir.join("session.jsonl");
    (dir, home, path)
}

/// Whether the shipped module refused this run.
fn refused(dir: &Path, home: &Path, transcript: &Path) -> bool {
    let outcome = hook(dir, home, Some(transcript));
    let (answer, cause) = channels(&outcome);
    answer.contains("turn ask twice") || cause.contains("turn ask twice")
}

/// A repository declaring two extractors, plus a scrubbed state home.
///
/// `transcript` is `None` for the host that hands over no path — the common case
/// (CLOUD-388), and the one that must not read as a clean session.
fn fixture(name: &str, transcript: Option<&str>) -> (PathBuf, PathBuf, Option<PathBuf>) {
    let dir = scratch(&format!("extracted-{name}"));
    let home = scratch(&format!("extracted-home-{name}"));
    write(&dir, "batten.toml", &config());
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    let path = transcript.map(|body| {
        write(&dir, "session.jsonl", body);
        dir.join("session.jsonl")
    });
    (dir, home, path)
}

/// Drive `batten hook` for one call, with the state root contained.
fn hook(dir: &Path, home: &Path, transcript: Option<&Path>) -> std::process::Output {
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
        .args(["hook", "--harness", "claude-code"])
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

// --- the shipped module over the engine's own count (CLOUD-1341) --------------

#[test]
fn a_session_that_re_asks_past_the_threshold_is_refused() {
    // THE DEFECT ARM, and the case `#MUTANT repeats-may-go-unpriced` names.
    //
    // N CALLS ARE N-1 RECURRENCES, so clearing a threshold of 100 takes 102 calls
    // rather than 101. That off-by-one is the whole reason this is a compiled tier
    // and not a `with input as` case: a fabricated `{"repeats": 101}` asserts the
    // author's arithmetic, where this asserts the engine's.
    let (dir, home, transcript) = shipped_fixture("past", &repeated_session(102));
    assert!(
        refused(&dir, &home, &transcript),
        "102 identical calls are 101 recurrences and must clear the threshold of 100"
    );
}

#[test]
fn the_call_that_reaches_the_threshold_does_not_cross_it() {
    // THE BOUNDARY FROM BELOW. 101 calls are exactly 100 recurrences, which is AT
    // the threshold and clean — the arm that would go red if the engine counted
    // occurrences where the module reads recurrences.
    let (dir, home, transcript) = shipped_fixture("at", &repeated_session(101));
    assert!(
        !refused(&dir, &home, &transcript),
        "101 identical calls are 100 recurrences, which is at the threshold rather than past it"
    );
}

#[test]
fn a_busy_session_that_never_repeats_is_clean() {
    // THE ANTI-VACUITY MIRROR (CLOUD-418). Without it a predicate firing on any
    // long session satisfies the deny case above while deciding nothing — and this
    // is the arm that a SUM over identities fails: 300 distinct calls sum to 0
    // recurrences per identity but would have summed to nothing useful had the
    // fact been a running total over the stream, which is the defect this row
    // shipped once.
    let (dir, home, transcript) = shipped_fixture(
        "varied",
        &calls_session(300, false, &|index| format!("{PROSE}-{index}")),
    );
    assert!(
        !refused(&dir, &home, &transcript),
        "a long session that repeats nothing must stay silent"
    );
}

#[test]
fn a_replayed_call_is_not_a_second_call() {
    // COMPACTION RE-EMITS A `tool_use` UNDER THE ID IT ALREADY CARRIED, and
    // counting those measures what the host chose to replay rather than what the
    // session did. 300 records under one id are ONE call, so this is silent; an
    // engine that did not dedupe would read 299 recurrences and refuse.
    let (dir, home, transcript) = shipped_fixture(
        "replay",
        &calls_session(300, true, &|_| String::from(PROSE)),
    );
    assert!(
        !refused(&dir, &home, &transcript),
        "a replayed tool_use id is the same call, not another one"
    );
}
