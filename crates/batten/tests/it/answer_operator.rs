//! `policy/answer-the-operator.rego` over the compiled engine.
//!
//! The module's own `test_` cases hand themselves a count; these prove the count
//! is what the ENGINE computes from a real transcript shape, including the
//! host's `queued_command` attachment for a message sent mid-turn, which is the
//! case this row was measured on.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::StreamedChild as _;

use std::path::{Path, PathBuf};

use common::{StateHome as _, at_root, batten, init_repo, scratch, write};

/// Prose distinctive enough that finding it anywhere is unambiguous.
const PROSE: &str = "OPERATOR-PROSE-THAT-MUST-NOT-REACH-ANY-OUTPUT";

const TOKEN: &str = "turn answer missing";

fn config() -> String {
    r#"version = 1

[[rule]]
id = "turn answer missing"
kind = "policy"
scope = "mediated_call"
module = "answer-the-operator.rego"
severity = "deny"

[[rule.extract]]
id = "unanswered-human-calls"
count = "unanswered-human-calls"

[[verdict]]
id = "turn answer missing"
gloss = "the operator spoke and this session answered only with tool calls"
class = "A fixture copy of the shipped class."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "answer-the-operator.rego"
"#
    .to_owned()
}

/// The operator typing a prompt.
fn prompt() -> serde_json::Value {
    serde_json::json!({
        "type": "user", "sessionId": "s-1",
        "message": {"role": "user", "content": PROSE},
    })
}

/// The operator sending a message while a turn runs, as the host records it.
fn queued() -> serde_json::Value {
    serde_json::json!({
        "type": "attachment", "sessionId": "s-1",
        "attachment": {"type": "queued_command", "prompt": PROSE,
                       "commandMode": "prompt", "origin": {"kind": "human"},
                       "humanTurn": true},
    })
}

fn said() -> serde_json::Value {
    serde_json::json!({
        "type": "assistant", "sessionId": "s-1",
        "message": {"role": "assistant", "content": [{"type": "text", "text": PROSE}]},
    })
}

fn acted(index: usize) -> serde_json::Value {
    serde_json::json!({
        "type": "assistant", "sessionId": "s-1",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": format!("t{index}"), "name": "Bash",
             "input": {"command": PROSE}}
        ]},
    })
}

fn result(index: usize) -> serde_json::Value {
    serde_json::json!({
        "type": "user", "sessionId": "s-1",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": format!("t{index}"), "content": PROSE}
        ]},
    })
}

fn fixture(name: &str, records: &[serde_json::Value]) -> (PathBuf, PathBuf, PathBuf) {
    let dir = scratch(&format!("answer-operator-{name}"));
    let home = scratch(&format!("answer-operator-home-{name}"));
    write(&dir, "batten.toml", &config());
    let body = std::fs::read_to_string(at_root("policy/answer-the-operator.rego"))
        .expect("the shipped module is committed");
    write(&dir, "answer-the-operator.rego", &body);
    init_repo(&dir);
    let jsonl = records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    write(&dir, "session.jsonl", &jsonl);
    let path = dir.join("session.jsonl");
    (dir, home, path)
}

fn channels(dir: &Path, home: &Path, transcript: &Path) -> String {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "probe-command"},
        "transcript_path": transcript.display().to_string(),
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
        child
            .stdin
            .take()
            .expect("the child's stdin")
            .write_all(envelope.as_bytes())
            .expect("write the envelope");
    }
    let outcome = child.streamed_wait().expect("run batten hook");
    format!(
        "{}{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    )
}

fn refused(records: &[serde_json::Value], name: &str) -> bool {
    let (dir, home, transcript) = fixture(name, records);
    channels(&dir, &home, &transcript).contains(TOKEN)
}

#[test]
fn a_mid_turn_message_answered_by_tools_alone_is_refused() {
    // The measured shape: the session is working, the operator sends a message,
    // and the next action is another tool call with nothing said.
    let records = [prompt(), said(), acted(0), result(0), queued(), acted(1)];
    assert!(
        refused(&records, "mid-turn"),
        "an ignored mid-turn message must be refused"
    );
}

#[test]
fn a_prompt_answered_by_tools_alone_is_refused() {
    let records = [prompt(), acted(0)];
    assert!(
        refused(&records, "prompt"),
        "a prompt answered only by a tool call must be refused"
    );
}

#[test]
fn text_after_the_message_clears_it() {
    // THE DISCHARGE, and why `deny` cannot wedge a session: text is never a
    // mediated call, and one sentence zeroes the count.
    let records = [
        prompt(),
        said(),
        acted(0),
        result(0),
        queued(),
        said(),
        acted(1),
    ];
    assert!(
        !refused(&records, "answered"),
        "an answered message must not be refused"
    );
}

#[test]
fn tool_results_are_not_the_operator_speaking() {
    // A host renders tool results in the user role; they must not count as the
    // operator, or every action after a result would be refused.
    let records = [
        prompt(),
        said(),
        acted(0),
        result(0),
        acted(1),
        result(1),
        acted(2),
    ];
    assert!(
        !refused(&records, "results"),
        "tool results are not operator messages"
    );
}

/// A background task's completion as the host records it: a bare user-role
/// string whose `origin.kind` is not `human`.
fn notified() -> serde_json::Value {
    serde_json::json!({
        "type": "user", "sessionId": "s-1", "origin": {"kind": "task-notification"},
        "message": {"role": "user", "content": PROSE},
    })
}

#[test]
fn a_task_notification_is_not_the_operator_speaking() {
    // Measured: 300 records of this shape in one session. Read as the operator,
    // the gate would demand narration after every background task.
    let records = [prompt(), said(), acted(0), notified(), acted(1)];
    assert!(
        !refused(&records, "notified"),
        "a task notification is not an operator message"
    );
}

#[test]
fn a_queued_message_marked_only_by_origin_is_the_operator() {
    let records = [
        prompt(),
        said(),
        serde_json::json!({
            "type": "attachment", "sessionId": "s-1",
            "attachment": {"type": "queued_command", "prompt": PROSE,
                           "commandMode": "prompt", "origin": {"kind": "human"}},
        }),
        acted(0),
    ];
    assert!(
        refused(&records, "origin-only"),
        "origin.kind human is the operator"
    );
}

/// A Claude Code Stop over `transcript`: the exit code and both channels.
fn stopped(dir: &Path, home: &Path, transcript: &Path, active: bool) -> (Option<i32>, String) {
    let envelope = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "stop_hook_active": active,
        "transcript_path": transcript.display().to_string(),
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
        child
            .stdin
            .take()
            .expect("the child's stdin")
            .write_all(envelope.as_bytes())
            .expect("write the envelope");
    }
    let outcome = child.streamed_wait().expect("run batten hook");
    (
        outcome.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&outcome.stdout),
            String::from_utf8_lossy(&outcome.stderr)
        ),
    )
}

/// CLOUD-2861: a turn the operator opened and only tool calls answered cannot
/// end. The refusal names the message's transcript line and nothing on it.
///
/// Fails by: the Stop rung removed, where the finding is only advice and the
/// Stop exits 0.
#[test]
fn a_stop_after_an_operator_message_answered_by_tools_alone_is_refused() {
    let (dir, home, transcript) = fixture("stop-refused", &[said(), prompt(), acted(0)]);
    let (code, out) = stopped(&dir, &home, &transcript, false);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains(TOKEN), "{out}");
    assert!(
        out.contains("session.jsonl:2"),
        "the operator line is named\n{out}"
    );
    assert!(
        !out.contains(PROSE),
        "no session text may reach any output\n{out}"
    );
}

#[test]
fn a_stop_after_one_text_block_ends() {
    let (dir, home, transcript) =
        fixture("stop-answered", &[prompt(), acted(0), result(0), said()]);
    let (code, out) = stopped(&dir, &home, &transcript, false);
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn a_stop_after_a_task_notification_ends_without_text() {
    let records = [prompt(), said(), acted(0), notified(), acted(1)];
    let (dir, home, transcript) = fixture("stop-notified", &records);
    let (code, out) = stopped(&dir, &home, &transcript, false);
    assert_eq!(code, Some(0), "{out}");
}

/// One refusal per operator message: the receipt holds the second Stop open,
/// and the finding still reaches the advisory channel.
///
/// Fails by: the receipt unread or unwritten, which refuses every Stop over
/// the same message (CLOUD-889's loop).
#[test]
fn the_second_stop_over_the_same_message_is_advice() {
    let (dir, home, transcript) = fixture("stop-twice", &[prompt(), acted(0)]);
    let (first, out) = stopped(&dir, &home, &transcript, false);
    assert_eq!(first, Some(2), "{out}");
    let (second, out) = stopped(&dir, &home, &transcript, false);
    assert_eq!(second, Some(0), "{out}");
    assert!(out.contains(TOKEN), "the finding stays advice\n{out}");
}

#[test]
fn a_stop_with_stop_hook_active_is_never_refused() {
    let (dir, home, transcript) = fixture("stop-active", &[prompt(), acted(0)]);
    let (code, out) = stopped(&dir, &home, &transcript, true);
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn no_transcript_text_reaches_any_output() {
    let records = [prompt(), acted(0)];
    let (dir, home, transcript) = fixture("scrub", &records);
    let out = channels(&dir, &home, &transcript);
    assert!(
        !out.contains(PROSE),
        "no session text may reach any output\n{out}"
    );
}
