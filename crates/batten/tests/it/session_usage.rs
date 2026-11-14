//! A session reads its own token use from the transcript (CLOUD-415).
//!
//! Every assistant record in a Claude Code transcript carries `message.usage`,
//! and one message is written as several records repeating the same id and
//! usage. These cases hold the fold to exact integers over the compiled binary:
//! `doctor session` for the reading, `adjudicate` for the facts a policy row
//! reads. The stored-format case lives beside the cache key it needs, in
//! `transcript.rs`'s own tests (`a_tally_stored_in_the_old_format_is_folded_again`).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{StateHome as _, batten, git_in, scratch, stdout, write};

/// Prose distinctive enough that finding it anywhere is unambiguous.
const PROSE: &str = "SESSION-USAGE-PROSE-THAT-MUST-NOT-REACH-ANY-OUTPUT";

/// A repository declaring a transcript and no task store.
const DECLARED: &str =
    "version = 1\n\n[transcript]\npath = \"session.jsonl\"\nharness = \"claude-code\"\n";

fn operator() -> serde_json::Value {
    serde_json::json!({
        "type": "user",
        "sessionId": "s-1",
        "message": {"role": "user", "content": PROSE},
    })
}

/// One record of message `id`, carrying `usage` — a host writes one per block.
fn assistant(id: &str, usage: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "type": "assistant",
        "sessionId": "s-1",
        "message": {
            "id": id,
            "role": "assistant",
            "content": [{"type": "text", "text": PROSE}],
            "usage": usage,
        },
    })
}

fn usage(input: u64, cache_read: u64, cache_write: u64, output: u64) -> serde_json::Value {
    serde_json::json!({
        "input_tokens": input,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_write,
        "output_tokens": output,
    })
}

fn jsonl(records: &[serde_json::Value]) -> String {
    let mut text = String::new();
    for record in records {
        text.push_str(&record.to_string());
        text.push('\n');
    }
    text
}

/// Three messages, one record each. Context is the LAST message's
/// `30 + 300 + 3000`; the sums are over all three.
fn three_messages() -> Vec<serde_json::Value> {
    vec![
        operator(),
        assistant("m1", &usage(10, 100, 1000, 5)),
        assistant("m2", &usage(20, 200, 2000, 6)),
        assistant("m3", &usage(30, 300, 3000, 7)),
    ]
}

const THREE_MESSAGES_LINE: &str =
    "doctor session: turns=4 context=3330 cache_read=600 cache_write=6000 input=60 output=18";

fn repository(name: &str, transcript: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("session-usage-{name}"));
    let home = scratch(&format!("session-usage-home-{name}"));
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "batten.toml", DECLARED);
    write(&dir, "session.jsonl", transcript);
    (dir, home)
}

fn session(dir: &Path, home: &Path, extra: &[&str]) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .state_home(home)
        .args(["doctor", "session"])
        .args(extra)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_CONFIG_FROM");
    command.output().expect("run batten doctor session")
}

fn usage_line(output: &Output) -> String {
    stdout(output)
        .lines()
        .find(|line| line.contains("turns="))
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_session_reads_its_exact_usage() {
    let (dir, home) = repository("exact", &jsonl(&three_messages()));
    let output = session(&dir, &home, &[]);
    assert_eq!(
        usage_line(&output),
        THREE_MESSAGES_LINE,
        "got: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains(PROSE),
        "no byte of the transcript reaches the channel"
    );
}

#[test]
fn usage_sums_across_a_split_fold_as_the_whole_parse() {
    // THE SPLIT FALLS BETWEEN TWO COPIES OF ONE MESSAGE: the second read starts
    // on a record whose id the first read ended on, and only a stored last id
    // can know it was already counted.
    let first = vec![operator(), assistant("m1", &usage(10, 100, 1000, 5))];
    let rest = vec![
        assistant("m1", &usage(10, 100, 1000, 5)),
        assistant("m2", &usage(20, 200, 2000, 6)),
    ];
    let (dir, home) = repository("split", &jsonl(&first));
    let before = session(&dir, &home, &[]);
    assert_eq!(
        usage_line(&before),
        "doctor session: turns=2 context=1110 cache_read=100 cache_write=1000 input=10 output=5",
        "the first part read alone: {}",
        stdout(&before)
    );
    let whole: Vec<_> = first.into_iter().chain(rest).collect();
    write(&dir, "session.jsonl", &jsonl(&whole));
    let after = session(&dir, &home, &[]);
    let expected =
        "doctor session: turns=4 context=2220 cache_read=300 cache_write=3000 input=30 output=11";
    assert_eq!(
        usage_line(&after),
        expected,
        "the continued fold: {}",
        stdout(&after)
    );
    let (cold_dir, cold_home) = repository("split-whole", &jsonl(&whole));
    assert_eq!(
        usage_line(&session(&cold_dir, &cold_home, &[])),
        expected,
        "the whole parse agrees with the continued fold"
    );
}

#[test]
fn a_message_written_as_three_records_is_counted_once() {
    let copy = usage(10, 100, 1000, 5);
    let records = vec![
        operator(),
        assistant("m1", &copy),
        assistant("m1", &copy),
        assistant("m1", &copy),
    ];
    let (dir, home) = repository("copies", &jsonl(&records));
    let output = session(&dir, &home, &[]);
    assert_eq!(
        usage_line(&output),
        "doctor session: turns=4 context=1110 cache_read=100 cache_write=1000 input=10 output=5",
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn a_transcript_with_no_usage_is_could_not_look_not_zero() {
    let records = vec![
        operator(),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "s-1",
            "message": {"id": "m1", "role": "assistant", "content": [{"type": "text", "text": PROSE}]},
        }),
    ];
    let (dir, home) = repository("no-usage", &jsonl(&records));
    let output = session(&dir, &home, &[]);
    assert_eq!(
        usage_line(&output),
        "doctor session: turns=2 context=- cache_read=- cache_write=- input=- output=-",
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn a_malformed_record_is_silent() {
    let mut records = three_messages();
    records.insert(
        2,
        assistant(
            "m-bad",
            &serde_json::json!({
                "input_tokens": "MALFORMED-COUNT",
                "cache_read_input_tokens": 9,
                "cache_creation_input_tokens": 9,
                "output_tokens": 9,
            }),
        ),
    );
    let (dir, home) = repository("malformed", &jsonl(&records));
    let output = session(&dir, &home, &[]);
    // One more turn than the fixture without it, and not one more token.
    assert_eq!(
        usage_line(&output),
        "doctor session: turns=5 context=3330 cache_read=600 cache_write=6000 input=60 output=18",
        "got: {}",
        stdout(&output)
    );
    let both = format!(
        "{}{}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !both.contains("MALFORMED-COUNT"),
        "nothing is printed for it: {both}"
    );
}

#[test]
fn doctor_session_prints_usage_with_no_task_store_declared() {
    // NO `tasks` TEMPLATE: the store half is could-not-look, and the usage line
    // must not sit behind it.
    let (dir, home) = repository("no-store", &jsonl(&three_messages()));
    let output = session(&dir, &home, &[]);
    assert!(
        stdout(&output).contains("no readable task store"),
        "the premise: the store is undeclared: {}",
        stdout(&output)
    );
    assert_eq!(
        usage_line(&output),
        THREE_MESSAGES_LINE,
        "got: {}",
        stdout(&output)
    );
    let json = session(&dir, &home, &["--json"]);
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&json)).expect("the report is JSON");
    for (field, value) in [
        ("turns", 4),
        ("context", 3330),
        ("cache_read", 600),
        ("cache_write", 6000),
        ("input", 60),
        ("output", 18),
    ] {
        assert_eq!(report[field], value, "field {field}: {report}");
    }
}

// --- the facts a policy row reads -------------------------------------------

/// A module that fires only where the context fact is present and over 1000.
const PROBE: &str = r#"package batten.session_usage_probe

import rego.v1

rules contains "context-over"

violation contains {
	"rule": "context-over",
	"verdict": "context over probe",
} if {
	input.facts.extracted["context-tokens"] > 1000
}

test_fires_over_the_threshold if {
	some v in violation with input as {"facts": {"extracted": {"context-tokens": 1001}}}
	v.rule == "context-over"
}
"#;

const POLICY: &str = r#"version = 1

[[rule]]
id = "context-over"
kind = "policy"
scope = "mediated_call"
module = "probe.rego"
severity = "warn"

[[rule.extract]]
id = "context-tokens"
count = "context-tokens"

[[rule.extract]]
id = "cache-read-tokens"
count = "cache-read-tokens"

[[rule.extract]]
id = "cache-write-tokens"
count = "cache-write-tokens"

[[rule.extract]]
id = "output-tokens"
count = "output-tokens"

[[verdict]]
id = "context over probe"
gloss = "the session's context is over the fixture's threshold"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe read first"
kind = "document"
target = "probe.rego"
"#;

fn adjudicated(name: &str, transcript: &str) -> String {
    let dir = scratch(&format!("session-usage-policy-{name}"));
    let home = scratch(&format!("session-usage-policy-home-{name}"));
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "batten.toml", POLICY);
    write(&dir, "probe.rego", PROBE);
    write(&dir, "session.jsonl", transcript);
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "probe-command"},
        "transcript_path": dir.join("session.jsonl").display().to_string(),
    })
    .to_string();
    let mut invocation = batten();
    invocation
        .current_dir(&dir)
        .state_home(&home)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = invocation.spawn().expect("spawn batten adjudicate");
    {
        use std::io::Write as _;
        let mut sink = child.stdin.take().expect("the child's stdin");
        sink.write_all(envelope.as_bytes())
            .expect("write the envelope");
    }
    let outcome = child.wait_with_output().expect("run batten adjudicate");
    format!(
        "{}{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    )
}

#[test]
fn a_policy_row_reads_the_four_facts() {
    let over = adjudicated("over", &jsonl(&three_messages()));
    assert!(
        over.contains("context over probe"),
        "a context of 3330 is over 1000: {over}"
    );
    let under = adjudicated(
        "under",
        &jsonl(&[operator(), assistant("m1", &usage(10, 20, 30, 5))]),
    );
    assert!(
        !under.contains("context over probe"),
        "a context of 60 is under 1000: {under}"
    );
    assert!(
        !over.contains(PROSE),
        "no byte of the transcript reaches the channel"
    );
}
