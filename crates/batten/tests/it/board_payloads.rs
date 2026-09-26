//! `[tasks.board-payloads]` — this session's own `get_issue` payloads, recovered
//! from its transcript (CLOUD-782), over the task's own body (CLOUD-1752).
//!
//! Every case drives a FIXTURE transcript, never the live one: the host produces
//! exactly one, so a case reading it would pass for the wrong reason and could
//! never fail (CLOUD-418).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/board-payloads.sh mise.toml kind:mechanism crates/batten/tests/it/board_payloads.rs
// carried: tests/board-payloads.bats mise.toml kind:mechanism crates/batten/tests/it/board_payloads.rs
// carried: "a get_issue payload is recovered" mise.toml kind:mechanism
// carried: "CLOUD-782: a LATER save_issue response does not displace the get_issue payload" mise.toml kind:mechanism
// carried: "CLOUD-782: newest wins among two get_issue payloads — the compaction case" mise.toml kind:mechanism
// carried: "CLOUD-782: a reconnected server alias still matches on the suffix" mise.toml kind:mechanism
// carried: "CLOUD-782: an id present only in a save_issue response is not recovered" mise.toml kind:mechanism
// carried: "several ids are recovered in one run" mise.toml kind:mechanism
// carried: "an id absent from the transcript is exit 1 and named" mise.toml kind:mechanism
// carried: "an unreadable transcript is exit 2, never an empty harvest" mise.toml kind:mechanism
// carried: "CLOUD-1033: a transcript with an undecodable line is could-not-look, not a miss" mise.toml kind:mechanism
// carried: "CLOUD-1033: the decode failure names the line and carries none of it" mise.toml kind:mechanism
// carried: "CLOUD-1033: a genuine miss over a decodable transcript still exits 1" mise.toml kind:mechanism
// carried: "a malformed id is a caller bug" mise.toml kind:mechanism
// carried: "no arguments is a caller bug" mise.toml kind:mechanism
// carried: "the report carries no substring of any payload body" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const TODO: &str =
    r#"{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}"#;

/// A fixture transcript: one `tool_use`/`tool_result` pair per call, joined by
/// id, in the shape the host writes. The pair carries the tool name; the
/// payload alone never does, which is the whole point.
struct Transcript {
    dir: PathBuf,
    lines: String,
    calls: usize,
}

impl Transcript {
    fn new(name: &str) -> Self {
        Self {
            dir: common::scratch(&format!("board-payloads-{name}")),
            lines: String::new(),
            calls: 0,
        }
    }

    fn call(mut self, tool: &str, payload: &str) -> Self {
        self.calls += 1;
        let id = format!("tu{}", self.calls);
        let text = serde_json::Value::String(payload.to_owned());
        let _ = writeln!(
            self.lines,
            r#"{{"type":"assistant","message":{{"content":[{{"type":"tool_use","id":"{id}","name":"{tool}"}}]}}}}"#
        );
        let _ = writeln!(
            self.lines,
            r#"{{"type":"user","message":{{"content":[{{"type":"tool_result","tool_use_id":"{id}","content":[{{"type":"text","text":{text}}}]}}]}}}}"#
        );
        self
    }

    fn raw(mut self, line: &str) -> Self {
        self.lines.push_str(line);
        self
    }

    fn path(&self) -> PathBuf {
        self.dir.join("transcript.jsonl")
    }

    fn out(&self) -> PathBuf {
        self.dir.join("out")
    }

    /// The body over `ids`: `(exit, stdout+stderr)`.
    fn run(&self, ids: &str) -> (Option<i32>, String) {
        std::fs::write(self.path(), &self.lines).expect("the transcript");
        self.run_at(&self.path(), ids)
    }

    fn run_at(&self, transcript: &Path, ids: &str) -> (Option<i32>, String) {
        let out = common::task_command(&self.dir, "board-payloads")
            .env("BATTEN_TRANSCRIPT_FILE", transcript)
            .env("BOARD_PAYLOADS_DIR", self.out())
            .env("usage_id", ids)
            .output()
            .expect("run board-payloads");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn recovered(&self, id: &str) -> serde_json::Value {
        let text = std::fs::read_to_string(self.out().join(format!("{id}.json")))
            .unwrap_or_else(|_| panic!("{id} was recovered"));
        serde_json::from_str(&text).expect("a recovered payload is JSON")
    }
}

#[test]
fn a_get_issue_payload_is_recovered() {
    let t = Transcript::new("recovered").call("mcp__Linear__get_issue", TODO);
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(t.recovered("CLOUD-9")["status"], "Todo");
}

/// THE DISCRIMINATING CASE: a later `save_issue` response is shape-identical
/// across id, status and attachments and omits only `relations`.
#[test]
fn a_later_save_issue_response_does_not_displace_the_get_issue_payload() {
    let t = Transcript::new("save-later")
        .call("mcp__Linear__get_issue", TODO)
        .call(
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-9","status":"In Progress","attachments":[]}"#,
        );
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(0), "{text}");
    let payload = t.recovered("CLOUD-9");
    assert_eq!(payload["status"], "Todo");
    assert!(payload.get("relations").is_some());
    // And an id present ONLY in a save_issue response is not recovered.
    let only = Transcript::new("save-only").call(
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-9","status":"Done","attachments":[]}"#,
    );
    let (code, text) = only.run("CLOUD-9");
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-9"), "{text}");
}

#[test]
fn newest_wins_among_two_get_issue_payloads() {
    let t = Transcript::new("newest")
        .call(
            "mcp__Linear__get_issue",
            r#"{"id":"CLOUD-9","status":"Backlog","attachments":[],"relations":{"blockedBy":[]}}"#,
        )
        .call("mcp__Linear__get_issue", TODO);
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(t.recovered("CLOUD-9")["status"], "Todo");
}

#[test]
fn a_reconnected_server_alias_still_matches_on_the_suffix() {
    let t =
        Transcript::new("alias").call("mcp__4db58e41-cd4e-4818-8922-46cf616593f4__get_issue", TODO);
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(t.recovered("CLOUD-9")["status"], "Todo");
}

#[test]
fn several_ids_are_recovered_in_one_run() {
    let t = Transcript::new("several")
        .call("mcp__Linear__get_issue", TODO)
        .call(
            "mcp__Linear__get_issue",
            r#"{"id":"CLOUD-10","status":"Done","attachments":[],"relations":{"blockedBy":[]}}"#,
        );
    let (code, text) = t.run("CLOUD-9 CLOUD-10");
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("recovered 2 of 2"), "{text}");
}

#[test]
fn an_id_absent_from_the_transcript_is_exit_1_and_named() {
    let t = Transcript::new("absent").call("mcp__Linear__get_issue", TODO);
    let (code, text) = t.run("CLOUD-9 CLOUD-404");
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-404"), "{text}");
    assert!(!text.contains("CLOUD-9 "), "{text}");
    // Over a decoded transcript a miss is a miss, never could-not-look.
    let (code, text) = t.run("CLOUD-404");
    assert_eq!(code, Some(1), "{text}");
    assert!(!text.contains("did not decode"), "{text}");
}

#[test]
fn an_unreadable_transcript_is_could_not_look() {
    let t = Transcript::new("unreadable");
    let (code, text) = t.run_at(&t.dir.join("absent.jsonl"), "CLOUD-9");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("not an empty harvest"), "{text}");
    assert!(text.contains("batten capture show"), "{text}");
    // Said as ABSENCE, not left to the decode check to trip over.
    assert!(text.contains("no readable transcript"), "{text}");
    assert!(!text.contains("did not decode"), "{text}");
}

/// CLOUD-1033: one torn line aborts the parse for every id, so swallowing it
/// would read as "the id is not here" over content never read.
#[test]
fn a_transcript_with_an_undecodable_line_is_could_not_look() {
    let t = Transcript::new("torn")
        .call("mcp__Linear__get_issue", TODO)
        .raw("{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"tex\n");
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("did not decode") && text.contains("not an empty harvest"),
        "{text}"
    );
    assert!(!text.contains("recovered 0"), "{text}");
}

#[test]
fn the_decode_failure_names_the_line_and_carries_none_of_it() {
    let t = Transcript::new("torn-pointer")
        .call("mcp__Linear__get_issue", TODO)
        .raw("{\"secret\":\"customer detail here\",}\n");
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("line 3"), "{text}");
    assert!(!text.contains("customer detail"), "{text}");
}

#[test]
fn a_malformed_id_or_none_is_a_caller_bug() {
    let t = Transcript::new("caller").call("mcp__Linear__get_issue", TODO);
    assert_eq!(t.run("not-an-id").0, Some(2));
    assert_eq!(t.run("").0, Some(2));
}

#[test]
fn the_report_carries_no_substring_of_any_payload_body() {
    let t = Transcript::new("pointer").call(
        "mcp__Linear__get_issue",
        r#"{"id":"CLOUD-9","status":"Todo","description":"customer detail here","attachments":[],"relations":{"blockedBy":[]}}"#,
    );
    let (code, text) = t.run("CLOUD-9");
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("customer detail"), "{text}");
}
