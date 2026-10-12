//! Every tool result is stored, and one over the bound reaches the model as a
//! pointer to a view of its text (CLOUD-2223).
//!
//! The hook mediates every call, so every result crosses `PostToolUse`. Before
//! this, the store dropped every built-in tool's result as an unreadable shape,
//! and nothing bounded what the model read: one task log read whole was 57,764
//! tokens, of which two lines were the verdict.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common;

fn repo(name: &str) -> PathBuf {
    common::Fixture::at(common::scratch(name).join("repo"))
        .config("version = 1\n")
        .git()
        .base_commit()
        .build()
}

/// A `Read` result as Claude Code shapes it: the text nested under `/file`.
fn read_result(content: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "text",
        "file": {
            "filePath": "/repo/big.log",
            "content": content,
            "numLines": content.lines().count(),
            "startLine": 1,
            "totalLines": content.lines().count(),
        }
    })
}

fn post_tool(dir: &Path, result: &serde_json::Value) -> std::process::Output {
    post_tool_on(dir, "claude-code", result)
}

fn post_tool_on(dir: &Path, harness: &str, result: &serde_json::Value) -> std::process::Output {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "bound",
        "tool_name": "Read",
        "tool_input": { "file_path": "big.log" },
        "tool_response": result,
    });
    common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", harness],
        &payload.to_string(),
    )
}

/// Lines distinct enough that one of them found in the output is the payload.
fn payload(lines: usize) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for n in 0..lines {
        let _ = writeln!(text, "payload line {n:05} of the log");
    }
    text
}

#[test]
fn a_structured_tool_result_is_stored() {
    let dir = repo("result-bound-stored");
    let posted = post_tool(&dir, &read_result("small\n"));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let calls = common::run(&dir, &["capture", "list", "--calls", "-J"]);
    let rows: serde_json::Value = serde_json::from_slice(&calls.stdout).expect("JSON rows");
    let row = rows
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["tool"] == "Read"))
        .unwrap_or_else(|| panic!("a Read row: {rows}"));
    assert!(
        row.get("digest").is_some(),
        "the Read result is in the store: {row}"
    );
}

#[test]
fn a_result_within_the_bound_is_left_alone() {
    let dir = repo("result-bound-small");
    // ~3KB: over the 1KB inline threshold, so the bound itself is what admits it.
    let posted = post_tool(&dir, &read_result(&payload(100)));
    let said = String::from_utf8_lossy(&posted.stdout);
    assert!(!said.contains("output point now"), "{said}");
    assert!(!said.contains("updatedToolOutput"), "{said}");
}

#[test]
fn an_oversized_result_becomes_a_pointer_to_a_view_of_its_text() {
    let dir = repo("result-bound-large");
    let body = payload(2000);
    let posted = post_tool(&dir, &read_result(&body));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let said = String::from_utf8_lossy(&posted.stdout);
    assert!(
        said.contains("updatedToolOutput"),
        "the result is replaced: {said}"
    );
    assert!(
        said.contains("batten note output point now at /file/content:"),
        "the pointer names the text leaf and its view lines: {said}"
    );
    assert!(
        !said.contains("payload line 01999"),
        "no byte of the payload reaches the model: {said}"
    );
    // THE VIEW HOLDS THE TEXT ON ITS OWN LINES, so a line range re-reads a slice.
    let view = said
        .split("; read ")
        .nth(1)
        .and_then(|rest| rest.split(['"', '\\']).next())
        .unwrap_or_else(|| panic!("the pointer names the view: {said}"));
    let text = std::fs::read_to_string(view).expect("the view exists");
    assert!(
        text.lines()
            .any(|line| line == "payload line 01999 of the log"),
        "{view}"
    );
}

#[test]
fn following_the_pointer_returns_text_not_another_pointer() {
    // CLOUD-2228. The pointer's route is `read <view>`, and the view of an
    // oversized result is itself over the bound, so reading it was bounded
    // again into a second pointer: the text was never reachable by the route
    // printed. Measured on #1132, every view over ~8KB.
    let dir = repo("result-bound-follow");
    let first = post_tool(&dir, &read_result(&payload(2000)));
    let said = String::from_utf8_lossy(&first.stdout);
    let view = said
        .split("; read ")
        .nth(1)
        .and_then(|rest| rest.split(['"', '\\']).next())
        .unwrap_or_else(|| panic!("the pointer names the view: {said}"))
        .to_owned();
    let text = std::fs::read_to_string(&view).expect("the view exists");
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "bound",
        "tool_name": "Read",
        "tool_input": { "file_path": view },
        "tool_response": read_result(&text),
    });
    let followed = common::run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload.to_string(),
    );
    assert_eq!(
        followed.status.code(),
        Some(0),
        "{}",
        common::stderr(&followed)
    );
    let again = String::from_utf8_lossy(&followed.stdout);
    assert!(
        !again.contains("output point now"),
        "the view is read, not re-bounded: {again}"
    );
    assert!(!again.contains("updatedToolOutput"), "{again}");
}

#[test]
fn a_built_in_result_is_evicted_before_a_tracker_read() {
    // Storing every result must not displace what gates resolve: a store bounded
    // to two records keeps the tracker read through three built-in results.
    let dir = common::Fixture::at(common::scratch("result-bound-evict").join("repo"))
        .config("version = 1\n\n[capture]\nmax_records = 2\n")
        .git()
        .base_commit()
        .build();
    let tracker = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "bound",
        "tool_name": "mcp__tracker__get_issue",
        "tool_input": {},
        "tool_response": [{ "type": "text", "text": "{\"id\":\"CLOUD-9\",\"statusType\":\"duplicate\"}" }],
    });
    let stored = common::run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &tracker.to_string(),
    );
    assert_eq!(stored.status.code(), Some(0), "{}", common::stderr(&stored));
    for n in 0..3 {
        post_tool(&dir, &read_result(&format!("built-in result {n}\n")));
    }
    let calls = common::run(&dir, &["capture", "list", "--calls", "-J"]);
    let rows: serde_json::Value = serde_json::from_slice(&calls.stdout).expect("JSON rows");
    let digest = rows
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["tool"] == "mcp__tracker__get_issue")
        })
        .and_then(|row| row["digest"].as_str())
        .unwrap_or_else(|| panic!("the tracker row: {rows}"))
        .to_owned();
    let shown = common::run(&dir, &["capture", "show", &format!("response:{digest}")]);
    assert_eq!(
        shown.status.code(),
        Some(0),
        "the tracker read survives the built-in results: {}",
        common::stderr(&shown)
    );
}

#[test]
fn a_host_that_cannot_rewrite_still_gets_the_pointer() {
    // The neutral adapter honours no rewrite, so the result reaches the model
    // whole; the pointer rides the advisory channel beside it, never silently
    // dropped with the rewrite.
    let dir = repo("result-bound-no-rewrite");
    let posted = post_tool_on(&dir, "exit-code", &read_result(&payload(2000)));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&posted.stdout),
        common::stderr(&posted)
    );
    assert!(!said.contains("updatedToolOutput"), "{said}");
    assert!(
        said.contains("output point now"),
        "the pointer still arrives: {said}"
    );
}
