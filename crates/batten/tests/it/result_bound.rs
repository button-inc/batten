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

/// The view a pointer names, read from the hook's decoded JSON rather than its
/// raw bytes: a Windows path's `\` is escaped there, and splitting the raw text
/// on it cut the path at `C:` (measured on #1132's `windows` job).
fn view_named(stdout: &[u8]) -> String {
    fn find(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::String(text) => text
                .split("; read ")
                .nth(1)
                .and_then(|rest| rest.lines().next())
                .map(|path| path.trim().to_owned()),
            serde_json::Value::Array(items) => items.iter().find_map(find),
            serde_json::Value::Object(fields) => fields.values().find_map(find),
            _ => None,
        }
    }
    let answer: serde_json::Value =
        serde_json::from_slice(stdout).expect("the hook answers one JSON document");
    find(&answer).unwrap_or_else(|| panic!("the pointer names the view: {answer}"))
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
    let view = view_named(&posted.stdout);
    let text = std::fs::read_to_string(&view).expect("the view exists");
    assert!(
        text.lines()
            .any(|line| line == "payload line 01999 of the log"),
        "{view}"
    );
}

#[test]
fn a_result_too_large_to_hold_reaches_the_model_as_a_pointer() {
    // CLOUD-2224. Past the spill floor the leaf is streamed to a file and never
    // held, so it reaches the model as a pointer to the stored bytes, and those
    // bytes are the whole leaf.
    let dir = repo("result-bound-spilled");
    let body = payload(400_000);
    let posted = post_tool(&dir, &read_result(&body));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let said = String::from_utf8_lossy(&posted.stdout);
    assert!(
        said.contains("updatedToolOutput"),
        "the result is replaced: {said}"
    );
    assert!(said.contains("output point now"), "{said}");
    assert!(
        !said.contains("payload line 399999"),
        "no byte of the bulk reaches the model"
    );
    // THE ROUTE'S HANDLE, `response:<digest>`, not the pointer's generic hint.
    let handle = said.split("response:").nth(1).map_or_else(
        || panic!("the pointer names the stored leaf: {said}"),
        |rest| {
            let digest: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            format!("response:{digest}")
        },
    );
    let shown = common::run(&dir, &["capture", "show", &handle, "--raw"]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("payload line 399999 of the log"),
        "the stored leaf is whole: {}",
        common::stderr(&shown)
    );
}

/// A RESULT OVER THE BOUND NEVER ENTERS MEMORY WHOLE (CLOUD-2224): the read
/// spills it at the bound, so its pointer carries the stored leaf's handle
/// beside the view's lines. Measured by the row's cold read: a spill floor of a
/// million tokens held every result between the bound and ~4 MB whole, and
/// that path's pointer carried no handle. `#MUTANT spill-floor-restored`.
#[test]
fn a_result_over_the_bound_is_spilled_not_held() {
    let dir = repo("result-bound-spilled-at-bound");
    let posted = post_tool(&dir, &read_result(&payload(2000)));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let said = String::from_utf8_lossy(&posted.stdout);
    assert!(
        said.contains("output point now at /file/content:"),
        "the view's lines: {said}"
    );
    assert!(
        said.contains("response:"),
        "and the spilled leaf's stored handle: {said}"
    );
}

/// A RAISED BOUND KEEPS A SPILLED RESULT WHOLE (CLOUD-2224): the read spills at
/// the default, before the authority is known, so a result within a raised
/// bound is left to the host as it sent it. `#MUTANT raised-bound-ignored`.
#[test]
fn a_raised_bound_keeps_a_spilled_result_whole() {
    let dir = common::Fixture::at(common::scratch("result-bound-raised").join("repo"))
        .config("version = 1\n\n[capture]\nresult_max_tokens = 200000\n")
        .git()
        .base_commit()
        .build();
    let posted = post_tool(&dir, &read_result(&payload(2000)));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let said = String::from_utf8_lossy(&posted.stdout);
    assert!(!said.contains("output point now"), "{said}");
    assert!(!said.contains("updatedToolOutput"), "{said}");
}

#[test]
fn following_the_pointer_returns_text_not_another_pointer() {
    // CLOUD-2228. The pointer's route is `read <view>`, and the view of an
    // oversized result is itself over the bound, so reading it was bounded
    // again into a second pointer: the text was never reachable by the route
    // printed. Measured on #1132, every view over ~8KB.
    let dir = repo("result-bound-follow");
    let first = post_tool(&dir, &read_result(&payload(2000)));
    let view = view_named(&first.stdout);
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

/// Every digest a row in the call log names.
fn recorded_digests(dir: &Path) -> Vec<String> {
    let calls = common::run(dir, &["capture", "list", "--calls", "-J"]);
    let rows: serde_json::Value = serde_json::from_slice(&calls.stdout).expect("JSON rows");
    rows.as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["digest"].as_str().map(str::to_owned))
        .collect()
}

/// A SPILLED RESULT IS RECORDED (CLOUD-2397): the leaf stored from its spill
/// file is named by a call row, so eviction ranks it rather than keeping it past
/// every tracker read. `#MUTANT spill-unrecorded`.
#[test]
fn a_spilled_result_is_recorded() {
    let dir = repo("result-bound-spill-recorded");
    let posted = post_tool(&dir, &read_result(&payload(2000)));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let said = String::from_utf8_lossy(&posted.stdout);
    let digest: String = said.split("response:").nth(1).map_or_else(
        || panic!("the pointer names the stored leaf: {said}"),
        |rest| rest.chars().take_while(char::is_ascii_hexdigit).collect(),
    );
    let calls = common::run(&dir, &["capture", "list", "--calls", "-J"]);
    let rows: serde_json::Value = serde_json::from_slice(&calls.stdout).expect("JSON rows");
    let named: Vec<&serde_json::Value> = rows
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["digest"] == digest.as_str())
        .collect();
    assert!(!named.is_empty(), "a row names the spill {digest}: {rows}");
    // A LEAF IS PART OF THE RESULT, so its row is ranked and never selected.
    assert!(
        named.iter().any(|row| row["fidelity"] == "prefix"),
        "the spill's own row does not claim the whole response: {rows}"
    );
}

/// A BOUNDED RESULT IS RECORDED (CLOUD-2397): a result held whole but over a
/// lowered token bound is stored as its JSON, and a row names that capture.
/// Under the 2000-token spill floor, so it is held rather than spilled, and a
/// string, so the stored JSON is not the bytes `capture_response` keeps.
/// `#MUTANT bound-unrecorded`.
#[test]
fn a_bounded_result_is_recorded() {
    let dir = common::Fixture::at(common::scratch("result-bound-bound-recorded").join("repo"))
        .config("version = 1\n\n[capture]\nresult_max_tokens = 500\n")
        .git()
        .base_commit()
        .build();
    let posted = post_tool(&dir, &serde_json::Value::String(payload(150)));
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let view = PathBuf::from(view_named(&posted.stdout));
    let digest = view
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_else(|| panic!("the view is named by its digest: {}", view.display()))
        .to_owned();
    let recorded = recorded_digests(&dir);
    assert!(
        recorded.contains(&digest),
        "a row names the bounded result {digest}: {recorded:?}"
    );
}

/// A store over a one-record budget holding a recorded tracker read and one
/// record no row names, made `age` ago; evicts, and says whether each survived
/// as `(row_less, read)`.
fn evict_beside_a_read(name: &str, age: std::time::Duration) -> (bool, bool) {
    use batten::capture::{CallRow, CaptureConfig, Stream};
    let store = common::scratch(name);
    let row_less = batten::capture::store_in(&store, Stream::Response, b"a capture no row names")
        .expect("store the row-less record");
    let row_less_path = store.join(format!("response-{}", row_less.digest));
    std::fs::File::options()
        .write(true)
        .open(&row_less_path)
        .and_then(|file| file.set_modified(std::time::SystemTime::now() - age))
        .expect("age the row-less record");
    let read = batten::capture::store_in(&store, Stream::Response, b"{\"id\":\"CLOUD-9\"}")
        .expect("store the read");
    batten::capture::record_call_in(
        &store,
        &CallRow {
            order: 0,
            session: "fixture".to_owned(),
            source: batten::capture::POST_TOOL_MEMBER.to_owned(),
            host: "claude-code".to_owned(),
            tool: "mcp__tracker__get_issue".to_owned(),
            event: "PostToolUse".to_owned(),
            fidelity: batten::capture::Fidelity::LexicalBytes.as_str().to_owned(),
            seen_at: None,
            class: None,
            digest: Some(read.digest.clone()),
            absent: None,
        },
    )
    .expect("record the read");
    let one = CaptureConfig {
        max_bytes: None,
        max_records: Some(1),
        inline_max_bytes: None,
        result_max_tokens: None,
    };
    batten::capture::evict_to_budget_in(&store, Some(&one)).expect("evict");
    (
        row_less_path.exists(),
        store.join(format!("response-{}", read.digest)).exists(),
    )
}

/// A CAPTURE NO ROW NAMES IS EVICTED FIRST (CLOUD-2397): nothing can select it,
/// so it must not outlive a tracker read a gate resolves. Measured: 76 row-less
/// records held the 8 MiB budget, and every tracker read stored after them was
/// evicted at once. `#MUTANT unrecorded-evicted-last`.
#[test]
fn an_unrecorded_capture_is_evicted_before_a_tracker_read() {
    let past_grace = batten::capture::UNRECORDED_GRACE * 2;
    let (row_less, read) = evict_beside_a_read("result-bound-unrecorded", past_grace);
    assert!(!row_less, "the orphan goes");
    assert!(read, "the tracker read stays");
}

/// A CAPTURE STILL BEING RECORDED IS NOT AN ORPHAN (CLOUD-2397): a writer stores
/// the blob before it appends the row, so a concurrent eviction sees a fresh
/// record no row names yet, and must not take it first.
/// `#MUTANT in-flight-evicted-first`.
#[test]
fn a_capture_still_being_recorded_is_not_evicted_as_an_orphan() {
    let (row_less, read) = evict_beside_a_read("result-bound-in-flight", std::time::Duration::ZERO);
    assert!(row_less, "the capture mid-write stays");
    assert!(!read, "the ranked record goes first");
}

/// THE CALL THAT STORES A RESPONSE NEVER EVICTS IT (CLOUD-2302): its row is the
/// newest, so it ranks last, but a budget the store cannot meet without it took
/// it in the same call, and the `capture show` a reader runs next found nothing.
/// `#MUTANT kept-digest-evicted`.
#[test]
fn a_spilled_leaf_does_not_outlive_the_mcp_response_stored_after_it() {
    let dir = common::Fixture::at(common::scratch("result-bound-keep").join("repo"))
        .config("version = 1\n\n[capture]\nmax_bytes = 512\n")
        .git()
        .base_commit()
        .build();
    let tool = "mcp__linear__get_issue";
    let issue = serde_json::json!({ "id": "CLOUD-1", "description": payload(60) }).to_string();
    assert!(
        issue.len() > 512,
        "the premise: the response alone exceeds the budget"
    );
    let posted = common::run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "bound",
            "tool_name": tool,
            "tool_input": { "id": "CLOUD-1" },
            "tool_response": [{ "type": "text", "text": issue }],
        })
        .to_string(),
    );
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    // The one call this store has seen, so its one row names the response.
    let recorded = recorded_digests(&dir);
    let [digest] = recorded.as_slice() else {
        panic!("one row naming the MCP response: {recorded:?}");
    };
    let shown = common::run(&dir, &["capture", "show", &format!("response:{digest}")]);
    assert_eq!(
        shown.status.code(),
        Some(0),
        "the MCP response was evicted by the call that stored it: {}",
        common::stderr(&shown)
    );
}

// --- spilled leaves are pointers a native read follows (CLOUD-2284) -------------

/// Post an MCP response whose one text leaf is `leaf`, as Claude Code shapes it.
fn mcp_post(dir: &Path, leaf: &str) -> std::process::Output {
    mcp_post_in(dir, leaf, "bound")
}

/// [`mcp_post`] in its own session.
fn mcp_post_in(dir: &Path, leaf: &str, session: &str) -> std::process::Output {
    common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": session,
            "tool_name": "mcp__linear__get_issue",
            "tool_input": { "id": "CLOUD-1" },
            "tool_response": [{ "type": "text", "text": leaf }],
        })
        .to_string(),
    )
}

/// The `output point now` note in the hook's decoded answer.
fn note_of(stdout: &[u8]) -> String {
    fn find(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::String(text) if text.contains("output point now at") => {
                Some(text.clone())
            }
            serde_json::Value::Array(items) => items.iter().find_map(find),
            serde_json::Value::Object(fields) => fields.values().find_map(find),
            _ => None,
        }
    }
    let answer: serde_json::Value =
        serde_json::from_slice(stdout).expect("the hook answers one JSON document");
    find(&answer).unwrap_or_else(|| panic!("a pointer: {answer}"))
}

/// One `<pointer>:<from>-<to>(<n>B <t>T)` subject.
#[derive(Debug)]
struct Spilled {
    pointer: String,
    from: usize,
    to: usize,
    bytes: usize,
    tokens: u64,
}

/// Every counted subject the note names.
fn spilled_subjects(note: &str) -> Vec<Spilled> {
    let head = note.split(';').next().unwrap_or_default();
    let words: Vec<&str> = head.split_whitespace().collect();
    let mut found = Vec::new();
    for pair in words.windows(2) {
        let (Some((left, bytes)), Some(tokens)) = (
            pair[0]
                .strip_suffix('B')
                .and_then(|word| word.split_once('(')),
            pair[1].strip_suffix("T)"),
        ) else {
            continue;
        };
        let (pointer, lines) = left.rsplit_once(':').expect("pointer:lines");
        let (from, to) = lines.split_once('-').expect("from-to");
        found.push(Spilled {
            pointer: pointer.to_owned(),
            from: from.parse().unwrap(),
            to: to.parse().unwrap(),
            bytes: bytes.parse().unwrap(),
            tokens: tokens.parse().unwrap(),
        });
    }
    found
}

/// Lines `from..=to` of the view, joined with `\n`.
fn section(view: &str, subject: &Spilled) -> String {
    let text = std::fs::read_to_string(view).expect("the view exists");
    let lines: Vec<&str> = text.split('\n').collect();
    lines[subject.from - 1..subject.to].join("\n")
}

/// One line of JSON, `count` objects long.
fn json_leaf(count: usize) -> String {
    let items: Vec<serde_json::Value> = (0..count)
        .map(|n| serde_json::json!({ "id": n, "name": format!("item {n:05} of the list") }))
        .collect();
    serde_json::Value::Array(items).to_string()
}

/// The stored leaf's `response:<digest>` handle the note names.
fn leaf_handle(note: &str) -> String {
    let rest = note
        .split("response:")
        .nth(1)
        .unwrap_or_else(|| panic!("a stored leaf: {note}"));
    let digest: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    format!("response:{digest}")
}

/// AN MCP SPILL IS READ UNDER ITS OWN POINTER (CLOUD-2284): the view walks the
/// content array, so the text sits under `## /0/text`, not escaped under `/`.
#[test]
fn an_mcp_spill_is_read_under_its_own_pointer() {
    let dir = repo("result-bound-mcp-spill");
    let body = payload(2000);
    let posted = mcp_post(&dir, &body);
    assert!(
        !posted.stdout.is_empty(),
        "no answer: {}",
        common::stderr(&posted)
    );
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let note = note_of(&posted.stdout);
    assert!(note.contains("/0/text:"), "{note}");
    let view = view_named(&posted.stdout);
    let subjects = spilled_subjects(&note);
    let text = subjects
        .iter()
        .find(|subject| subject.pointer == "/0/text")
        .unwrap_or_else(|| panic!("{subjects:?}"));
    assert_eq!(section(&view, text), body);

    let bounded = common::Fixture::at(common::scratch("result-bound-mcp-bounded").join("repo"))
        .config("version = 1\n\n[capture]\nresult_max_tokens = 500\n")
        .git()
        .base_commit()
        .build();
    let posted = mcp_post_in(&bounded, &payload(150), "bound-small");
    assert!(
        !posted.stdout.is_empty(),
        "no answer: {}",
        common::stderr(&posted)
    );
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    assert!(note_of(&posted.stdout).contains("/0/text:"));
}

/// A TARGETLESS RESULT IS BOUND BY ITS SESSION'S HOME, NOT THE DIRECTORY IT
/// CROSSED (CLOUD-2705, by CLOUD-2672's design). An MCP answer names no path, so
/// it is judged where its session started; a visit to a repository declaring a
/// tighter bound does not move that. Fails by: the second repository's bound
/// applying to a session homed in the first.
#[test]
fn a_targetless_result_is_bound_by_its_sessions_home() {
    let home = repo("result-bound-home-default");
    // The session homes in a repository with the default bound.
    let first = mcp_post_in(&home, &payload(2000), "homed");
    assert!(note_of(&first.stdout).contains("/0/text:"));
    let visited = common::Fixture::at(common::scratch("result-bound-home-visited").join("repo"))
        .config("version = 1\n\n[capture]\nresult_max_tokens = 500\n")
        .git()
        .base_commit()
        .build();
    // Under the visited repository's own bound this would be rewritten, and its
    // own session proves it; under the home's default it is not.
    let own = mcp_post_in(&visited, &payload(150), "visited-own");
    assert!(note_of(&own.stdout).contains("/0/text:"));
    let homed = mcp_post_in(&visited, &payload(150), "homed");
    assert_eq!(homed.status.code(), Some(0), "{}", common::stderr(&homed));
    assert!(
        homed.stdout.is_empty(),
        "the visited repository's bound governed a session homed elsewhere: {}",
        String::from_utf8_lossy(&homed.stdout)
    );
}

/// EVERY SPILL POINTER NAMES ITS LINES, BYTES AND TOKENS (CLOUD-2284), and each
/// holds: the view exists, its lines are the section, the section is the leaf.
#[test]
fn every_spill_pointer_names_its_lines_bytes_and_tokens() {
    let dir = repo("result-bound-spill-counts");
    let text = payload(2000);
    let json = json_leaf(2000);
    let cases = [
        (
            post_tool(&dir, &read_result(&text)),
            "/file/content",
            text.clone(),
            false,
        ),
        (mcp_post(&dir, &text), "/0/text", text.clone(), false),
        (mcp_post(&dir, &json), "/0/text", json.clone(), true),
    ];
    for (posted, pointer, leaf, pretty) in cases {
        assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
        let note = note_of(&posted.stdout);
        let view = view_named(&posted.stdout);
        let subjects = spilled_subjects(&note);
        let subject = subjects
            .iter()
            .find(|subject| subject.pointer == pointer)
            .unwrap_or_else(|| panic!("{pointer} in {note}"));
        let section = section(&view, subject);
        assert_eq!(section.len(), subject.bytes, "{pointer}");
        assert_eq!(
            subject.tokens,
            batten::o200k::chunked_tokens(section.as_bytes()),
            "{pointer}"
        );
        if pretty {
            let parsed: serde_json::Value = serde_json::from_str(&section).unwrap();
            let posted: serde_json::Value = serde_json::from_str(&leaf).unwrap();
            assert_eq!(parsed, posted);
        } else {
            assert_eq!(section, leaf, "{pointer}");
        }
    }
}

/// ONE-LINE JSON IS PRETTY-PRINTED UNDER THE CAP (CLOUD-2284), so a line range
/// means something, and the stored leaf keeps the host's bytes; over the cap
/// the section is the leaf as it came.
#[test]
fn a_one_line_json_spill_is_pretty_printed_under_the_cap() {
    let dir = repo("result-bound-json-pretty");
    let small = json_leaf(2000);
    let posted = mcp_post(&dir, &small);
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let note = note_of(&posted.stdout);
    let subjects = spilled_subjects(&note);
    let subject = subjects
        .iter()
        .find(|subject| subject.pointer == "/0/text")
        .unwrap_or_else(|| panic!("{note}"));
    assert!(subject.to > subject.from, "pretty-printed: {subject:?}");
    let pretty = section(&view_named(&posted.stdout), subject);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&pretty).unwrap(),
        serde_json::from_str::<serde_json::Value>(&small).unwrap()
    );
    let shown = common::run(&dir, &["capture", "show", &leaf_handle(&note), "--raw"]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains(&small),
        "{}",
        common::stderr(&shown)
    );

    let big = json_leaf(40_000);
    assert!(big.len() > 1 << 20, "the premise: over the cap");
    let dir = repo("result-bound-json-capped");
    let posted = mcp_post(&dir, &big);
    assert_eq!(posted.status.code(), Some(0), "{}", common::stderr(&posted));
    let note = note_of(&posted.stdout);
    let subjects = spilled_subjects(&note);
    let subject = subjects
        .iter()
        .find(|subject| subject.pointer == "/0/text")
        .unwrap_or_else(|| panic!("{note}"));
    assert_eq!(subject.from, subject.to, "one line: {subject:?}");
    assert_eq!(section(&view_named(&posted.stdout), subject), big);
}

/// A SPILL NOTE NAMES NO `--field` ROUTE (CLOUD-2284): the stored leaf is not a
/// JSON document, so that route refused; the view is the one route, on both arms.
#[test]
fn a_spill_note_names_no_field_route() {
    for (harness, name) in [
        ("exit-code", "result-bound-route-full"),
        ("claude-code", "result-bound-route-pointer"),
    ] {
        let dir = repo(name);
        let posted = post_tool_on(&dir, harness, &read_result(&payload(2000)));
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&posted.stdout),
            common::stderr(&posted)
        );
        assert!(!said.contains("--field"), "{harness}: {said}");
        assert!(said.contains("; read "), "{harness}: {said}");
    }
}
