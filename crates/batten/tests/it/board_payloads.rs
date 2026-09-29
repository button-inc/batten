//! `[tasks.board-payloads]`'s successor — this session's own `get_issue`
//! payloads, recovered so a sweep pays the fetch once (CLOUD-782) — over the
//! compiled `batten capture find` and `batten board sweep --issue` (CLOUD-843).
//!
//! The task recovered payloads out of ONE harness's transcript, by joining a
//! `tool_use` block's name to its `tool_result` in `jq`. The capture store holds
//! the same bytes on every host — the mediated post-tool boundary writes each
//! response as it happens, with the tool's own name beside it — and
//! `capture find` already resolves a key out of it (CLOUD-1121), with the
//! task's two load-bearing rules: select by TOOL NAME on the `__`-delimited
//! suffix, and newest qualifying response wins. So the port deletes the second
//! route rather than moving it, and these cases drive the store the way a host
//! does: one post-tool event per call, against an isolated state home.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/board-payloads.sh subject:mise.toml crates/batten/tests/it/board_payloads.rs
// ported: tests/board-payloads.bats subject:mise.toml crates/batten/tests/it/board_payloads.rs
// carried: [tasks.board-payloads] crates/batten/src/capture.rs kind:mechanism crates/batten/tests/it/board_payloads.rs runs:batten+capture+find
// carried: "a get_issue payload is recovered" crates/batten/tests/it/board_payloads.rs
// carried: "CLOUD-782: a LATER save_issue response does not displace the get_issue payload" crates/batten/tests/it/board_payloads.rs
// carried: "CLOUD-782: newest wins among two get_issue payloads — the compaction case" crates/batten/tests/it/board_payloads.rs
// carried: "CLOUD-782: a reconnected server alias still matches on the suffix" crates/batten/tests/it/board_payloads.rs
// carried: "CLOUD-782: an id present only in a save_issue response is not recovered" crates/batten/tests/it/board_payloads.rs
// carried: "several ids are recovered in one run" crates/batten/tests/it/board_payloads.rs
// changed: "an id absent from the transcript is exit 1 and named" crates/batten/src/lib.rs the store's miss is `Usage` (1) naming the key, and `board sweep --issue` refuses the whole set by name before any gate runs
// changed: "an unreadable transcript is exit 2, never an empty harvest" crates/batten/src/capture.rs there is no transcript to be unreadable: the store is written by the mediated boundary on every host, and an empty store is a miss that refuses
// changed: "CLOUD-1033: a transcript with an undecodable line is could-not-look, not a miss" crates/batten/src/capture.rs each capture is decoded when it is WRITTEN, and a response that did not decode is recorded as an absence with its reason, never stored as a payload
// changed: "CLOUD-1033: the decode failure names the line and carries none of it" crates/batten/src/capture.rs as above: a decode failure is a reason id on the provenance row, which carries no byte of the response
// carried: "CLOUD-1033: a genuine miss over a decodable transcript still exits 1" crates/batten/tests/it/board_payloads.rs
// changed: "a malformed id is a caller bug" crates/batten/src/capture.rs the key is compared for equality at a declared path, so a malformed one is a miss that refuses by name rather than a shape check
// changed: "no arguments is a caller bug" crates/batten/src/cli.rs clap refuses `capture find` without its key
// carried: "the report carries no substring of any payload body" crates/batten/tests/it/board_payloads.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// The store is driven through the POSIX post-tool path, as `cli.rs`'s own
// `capture find` cases are.
#![cfg(unix)]

use crate::common;
use crate::common::StateHome as _;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Output, Stdio};

const TODO: &str =
    r#"{"id":"CLOUD-9","status":"Todo","attachments":[],"relations":{"blockedBy":[]}}"#;

/// A fixture repository with an isolated capture store, and a sweep table whose
/// one gate reads the set and says nothing about it.
struct Store {
    dir: PathBuf,
    home: PathBuf,
}

impl Store {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("board-payloads-{name}"));
        common::init_repo(&dir);
        common::write(
            &dir,
            "batten.toml",
            "version = 1\n\n[[board.sweep]]\nname = \"reads\"\nrun = [\"true\"]\n",
        );
        let home = common::scratch(&format!("board-payloads-{name}-home"));
        Self { dir, home }
    }

    /// One post-tool event, in the MCP content-block shape a host hands over.
    fn call(self, tool: &str, payload: &str) -> Self {
        let event = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "board-payloads",
            "tool_name": tool,
            "tool_input": {},
            "tool_response": [{ "type": "text", "text": payload }],
        })
        .to_string();
        let mut command = common::batten();
        command
            .current_dir(&self.dir)
            .args(["adjudicate", "--harness", "claude-code"])
            .env_remove("CLAUDE_PROJECT_DIR")
            .state_home(&self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn the post-tool event");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(event.as_bytes())
            .expect("write the event");
        let done = child.wait_with_output().expect("run the post-tool event");
        assert!(
            done.status.success(),
            "recording a response must not fail: {}",
            String::from_utf8_lossy(&done.stderr)
        );
        self
    }

    fn batten(&self, args: &[&str]) -> Output {
        common::batten()
            .current_dir(&self.dir)
            .args(args)
            .env_remove("CLAUDE_PROJECT_DIR")
            .state_home(&self.home)
            .stdin(Stdio::null())
            .output()
            .expect("run batten")
    }

    /// The newest stored `get_issue` read for `id`, as the document it was.
    fn recovered(&self, id: &str) -> (Option<i32>, Option<serde_json::Value>) {
        let out = self.batten(&["capture", "find", id, "--tool", "get_issue", "--raw"]);
        (out.status.code(), serde_json::from_slice(&out.stdout).ok())
    }
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_get_issue_payload_is_recovered() {
    let store = Store::new("recovered").call("mcp__Linear__get_issue", TODO);
    let (code, payload) = store.recovered("CLOUD-9");
    assert_eq!(code, Some(0));
    assert_eq!(payload.unwrap()["status"], "Todo");
}

/// THE DISCRIMINATING CASE: a later `save_issue` response is shape-identical
/// across id, status and attachments and omits only `relations`.
#[test]
fn a_later_save_issue_response_does_not_displace_the_get_issue_payload() {
    let store = Store::new("save-later")
        .call("mcp__Linear__get_issue", TODO)
        .call(
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-9","status":"In Progress","attachments":[]}"#,
        );
    let (code, payload) = store.recovered("CLOUD-9");
    assert_eq!(code, Some(0));
    let payload = payload.unwrap();
    assert_eq!(payload["status"], "Todo");
    assert!(payload.get("relations").is_some());
    // And an id present ONLY in a save_issue response is not recovered.
    let only = Store::new("save-only").call(
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-9","status":"Done","attachments":[]}"#,
    );
    assert_eq!(only.recovered("CLOUD-9").0, Some(1));
}

#[test]
fn newest_wins_among_two_get_issue_payloads() {
    let store = Store::new("newest")
        .call(
            "mcp__Linear__get_issue",
            r#"{"id":"CLOUD-9","status":"Backlog","attachments":[],"relations":{"blockedBy":[]}}"#,
        )
        .call("mcp__Linear__get_issue", TODO);
    assert_eq!(store.recovered("CLOUD-9").1.unwrap()["status"], "Todo");
}

#[test]
fn a_reconnected_server_alias_still_matches_on_the_suffix() {
    let store =
        Store::new("alias").call("mcp__4db58e41-cd4e-4818-8922-46cf616593f4__get_issue", TODO);
    assert_eq!(store.recovered("CLOUD-9").1.unwrap()["status"], "Todo");
}

/// Several keys in one sweep: each resolved out of the store and handed to the
/// gates as ONE set, which the sweep counts before any gate runs.
#[test]
fn several_ids_are_resolved_in_one_sweep() {
    let store = Store::new("several")
        .call("mcp__Linear__get_issue", TODO)
        .call(
            "mcp__Linear__get_issue",
            r#"{"id":"CLOUD-10","status":"Done","attachments":[],"relations":{"blockedBy":[]}}"#,
        );
    let out = store.batten(&[
        "board", "sweep", "--issue", "CLOUD-9", "--issue", "CLOUD-10",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(said(&out).contains("2 issue(s)"), "{}", said(&out));
    assert!(said(&out).contains("reads ok"), "{}", said(&out));
}

/// A MISS IS NAMED AND REFUSES, and a sweep with one key missing runs no gate:
/// sweeping a short closure is what every board gate refuses.
#[test]
fn an_id_absent_from_the_store_is_refused_and_named() {
    let store = Store::new("absent").call("mcp__Linear__get_issue", TODO);
    let out = store.batten(&["capture", "find", "CLOUD-404", "--tool", "get_issue"]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("CLOUD-404"), "{}", said(&out));
    let out = store.batten(&[
        "board",
        "sweep",
        "--issue",
        "CLOUD-9",
        "--issue",
        "CLOUD-404",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("CLOUD-404"), "{}", said(&out));
    assert!(!said(&out).contains("reads ok"), "{}", said(&out));
    // Over a store that DOES hold reads, a miss is still a miss.
    assert_eq!(store.recovered("CLOUD-9").0, Some(0));
}

#[test]
fn the_report_carries_no_substring_of_any_payload_body() {
    let store = Store::new("pointer").call(
        "mcp__Linear__get_issue",
        r#"{"id":"CLOUD-9","status":"Todo","description":"customer detail here","attachments":[],"relations":{"blockedBy":[]}}"#,
    );
    let find = store.batten(&["capture", "find", "CLOUD-9", "--tool", "get_issue"]);
    assert_eq!(find.status.code(), Some(0), "{}", said(&find));
    assert!(!said(&find).contains("customer detail"), "{}", said(&find));
    let sweep = store.batten(&["board", "sweep", "--issue", "CLOUD-9"]);
    assert_eq!(sweep.status.code(), Some(0), "{}", said(&sweep));
    assert!(
        !said(&sweep).contains("customer detail"),
        "{}",
        said(&sweep)
    );
}
