//! `[tasks.finding-sink-check]` — a turn that cites `path:line` evidence and
//! gives it no OPEN row stranded a finding (CLOUD-252, CLOUD-475, CLOUD-775),
//! over the task's own body (CLOUD-1717).
//!
//! Every case owns its git dir: the check resolves a row's column from a read
//! receipt under it, and a live session's receipts deciding a case would pass it
//! for a reason the case never states.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/finding-sink-check.sh mise.toml kind:mechanism crates/batten/tests/it/finding_sink.rs
// carried: tests/finding-sink-check.bats mise.toml kind:mechanism crates/batten/tests/it/finding_sink.rs
// carried: "THE STRANDED FINDING: path:line evidence with no durable write is reported" mise.toml kind:mechanism
// carried: "the same turn with a tracker write is clean" mise.toml kind:mechanism
// carried: "prose with no path:line is clean — ordinary conversation is not noise" mise.toml kind:mechanism
// carried: "a durable write counts under the UUID prefix, not only the readable alias" mise.toml kind:mechanism
// carried: "CLOUD-475: a COMMENT alone is not a home — recorded is not scheduled" mise.toml kind:mechanism
// carried: "CLOUD-475: comment PLUS a new open row is a home — the CLOUD-473 shape" mise.toml kind:mechanism
// carried: "CLOUD-475: save_issue WITH an id is an annotation, not a filing" mise.toml kind:mechanism
// carried: "a memory write counts as durable too, not only the tracker" mise.toml kind:mechanism
// carried: "a read-only tool call is not a durable write" mise.toml kind:mechanism
// carried: "a subagent's write is not credited to the orchestrator's turn" mise.toml kind:mechanism
// carried: "a subagent's prose is not judged as the orchestrator's" mise.toml kind:mechanism
// carried: "a tool_result does not open a new turn" mise.toml kind:mechanism
// carried: "POINTER, NEVER PAYLOAD: the report carries no byte of the prose" mise.toml kind:mechanism
// carried: "ONLY THE LAST TURN is judged — an earlier stranding is not re-reported" mise.toml kind:mechanism
// carried: "a stranding in the last turn fires even when earlier turns were clean" mise.toml kind:mechanism
// carried: "a path:line-looking string that is not a source file does not fire" mise.toml kind:mechanism
// changed: "an unparseable transcript exits 2 — could not look is not a verdict" mise.toml exits 0 with the reason on stderr and nothing on stdout: the handler door has no abstention code, a 3 is a violation shown every turn and a 2 a refusal
// changed: "an absent transcript path exits 2, not 0" mise.toml exits 0 with nothing on stdout, for the same reason, and says why on stderr
// changed: "empty stdin exits 2 rather than reporting a clean session" mise.toml exits 0 with nothing on stdout, for the same reason, and says why on stderr
// carried: "ANTI-VACUITY: a transcript with no turns exits 0 and says it judged nothing" mise.toml kind:mechanism
// carried: "ANTI-VACUITY: the suite's own fired case is reachable" mise.toml kind:mechanism
// carried: "CLOUD-775: an annotation on a TERMINAL row still reports — CLOUD-475 survives" mise.toml kind:mechanism
// carried: "CLOUD-775: an amendment to a NON-TERMINAL row is a home" mise.toml kind:mechanism
// carried: "CLOUD-775: a row this clone has no recorded read of is not a home" mise.toml kind:mechanism
// carried: "CLOUD-775: a receipt that recorded no column is not a home either" mise.toml kind:mechanism
// carried: "CLOUD-775: an unrecognised column is not a home" mise.toml kind:mechanism
// carried: "CLOUD-775: a comment on an OPEN row is a home, named by issueId" mise.toml kind:mechanism
// carried: "CLOUD-775: every open column the board carries is a home" mise.toml kind:mechanism
// carried: "CLOUD-775: outside a checkout every row reads as closed" mise.toml kind:mechanism
// carried: "CLOUD-775: an id that is not an issue key is not a home" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

const CITED: &str = "The ordering key is wrong at mise-tasks/checks-green.sh:164.";

/// A transcript under construction, beside a clone that owns its receipts.
struct Turns {
    root: PathBuf,
    repo: PathBuf,
    lines: String,
}

impl Turns {
    fn new(name: &str) -> Self {
        let root = common::scratch(&format!("finding-sink-{name}"));
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).expect("the clone");
        common::init_repo(&repo);
        std::fs::create_dir_all(repo.join(".git/batten-receipts")).expect("receipts");
        Self {
            root,
            repo,
            lines: String::new(),
        }
    }

    fn line(mut self, value: &serde_json::Value) -> Self {
        let _ = writeln!(self.lines, "{value}");
        self
    }

    fn prompt(self) -> Self {
        self.line(
            &serde_json::json!({"type":"user","isSidechain":false,"message":{"content":"go"}}),
        )
    }

    fn say(self, text: &str) -> Self {
        self.line(&serde_json::json!({"type":"assistant","isSidechain":false,"message":{"content":[{"type":"text","text":text}]}}))
    }

    fn tool(self, name: &str) -> Self {
        self.line(&serde_json::json!({"type":"assistant","isSidechain":false,"message":{"content":[{"type":"tool_use","name":name,"input":{}}]}}))
    }

    /// A call naming a row that already exists, by `id` or `issueId`.
    fn on_row(self, name: &str, field: &str, key: &str) -> Self {
        self.line(&serde_json::json!({"type":"assistant","isSidechain":false,"message":{"content":[{"type":"tool_use","name":name,"input":{field:key}}]}}))
    }

    fn result(self) -> Self {
        self.line(&serde_json::json!({"type":"user","isSidechain":false,"message":{"content":[{"type":"tool_result","content":"ok"}]}}))
    }

    fn sub_say(self, text: &str) -> Self {
        self.line(&serde_json::json!({"type":"assistant","isSidechain":true,"message":{"content":[{"type":"text","text":text}]}}))
    }

    fn sub_tool(self, name: &str) -> Self {
        self.line(&serde_json::json!({"type":"assistant","isSidechain":true,"message":{"content":[{"type":"tool_use","name":name,"input":{}}]}}))
    }

    /// Field 5 of the read receipt: the column this clone saw on its last read.
    fn receipt(self, key: &str, column: &str) -> Self {
        std::fs::write(
            self.repo
                .join(format!(".git/batten-receipts/issue-read.{key}")),
            format!("{key} 2026-08-20T00:00:00.000Z 1 - {column}\n"),
        )
        .expect("receipt");
        self
    }

    fn write(&self) {
        std::fs::write(self.transcript(), &self.lines).expect("the transcript");
    }

    fn transcript(&self) -> PathBuf {
        self.root.join("transcript.jsonl")
    }

    fn check_in(&self, dir: &PathBuf, stdin: &str) -> (Option<i32>, String) {
        let mut child = common::task_command(dir, "finding-sink-check")
            .env("GIT_CEILING_DIRECTORIES", &self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the check");
        let _ = child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes());
        let out = child.wait_with_output().expect("run the check");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    /// The check over this transcript's path, the shape a hand run pipes.
    fn check(&self) -> (Option<i32>, String) {
        self.write();
        self.check_in(&self.repo, &self.transcript().display().to_string())
    }

    /// The check over a host `Stop` payload, the shape the handler door pipes.
    fn check_stop(&self) -> (Option<i32>, String) {
        self.write();
        let payload = serde_json::json!({
            "hook_event_name": "Stop",
            "transcript_path": self.transcript().display().to_string(),
        });
        self.check_in(&self.repo, &payload.to_string())
    }
}

fn fired(result: &(Option<i32>, String), turn: u32) {
    assert_eq!(result.0, Some(1), "{}", result.1);
    assert!(
        result
            .1
            .contains(&format!("turn:{turn} finding-without-durable-write")),
        "{}",
        result.1
    );
}

fn clean(result: &(Option<i32>, String)) {
    assert_eq!(result.0, Some(0), "{}", result.1);
    assert!(result.1.is_empty(), "{}", result.1);
}

#[test]
fn a_cited_finding_with_no_durable_write_fires() {
    let turns = Turns::new("stranded")
        .prompt()
        .say("The guard is wrong at mise-tasks/land.sh:200 and nothing covers it.");
    fired(&turns.check(), 1);
    // The handler door hands the host's Stop payload; the same verdict.
    fired(&turns.check_stop(), 1);
    // A read-only call is not a durable write.
    let turns = Turns::new("read-only")
        .prompt()
        .say("Found it at mise-tasks/released.sh:82.")
        .tool("Bash")
        .tool("mcp__Linear__get_issue");
    fired(&turns.check(), 1);
}

#[test]
fn a_durable_write_clears_it_under_any_server_alias() {
    for tool in [
        "mcp__Linear__save_issue",
        "mcp__4db58e41-cd4e-4818-8922-46cf616593f4__save_issue",
        "mcp__serena__write_memory",
    ] {
        let turns = Turns::new("durable")
            .prompt()
            .say("Broken at crates/batten/src/config.rs:42.")
            .tool(tool);
        clean(&turns.check());
    }
}

#[test]
fn ordinary_prose_and_non_source_colons_do_not_fire() {
    for text in [
        "Rebased onto main and pushed. The gate is green and the PR is open.",
        "The run took 12:30 and the ratio was 3:1.",
    ] {
        clean(&Turns::new("prose").prompt().say(text).check());
    }
}

#[test]
fn a_comment_alone_is_not_a_home() {
    let turns = Turns::new("comment")
        .prompt()
        .say(CITED)
        .tool("mcp__Linear__save_comment");
    let result = turns.check();
    fired(&result, 1);
    // It names the PRACTICE: what is missing is an open row.
    assert!(result.1.contains("OPEN row"), "{}", result.1);
    // A comment PLUS a new open row is the working practice, and passes.
    let turns = Turns::new("comment-and-row")
        .prompt()
        .say(CITED)
        .tool("mcp__Linear__save_comment")
        .tool("mcp__Linear__save_issue");
    clean(&turns.check());
    // save_issue WITH an id is an annotation, not a filing.
    let turns = Turns::new("with-id").prompt().say(CITED).on_row(
        "mcp__Linear__save_issue",
        "id",
        "CLOUD-199",
    );
    fired(&turns.check(), 1);
}

#[test]
fn a_subagents_write_is_not_credited_to_the_turn() {
    let turns = Turns::new("sub-write")
        .prompt()
        .say("Broken at crates/batten/src/git.rs:100.")
        .sub_tool("mcp__Linear__save_issue");
    fired(&turns.check(), 1);
    // Nor is its prose judged as the orchestrator's.
    let turns = Turns::new("sub-prose")
        .prompt()
        .say("Rebased and pushed.")
        .sub_say("The subagent found something at crates/batten/src/lint.rs:7.");
    clean(&turns.check());
}

#[test]
fn a_tool_result_does_not_open_a_new_turn() {
    let turns = Turns::new("result")
        .prompt()
        .say("Broken at mise-tasks/land.sh:200.")
        .tool("Bash")
        .result()
        .tool("mcp__Linear__save_issue");
    clean(&turns.check());
}

#[test]
fn the_report_carries_no_byte_of_the_prose() {
    let turns = Turns::new("pointer")
        .prompt()
        .say("The defect is at mise-tasks/land.sh:200 — SENTINELXYZZY is the distinctive marker.");
    let result = turns.check();
    assert_eq!(result.0, Some(1), "{}", result.1);
    assert!(!result.1.contains("SENTINELXYZZY"), "{}", result.1);
    assert!(!result.1.contains("The defect is at"), "{}", result.1);
}

#[test]
fn only_the_last_turn_is_judged() {
    let turns = Turns::new("earlier")
        .prompt()
        .say("Broken at mise-tasks/land.sh:200.")
        .prompt()
        .say("Fixed and pushed, nothing further.");
    clean(&turns.check());
    let turns = Turns::new("later")
        .prompt()
        .say("Rebased and pushed.")
        .prompt()
        .say("Broken at mise-tasks/land.sh:200.");
    fired(&turns.check(), 2);
}

/// Could-not-look is abstained (3), never clean and never a refusal: at the
/// handler door a 2 IS a refusal, and "no transcript" is not one.
#[test]
fn an_unreadable_transcript_abstains() {
    let turns = Turns::new("unparseable");
    std::fs::write(turns.transcript(), "this is not json\n").expect("write");
    let (code, text) = turns.check_in(&turns.repo, &turns.transcript().display().to_string());
    assert_eq!(code, Some(0), "{text}");
    let absent = turns.root.join("nope.jsonl").display().to_string();
    assert_eq!(turns.check_in(&turns.repo, &absent).0, Some(0));
    assert_eq!(turns.check_in(&turns.repo, "").0, Some(0));
    assert_eq!(turns.check_in(&turns.repo, "{}").0, Some(0));
}

#[test]
fn a_transcript_with_no_turns_says_it_judged_nothing() {
    let (code, text) = Turns::new("empty").check();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("nothing to judge"), "{text}");
}

#[test]
fn an_annotation_on_a_terminal_row_still_reports() {
    let turns = Turns::new("terminal")
        .receipt("CLOUD-199", "done")
        .prompt()
        .say(CITED)
        .on_row("mcp__Linear__save_comment", "issueId", "CLOUD-199");
    fired(&turns.check(), 1);
}

#[test]
fn an_amendment_to_an_open_row_is_a_home_in_every_open_column() {
    for column in ["backlog", "todo", "in-progress", "in-review"] {
        let turns = Turns::new("open")
            .receipt("CLOUD-408", column)
            .prompt()
            .say(CITED)
            .on_row("mcp__Linear__save_issue", "id", "CLOUD-408");
        clean(&turns.check());
    }
    // A comment names its row `issueId`, and reaches the column too.
    let turns = Turns::new("open-comment")
        .receipt("CLOUD-407", "todo")
        .prompt()
        .say(CITED)
        .on_row("mcp__Linear__save_comment", "issueId", "CLOUD-407");
    clean(&turns.check());
}

/// Could-not-look lands on the side of closed, or it buys silence.
#[test]
fn a_row_with_no_readable_open_column_is_not_a_home() {
    for (key, receipt) in [
        ("CLOUD-404", None),
        ("CLOUD-405", Some("-")),
        ("CLOUD-406", Some("archived")),
        ("7f3a-not-a-key", None),
    ] {
        let mut turns = Turns::new("not-a-home");
        if let Some(column) = receipt {
            turns = turns.receipt(key, column);
        }
        let turns = turns
            .prompt()
            .say(CITED)
            .on_row("mcp__Linear__save_issue", "id", key);
        fired(&turns.check(), 1);
    }
}

#[test]
fn outside_a_checkout_every_row_reads_as_closed() {
    let turns = Turns::new("outside")
        .receipt("CLOUD-409", "todo")
        .prompt()
        .say(CITED)
        .on_row("mcp__Linear__save_issue", "id", "CLOUD-409");
    turns.write();
    let outside = turns.root.clone();
    let path = turns.transcript().display().to_string();
    fired(&turns.check_in(&outside, &path), 1);
}

/// The declared door the engine's end-of-turn ladder runs.
#[test]
fn the_stop_handler_row_runs_this_task() {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("the config");
    let config: toml::Value = toml::from_str(&text).expect("parses");
    let rows = config["hook"]["handler"].as_array().expect("handler rows");
    let row = rows
        .iter()
        .find(|row| row["id"].as_str() == Some("finding-sink"))
        .expect("the finding-sink row");
    assert_eq!(row["on"].as_str(), Some("stop"));
    let run: Vec<&str> = row["run"]
        .as_array()
        .expect("run")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(run.last(), Some(&"finding-sink-check"), "{run:?}");
}
