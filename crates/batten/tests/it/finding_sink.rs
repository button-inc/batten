//! `[tasks.finding-sink-check]` — a turn that cites `path:line` evidence and
//! gives it no OPEN row stranded a finding (CLOUD-252, CLOUD-475, CLOUD-775) —
//! over the compiled binary: `batten record decide turn-writes` reads the turn
//! (`crates/batten/src/turn.rs`) and `policy/finding-sink.rego` decides
//! (CLOUD-843).
//!
//! Every case runs the COMMITTED task's argv (read out of `mise.toml`) against
//! a scratch repository registering the real module and the committed
//! `[[pattern]]` rows, and owns its git dir: the reading resolves a row's column
//! from a read receipt under it, and a live session's receipts deciding a case
//! would pass it for a reason the case never states.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/finding-sink-check.sh subject:mise.toml crates/batten/tests/it/finding_sink.rs
// ported: tests/finding-sink-check.bats subject:mise.toml crates/batten/tests/it/finding_sink.rs
// carried: "[tasks.finding-sink-check] body" policy/finding-sink.rego crates/batten/tests/it/finding_sink.rs
// carried: "[tasks.finding-sink-check] body, the reading" crates/batten/src/turn.rs kind:mechanism crates/batten/tests/it/finding_sink.rs
// carried: "THE STRANDED FINDING: path:line evidence with no durable write is reported" policy/finding-sink.rego
// carried: "the same turn with a tracker write is clean" policy/finding-sink.rego
// carried: "prose with no path:line is clean — ordinary conversation is not noise" crates/batten/src/turn.rs kind:mechanism
// carried: "a durable write counts under the UUID prefix, not only the readable alias" policy/finding-sink.rego
// carried: "CLOUD-475: a COMMENT alone is not a home — recorded is not scheduled" policy/finding-sink.rego
// carried: "CLOUD-475: comment PLUS a new open row is a home — the CLOUD-473 shape" policy/finding-sink.rego
// carried: "CLOUD-475: save_issue WITH an id is an annotation, not a filing" policy/finding-sink.rego
// carried: "a memory write counts as durable too, not only the tracker" policy/finding-sink.rego
// carried: "a read-only tool call is not a durable write" policy/finding-sink.rego
// carried: "a subagent's write is not credited to the orchestrator's turn" crates/batten/src/turn.rs kind:mechanism
// carried: "a subagent's prose is not judged as the orchestrator's" crates/batten/src/turn.rs kind:mechanism
// carried: "a tool_result does not open a new turn" crates/batten/src/turn.rs kind:mechanism
// carried: "POINTER, NEVER PAYLOAD: the report carries no byte of the prose" crates/batten/src/turn.rs kind:mechanism
// carried: "ONLY THE LAST TURN is judged — an earlier stranding is not re-reported" crates/batten/src/turn.rs kind:mechanism
// carried: "a stranding in the last turn fires even when earlier turns were clean" crates/batten/src/turn.rs kind:mechanism
// carried: "a path:line-looking string that is not a source file does not fire" batten.toml
// carried: "ANTI-VACUITY: a transcript with no turns exits 0 and says it judged nothing" crates/batten/src/lib.rs kind:verb
// carried: "ANTI-VACUITY: the suite's own fired case is reachable" policy/finding-sink.rego
// carried: "CLOUD-775: an annotation on a TERMINAL row still reports — CLOUD-475 survives" policy/finding-sink.rego
// carried: "CLOUD-775: an amendment to a NON-TERMINAL row is a home" policy/finding-sink.rego
// carried: "CLOUD-775: a row this clone has no recorded read of is not a home" crates/batten/src/turn.rs kind:mechanism
// carried: "CLOUD-775: a receipt that recorded no column is not a home either" policy/finding-sink.rego
// carried: "CLOUD-775: an unrecognised column is not a home" policy/finding-sink.rego
// carried: "CLOUD-775: a comment on an OPEN row is a home, named by issueId" policy/finding-sink.rego
// carried: "CLOUD-775: every open column the board carries is a home" policy/finding-sink.rego
// carried: "CLOUD-775: an id that is not an issue key is not a home" crates/batten/src/turn.rs kind:mechanism
// carried: "the mediated route files through batten mcp call, and a mediated read is not a home" crates/batten/src/turn.rs kind:mechanism
// carried: "#1052: a row's column is known only from a read receipt, which a listing never mints" batten.toml
// changed: "a firing exits 1 with turn:<n> finding-without-durable-write" crates/batten/src/lib.rs a firing is `check`'s exit 2 with the pointer `turn:<n>` and the rule `turn file missing`: one exit table, no per-verb exception, and the stop handler's door says an exit 2 exactly as it said an exit 1
// changed: "the refusal names the practice: OPEN row" batten.toml the practice is the verdict's gloss and class, which `policy explain turn file missing` prints, rather than a sentence the task wrote beside the pointer
// changed: "a clean turn prints nothing on either stream" crates/batten/src/lib.rs a clean turn prints nothing on STDOUT, the channel the handler door reads; stderr is the engine's diagnostic channel
// changed: "CLOUD-775: outside a checkout every row reads as closed" crates/batten/src/record.rs outside a checkout there is no record store to decide over, so the verb abstains at exit 0 — the handler door's pass — rather than firing
// changed: "an unparseable transcript exits 2 — could not look is not a verdict" crates/batten/src/record.rs exits 0 with the reason on stderr and nothing on stdout, and removes any stale record: the handler door has no abstention code
// changed: "an absent transcript path exits 2, not 0" crates/batten/src/record.rs exits 0 with nothing on stdout, for the same reason, and says why on stderr
// changed: "empty stdin exits 2 rather than reporting a clean session" crates/batten/src/record.rs exits 0 with nothing on stdout, for the same reason, and says why on stderr

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const CITED: &str = "The ordering key is wrong at mise-tasks/checks-green.sh:164.";

/// The committed task's argv after `cargo run --quiet -p batten --`, split the
/// way `sh` splits it: whitespace, and single quotes grouping.
fn committed_argv() -> Vec<String> {
    let text = std::fs::read_to_string(common::at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&text).expect("mise.toml parses");
    let run = parsed["tasks"]["finding-sink-check"]["run"]
        .as_str()
        .expect("the task is one argv string");
    let (_, argv) = run
        .split_once(" -- ")
        .expect("the task runs the engine with `cargo run ... --`");
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in argv.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            _ => word.push(c),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// A scratch repository registering the real module, the committed pattern
/// rows, and the rule, verdict and record the module needs.
fn repo_at(repo: &Path) {
    let module =
        std::fs::read_to_string(common::at_root("policy/finding-sink.rego")).expect("the module");
    common::write(repo, "policy/finding-sink.rego", &module);
    let mut config = String::from(
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "turn file missing"
gloss = "a turn cited path:line evidence and gave it no OPEN row"
class = "fixture"

[[verdict.route]]
id = "issue file first"
kind = "command"
target = "file an open issue"

[[rule]]
id = "turn file missing"
kind = "policy"
scope = "tree"
module = "policy/finding-sink.rego"
severity = "deny"

[[record]]
record = "turn-writes"
writer = "mise run finding-sink-check"
"#,
    );
    config.push_str(&common::declared_patterns());
    common::write(repo, "batten.toml", &config);
    common::init_repo(repo);
    common::git_in(repo, &["add", "-A"]);
    common::git_in(repo, &["commit", "-qm", "register the module"]);
    std::fs::create_dir_all(repo.join(".git/batten-receipts")).expect("receipts");
}

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
        repo_at(&repo);
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

    /// A `Bash` block running `command` — the route this repository files through.
    fn bash(self, command: &str) -> Self {
        self.line(&serde_json::json!({"type":"assistant","isSidechain":false,"message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":command}}]}}))
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

    /// The committed task's argv, run in `dir` with `stdin`: (exit, stdout, both).
    fn check_in(&self, dir: &Path, stdin: &str) -> (Option<i32>, String, String) {
        let argv = committed_argv();
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let out = common::run_with_stdin(dir, &args, stdin);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let both = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
        (out.status.code(), stdout, both)
    }

    /// The check over this transcript's path, the shape a hand run pipes.
    fn check(&self) -> (Option<i32>, String, String) {
        self.write();
        self.check_in(&self.repo, &self.transcript().display().to_string())
    }

    /// The check over a host `Stop` payload, the shape the handler door pipes.
    fn check_stop(&self) -> (Option<i32>, String, String) {
        self.write();
        let payload = serde_json::json!({
            "hook_event_name": "Stop",
            "transcript_path": self.transcript().display().to_string(),
        });
        self.check_in(&self.repo, &payload.to_string())
    }
}

fn fired(result: &(Option<i32>, String, String), turn: u32) {
    assert_eq!(result.0, Some(2), "{}", result.2);
    assert!(
        result.2.contains(&format!("turn:{turn}")),
        "the pointer is the turn: {}",
        result.2
    );
    assert!(result.2.contains("turn file missing"), "{}", result.2);
}

fn clean(result: &(Option<i32>, String, String)) {
    assert_eq!(result.0, Some(0), "{}", result.2);
    assert!(result.1.is_empty(), "nothing on stdout: {}", result.2);
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
fn a_filing_through_the_mediated_route_clears_it() {
    // THE SANCTIONED ROUTE. The raw MCP tools are denied here, so a filing is a
    // `Bash` block running `batten mcp call`; reading only tool names made the
    // one permitted way to file a finding invisible to the gate that demands it.
    let turns = Turns::new("mediated-file")
        .prompt()
        .say("Broken at crates/batten/src/record.rs:943.")
        .bash("batten mcp call Linear save_issue \"$(cat issue.json)\"");
    clean(&turns.check());
    // A mediated READ is still not a home.
    let turns = Turns::new("mediated-read")
        .prompt()
        .say("Broken at crates/batten/src/record.rs:943.")
        .bash("batten mcp call Linear get_issue '{\"id\":\"CLOUD-1\"}'");
    fired(&turns.check(), 1);
    // A mediated MEMORY write is not a home: the retired body credited the
    // mediated route for `save_(issue|comment)` alone.
    let turns = Turns::new("mediated-memory")
        .prompt()
        .say("Broken at crates/batten/src/record.rs:943.")
        .bash("batten mcp call serena write_memory '{\"memory_name\":\"x\"}'");
    fired(&turns.check(), 1);
    // A mediated amendment names its row, and reaches the column.
    let turns = Turns::new("mediated-amend")
        .receipt("CLOUD-410", "in-progress")
        .prompt()
        .say("Broken at crates/batten/src/record.rs:943.")
        .bash("batten mcp call Linear save_comment '{\"issueId\":\"CLOUD-410\",\"body\":\"x\"}'");
    clean(&turns.check());
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
    fired(&turns.check(), 1);
    // It names the PRACTICE, and #1052's remedy: a row's column is known only
    // from a READ receipt, which a listing never mints. The committed verdict
    // row carries both, and `policy explain` is where a reader meets them.
    let explained = common::run(
        &common::at_root("."),
        &["policy", "explain", "turn file missing"],
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&explained.stdout),
        String::from_utf8_lossy(&explained.stderr)
    );
    assert!(said.contains("OPEN row"), "{said}");
    assert!(
        said.contains(
            "A read is recorded by batten mcp call <server> get_issue on that row; a listing records none."
        ),
        "{said}"
    );
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
    assert_eq!(result.0, Some(2), "{}", result.2);
    assert!(!result.2.contains("SENTINELXYZZY"), "{}", result.2);
    assert!(!result.2.contains("The defect is at"), "{}", result.2);
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

/// Could-not-look is not a refusal: at the handler door a 2 IS a refusal, and
/// "no transcript" is not one, so the verb exits 0 with nothing on stdout.
#[test]
fn an_unreadable_transcript_abstains() {
    let turns = Turns::new("unparseable");
    std::fs::write(turns.transcript(), "this is not json\n").expect("write");
    let (code, stdout, both) =
        turns.check_in(&turns.repo, &turns.transcript().display().to_string());
    assert_eq!(code, Some(0), "{both}");
    assert!(stdout.is_empty(), "{both}");
    assert!(both.contains("abstained"), "{both}");
    let absent = turns.root.join("nope.jsonl").display().to_string();
    assert_eq!(turns.check_in(&turns.repo, &absent).0, Some(0));
    assert_eq!(turns.check_in(&turns.repo, "").0, Some(0));
    assert_eq!(turns.check_in(&turns.repo, "{}").0, Some(0));
}

/// A firing leaves no record behind. The retired body said its verdict on
/// stderr and in its exit code and wrote nothing, so a stranding on one turn
/// never refused a later `check` or `enforce` over the whole ruleset — the
/// `verify` and `land` gates. A reading left in the store would, until the next
/// `stop` rewrote it.
#[test]
fn a_decided_record_never_answers_a_later_check() {
    let turns = Turns::new("stale").prompt().say(CITED);
    fired(&turns.check(), 1);
    for argv in [
        &["check"][..],
        &["check", "--rule", "turn file missing"][..],
        &["enforce"][..],
    ] {
        let decided = common::run(&turns.repo, argv);
        assert_eq!(
            decided.status.code(),
            Some(0),
            "{argv:?}: the decided record is gone, so nothing is decided: {}{}",
            String::from_utf8_lossy(&decided.stdout),
            String::from_utf8_lossy(&decided.stderr)
        );
    }
    // And an abstention after it is silent too.
    let (code, _, both) = turns.check_in(&turns.repo, "");
    assert_eq!(code, Some(0), "{both}");
}

#[test]
fn a_transcript_with_no_turns_says_it_judged_nothing() {
    let (code, stdout, both) = Turns::new("empty").check();
    assert_eq!(code, Some(0), "{both}");
    assert!(stdout.is_empty(), "{both}");
    assert!(both.contains("nothing to judge"), "{both}");
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

/// Outside a checkout there is no record store: the verb abstains, which the
/// handler door reads as a pass.
#[test]
fn outside_a_checkout_the_check_abstains() {
    let outside = common::scratch_outside_tree("finding-sink", "outside");
    let transcript = outside.join("transcript.jsonl");
    let prompt = serde_json::json!({"type":"user","message":{"content":"go"}});
    let say = serde_json::json!({"type":"assistant","message":{"content":[{"type":"text","text":CITED}]}});
    std::fs::write(&transcript, format!("{prompt}\n{say}\n")).expect("the transcript");
    let argv = committed_argv();
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = common::run_with_stdin(&outside, &args, &transcript.display().to_string());
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
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
    // And the task is the engine's verb, one argv, no body.
    let argv = committed_argv();
    assert_eq!(
        argv.get(..3),
        Some(
            &[
                "record".to_owned(),
                "decide".to_owned(),
                "turn-writes".to_owned()
            ][..]
        )
    );
}
