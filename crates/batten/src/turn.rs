//! The judged turn of a session, reduced to what a module decides over
//! (CLOUD-252, CLOUD-475, CLOUD-775; retired off `[tasks.finding-sink-check]`
//! under CLOUD-843).
//!
//! # What moved here, and what did not
//!
//! The task read a host transcript with two `jq` passes and decided, in the same
//! string, whether the last turn stranded a finding. The two halves go to two
//! homes. The READING is this module: where the turn starts, which blocks are the
//! orchestrator's, whether its prose carries a citation, and which tool calls it
//! made. The DECISION — which of those calls is a home for a finding — names a
//! tracker's methods and a board's columns, so it is a consumer module reading
//! the record this produces, and nothing here knows a method name.
//!
//! # The one arm that reads prose, bounded to a boolean
//!
//! `transcript.rs` refuses to interpret prose, and `rules/policy-modules.md`
//! records that `extracted` cannot grow an arm that does. This module is the
//! producer that gate's own measured instance always needed: it applies ONE
//! pattern the consumer declares to the judged turn's assistant text and keeps
//! only whether it matched. No byte of the prose reaches the record, the output
//! or an error, which is non-negotiable rule 4 held by the type — [`Turn`] has no
//! field a sentence could occupy.
//!
//! # Could-not-look is not a finding
//!
//! No path, an unreadable file, or a line that is not JSON is
//! [`Reading::Unreadable`]: the caller records nothing, so the module is silent,
//! which is the handler door's pass. A stream with no turn at all is
//! [`Reading::Read`] with `turns == 0` — a real answer, which the module reads as
//! nothing to judge.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Where the transcript is, from what a `Stop` handler is handed on stdin.
///
/// Two shapes, as the retired task read them: the host's own `Stop` payload,
/// whose `transcript_path` names the file, or a bare path piped by hand.
/// Whitespace is stripped from the path whole, as the task did.
#[must_use]
pub fn transcript_of(stdin: &str) -> Option<PathBuf> {
    let trimmed = stdin.trim();
    let named = if trimmed.starts_with('{') {
        let payload: Value = serde_json::from_str(trimmed).ok()?;
        payload.get("transcript_path")?.as_str()?.to_owned()
    } else {
        trimmed.to_owned()
    };
    let path: String = named.chars().filter(|c| !c.is_whitespace()).collect();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// One tool call the judged turn made: its name, and the row it named if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The tool's name, or `mcp call <server> <method>` for a mediated call, so
    /// a module can tell the route apart from a direct call of the same method.
    pub name: String,
    /// The row key the call named, or empty for a call naming none.
    pub key: String,
}

/// The judged turn, reduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// How many turns a person opened, which is also the judged turn's number.
    pub turns: usize,
    /// Whether the judged turn's own prose carries the declared citation.
    pub cited: bool,
    /// The judged turn's own tool calls, in order.
    pub calls: Vec<Call>,
}

/// What reading a transcript answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// The transcript could not be read as JSONL: record nothing.
    Unreadable,
    /// The turn, reduced.
    Read(Turn),
}

/// The consumer's vocabulary for one reading. Every member is declared by the
/// consumer: which prose is evidence, how a mediated call names its row, and
/// which input fields of a direct call carry one.
#[derive(Debug)]
pub struct Vocabulary<'a> {
    /// A match anywhere in the turn's prose is a citation.
    pub citation: &'a regex::Regex,
    /// Applied to a mediated call's command; its `key` group is the row.
    pub key: &'a regex::Regex,
    /// The input fields of a direct call that name its row, in precedence order.
    pub fields: &'a [String],
}

/// A person's turn boundary: an authored `user` record, never a `tool_result`.
fn opens_a_turn(line: &Value) -> bool {
    if line.get("isSidechain") == Some(&Value::Bool(true)) {
        return false;
    }
    if line.get("type").and_then(Value::as_str) != Some("user") {
        return false;
    }
    match line
        .get("message")
        .and_then(|message| message.get("content"))
    {
        Some(Value::String(_)) => true,
        Some(Value::Array(blocks)) => blocks.iter().any(is_text),
        _ => false,
    }
}

/// A `text` block: what makes a `user` record a person speaking rather than
/// the harness handing a `tool_result` back.
fn is_text(block: &Value) -> bool {
    block.get("type").and_then(Value::as_str) == Some("text")
}

/// The orchestrator's own assistant blocks: a subagent's are not this turn's.
fn orchestrator_blocks(line: &Value) -> &[Value] {
    if line.get("isSidechain") == Some(&Value::Bool(true)) {
        return &[];
    }
    if line.get("type").and_then(Value::as_str) != Some("assistant") {
        return &[];
    }
    line.get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// The engine's own mediated route, read off a `Bash` call's command, as the
/// call's name: `mcp call <server> <method>`. The verb is this crate's, so
/// naming it here names no consumer.
///
/// **THE ROUTE STAYS IN THE NAME, and dropping it widened the gate.** Recorded
/// as the bare method, a mediated `write_memory` read exactly like a direct one,
/// so the module's durable-write arm credited a route the retired body never
/// did. Which mediated methods are a home is the module's decision, and it can
/// only make it if the record says which route a call took.
fn mediated_call(command: &str) -> Option<String> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let at = words
        .windows(2)
        .position(|pair| pair.first() == Some(&"mcp") && pair.get(1) == Some(&"call"))?;
    // `mcp call <server> <method>`: the server and method follow `mcp call`.
    let word = |offset: usize| -> Option<String> {
        let found: String = words
            .get(at + offset)?
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            .collect();
        (!found.is_empty()).then_some(found)
    };
    let (server, method) = (word(2)?, word(3)?);
    Some(format!("mcp call {server} {method}"))
}

/// A scalar input field as the row key, `jq`'s `tostring` for a number.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// One tool call, reduced to its name and the row it named.
fn call_of(block: &Value, vocabulary: &Vocabulary<'_>) -> Call {
    let name = block
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let input = block.get("input");
    // THE SANCTIONED ROUTE. Where the raw MCP tools are denied, a filing arrives
    // as a `Bash` block running the engine's own `mcp call`, and its method and
    // row come from the command rather than from the tool's name.
    if name == "Bash"
        && let Some(command) = input
            .and_then(|input| input.get("command"))
            .and_then(Value::as_str)
        && let Some(method) = mediated_call(command)
    {
        let key = vocabulary
            .key
            .captures(command)
            .and_then(|captures| captures.name("key"))
            .map(|found| found.as_str().to_owned())
            .unwrap_or_default();
        return Call { name: method, key };
    }
    let key = vocabulary
        .fields
        .iter()
        .find_map(|field| {
            input
                .and_then(|input| input.get(field.as_str()))
                .filter(|value| !value.is_null())
                .and_then(scalar)
        })
        .unwrap_or_default();
    Call { name, key }
}

/// Read the judged turn out of one transcript body.
///
/// ONLY THE LAST TURN IS JUDGED (CLOUD-479): an earlier stranding was the earlier
/// turn's to report, and re-reporting it every turn after is how a channel stops
/// being read.
#[must_use]
pub fn read(body: &str, vocabulary: &Vocabulary<'_>) -> Reading {
    let mut lines = Vec::new();
    for raw in body.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let Ok(line) = serde_json::from_str::<Value>(raw) else {
            return Reading::Unreadable;
        };
        lines.push(line);
    }
    let boundaries: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| opens_a_turn(line))
        .map(|(at, _)| at)
        .collect();
    let turns = boundaries.len();
    let Some(&start) = boundaries.last() else {
        return Reading::Read(Turn {
            turns: 0,
            cited: false,
            calls: Vec::new(),
        });
    };
    let mut cited = false;
    let mut calls = Vec::new();
    for line in lines.get(start..).unwrap_or_default() {
        for block in orchestrator_blocks(line) {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    let text = block
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .replace('\n', " ");
                    if vocabulary.citation.is_match(&text) {
                        cited = true;
                    }
                }
                Some("tool_use") => calls.push(call_of(block, vocabulary)),
                _ => {}
            }
        }
    }
    Reading::Read(Turn {
        turns,
        cited,
        calls,
    })
}

/// The column a read receipt recorded for `key`, or `-` where there is none.
///
/// `receipt` names the receipt family (`<receipt>.<key>` under `$GIT_DIR`'s
/// receipt store) and `field` the 1-indexed field of its first line, both the
/// consumer's. A key that is not one path component has no receipt — it could
/// otherwise name a file outside the store — and reads as `-`, which a module
/// reads as no open row: could-not-look lands on the side of closed, or it buys
/// silence (CLOUD-775).
#[must_use]
pub fn column(git_dir: Option<&Path>, receipt: &str, field: usize, key: &str) -> String {
    let unsafe_key = key.is_empty()
        || key == "."
        || key == ".."
        || key.contains('/')
        || key.contains('\\')
        || key.contains('\0');
    let Some(git_dir) = git_dir else {
        return "-".to_owned();
    };
    if unsafe_key || field == 0 {
        return "-".to_owned();
    }
    let path = git_dir
        .join("batten-receipts")
        .join(format!("{receipt}.{key}"));
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| nth_field(&text, field))
        .unwrap_or_else(|| "-".to_owned())
}

/// The 1-indexed whitespace-separated `field` of `text`'s first line.
fn nth_field(text: &str, field: usize) -> Option<String> {
    let first = text.lines().next()?;
    let value = first.split_whitespace().nth(field.checked_sub(1)?)?;
    Some(value.to_owned())
}

/// A value that cannot be a column: empty, or carrying a tab or newline that
/// would forge a column or a line. No host registers such a name, so it is
/// recorded as `-`.
fn forged(value: &str) -> bool {
    value.is_empty() || value.contains(['\t', '\n'])
}

/// The record a module reads: `turns`, `cited`, then one `call` line per call.
///
/// `call<TAB><name><TAB><key|-><TAB><column|->`. The column is resolved here
/// because a module cannot read the receipt store.
#[must_use]
pub fn render(turn: &Turn, columns: &dyn Fn(&str) -> String) -> String {
    let mut body = String::new();
    body.push_str("turns\t");
    body.push_str(&turn.turns.to_string());
    body.push_str("\ncited\t");
    body.push_str(if turn.cited { "true" } else { "false" });
    body.push('\n');
    for call in &turn.calls {
        let key: &str = if forged(&call.key) { "-" } else { &call.key };
        let column = if key == "-" {
            "-".to_owned()
        } else {
            columns(key)
        };
        let name: &str = if forged(&call.name) { "-" } else { &call.name };
        for (at, value) in ["call", name, key, column.as_str()].into_iter().enumerate() {
            if at > 0 {
                body.push('\t');
            }
            body.push_str(value);
        }
        body.push('\n');
    }
    body
}

//MUTANT-SUITE crates/batten/src/turn.rs
//MUTANT sidechain-credited|s@^    if line.get("isSidechain") == Some(&Value::Bool(true)) {$@    if false {@|a_subagents_blocks_are_not_the_turns
//MUTANT tool-result-opens-a-turn|s@^    block.get("type").and_then(Value::as_str) == Some("text")$@    true@|a_tool_result_does_not_open_a_turn
//MUTANT whole-transcript-judged|s@^    let Some(&start) = boundaries.last() else {$@    let Some(\&start) = boundaries.first() else {@|only_the_last_turn_is_judged
//MUTANT mediated-route-unseen|s@^    if name == "Bash"$@    if name == "never"@|a_mediated_call_names_its_method_and_row
//MUTANT mediated-route-dropped|s@^    Some(format!("mcp call {server} {method}"))$@    Some(format!("{server} {method}").split_off(server.len() + 1))@|a_mediated_call_names_its_method_and_row
//MUTANT citation-ignored|s@^                        cited = true;$@                        cited = false;@|a_citation_in_the_last_turn_is_read
//MUTANT receipt-field-ignored|s@^    let value = first.split_whitespace().nth(field.checked_sub(1)?)?;$@    let value = first.split_whitespace().next()?;@|a_receipt_column_is_its_declared_field

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn citation() -> regex::Regex {
        regex::Regex::new(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+:[0-9]+").unwrap()
    }

    fn key() -> regex::Regex {
        regex::Regex::new(r"(?:id|issueId)[^A-Z]{0,4}(?P<key>[A-Z]+-[0-9]+)").unwrap()
    }

    fn fields() -> Vec<String> {
        vec!["id".to_owned(), "issueId".to_owned()]
    }

    fn turn(body: &str) -> Turn {
        let (citation, key, fields) = (citation(), key(), fields());
        let vocabulary = Vocabulary {
            citation: &citation,
            key: &key,
            fields: &fields,
        };
        match read(body, &vocabulary) {
            Reading::Read(turn) => turn,
            Reading::Unreadable => panic!("the fixture is JSONL"),
        }
    }

    const PROMPT: &str = r#"{"type":"user","message":{"content":"go"}}"#;
    const CITES: &str = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Broken at src/a.rs:4."}]}}"#;
    const CLEAN: &str =
        r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Pushed."}]}}"#;

    #[test]
    fn a_citation_in_the_last_turn_is_read() {
        let read = turn(&format!("{PROMPT}\n{CITES}\n"));
        assert_eq!(read.turns, 1);
        assert!(read.cited);
        assert!(!turn(&format!("{PROMPT}\n{CLEAN}\n")).cited);
    }

    #[test]
    fn only_the_last_turn_is_judged() {
        let read = turn(&format!("{PROMPT}\n{CITES}\n{PROMPT}\n{CLEAN}\n"));
        assert_eq!(read.turns, 2);
        assert!(
            !read.cited,
            "the earlier turn's citation is not this turn's"
        );
    }

    #[test]
    fn a_tool_result_does_not_open_a_turn() {
        let result =
            r#"{"type":"user","message":{"content":[{"type":"tool_result","content":"ok"}]}}"#;
        let read = turn(&format!("{PROMPT}\n{CITES}\n{result}\n{CLEAN}\n"));
        assert_eq!(read.turns, 1);
        assert!(read.cited, "the result is inside the turn that cited");
    }

    #[test]
    fn a_subagents_blocks_are_not_the_turns() {
        let sub = r#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"text","text":"at src/b.rs:9"},{"type":"tool_use","name":"mcp__x__save_issue","input":{}}]}}"#;
        let read = turn(&format!("{PROMPT}\n{CLEAN}\n{sub}\n"));
        assert!(!read.cited);
        assert!(read.calls.is_empty());
    }

    #[test]
    fn a_mediated_call_names_its_method_and_row() {
        let bash = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"batten mcp call Linear save_comment '{\"issueId\":\"ABC-7\"}'"}}]}}"#;
        let read = turn(&format!("{PROMPT}\n{bash}\n"));
        assert_eq!(
            read.calls,
            vec![Call {
                name: "mcp call Linear save_comment".to_owned(),
                key: "ABC-7".to_owned()
            }]
        );
        // A direct call names its row by a declared field, a number included.
        let direct = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"t","input":{"id":12}}]}}"#;
        assert_eq!(turn(&format!("{PROMPT}\n{direct}\n")).calls[0].key, "12");
        // A mediated memory write keeps its route, so a module need not credit it.
        let memory = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"batten mcp call serena write_memory x"}}]}}"#;
        assert_eq!(
            turn(&format!("{PROMPT}\n{memory}\n")).calls[0].name,
            "mcp call serena write_memory"
        );
        // A Bash call that is not the mediated route is just `Bash`.
        let plain = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}}"#;
        assert_eq!(turn(&format!("{PROMPT}\n{plain}\n")).calls[0].name, "Bash");
    }

    #[test]
    fn a_line_that_is_not_json_is_unreadable_and_no_turn_is_zero() {
        let (citation, key, fields) = (citation(), key(), fields());
        let vocabulary = Vocabulary {
            citation: &citation,
            key: &key,
            fields: &fields,
        };
        assert_eq!(read("not json\n", &vocabulary), Reading::Unreadable);
        assert_eq!(
            read("", &vocabulary),
            Reading::Read(Turn {
                turns: 0,
                cited: false,
                calls: Vec::new()
            })
        );
    }

    #[test]
    fn the_transcript_is_named_by_payload_or_by_path() {
        assert_eq!(
            transcript_of(r#"{"transcript_path":"/t/x.jsonl"}"#),
            Some(PathBuf::from("/t/x.jsonl"))
        );
        assert_eq!(
            transcript_of(" /t/y.jsonl\n"),
            Some(PathBuf::from("/t/y.jsonl"))
        );
        assert_eq!(transcript_of(""), None);
        assert_eq!(transcript_of("{}"), None);
    }

    #[test]
    fn a_receipt_column_is_its_declared_field() {
        let dir = std::env::temp_dir().join(format!("batten-turn-column-{}", std::process::id()));
        let store = dir.join("batten-receipts");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("issue-read.ABC-1"), "ABC-1 t 1 - todo\n").unwrap();
        assert_eq!(column(Some(&dir), "issue-read", 5, "ABC-1"), "todo");
        assert_eq!(column(Some(&dir), "issue-read", 5, "ABC-2"), "-");
        assert_eq!(column(Some(&dir), "issue-read", 5, "../x"), "-");
        assert_eq!(column(None, "issue-read", 5, "ABC-1"), "-");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_record_carries_no_byte_of_the_prose() {
        let body = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"SENTINEL at src/a.rs:4"}]}}"#;
        let read = turn(&format!("{PROMPT}\n{body}\n"));
        let rendered = render(&read, &|_| "-".to_owned());
        assert!(!rendered.contains("SENTINEL"));
        assert_eq!(rendered, "turns\t1\ncited\ttrue\n");
    }
}
