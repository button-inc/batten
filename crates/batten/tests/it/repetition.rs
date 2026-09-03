//! `policy/repetition-without-progress.rego` over the compiled engine (CLOUD-1347).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `facts.extracted` object, so
//! they are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names. What only the real boundary can prove
//! is that `repeat-depth` is the RUN the engine actually computes: a fabricated
//! `{"repeat-depth": 3}` asserts the author's arithmetic, where a fixture stream
//! of real `tool_use` records asserts the engine's.
//!
//! # The two arms that carry the design
//!
//! Adjacency is what does the false-positive work, so the case that matters most
//! is not the refusal — it is `an_intervening_distinct_call_clears_the_run`. The
//! edit-then-retest loop must be false by construction rather than by carve-out,
//! and that is the arm a window-based reading would fail.
//!
//! The other is `a_replayed_call_is_not_a_second_call`: compaction re-emits a
//! `tool_use` under the id it already carried, so counting replays measures what
//! the host chose to re-emit rather than what the session did.
//!
//! # Rule 4
//!
//! `no_argument_text_reaches_any_output` is the standing guarantee. The fixture
//! embeds distinctive prose in every argument object; the fingerprint is hashed
//! and dropped inside `transcript.rs`, and only a run length is projected, so
//! finding that prose anywhere in either channel is the leak.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{StateHome as _, at_root, batten, git_in, scratch, write};

/// Prose distinctive enough that finding it anywhere is unambiguous.
const PROSE: &str = "REPETITION-PROSE-THAT-MUST-NOT-REACH-ANY-OUTPUT";

/// The SHIPPED module's registration, so a mutation of it reddens these cases.
///
/// **`deny` here where the repository ships `warn`, deliberately.** This fixture
/// pins the PREDICATE — whether the engine builds the run the module reads — and
/// a refusal is the unambiguous observable for that. The severity the row ships
/// at is a separate decision recorded beside the row, and CLOUD-1352 owns it.
///
/// **No `[[pattern]]` rows**, so the compiled tier gets the same empty vocabulary
/// a consumer has: declaring pattern ids would supply input no consumer supplies.
fn config() -> String {
    String::from(
        r#"version = 1

[[rule]]
id = "repetition-without-progress"
kind = "policy"
scope = "mediated_call"
module = "repetition-without-progress.rego"
severity = "deny"

[[rule.extract]]
id = "repeat-depth"
count = "repeat-depth"

[[rule.extract]]
id = "distinct-calls"
count = "distinct-calls"

[[verdict]]
id = "turn ask twice"
gloss = "this session has already made this call, with these arguments, with nothing in between"
class = "A call you have already made, with the same arguments and nothing in between, told you what it told you the first time."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "repetition-without-progress.rego"
"#,
    )
}

/// One `tool_use` record, in the host's own shape.
fn call(index: usize, id: &str, name: &str, argument: &str) -> serde_json::Value {
    let _ = index;
    serde_json::json!({
        "type": "assistant",
        "sessionId": "s-1",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": id, "name": name,
             "input": {"command": argument, "note": PROSE}}
        ]},
    })
}

/// A session whose calls are described by `(name, argument)` pairs, each with its
/// own `tool_use` id unless `replayed`.
fn session(calls: &[(&str, &str)], replayed: bool) -> String {
    calls
        .iter()
        .enumerate()
        .map(|(index, (name, argument))| {
            let id = if replayed {
                String::from("t0")
            } else {
                format!("t{index}")
            };
            call(index, &id, name, argument).to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The same call `count` times, with nothing between them.
fn identical(count: usize) -> String {
    let calls: Vec<(&str, &str)> = (0..count).map(|_| ("ReadNotifications", "poll")).collect();
    session(&calls, false)
}

fn fixture(name: &str, transcript: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = scratch(&format!("repetition-{name}"));
    let home = scratch(&format!("repetition-home-{name}"));
    write(&dir, "batten.toml", &config());
    let module = std::fs::read_to_string(at_root("policy/repetition-without-progress.rego"))
        .expect("the shipped module is committed");
    write(&dir, "repetition-without-progress.rego", &module);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "session.jsonl", transcript);
    let path = dir.join("session.jsonl");
    (dir, home, path)
}

fn channels(dir: &Path, home: &Path, transcript: Option<&Path>) -> (String, String) {
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
    let outcome = child.wait_with_output().expect("run batten hook");
    (
        String::from_utf8_lossy(&outcome.stdout).into_owned(),
        String::from_utf8_lossy(&outcome.stderr).into_owned(),
    )
}

fn reported(dir: &Path, home: &Path, transcript: &Path) -> bool {
    let (answer, cause) = channels(dir, home, Some(transcript));
    answer.contains("turn ask twice") || cause.contains("turn ask twice")
}

#[test]
fn a_trailing_run_of_identical_calls_is_reported() {
    // THE DEFECT ARM, and the case `#MUTANT run-may-go-unpriced` names. Three
    // identical calls with nothing between them is a depth of 3 — the threshold
    // every documented detector is stated in.
    let (dir, home, transcript) = fixture("run", &identical(3));
    assert!(
        reported(&dir, &home, &transcript),
        "three identical calls in a row must reach the threshold"
    );
}

#[test]
fn two_in_a_row_is_not_a_run() {
    // THE BOUNDARY FROM BELOW. An off-by-one here moves the whole population the
    // rule fires on, and the engine is what decides it: a depth counts CALLS, not
    // repeats, so two identical calls are a depth of 2 and clean.
    let (dir, home, transcript) = fixture("two", &identical(2));
    assert!(
        !reported(&dir, &home, &transcript),
        "two identical calls are a depth of two, which is below the threshold"
    );
}

#[test]
fn an_intervening_distinct_call_clears_the_run() {
    // THE ARM THAT MAKES ADJACENCY WORTH HAVING, and the anti-vacuity mirror
    // (CLOUD-418). A session that ran one command many times WITH work between
    // them is the edit-then-retest loop, and it must be false by construction
    // rather than by carve-out. A window-based reading fails exactly here.
    let calls: Vec<(&str, &str)> = vec![
        ("Bash", "mise run test"),
        ("Edit", "fix one"),
        ("Bash", "mise run test"),
        ("Edit", "fix two"),
        ("Bash", "mise run test"),
        ("Edit", "fix three"),
        ("Bash", "mise run test"),
    ];
    let (dir, home, transcript) = fixture("interleaved", &session(&calls, false));
    assert!(
        !reported(&dir, &home, &transcript),
        "a rerun with work between is progress, not a run"
    );
}

#[test]
fn a_different_argument_is_a_different_call() {
    // The fingerprint is (tool, arguments), so the same TOOL with varying
    // arguments is not a run. Without this the predicate would fire on any
    // session that used one tool heavily.
    let calls: Vec<(&str, &str)> = vec![
        ("Bash", "one"),
        ("Bash", "two"),
        ("Bash", "three"),
        ("Bash", "four"),
    ];
    let (dir, home, transcript) = fixture("varied", &session(&calls, false));
    assert!(
        !reported(&dir, &home, &transcript),
        "the same tool with different arguments is not the same call"
    );
}

#[test]
fn a_replayed_call_is_not_a_second_call() {
    // COMPACTION RE-EMITS A `tool_use` UNDER THE ID IT ALREADY CARRIED, so
    // counting replays measures what the host chose to re-emit rather than what
    // the session did. Nine records under one id are ONE call.
    let calls: Vec<(&str, &str)> = (0..9).map(|_| ("ReadNotifications", "poll")).collect();
    let (dir, home, transcript) = fixture("replay", &session(&calls, true));
    assert!(
        !reported(&dir, &home, &transcript),
        "a replayed tool_use id is the same call, not another one"
    );
}

#[test]
fn a_missing_transcript_is_not_a_clean_session() {
    // COULD NOT LOOK IS NOT INNOCENCE. A host that hands over no path is the
    // common case, and reading it as "nothing was repeated" is the false green.
    let (dir, home, _transcript) = fixture("absent", &identical(9));
    let (answer, cause) = channels(&dir, &home, None);
    assert!(
        !answer.contains("turn ask twice") && !cause.contains("turn ask twice"),
        "an unlooked-at session is not a finding\n{answer}{cause}"
    );
}

#[test]
fn no_argument_text_reaches_any_output() {
    // RULE 4, as a standing guarantee. The fingerprint is hashed and dropped
    // inside `transcript.rs` and only a run length is projected, so finding the
    // fixture's prose in either channel is the leak.
    let (dir, home, transcript) = fixture("scrub", &identical(9));
    let (answer, cause) = channels(&dir, &home, Some(&transcript));
    assert!(
        !answer.contains(PROSE) && !cause.contains(PROSE),
        "no argument text may reach any output\n{answer}{cause}"
    );
}
