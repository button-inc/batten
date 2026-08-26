//! `stop-posture` over the compiled binary (CLOUD-1051).
//!
//! # The defect this file exists because of, stated first
//!
//! The module shipped with sixteen `test_` rules, all green, and **never fired
//! on any event**. `adjudicate` returns `Allow` at `Stop` before any rule is
//! read — CLOUD-889's runaway removed by construction — so a `mediated_call`
//! module was unreachable at the one moment that projects the field it reads.
//! Its own suite could not see that: a `with input as` case fabricates the very
//! shape the engine may be unable to produce.
//!
//! That is exactly the class `.claude/rules/policy-modules.md` names, and this
//! is the tier it names as the only one that can catch it. Every case below runs
//! `batten hook --harness claude-code` against a real payload and reads what a
//! host would read.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// The committed module, the rows it needs, and nothing else.
///
/// The module is COPIED from `policy/`, never re-typed, so this fixture cannot
/// drift from what ships. The pattern and verdict rows are re-declared because a
/// fixture config is a whole authority — house style §8 admits no directory walk
/// and no merge — and because the load-time registry check refuses a token no
/// row declares.
const CONFIG: &str = r##"version = 1

[[pattern]]
id = "md-fenced-block"
regex = '```[^`]*```'

[[pattern]]
id = "md-code-span"
regex = '`[^`]*`'

[[pattern]]
id = "md-quoted-span"
regex = '"[^"]*"'

[[pattern]]
id = "md-block-quote"
regex = '(?m)^[[:space:]]*>[^\n]*'

[[pattern]]
id = "hedged-flag-framing"
regex = "(?i)worth (noting|flagging|mentioning|naming)|one thing (I would|I['’]?d) (flag|note)|I['’]?d (flag|note) (that|one)|I would (flag|note) that|I should (note|flag)|(it|that)['’]?s worth (noting|flagging|mentioning|naming)|bears (noting|flagging|mentioning|naming)"

[[verdict]]
id = "V-HEDGED-FLAG-FRAMING"
gloss = "a finding was written as editorial instead of durably"
class = """
Chat stores nothing, so a finding's home is an issue or a memory. A sentence \
that flags one in passing is the double-write CLOUD-200 and CLOUD-248 exist to \
kill.
"""

[[verdict.route]]
id = "R-WRITE-IT-DOWN"
kind = "issue"
target = "put it in the row that already owns it, or file one"

[[rule]]
id = "stop-posture"
kind = "policy"
scope = "mediated_call"
module = "policy/stop-posture.rego"
severity = "deny"
"##;

fn repo(name: &str) -> PathBuf {
    let dir = scratch(name);
    fs::write(dir.join("batten.toml"), CONFIG).expect("write config");
    fs::create_dir_all(dir.join("policy")).expect("policy dir");
    let source = common::at_root("policy/stop-posture.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(source, dir.join("policy/stop-posture.rego")).expect("install committed module");
    dir
}

/// A Claude `Stop` payload, as the host sends one.
fn stop_payload(message: &str, active: bool) -> String {
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "stop_hook_active": active,
        "last_assistant_message": message,
    })
    .to_string()
}

fn hook(dir: &Path, payload: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .env_remove("BATTEN_HOOK_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

/// THE CASE THE MODULE'S OWN SUITE COULD NOT MAKE: the engine builds the input,
/// runs the module, and the nudge reaches the host's advisory channel.
#[test]
fn a_hedged_final_message_reaches_the_host_advisory_channel() {
    let dir = repo("stop-posture-fires");
    let output = hook(
        &dir,
        &stop_payload("One thing I would flag is the exit code.", false),
    );
    let stdout = stdout_of(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an advisory never changes the exit code: {stdout}"
    );
    assert!(
        stdout.contains("additionalContext"),
        "the nudge travels on the advisory channel: {stdout}"
    );
    assert!(
        stdout.contains("stop-posture"),
        "and it names the predicate: {stdout}"
    );
}

/// NEVER A VERDICT. CLOUD-97 and CLOUD-219 each ruled a deny out at this moment
/// independently, and the property is structural — `hookSpecificOutput` here has
/// no field a refusal could occupy.
#[test]
fn the_nudge_carries_no_permission_decision() {
    let dir = repo("stop-posture-not-a-verdict");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload("One thing I would flag is the exit code.", false),
    ));
    assert!(
        !stdout.contains("permissionDecision"),
        "an advisory has no verdict field: {stdout}"
    );
    assert!(
        !stdout.contains("\"deny\""),
        "and cannot spell one: {stdout}"
    );
}

/// POINTER, NEVER PAYLOAD (rule 4), and load-bearing here rather than
/// decorative: handing the matched prose back would make this a mirror, and a
/// mirror is cleared by restating it — which is the double-write.
#[test]
fn no_byte_of_the_matched_prose_reaches_the_channel() {
    let dir = repo("stop-posture-pointer-only");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload(
            "One thing I would flag is that the widget cache is unbounded.",
            false,
        ),
    ));
    for fragment in ["widget", "unbounded", "cache", "I would flag"] {
        assert!(
            !stdout.contains(fragment),
            "the nudge carried {fragment:?} from the turn's own prose: {stdout}"
        );
    }
}

/// A CLEAN TURN IS SILENT, which is the common case and what the channel's
/// credibility rests on. Without this every assertion above is satisfied by a
/// module that fires on everything.
#[test]
fn a_clean_final_message_says_nothing() {
    let dir = repo("stop-posture-silent");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload("Landed and pushed; CI is green.", false),
    ));
    assert!(
        !stdout.contains("additionalContext"),
        "silence is the default: {stdout}"
    );
}

/// THE RECURSION BOUND, from the payload rather than a state file.
/// `stop_hook_active` is true on the invocation a previous `Stop` continuation
/// caused, so one nudge per turn is deterministic.
#[test]
fn a_repeat_stop_is_bounded_to_one_nudge_per_turn() {
    let dir = repo("stop-posture-bounded");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload("One thing I would flag is the exit code.", true),
    ));
    assert!(
        !stdout.contains("additionalContext"),
        "the second Stop of a turn says nothing: {stdout}"
    );
}

/// NOT A STOP, so there is no final message and nothing to judge — and the
/// module must not fire on a tool call that happens to carry prose.
#[test]
fn a_tool_call_is_not_judged_by_the_end_of_turn_rule() {
    let dir = repo("stop-posture-pre-tool");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "s-1",
        "tool_name": "Bash",
        "tool_input": {"command": "echo one thing I would flag"},
    })
    .to_string();
    let stdout = stdout_of(&hook(&dir, &payload));
    assert!(
        !stdout.contains("additionalContext"),
        "the Stop projections are null on every other event: {stdout}"
    );
}
