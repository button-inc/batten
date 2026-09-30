//! The `claude-code-cloud` preset and the module pre-approval channel, driven
//! through `batten adjudicate --harness claude-code` over real envelopes
//! (CLOUD-1949).
//!
//! **The owner's rule is the acceptance**: the host never halts on a prompt. In
//! plan mode a call reads or is refused; a read is pre-approved in every mode;
//! a `batten` verb whose declared effect is read or write is pre-approved
//! outside plan mode; and nothing any other row refuses is ever pre-approved.
//!
//! **This tier exists because the module suite was green over a dead preset.**
//! Every `test_` rule in the three modules passed while the live hook granted
//! nothing: helper rules that read `input` answered the live call with a value
//! computed under a test's `with input as`, and module-level constant sets read
//! as undefined on the hook path. Only a run of the compiled binary over the
//! committed `batten.toml` could see either, which is what every case here is.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// The engine-side rows this suite kills, declared beside the code they mutate
// (`src/lib.rs`) and mirrored here so a board obligation naming this file binds:
/*
#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT preapprove-before-refusal|s@^            decided => decided,$@            decided => hook::policy_preapproval(policy, envelope, facts).map_or(decided, hook::Decision::Preapproved),@|a_refused_call_is_never_preapproved
#MUTANT advice-beside-the-grant|s@^    let context = matches!(decision, hook::Decision::Preapproved(_)) \&\& !advice.is_empty();$@    let context = false;@|a_preapproval_carries_the_calls_advice_in_one_document
*/

use crate::common;

use std::path::PathBuf;

use common::{StateHome as _, run_with_stdin, stdout};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn envelope(mode: &str, tool: &str, input: &serde_json::Value) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "permission_mode": mode,
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string()
}

fn shell(mode: &str, command: &str) -> String {
    envelope(mode, "Bash", &serde_json::json!({ "command": command }))
}

/// Every document the hook put on stdout, parsed.
fn documents(payload: &str) -> Vec<serde_json::Value> {
    let outcome = run_with_stdin(
        &root(),
        &["adjudicate", "--harness", "claude-code"],
        payload,
    );
    stdout(&outcome)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("the host reads JSON"))
        .collect()
}

/// The one verdict document, or `None` when the hook said nothing verdict-shaped.
fn verdict(payload: &str) -> Option<(String, String)> {
    documents(payload).iter().find_map(|document| {
        let inner = document.get("hookSpecificOutput")?;
        Some((
            inner.get("permissionDecision")?.as_str()?.to_owned(),
            inner.get("permissionDecisionReason")?.as_str()?.to_owned(),
        ))
    })
}

fn assert_granted_by(payload: &str, rule: &str) {
    let (decision, reason) = verdict(payload).unwrap_or_default();
    assert_eq!(decision, "allow", "must be pre-approved: {payload}");
    assert!(
        reason.contains(rule),
        "the grant must be `{rule}`'s: {reason}"
    );
}

fn assert_not_granted(payload: &str) {
    if let Some((decision, reason)) = verdict(payload) {
        assert_ne!(
            decision, "allow",
            "must not be pre-approved: {payload}\n{reason}"
        );
    }
}

fn assert_plan_refused(payload: &str) {
    let (decision, reason) = verdict(payload).unwrap_or_default();
    assert_eq!(decision, "deny", "must be refused: {payload}");
    assert!(
        reason.contains("plan write refused"),
        "the refusal must be the preset's: {reason}"
    );
}

fn assert_not_plan_refused(payload: &str) {
    if let Some((_, reason)) = verdict(payload) {
        assert!(
            !reason.contains("plan write refused"),
            "must not be refused in plan mode: {payload}"
        );
    }
}

#[test]
fn a_host_read_is_preapproved_in_every_mode() {
    for mode in ["default", "plan", "auto"] {
        let read = envelope(
            mode,
            "Read",
            &serde_json::json!({ "file_path": "README.md" }),
        );
        assert_granted_by(&read, "call read now");
    }
}

/// DROPPING A PR SUBSCRIPTION NEVER STOPS THE WORLD. The owner's ruling: the
/// harness subscribes unasked, so the undo is granted in every mode and never
/// refused in plan mode — measured 2026-09-30 as `plan write refused` on the
/// drop, with the host in plan mode and the session halted on it.
#[test]
fn an_unsubscribe_is_preapproved_in_every_mode() {
    let drop = serde_json::json!({ "owner": "o", "repo": "r", "pullNumber": 1 });
    for mode in ["default", "plan", "auto", "acceptEdits"] {
        for tool in [
            "mcp__Claude_Code_Remote__unsubscribe_pr_activity",
            "mcp__github__unsubscribe_pr_activity",
        ] {
            assert_granted_by(&envelope(mode, tool, &drop), "watch drop now");
        }
    }
    // The subscribe is the one call the grant must never reach.
    assert_not_granted(&envelope(
        "auto",
        "mcp__Claude_Code_Remote__subscribe_pr_activity",
        &drop,
    ));
}

#[test]
fn a_read_pipeline_is_preapproved() {
    assert_granted_by(
        &shell("default", "ls crates && git status 2>/dev/null"),
        "call read now",
    );
}

#[test]
fn a_reader_redirected_into_a_file_is_not_preapproved() {
    assert_not_granted(&shell("default", "ls > out.txt"));
    // A bare redirection runs no program, so only the SEGMENT can say it writes.
    assert_not_granted(&shell("default", "ls; > out.txt"));
}

#[test]
fn a_writer_in_a_substitution_spoils_the_line() {
    assert_not_granted(&shell("default", "ls $(rm -rf x)"));
}

#[test]
fn an_mcp_read_verb_is_preapproved() {
    let read = envelope(
        "default",
        "mcp__serena__list_memories",
        &serde_json::json!({}),
    );
    assert_granted_by(&read, "call read now");
}

/// THE MEASURED CASE (CLOUD-1978): a session-management read in plan mode is
/// granted. Measured 2026-09-28 against the live host — with this grant, the
/// call ran and the owner saw no dialog.
#[test]
fn a_session_read_is_preapproved_in_plan_mode() {
    let read = envelope(
        "plan",
        "mcp__Claude_Code_Remote__get_session",
        &serde_json::json!({}),
    );
    assert_granted_by(&read, "call read now");
}

/// A prompt unique to one case, and its receipts removed when the case ends,
/// so the real checkout's store keeps nothing a case wrote.
struct Dispatch {
    prompt: String,
    git_dir: PathBuf,
}

impl Dispatch {
    fn new(case: &str) -> Self {
        let prompt = format!("dispatch fixture {case} {}", std::process::id());
        let git_dir = batten::git::git_dir(&root()).expect("the checkout has a git dir");
        Dispatch { prompt, git_dir }
    }

    fn linted(&self) -> &Self {
        batten::dispatch::record_brief(&self.git_dir, &self.prompt).expect("store writable");
        self
    }

    fn approved(&self) -> &Self {
        let asked = format!("Dispatch brief:{}?", batten::dispatch::digest(&self.prompt));
        let input = serde_json::json!({ "questions": [{ "question": asked, "options": [] }] });
        let result = serde_json::json!({ "answers": { asked: batten::dispatch::APPROVE_LABEL } });
        batten::dispatch::record_approvals(&self.git_dir, &input, &result).expect("store writable");
        self
    }

    fn call(mode: &str, prompt: &str) -> String {
        envelope(
            mode,
            "mcp__Claude_Code_Remote__create_session",
            &serde_json::json!({ "prompt": prompt }),
        )
    }
}

impl Drop for Dispatch {
    fn drop(&mut self) {
        let digest = batten::dispatch::digest(&self.prompt);
        let store = self.git_dir.join("batten-receipts");
        for name in [batten::dispatch::BRIEF, batten::dispatch::APPROVED] {
            let _ = std::fs::remove_file(store.join(format!("{name}.{digest}")));
        }
    }
}

#[test]
fn a_linted_and_approved_dispatch_is_preapproved_in_auto() {
    let fixture = Dispatch::new("cleared");
    fixture.linted().approved();
    assert_granted_by(&Dispatch::call("auto", &fixture.prompt), "call open now");
}

/// THE CASE `dispatch-uncleared` KILLS: linted but never approved — the owner
/// rejected the bundle or has not answered — so the host keeps asking.
#[test]
fn a_dispatch_without_approval_is_not_preapproved() {
    let fixture = Dispatch::new("unapproved");
    fixture.linted();
    assert_not_granted(&Dispatch::call("auto", &fixture.prompt));
}

/// The grant is bound to the bytes the owner saw: an edited prompt clears
/// nothing, and auto mode is the only mode the ruling grants in.
#[test]
fn an_edited_prompt_or_another_mode_is_not_preapproved() {
    let fixture = Dispatch::new("edited");
    fixture.linted().approved();
    let edited = format!("{} and one more thing", fixture.prompt);
    assert_not_granted(&Dispatch::call("auto", &edited));
    assert_not_granted(&Dispatch::call("default", &fixture.prompt));
}

/// CLOUD-2026: in auto mode no subagent or workflow call is put to the owner,
/// implementers included.
#[test]
fn an_implementer_subagent_and_a_workflow_are_preapproved_in_auto() {
    let implementer = envelope(
        "auto",
        "Agent",
        &serde_json::json!({ "subagent_type": "general-purpose", "prompt": "x", "description": "x" }),
    );
    assert_granted_by(&implementer, "agent open now");
    let workflow = envelope(
        "auto",
        "Workflow",
        &serde_json::json!({ "script": "export const meta = {}" }),
    );
    assert_granted_by(&workflow, "agent open now");
}

/// THE CASE `subagent-mode-unchecked` KILLS: outside auto mode the host's own
/// posture stands, and in default mode nothing refuses the spawn, so only the
/// mode conjunct keeps it from being granted.
#[test]
fn an_implementer_subagent_is_not_preapproved_in_default_mode() {
    let implementer = envelope(
        "default",
        "Agent",
        &serde_json::json!({ "subagent_type": "general-purpose", "prompt": "x", "description": "x" }),
    );
    assert_not_granted(&implementer);
}

/// Plan mode keeps its posture: an implementer spawn is refused there.
#[test]
fn an_implementer_subagent_is_not_preapproved_in_plan_mode() {
    let implementer = envelope(
        "plan",
        "Agent",
        &serde_json::json!({ "subagent_type": "general-purpose", "prompt": "x", "description": "x" }),
    );
    assert_plan_refused(&implementer);
}

/// A worktree spawn stays refused in auto mode: the deny is composed first.
#[test]
fn a_worktree_spawn_is_refused_in_auto() {
    let worktree = envelope(
        "auto",
        "Agent",
        &serde_json::json!({ "subagent_type": "general-purpose", "isolation": "worktree", "prompt": "x" }),
    );
    let (decision, reason) = verdict(&worktree).unwrap_or_default();
    assert_eq!(decision, "deny", "{reason}");
    assert!(reason.contains("spawn place wrong"), "{reason}");
}

#[test]
fn an_mcp_write_is_not_preapproved() {
    let write = envelope(
        "default",
        "mcp__Linear__save_comment",
        &serde_json::json!({}),
    );
    assert_not_granted(&write);
}

#[test]
fn a_declared_read_only_subagent_is_preapproved() {
    let explore = envelope(
        "plan",
        "Agent",
        &serde_json::json!({ "subagent_type": "Explore", "prompt": "x", "description": "x" }),
    );
    assert_granted_by(&explore, "call read now");
}

#[test]
fn a_batten_lifecycle_verb_is_preapproved_outside_plan_mode() {
    assert_granted_by(
        &shell("default", "batten override spend --admission x"),
        "call grant now",
    );
    assert_granted_by(
        &shell("auto", "batten override spend --admission x"),
        "call grant now",
    );
}

#[test]
fn a_destructive_batten_verb_is_not_preapproved() {
    assert_not_granted(&shell("default", "batten target prune -y"));
}

#[test]
fn a_batten_verb_beside_a_push_is_not_preapproved() {
    assert_not_granted(&shell(
        "default",
        "batten claim check && git push origin main",
    ));
}

#[test]
fn a_plan_mode_write_is_refused() {
    assert_plan_refused(&shell("plan", "python3 x.py"));
    assert_plan_refused(&shell("plan", "batten override spend --admission x"));
    assert_plan_refused(&shell("plan", "git status && git commit -m x"));
}

#[test]
fn the_plan_file_is_writable_in_plan_mode() {
    let write = envelope(
        "plan",
        "Write",
        &serde_json::json!({ "file_path": "/root/.claude/plans/a-plan.md", "content": "x" }),
    );
    assert_not_plan_refused(&write);
    assert_not_plan_refused(&envelope("plan", "ExitPlanMode", &serde_json::json!({})));
}

#[test]
fn outside_plan_mode_a_write_is_not_the_presets_to_refuse() {
    assert_not_plan_refused(&shell("default", "python3 x.py"));
    // A host that sent no mode is not in plan mode: nothing acts on a mode it was
    // not told.
    let unmoded = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "python3 x.py" },
    })
    .to_string();
    assert_not_plan_refused(&unmoded);
}

/// DENY FIRST. `grep` is on the engine's read-only floor, so the preset would
/// grant it — and this repository's `tool run loose` refuses it through Bash.
/// The refusal must stand.
#[test]
fn a_refused_call_is_never_preapproved() {
    let (decision, reason) = verdict(&shell("default", "grep foo README.md")).unwrap_or_default();
    assert_eq!(
        decision, "deny",
        "the refusal must outrank the grant: {reason}"
    );
    assert!(reason.contains("tool run loose"), "{reason}");
}

/// A warn-severity module of the fixture's own, so the advice this case needs
/// does not depend on which programs this checkout happens to pin.
const NUDGE: &str = r#"package batten.fixture_nudge

import rego.v1

rules contains "fixture list nudged"

violation contains {"rule": "fixture list nudged", "verdict": "fixture list nudged"} if {
	some program in input.call.programs
	program.name == "ls"
}

deny contains finding if some finding in violation

test_a_listing_is_nudged if {
	some v in violation with input as {"call": {"programs": [{"name": "ls"}]}}
	v.rule == "fixture list nudged"
}
"#;

const NUDGE_CONFIG: &str = r#"version = 1

[[rule]]
id = "plan write refused"
kind = "policy"
scope = "mediated_call"
preset = "claude-code-cloud"
severity = "deny"

[[rule]]
id = "fixture list nudged"
kind = "policy"
scope = "mediated_call"
module = "nudge.rego"
severity = "warn"

[[verdict]]
id = "fixture list nudged"
gloss = "a fixture nudge on a listing"
class = "A fixture class: the call proceeds, and the reader is told."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "nudge.rego"
"#;

/// ONE DOCUMENT. `ls` is a read the preset grants, and the fixture's own
/// warn-severity row nudges on it: the grant and the nudge must arrive together,
/// because the host reads the first document and a second one beside the grant
/// is discarded.
#[test]
fn a_preapproval_carries_the_calls_advice_in_one_document() {
    let dir = common::scratch("preapprove-advice");
    let home = common::scratch("preapprove-advice-home");
    common::write(&dir, "batten.toml", NUDGE_CONFIG);
    common::write(&dir, "nudge.rego", NUDGE);
    common::init_repo(&dir);
    let mut invocation = common::batten();
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
        child
            .stdin
            .take()
            .expect("the child's stdin")
            .write_all(shell("default", "ls").as_bytes())
            .expect("write the envelope");
    }
    let outcome = child.wait_with_output().expect("run batten adjudicate");
    let documents: Vec<serde_json::Value> = stdout(&outcome)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("the host reads JSON"))
        .collect();
    assert_eq!(documents.len(), 1, "one document per call: {documents:?}");
    let inner = &documents[0]["hookSpecificOutput"];
    assert_eq!(inner["permissionDecision"], "allow", "{inner}");
    assert!(
        inner["additionalContext"]
            .as_str()
            .is_some_and(|text| text.contains("fixture list nudged")),
        "the advice must ride the grant: {inner}"
    );
}
