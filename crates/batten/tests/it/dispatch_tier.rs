//! A dispatched session runs the model and effort its owner set (CLOUD-2949).
//!
//! `policy/dispatch-tier.rego` refuses a `create_session` call whose `model` is
//! not the alias `opus` or whose `effort` is not `low`, and an absent argument
//! like a wrong one. Every case asserts both sides: a suite that only checked the
//! deny would pass on a module that refuses every call.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin};

const MODULE: &str = include_str!("../../../../policy/dispatch-tier.rego");

const CONFIG: &str = r#"
version = 1

[[rule]]
id = "call open wrong"
no_fix_reason = "class 3 (a call rewrite): the subject is a tool call refused before it runs, so nothing persists for a command to repair; the refusal's remedy text is the route"
kind = "policy"
scope = "mediated_call"
module = "policy/dispatch-tier.rego"
severity = "deny"

[[verdict]]
id = "call open wrong"
gloss = "a dispatch names a model or effort its owner did not set, or names none"
class = """
A session this repository opens runs the model family and the effort its owner \
set. A `create_session` call that names another model, another effort, or omits \
either is refused, because an omitted model inherits the dispatcher's. The \
subject names which argument is wrong. Name both as the module allows and send \
the call again.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/dispatch-tier.rego"
"#;

const CREATE: &str = "mcp__x__create_session";

fn repo(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(CONFIG)
        .file("policy/dispatch-tier.rego", MODULE)
        .git()
        .build()
}

fn payload(tool: &str, input: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{encoded},\"tool_input\":{input}}}")
}

fn verdict(repo: &Path, tool: &str, input: &str) -> Option<i32> {
    run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(tool, input),
    )
    .status
    .code()
}

/// Fails by: `model-unread`, which stops reading the model and admits any.
#[test]
fn a_dispatch_on_another_model_or_none_is_refused() {
    let repo = repo("dispatch-tier-model");
    assert_eq!(
        verdict(
            &repo,
            CREATE,
            r#"{"prompt":"p","model":"other","effort":"low"}"#
        ),
        Some(2),
        "a model other than the alias is refused"
    );
    assert_eq!(
        verdict(&repo, CREATE, r#"{"prompt":"p","effort":"low"}"#),
        Some(2),
        "an omitted model inherits the dispatcher's and is refused"
    );
    assert_eq!(
        verdict(
            &repo,
            CREATE,
            r#"{"prompt":"p","model":"opus","effort":"low"}"#
        ),
        Some(0),
        "opus at low effort is admitted"
    );
}

/// Fails by: `effort-unread`, which stops reading the effort and admits `medium`.
#[test]
fn a_dispatch_at_another_effort_or_none_is_refused() {
    let repo = repo("dispatch-tier-effort");
    assert_eq!(
        verdict(
            &repo,
            CREATE,
            r#"{"prompt":"p","model":"opus","effort":"medium"}"#
        ),
        Some(2),
        "another effort is refused"
    );
    assert_eq!(
        verdict(&repo, CREATE, r#"{"prompt":"p","model":"opus"}"#),
        Some(2),
        "an omitted effort is refused"
    );
    assert_eq!(
        verdict(
            &repo,
            CREATE,
            r#"{"prompt":"p","model":"opus","effort":"low"}"#
        ),
        Some(0),
        "opus at low effort is admitted"
    );
}

/// Fails by: `every-call-judged`, which refuses `send_message` too.
#[test]
fn a_call_that_opens_no_session_is_not_judged() {
    let repo = repo("dispatch-tier-scope");
    assert_eq!(
        verdict(
            &repo,
            "mcp__x__send_message",
            r#"{"session_id":"s","message":"m"}"#
        ),
        Some(0),
        "a message opens no session"
    );
    assert_eq!(
        verdict(&repo, "Bash", r#"{"command":"echo create_session"}"#),
        Some(0),
        "a shell call opens no session"
    );
    assert_eq!(
        verdict(&repo, CREATE, r#"{"prompt":"p"}"#),
        Some(2),
        "a create_session naming neither argument is refused"
    );
}
