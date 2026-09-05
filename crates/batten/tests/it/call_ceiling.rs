//! The per-call ceiling, over the compiled binary (CLOUD-925).
//!
//! `[budget.<name>]` is a **file-set** budget — `files` globs plus `max_tokens`,
//! evaluated over the tree by `policy budget` — so the bound `fanout-guard`
//! carries had no spelling as a row at all: count this call's prompt, refuse past
//! a cap. CLOUD-312's row 6 read "config" as a destination with no mechanism
//! behind it, and this is the mechanism.
//!
//! **The boundary is the point of the suite.** `<=` passes, and it is inherited
//! from `budget::Report::over_budget` rather than decided again — CLOUD-925 §1
//! requires one authority for what a ceiling is, because which side of a boundary
//! is inclusive is exactly the detail that drifts silently. Both sides are
//! asserted, so turning `>` into `>=` fails.
//!
//! **The no-measurement claim is asserted with a counter, in `hook.rs`'s own
//! tests** rather than here. It is a property of `ceiling_rules` and not of the
//! command surface, so it is tested directly — `.claude/rules/rust.md`'s guidance
//! where the end-to-end route would need new public surface to observe an
//! internal count. A clock cannot stand in: reading a decoded string and dividing
//! by four is far inside the noise of a process start, so a timing assertion
//! passes on a build that measures every call, which is the CLOUD-418 failure.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// A repository capping `Task` prompts at `max` estimated tokens.
fn repo_capping(name: &str, max: usize) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            r#"
version = 1

[[rule]]
id = "fanout-prompt-budget"
kind = "shape"
scope = "mediated_call"
tool = "Task"
measures = "prompt"
counts = "tokens"
max = {max}
severity = "deny"
reason = "compute one digest once and pass that, or name only what this agent must read"
"#
        ))
        .git()
        .build()
}

/// A `Task` spawn carrying `prompt`. No command line — which is the whole reason
/// this needs CLOUD-924's tool selector to be reachable at all.
fn payload(prompt: &str) -> String {
    let encoded = serde_json::to_string(prompt).expect("a prompt is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Task\",\
         \"tool_input\":{{\"prompt\":{encoded}}}}}"
    )
}

fn verdict(repo: &Path, prompt: &str) -> Option<i32> {
    run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(prompt),
    )
    .status
    .code()
}

/// `budget::estimate_tokens` is characters over four, so this produces a prompt
/// estimating to exactly `tokens`. Built from one repeated ASCII byte: the
/// estimator counts bytes, and a multi-byte character would make the arithmetic
/// depend on the encoding rather than on the cap.
fn prompt_of(tokens: usize) -> String {
    "x".repeat(tokens * 4)
}

/// EXACTLY AT THE CAP PASSES — `budget::Report::over_budget`'s boundary.
///
/// Fails by: turning the ceiling's `>` into `>=`, which is the mutation §7 names.
#[test]
fn a_call_exactly_at_the_ceiling_is_allowed() {
    let repo = repo_capping("ceiling-at-cap", 100);
    assert_eq!(
        verdict(&repo, &prompt_of(100)),
        Some(0),
        "exactly at budget passes"
    );
}

/// One over refuses.
///
/// Fails by: never reaching the ceiling — which is the pre-CLOUD-925 state, since
/// no column could express a cap whose subject is one call.
#[test]
fn a_call_one_token_over_the_ceiling_is_refused() {
    let repo = repo_capping("ceiling-over-cap", 100);
    assert_eq!(
        verdict(&repo, &prompt_of(101)),
        Some(2),
        "one over the cap refuses"
    );
}

/// A PLANTED SECRET APPEARS IN NO EMITTED BYTE.
///
/// Rule 4, and the argument that makes counting a prompt admissible where
/// echoing one is not: `ceiling_refusal` is never handed the measured value, so
/// `Refusal` has no field a byte of it could occupy. Asserted rather than
/// promised, per §5.
#[test]
fn a_planted_secret_reaches_no_emitted_byte() {
    let repo = repo_capping("ceiling-pointer-only", 10);
    let secret = "hunter2-do-not-echo-me";
    let prompt = format!("{}{secret}{}", prompt_of(50), prompt_of(50));
    let output = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(&prompt),
    );
    let rendered = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(2), "well over the cap");
    assert!(
        rendered.contains("fanout-prompt-budget"),
        "the refusal must name the row: {rendered}"
    );
    assert!(
        !rendered.contains(secret),
        "the refusal carried a byte of the measured payload: {rendered}"
    );
}

/// A partial ceiling is a usage error, not a row that caps something unnamed.
///
/// Three distinct silent failures if defaulted, and the third is the dangerous
/// one: a pair with no `counts` cannot say whether `6000` means tokens or
/// artifacts, which is a cap three orders of magnitude out in the permissive
/// direction.
#[test]
fn a_partial_ceiling_is_refused_at_load() {
    let repo = Fixture::new("ceiling-partial")
        .config(
            r#"
version = 1

[[rule]]
id = "half-a-ceiling"
kind = "shape"
scope = "mediated_call"
tool = "Task"
max = 100
severity = "deny"
reason = "..."
"#,
        )
        .git()
        .build();
    let output = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(&prompt_of(10)),
    );
    // Exit 1 is the usage code: a config fault, never a policy verdict, so no
    // Batten failure can read as a deny (`.claude/rules/rust.md`).
    assert_eq!(
        output.status.code(),
        Some(1),
        "a partial ceiling is a config fault: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("`measures`"),
        "the refusal must name the columns it needs: {}",
        stderr(&output)
    );
}
