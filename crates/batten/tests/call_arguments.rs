//! Conditioning a mediated row on the arguments a call names (CLOUD-987).
//!
//! CLOUD-924 gave a row the tool a call names. This is the layer below it — the
//! call's own input — and the reason it exists is that CLOUD-312's rows 1 and 3
//! both turn on an argument rather than on the tool:
//!
//! * row 1 gates **creating** a tracker row and must not gate **editing** one,
//!   and the two differ only in whether the call named an `id`;
//! * row 3 fires only when a call **moves** something, which is a `state` it did
//!   or did not name.
//!
//! **THE ASYMMETRY IS THE PREDICATE, so both sides are asserted everywhere.** A
//! suite that only checked the deny would pass on a row that refuses every call,
//! and that specific over-fire is the one `issue-search-guard`'s own header
//! prices: *"Denying an update would demand a search before every edit to an
//! issue, which is absurd and would get the guard switched off within a day."* A
//! gate that gets switched off enforces nothing, so the allow cases are not
//! hygiene here — they are the thing being built.
//!
//! Fixture-scoped: the consumer rows arrive with CLOUD-312's rows 1-3, and a
//! suite written against a table that does not exist yet would assert nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// A repository whose one row refuses `save_issue` only when no `id` is named.
///
/// This is CLOUD-312's row 1 as config: the tool selector from CLOUD-924 does the
/// selecting, and `when_absent` decides whether that selection refuses.
fn repo_gating_creates(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            r#"
version = 1

[[rule]]
id = "search-before-filing"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_absent = "input-id"
severity = "deny"
reason = "search for an existing row before filing a new one; an update is never gated"
"#,
        )
        .git()
        .build()
}

/// A structured call carrying whatever `input` the case is about.
fn payload(tool: &str, input: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{encoded},\"tool_input\":{input}}}")
}

fn verdict(repo: &Path, tool: &str, input: &str) -> Option<i32> {
    run_with_stdin(
        repo,
        &["hook", "--harness", "exit-code"],
        &payload(tool, input),
    )
    .status
    .code()
}

/// ROW 1'S DISCRIMINATOR, both sides, in one case because they are one predicate.
///
/// A `save_issue` naming no `id` is a create and is gated; one naming an `id`
/// edits a row that already exists and is not. Asserting only the first would
/// pass on a build that refuses both, which is the guard-switched-off outcome the
/// module doc quotes.
///
/// Fails by: dropping the `when_absent` test from `tool_rules`, which reds the
/// second assertion — the row then refuses every `save_issue`.
#[test]
fn a_create_is_gated_and_an_update_is_not() {
    let repo = repo_gating_creates("args-create-vs-update");
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"title":"a new row"}"#),
        Some(2),
        "a call naming no id opens a row, and that is what the receipt gates"
    );
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","title":"an edit"}"#
        ),
        Some(0),
        "a call naming an id edits an existing row and must never be gated"
    );
}

/// The absence test collapses missing, null, empty and wrong-typed alike.
///
/// One definition of absence, in the decoder, rather than a second one in the
/// modifier — every other reader of the allowlist sees `None` for all four, and a
/// modifier that disagreed would make `id: ""` mean something different here than
/// it does to `Field::read`'s other callers.
///
/// Fails by: reading absence with `get("id").is_none()` instead of through
/// `Field::read`, which admits `null` and `""` as present.
#[test]
fn absence_means_what_the_decoder_means_by_it() {
    let repo = repo_gating_creates("args-absence-shapes");
    for input in [
        r#"{"title":"no id key at all"}"#,
        r#"{"id":null}"#,
        r#"{"id":""}"#,
        r#"{"id":{"nested":"object"}}"#,
        r#"{"id":42}"#,
    ] {
        assert_eq!(
            verdict(&repo, "mcp__Linear__save_issue", input),
            Some(2),
            "none of these names an id a gate could compare: {input}"
        );
    }
}

/// The modifier narrows the row it is on and nothing else.
///
/// A neighbouring tool is still not selected, so `when_absent` cannot widen a
/// row onto calls its `tool` never named — the two modifiers compose in the one
/// direction that keeps a policy engine honest.
#[test]
fn the_modifier_does_not_widen_the_selection() {
    let repo = repo_gating_creates("args-no-widening");
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_comment",
            r#"{"body":"a comment"}"#
        ),
        Some(0),
        "a comment names no id either, and this row is not about comments"
    );
    assert_eq!(
        verdict(&repo, "Bash", r#"{"command":"echo hi"}"#),
        Some(0),
        "an unrelated tool naming no id is not this row's business"
    );
}

/// A repository declaring no such modifier is unaffected.
///
/// Without this the suite could not tell a working modifier from one that refuses
/// nothing anywhere.
#[test]
fn a_row_without_the_modifier_still_refuses_on_selection_alone() {
    let repo = Fixture::new("args-no-modifier")
        .config(
            r#"
version = 1

[[rule]]
id = "no-save-issue-at-all"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
severity = "deny"
reason = "this tool is refused outright here"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(2),
        "a bare tool row refuses whether or not an id was named"
    );
}

/// ROW 3'S DISCRIMINATOR: a move is gated, a plain edit is not.
///
/// `when_present`'s reason for existing. `board-move-guard` fires only when a
/// call moves a row between columns, and a call that merely edits one names no
/// `state`. A row without this modifier would gate every edit — the same
/// over-fire `when_absent` prevents one key over, which is why both polarities
/// had to land together rather than one at a time.
///
/// Fails by: dropping the `when_present` test, which reds the second assertion.
#[test]
fn a_move_is_gated_and_a_plain_edit_is_not() {
    let repo = Fixture::new("args-move-vs-edit")
        .config(
            r#"
version = 1

[[rule]]
id = "record-the-move"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_present = "input-state"
severity = "deny"
reason = "record the column move before making it"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","state":"In Progress"}"#
        ),
        Some(2),
        "a call naming a state moves the row, and that is what this gates"
    );
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","title":"just an edit"}"#
        ),
        Some(0),
        "a call naming no state edits in place and must not be gated as a move"
    );
}

/// The two polarities over ONE projection can never fire, and are refused at
/// load rather than left to match nothing.
///
/// A row asking for the same key to be both absent and present is inert — it
/// loads, decides nothing, and reads from the file as a narrowing. Naming
/// *different* projections is legitimate, which the second half asserts so the
/// refusal cannot be over-broad.
///
/// Fails by: dropping `validate_polarity`, which makes the first call load and
/// silently gate nothing.
#[test]
fn the_two_polarities_over_one_projection_are_refused() {
    let contradictory = Fixture::new("args-contradiction")
        .config(
            r#"
version = 1

[[rule]]
id = "cannot-fire"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_absent = "input-id"
when_present = "input-id"
severity = "deny"
reason = "unreachable"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(&contradictory, "mcp__Linear__save_issue", r"{}"),
        Some(1),
        "a row that can never fire is a usage error, not a silently inert gate"
    );

    let over_two = Fixture::new("args-two-projections")
        .config(
            r#"
version = 1

[[rule]]
id = "moved-without-an-id"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_absent = "input-id"
when_present = "input-state"
severity = "deny"
reason = "a move must name the row it moves"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(
            &over_two,
            "mcp__Linear__save_issue",
            r#"{"state":"In Progress"}"#
        ),
        Some(2),
        "different projections are a legitimate conjunction and must still load"
    );
}

/// The refusal names the row and never the argument's value.
///
/// Rule 4, and the general form matters more than this instance: an issue key is
/// a pointer, but the allowlist's members include prose-bearing ones, so the rule
/// is that a projection may be COMPARED and never echoed. Asserted on a value
/// that would be unmistakable in the output.
#[test]
fn the_refusal_carries_no_argument_value() {
    let repo = repo_gating_creates("args-pointer-only");
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    let output = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload(
            "mcp__Linear__save_issue",
            &format!("{{\"title\":{encoded}}}"),
        ),
    );
    let rendered = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(2), "the row must refuse");
    assert!(
        rendered.contains("search-before-filing"),
        "the refusal must name the row: {rendered}"
    );
    assert!(
        !rendered.contains(secret),
        "the refusal carried a byte of the call's arguments: {rendered}"
    );
}
