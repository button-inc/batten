//! The tool selector on a mediated row, over the compiled binary (CLOUD-924).
//!
//! `adjudicate` returns `Allow` the moment `envelope.command` is empty, and an
//! MCP call, a `Read` and a `Task` spawn all carry an empty command — so before
//! this column no row could fire on a structured call at all. That is the gap
//! CLOUD-312's rows 4 and 5 report: two connector guards keyed on a tool name,
//! with nothing in config to retire onto.
//!
//! **The rotation case is the one worth reading first.** CLOUD-665 and CLOUD-684
//! are the same measured failure twice — a rule naming a server label the host
//! never registers under, matching nothing, silently. `mcp__Linear__save_issue`
//! and `mcp__cc451d34-…__save_issue` are the SAME tool behind two prefixes the
//! host minted, and this suite fails if a build stops treating them alike. That
//! is what `the_prefix_the_host_minted_does_not_decide_the_verdict` pins, and
//! collapsing the selector to an exact match is what turns it red.
//!
//! **The negative controls are the load-bearing half**, on
//! `pipeline_shapes.rs`' reasoning: CLOUD-199 measured that a guard with false
//! positives gets bypassed, and a bypassed guard enforces nothing. A suite
//! asserting only the denies would pass on a selector that fires on every call.
//! The sharpest of them is `Edit` against `NotebookEdit` — a bare suffix match
//! selects a neighbouring tool nobody named, which is the widening direction a
//! policy engine may never drift in.
//!
//! Fixture-scoped rather than judged against the committed `batten.toml`,
//! deliberately and only for now: the consumer rows that key on a tool arrive
//! with CLOUD-312's rows 1-5, and a suite written against them today would be
//! asserting over a table that does not exist yet.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// A repository whose one row refuses whatever tool `selector` names.
///
/// `severity = "deny"` and a `reason`, because a shape row cannot load without
/// one — the refusal reaches a model as the whole explanation (CLOUD-122).
fn repo_denying(name: &str, selector: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            r#"
version = 1

[[rule]]
id = "no-such-tool"
kind = "shape"
scope = "mediated_call"
tool = "{selector}"
severity = "deny"
reason = "this tool is refused here; use the sanctioned path instead"
"#
        ))
        .git()
        .build()
}

/// A structured call: a tool name and an input carrying no command line, which
/// is what every MCP call and every write tool actually sends.
fn payload(tool: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{encoded},\
         \"tool_input\":{{\"issueId\":\"CLOUD-1\"}}}}"
    )
}

fn verdict(repo: &Path, tool: &str) -> Option<i32> {
    run_with_stdin(repo, &["adjudicate", "--harness", "exit-code"], &payload(tool))
        .status
        .code()
}

fn assert_denied(repo: &Path, tool: &str) {
    assert_eq!(verdict(repo, tool), Some(2), "must refuse the tool: {tool}");
}

fn assert_allowed(repo: &Path, tool: &str) {
    assert_eq!(verdict(repo, tool), Some(0), "must allow the tool: {tool}");
}

/// A row naming a tool exactly fires on that tool.
///
/// Fails by: never reaching the selector at all, which is the pre-CLOUD-924
/// state — `adjudicate`'s `command.is_empty()` early return answers `Allow`
/// before any row is consulted.
#[test]
fn an_exact_tool_name_is_refused() {
    let repo = repo_denying("tool-selector-exact", "Bash");
    assert_denied(&repo, "Bash");
}

/// A row naming the final segment fires whatever prefix the host minted.
///
/// Fails by: collapsing the selector to `raw_tool == selector`.
#[test]
fn a_delimited_suffix_is_refused() {
    let repo = repo_denying("tool-selector-suffix", "save_issue");
    assert_denied(&repo, "mcp__Linear__save_issue");
}

/// CLOUD-665 AND CLOUD-684, REPLAYED AS A TEST — the measured defect this column
/// exists for.
///
/// Both names are the same tool behind a prefix the host chose, and one of them
/// is the alias this very repository's Linear server reconnected under
/// mid-session. A selector that answers differently for the two is a rule whose
/// verdict depends on a string no configuration controls.
///
/// Fails by: collapsing the selector to an exact match, which passes the first
/// assertion of `a_delimited_suffix_is_refused` and misses both of these.
#[test]
fn the_prefix_the_host_minted_does_not_decide_the_verdict() {
    let repo = repo_denying("tool-selector-rotation", "save_issue");
    assert_denied(&repo, "mcp__Linear__save_issue");
    assert_denied(&repo, "mcp__linear-server__save_issue");
    assert_denied(
        &repo,
        "mcp__cc451d34-6c83-4df3-bc3f-13fb7f627544__save_issue",
    );
}

/// A row must not fire on a neighbouring tool.
///
/// Fails by: any selector that matches more than it names — a substring test, or
/// a prefix one.
#[test]
fn a_neighbouring_tool_is_not_refused() {
    let repo = repo_denying("tool-selector-neighbour", "save_issue");
    assert_allowed(&repo, "mcp__Linear__save_comment");
    assert_allowed(&repo, "mcp__Linear__get_issue");
    assert_allowed(&repo, "Bash");
}

/// THE BARE-SUFFIX OVER-MATCH, which is why the `__` delimiter is load-bearing
/// rather than cosmetic.
///
/// `NotebookEdit` ends with the bytes of `Edit`, so a selector implemented as
/// `raw_tool.ends_with(selector)` refuses a tool the row never named — and it
/// would do so silently, reading as a correctly-scoped row in the file.
///
/// Fails by: dropping the `prefix.ends_with("__")` test from
/// `Rule::selects_tool`.
#[test]
fn a_bare_suffix_does_not_select_a_tool_nobody_named() {
    let repo = repo_denying("tool-selector-bare-suffix", "Edit");
    assert_denied(&repo, "Edit");
    assert_allowed(&repo, "NotebookEdit");
}

/// THE BARE NAME, which is what carries the mint on the dispatch boundary
/// (CLOUD-1264).
///
/// `batten mcp call` hands `mint_receipts` the bare METHOD (`get_issue`) where
/// `batten hook` hands it the host's `raw_tool` (`mcp__Linear__get_issue`). Both
/// have to select a row spelling the segment, or a receipt exists on one path
/// and not the other from the same rows — which is the state that made closing
/// the raw read path unsafe.
///
/// The pair is the point. Nothing else in this suite pins the `raw_tool ==
/// selector` arm for a name with no `__` in it, and the second assertion pins
/// the documented consequence: a row spelling the FULL name reaches the hook
/// path only, so a later widening of the suffix arm cannot land silently.
#[test]
fn a_bare_name_selects_a_row_spelling_the_segment() {
    let repo = repo_denying("tool-selector-bare-name", "get_issue");
    assert_denied(&repo, "get_issue");
    assert_denied(&repo, "mcp__Linear__get_issue");

    let full = repo_denying("tool-selector-full-name", "mcp__Linear__get_issue");
    assert_allowed(&full, "get_issue");
}

/// A repository declaring no tool-keyed row allows every structured call.
///
/// The cheap-when-irrelevant arm (§4). Without it every assertion above could
/// pass on a build that refuses nothing and a build that refuses everything
/// would be indistinguishable from one that selects correctly.
#[test]
fn a_repository_declaring_no_tool_row_judges_nothing() {
    let repo = Fixture::new("tool-selector-absent")
        .config(
            r#"
version = 1

[[rule]]
id = "unrelated"
kind = "shape"
scope = "mediated_call"
pattern = "gh pr merge"
severity = "deny"
reason = "use `mise run land`"
"#,
        )
        .git()
        .build();
    assert_allowed(&repo, "mcp__Linear__save_issue");
    assert_allowed(&repo, "Bash");
}

/// The refusal names the row and the tool, and no byte of the input.
///
/// Non-negotiable rule 4, and the argument `Field::ToolName` already carries: a
/// tool NAME is not content, but `Envelope::input` is the likeliest place in the
/// envelope for a secret, so the deny may name the first and never the second.
#[test]
fn the_refusal_names_the_row_and_the_tool_but_no_input() {
    let repo = Fixture::new("tool-selector-pointer-only")
        .config(
            r#"
version = 1

[[rule]]
id = "no-such-tool"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
severity = "deny"
reason = "this tool is refused here; use the sanctioned path instead"
"#,
        )
        .git()
        .build();
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    let with_secret = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"mcp__Linear__save_issue\",\
         \"tool_input\":{{\"description\":{encoded}}}}}"
    );
    let output = run_with_stdin(&repo, &["adjudicate", "--harness", "exit-code"], &with_secret);
    let rendered = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(2), "the row must refuse");
    assert!(
        rendered.contains("no-such-tool"),
        "the refusal must name the row: {rendered}"
    );
    assert!(
        !rendered.contains(secret),
        "the refusal carried a byte of the tool input: {rendered}"
    );
}
