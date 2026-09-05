//! Closing the raw tracker read path, over the compiled binary (CLOUD-1264).
//!
//! # Why this exists beside `connector_not_granted.rs`
//!
//! That row asserts what this repository's own committed `.claude/settings.json`
//! GRANTS, and its module states in as many words that registration happens in
//! the launcher — outside every gate here. So a session whose harness registers
//! the connector anyway keeps the raw tool on the model's surface, and the
//! `[[mcp.result]]` reduction beside it decides nothing: the two routes return
//! the same payload and the cheaper-looking one wins.
//!
//! It won. Measured on the grooming session that dispatched this work: raw
//! `get_issue` 12.2 MB over 755 calls and raw `save_issue` 7.1 MB over 517 —
//! 85% of all tool output, and 4 MB of it after the reduction landed. This tier
//! is over the row that refuses the call rather than the grant.
//!
//! # The two halves, and the second is the load-bearing one
//!
//! The denies are cheap to assert and would pass on a row that refused
//! everything. `pipeline_shapes.rs`' reasoning applies unchanged: CLOUD-199
//! measured that a guard with false positives gets bypassed, and a bypassed
//! guard enforces nothing. So every deny here is paired with a control, and the
//! sharpest of them is `get_issue_status` — a bare suffix test selects a verb
//! nobody named, which is the widening direction a policy engine may never
//! drift in.
//!
//! # The rotation case
//!
//! CLOUD-178 measured one connector exposed as `mcp__Linear__…`,
//! `mcp__<uuid>__…` and `mcp__claude_ai_Linear__…` across registration
//! episodes. A row naming one matches none of the others, silently. This suite
//! fails if a build stops treating them alike.
//!
//! # `Server::endpoint_contains` is the same rotation one layer down
//!
//! `Rule::selects_tool` absorbs the rotation for a RULE, by matching a
//! `__`-delimited segment. Dispatch has no analogue — the map key IS the name —
//! so the remedy this row hands a reader (`batten mcp call Linear get_issue …`)
//! would be a command that cannot run wherever the launcher keyed the connector
//! by something else. Measured 2026-09-02: the same connector at the same
//! address was keyed `Linear` in one container and by a UUID in another. The
//! cases at the bottom are that half.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stderr, stdout};

/// This repository's own rows, as committed — never a fixture rewriting them.
///
/// The same shape `connector_verbs.rs` uses, and for the same reason: a fixture
/// that restated the row would assert over a table this repository does not
/// ship, which is the one thing a committed-table tier exists to rule out.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let entry = entry.expect("a policy directory entry");
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(entry.file_name())).expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

fn payload(tool: &str) -> String {
    let tool = serde_json::to_string(tool).expect("a tool name is encodable");
    format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{tool},\"tool_input\":{{}}}}")
}

fn verdict(repo: &Path, tool: &str) -> Option<i32> {
    run_with_stdin(repo, &["adjudicate", "--harness", "exit-code"], &payload(tool))
        .status
        .code()
}

/// Every spelling of the raw read is refused.
///
/// Fails by: collapsing `Rule::selects_tool` to an exact match, which leaves the
/// row matching whichever single prefix its author happened to see.
#[test]
fn every_spelling_of_the_raw_read_is_refused() {
    let repo = repo("raw-read-spellings");
    for tool in [
        "mcp__Linear__get_issue",
        "mcp__4db58e41-cd4e-4818-8922-46cf616593f4__get_issue",
        "mcp__claude_ai_Linear__get_issue",
        // No server prefix at all, which is a shape a host may expose — and the
        // spelling `batten mcp call` itself hands the mint boundary.
        "get_issue",
    ] {
        assert_eq!(
            verdict(&repo, tool),
            Some(2),
            "the raw read must be refused under every registration episode: {tool}"
        );
    }
}

/// THE ANTI-VACUITY MIRROR. A row that refused everything would pass every
/// assertion above.
///
/// `get_issue_status` is the sharpest of these: it CONTAINS `get_issue`, so a
/// row implemented as `raw_tool.contains(selector)` — or as a bare
/// `ends_with` over a name spelled the other way round — reaches a verb this
/// repository has no verdict on. `strip_suffix` leaves `mcp__Linear__get_issue`
/// with nothing to test for `get_issue_status`, and the `__` bound is what keeps
/// it that way.
///
/// `save_issue` is deliberately NOT asserted here. It is refused by
/// `an-update-owes-a-recent-read` whenever no fresh receipt exists, so a case
/// asserting either verdict for it would be pinning a different row's behaviour
/// under this row's name.
#[test]
fn the_row_reaches_no_verb_it_does_not_name() {
    let repo = repo("raw-read-controls");
    for tool in [
        // The search `filing-needs-a-search` requires must stay open.
        "mcp__Linear__list_issues",
        // Already projected on every measured call, and a `shape` row cannot
        // express "without `fields`".
        "mcp__Linear__get_issue_status",
        "mcp__Linear__save_comment",
        // A different connector entirely: 0.3 MB on the measured session.
        "mcp__github__get_file_contents",
        "Read",
    ] {
        assert_eq!(
            verdict(&repo, tool),
            Some(0),
            "this row must not reach a verb it does not name: {tool}"
        );
    }
}

/// The refusal names the row and no byte of the call's input.
///
/// Non-negotiable rule 4, and the argument `Field::ToolName` already carries: a
/// tool NAME is not content, but `Envelope::input` is the likeliest place in the
/// envelope for a secret. A read's arguments are a tracker key today and are not
/// guaranteed to stay that narrow.
#[test]
fn the_refusal_carries_no_byte_of_the_call() {
    let repo = repo("raw-read-pointer-only");
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    let with_secret = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"mcp__Linear__get_issue\",\
         \"tool_input\":{{\"id\":{encoded}}}}}"
    );
    let output = run_with_stdin(&repo, &["adjudicate", "--harness", "exit-code"], &with_secret);
    let rendered = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(2), "the row must refuse");
    assert!(
        rendered.contains("no-raw-issue-read"),
        "the refusal must name the row so a reader can find its remedy: {rendered}"
    );
    assert!(
        !rendered.contains(secret),
        "the refusal carried a byte of the call's input: {rendered}"
    );
}

// ─── `endpoint_contains`: a server name that survives a registration episode ──

/// A repository declaring one wiring source that resolves `Linear` by address.
fn repo_resolving(name: &str, wiring: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            r#"
version = 1

[[mcp.source]]
id = "project"
path = "wiring.json"
node = "mcpServers"

[mcp.source.endpoint_contains]
Linear = "mcp.linear.app"
"#,
        )
        .file("wiring.json", wiring)
        .git()
        .build()
}

/// The name resolves whatever key the launcher minted.
///
/// Both halves matter. The first is the case that did not work before: a map
/// keyed by a per-session id, which no config can name in advance. The second is
/// the guarantee that adding the row re-points nothing — an exact key still wins,
/// so every table that resolves today reaches the entry it always did.
///
/// Neither arm asserts a completed dispatch: this suite stops at the socket, as
/// `mcp_dispatch.rs`'s header records. What it asserts is that resolution got
/// PAST the wiring — a server that did not resolve says so by name, and these
/// must not.
#[test]
fn a_declared_name_resolves_whatever_key_the_launcher_minted() {
    for (case, wiring) in [
        (
            "minted-key",
            r#"{"mcpServers": {"4db58e41-cd4e-4818-8922-46cf616593f4":
               {"url": "https://proxy.example/mcp?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp"}}}"#,
        ),
        (
            "literal-key",
            r#"{"mcpServers": {"Linear": {"url": "https://mcp.linear.app/mcp"}}}"#,
        ),
    ] {
        let repo = repo_resolving(&format!("endpoint-{case}"), wiring);
        let answer = run(&repo, &["mcp", "call", "Linear", "get_issue"]);
        let rendered = format!("{}{}", stderr(&answer), stdout(&answer));
        assert!(
            !rendered.contains("no declared source resolves this server"),
            "`Linear` must resolve under a {case} map: {rendered}"
        );
    }
}

/// A selector that matches more than one entry is a REFUSAL, never first-wins.
///
/// Which server the call reaches would otherwise depend on the order a launcher
/// happened to write its map, which is not a fact any configuration authored.
///
/// Fails by: taking the first match, which passes the case above and dispatches
/// to whichever entry sorts first.
#[test]
fn an_ambiguous_selector_refuses_rather_than_picking_one() {
    let repo = repo_resolving(
        "endpoint-ambiguous",
        r#"{"mcpServers": {
             "one": {"url": "https://mcp.linear.app/mcp"},
             "two": {"url": "https://mcp.linear.app/other"}}}"#,
    );
    let answer = run(&repo, &["mcp", "call", "Linear", "get_issue"]);
    let rendered = format!("{}{}", stderr(&answer), stdout(&answer));
    assert_eq!(
        answer.status.code(),
        Some(3),
        "an undecidable wiring file is could-not-look, not a policy verdict: {rendered}"
    );
    assert!(
        rendered.contains("matched 2 entries"),
        "the refusal must say how many answered: {rendered}"
    );
    // POINTER-ONLY. The count and the two config-authored names may appear; the
    // keys that matched are this host's per-session state and may not.
    for key in ["\"one\"", "\"two\""] {
        assert!(
            !rendered.contains(key),
            "the refusal named a matched key, which is host state: {rendered}"
        );
    }
}

/// A name no selector declares still falls through to the next source.
///
/// The source list IS the multi-harness precedence order, so a selector that
/// matched nothing must skip exactly as an absent key does. Refusing here would
/// make one host's wiring the reason another host's row is never consulted.
#[test]
fn a_name_no_selector_declares_is_a_skip_and_not_a_refusal() {
    let repo = repo_resolving(
        "endpoint-absent",
        r#"{"mcpServers": {"other": {"url": "https://example.invalid/mcp"}}}"#,
    );
    let answer = run(&repo, &["mcp", "call", "Linear", "get_issue"]);
    let rendered = format!("{}{}", stderr(&answer), stdout(&answer));
    assert!(
        rendered.contains("no declared source resolves this server"),
        "nothing answered, so this is the ordinary not-found answer: {rendered}"
    );
}

/// An empty substring is refused at LOAD, not discovered at dispatch.
///
/// `"".contains()` is true of every string, so the selector would match the whole
/// server map and turn the row into first-wins over everything — the precise
/// failure the ambiguity refusal exists to prevent, tripped on every call rather
/// than reported once here.
#[test]
fn an_empty_substring_is_refused_at_load() {
    let repo = Fixture::new("endpoint-empty-needle")
        .config(
            r#"
version = 1

[[mcp.source]]
id = "project"
path = "wiring.json"
node = "mcpServers"

[mcp.source.endpoint_contains]
Linear = ""
"#,
        )
        .file("wiring.json", r#"{"mcpServers": {}}"#)
        .git()
        .build();
    let answer = run(&repo, &["mcp", "call", "Linear", "get_issue"]);
    let rendered = format!("{}{}", stderr(&answer), stdout(&answer));
    assert_eq!(
        answer.status.code(),
        Some(1),
        "a malformed declaration is the author's mistake: {rendered}"
    );
    assert!(
        rendered.contains("empty endpoint substring"),
        "the refusal must name what is wrong with the row: {rendered}"
    );
}
