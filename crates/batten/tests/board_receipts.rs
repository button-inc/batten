//! The board's receipt family, as config rather than as three bash guards
//! (CLOUD-312 rows 1-3).
//!
//! Each of the three gates a write to the tracker on evidence that the write was
//! informed: row 1 that a search happened before a row was filed, row 2 that the
//! row was read recently before it was edited, row 3 that a column move was
//! recorded before it was made. All three were bash because none of their
//! predicates could be spelled as a rule — they turn on the call's ARGUMENTS, and
//! until CLOUD-987 no column read one.
//!
//! **THE ASYMMETRY IS THE PREDICATE, so both sides are asserted for every row.**
//! A suite that only checked the deny would pass on a row that refuses every
//! call, and that over-fire is the one each retiring script's own header prices:
//! gating an update "would demand a search before every edit to an issue, which
//! is absurd and would get the guard switched off within a day." A gate that gets
//! switched off enforces nothing, so the allow cases are the thing being built
//! rather than hygiene around it.
//!
//! ─── CLOUD-908's MAPPING, row 1 ──────────────────────────────────────────────
//!
//! `tests/issue-search-guard.bats`, ten cases, every one placed. An unmapped case
//! is a coverage loss wearing a retirement's clothes.
//!
// carried: "creating an issue with no receipt is denied, and the denial names the fix" crates/batten/tests/board_receipts.rs
// carried: "creating an issue with a receipt is allowed" crates/batten/tests/board_receipts.rs
// carried: "updating an existing issue is never gated, receipt or not" crates/batten/tests/board_receipts.rs
// carried: "all three live connector spellings are gated identically" crates/batten/tests/board_receipts.rs
// carried: "a tool that does not create an issue is never gated" crates/batten/tests/board_receipts.rs
// carried: "the CLOUD-504 over CLOUD-499 filing is refused, and allowed after the search" crates/batten/tests/board_receipts.rs
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce. Each names the general property that now covers it.
//!
// subsumed: "an unreadable or nameless payload fails open" crates/batten/tests/cli.rs
// subsumed: "outside a git repository the guard fails open rather than blocking every filing" crates/batten/src/receipt.rs
// subsumed: "the emitted denial is the hook shape, and it parses" crates/batten/tests/advisory_drain.rs
//!
//! CHANGED — behaviour that diverges deliberately.
//!
//! QUALIFIED BY ITS SUITE, and that is the mechanism reporting a real limit
//! rather than a workaround. A case TITLE is not unique across suites: this one
//! and `contract-drift.bats` both call their bypass case "the bypass is
//! honoured", and the ledger keys arms on the quoted string alone — so a bare
//! arm here made two arms claim one case, which
//! `the_one_completed_retirement_is_mapped_case_for_case` caught. `<suite>::<case>`
//! is the disambiguator, and `replay.sh` resolves an arm by trying it before the
//! bare form, so a case whose title collides is still attributed to the right
//! suite instead of silently borrowing the other's arm.
//!
// changed: "issue-search-guard.bats::the bypass is honoured" crates/batten/tests/guardrail_bypass.rs BATTEN_ISSUE_SEARCH_BYPASS is gone; a mediated deny takes the engine's own hatch, which is the same consolidation CLOUD-442 and CLOUD-444 made when memory-guard and claim-guard retired
//!
//! ─── CLOUD-909's REPLAY, row 1 ───────────────────────────────────────────────
//!
//! The mediated arm (`replay-call:`), because this is a `PreToolUse` body: the
//! captured envelope is handed to the engine in the fixture the dying body read it
//! in, and the compared axis is the DECISION rather than a pointer set. The
//! translation is stated rather than assumed — the shell body denies by printing a
//! decision document and exiting 0, the engine denies with exit 2 (§7).
//!
// replay-call: tests/issue-search-guard.bats 8e0acf1 mise-tasks/issue-search-guard.sh filing-needs-a-search deny=2 allow=0

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// This repository's own row 1, as committed — never a fixture rewriting it.
///
/// The committed `batten.toml` is the source of truth (§1), so a suite asserting
/// a hand-written copy of the row would pass over a config that says something
/// else. `include_str!` reads it at compile time, so this suite cannot drift from
/// the authority: a row edited in `batten.toml` is exercised by the next run
/// rather than by whoever remembers to update a duplicate.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../batten.toml"));
    // The modules the committed config names, copied by ENUMERATION rather than by
    // name, and staged BEFORE the commit so they are tracked like the config is.
    //
    // Enumerated because naming them would put a consumer's policy filenames in
    // `crates/**`, which is non-negotiable rule 1 — and `no-consumer-repo-name`
    // computes that rather than trusting a reader to notice, which is how the
    // first draft of this file was caught. It is also the more robust half: a
    // module added to `policy/` needs no edit here, where a list would silently
    // stop covering it.
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

/// Mint the `issue-search` receipt the way `issue-search-check` does.
///
/// Branch-keyed, and the filename is spelled the way `receipt.rs` spells it — the
/// engine reads the file the task already writes, so a second spelling here would
/// be testing a store nothing mints into.
fn mint_search_receipt(repo: &Path, branch: &str) {
    let store = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    // THE BODY IS THE TASK'S BODY, base line included. `branch_validity` refuses
    // a receipt that cannot say what it was taken against (CLOUD-516), so a
    // fixture minting existence alone would assert a state the real task never
    // produces — and it was minting exactly that until the task was corrected to
    // record the base.
    let base = common::git_in(repo, &["rev-parse", "HEAD"]);
    std::fs::write(
        store.join(format!("issue-search.{branch}")),
        format!("CLOUD-1 CLOUD-2\nbase {base}\n"),
    )
    .expect("mint the search receipt");
}

/// CARRIES: "creating an issue with no receipt is denied, and the denial names
/// the fix", and "creating an issue with a receipt is allowed".
///
/// One case for both because they are one predicate read in two directions, and
/// splitting them is how a suite ends up asserting only the deny.
#[test]
fn filing_without_a_search_is_refused_and_with_one_is_allowed() {
    let repo = repo("row1-search-then-file");
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"title":"a finding"}"#),
        Some(2),
        "a create with no search receipt on this branch is refused"
    );
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", r#"{"title":"a finding"}"#),
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("issue-search-check"),
        "the refusal must name the command that mints the receipt: {text}"
    );
    assert!(
        text.contains("filing-needs-a-search"),
        "and the row that refused, so a reader can find it in the config: {text}"
    );

    mint_search_receipt(&repo, "main");
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"title":"a finding"}"#),
        Some(0),
        "the same create, once the search is recorded, is allowed"
    );
}

/// CARRIES: "updating an existing issue is never gated, receipt or not".
///
/// The case the retiring script's header calls the one that would get the guard
/// switched off within a day, and the reason row 1 could not be config until
/// CLOUD-987. Asserted with NO receipt present, which is the state that makes it
/// discriminating: with one minted, an allow proves nothing about the modifier.
#[test]
fn an_update_is_never_gated() {
    let repo = repo("row1-update");
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","title":"an edit"}"#
        ),
        Some(0),
        "an update names an id, so it annotates a row that already exists"
    );
}

/// CARRIES: "all three live connector spellings are gated identically".
///
/// CLOUD-178's measurement replayed: one connector was exposed as
/// `mcp__Linear__save_issue`, `mcp__<uuid>__save_issue` and
/// `mcp__claude_ai_Linear__save_issue` across registration episodes, so a rule
/// naming one matched none of the others and the miss was silent. The script
/// hand-rolled a suffix match because it could not trust its own wiring; the row
/// gets it from `selects_tool`.
#[test]
fn every_connector_spelling_is_gated_identically() {
    let repo = repo("row1-spellings");
    for tool in [
        "mcp__Linear__save_issue",
        "mcp__1a2b3c4d-5e6f-7890-abcd-ef1234567890__save_issue",
        "mcp__claude_ai_Linear__save_issue",
        "save_issue",
    ] {
        assert_eq!(
            verdict(&repo, tool, r#"{"title":"a finding"}"#),
            Some(2),
            "whatever prefix the host minted, this is the creating verb: {tool}"
        );
    }
}

/// CARRIES: "a tool that does not create an issue is never gated".
///
/// The negative control the suffix match needs. `save_comment` attaches to
/// something that already exists, and a bare-suffix match would have pulled it in.
#[test]
fn a_tool_that_creates_nothing_is_not_gated() {
    let repo = repo("row1-other-verbs");
    for tool in [
        "mcp__Linear__save_comment",
        "mcp__Linear__save_document",
        "Bash",
    ] {
        assert_eq!(
            verdict(&repo, tool, r#"{"body":"not a filing"}"#),
            Some(0),
            "this verb opens no row, so it owes no search: {tool}"
        );
    }
}

/// CARRIES: "the CLOUD-504 over CLOUD-499 filing is refused, and allowed after
/// the search".
///
/// The measured incident this gate exists for, kept as a case rather than as
/// prose: 45 minutes re-deriving a cause already on the board, two wrong
/// diagnoses reported to a human, then a duplicate opened anyway (CLOUD-505).
#[test]
fn the_measured_duplicate_is_refused_and_then_allowed() {
    let repo = repo("row1-duplicate");
    let filing = r#"{"title":"`state record` refuses outright when any rule spawns"}"#;
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", filing),
        Some(2),
        "the filing that became a duplicate is refused before it is filed"
    );
    mint_search_receipt(&repo, "main");
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", filing),
        Some(0),
        "and allowed once the question has been asked — a search returning nothing still mints"
    );
}

/// The refusal carries no byte of what was being filed.
///
/// Non-negotiable rule 4, and it is load-bearing here rather than formal: the
/// thing this row refuses is a tracker write, so its input is a title and a body
/// somebody is composing. The retiring script was pointer-only by its own
/// discipline; the row inherits it structurally, and this asserts the inheritance
/// on a value that would be unmistakable in the output.
#[test]
fn the_refusal_carries_no_byte_of_the_filing() {
    let repo = repo("row1-pointer-only");
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
        !rendered.contains(secret),
        "the refusal must not echo what was being filed"
    );
}
