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
// carried: "creating an issue with no receipt is denied, and the denial names the fix" crates/batten/tests/it/board_receipts.rs
// carried: "all three live connector spellings are gated identically" crates/batten/tests/it/board_receipts.rs
// carried: "a tool that does not create an issue is never gated" crates/batten/tests/it/board_receipts.rs
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce. Each names the general property that now covers it.
//!
// subsumed: "an unreadable or nameless payload fails open" crates/batten/tests/it/cli.rs
// subsumed: "outside a git repository the guard fails open rather than blocking every filing" crates/batten/src/receipt.rs kind:mechanism
// subsumed: "the emitted denial is the hook shape, and it parses" crates/batten/tests/it/advisory_drain.rs
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
//! THE TWO ALLOW-AFTER-THE-RECEIPT ARMS MOVED HERE, and CLOUD-909's harness is
//! what moved them: declared `carried`, they could not replay, and the reason is
//! a tightening that had already landed. `branch_validity` voids a receipt that
//! records no base (CLOUD-516, measured — one receipt naming CLOUD-230 authorised
//! every edit behind four unrelated stories), where the retiring script asked
//! existence alone. The bats fixture is a bare `git init` with no `origin/main`,
//! so `issue-search-check` honestly records `base -` there and the engine reads
//! that as unproven. In a real checkout the ref resolves and the receipt is
//! valid, so the PROPERTY is carried — by
//! `filing_without_a_search_is_refused_and_with_one_is_allowed` and
//! `the_measured_duplicate_is_refused_and_then_allowed`, whose fixture mints the
//! base line the task really writes. What the bats fixture cannot express is the
//! precondition, which is the same shape as row 2's mtime arms below.
//!
// changed: "issue-search-guard.bats::creating an issue with a receipt is allowed" crates/batten/tests/it/board_receipts.rs the engine additionally requires the receipt to record the `origin/main` it was taken against (CLOUD-516); a bare-`git init` fixture has no such ref, so the receipt says `base -` and reads as unproven. Carried in `filing_without_a_search_is_refused_and_with_one_is_allowed`, which mints the base line
// changed: "issue-search-guard.bats::the CLOUD-504 over CLOUD-499 filing is refused, and allowed after the search" crates/batten/tests/it/board_receipts.rs same cause, same successor shape: the deny half replays, and the allow half needs a base line the fixture's repository cannot produce. Carried in `the_measured_duplicate_is_refused_and_then_allowed`
// changed: "issue-search-guard.bats::the bypass is honoured" crates/batten/tests/it/guardrail_bypass.rs BATTEN_ISSUE_SEARCH_BYPASS is gone; a mediated deny takes the engine's own hatch, which is the same consolidation CLOUD-442 and CLOUD-444 made when memory-guard and claim-guard retired
// changed: "issue-search-guard.bats::updating an existing issue is never gated, receipt or not" crates/batten/tests/it/board_receipts.rs the arm was true of row 1 alone and is now false of the config: row 2 below gates exactly that call on a RECENT read (CLOUD-508). The two rows are complements over one tool — `when_absent` and `when_present` on the same `input-id` — so this case's allow survives only where row 2 cannot key the subject, and `an_update_with_no_receipt_is_refused` is where the new answer is asserted
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
//!
//! ─── CLOUD-908's MAPPING, row 2 ──────────────────────────────────────────────
//!
//! `tests/issue-read-guard.bats`, sixteen cases, every one placed. EVERY ARM IS
//! SUITE-QUALIFIED, without waiting for a collision to prove it necessary: three
//! of these titles are word-for-word row 1's, because the two suites test the two
//! arms of one tool. A bare arm here would have let row 1's case borrow row 2's
//! verdict in whichever direction `replay.sh` looked first.
//!
// carried: "issue-read-guard.bats::an update with no receipt is denied, and the denial names the fix" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::an update from a fresh read is allowed" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::a fresh read of one issue does not authorise an update to a different one" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::creating an issue is never gated here, receipt or not" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::all three live connector spellings are gated identically" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::a tool that does not save an issue is never gated" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::an id that is not an issue key fails open rather than denying" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::the denial carries no payload content" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-guard.bats::a receipt minted from the declared field set alone authorises the update" crates/batten/tests/it/board_receipts.rs
//!
//! SUBSUMED — the plumbing became the engine's, and one seam became the surviving
//! half's own suite.
//!
// subsumed: "issue-read-guard.bats::an unreadable or nameless payload fails open" crates/batten/tests/it/cli.rs
// subsumed: "issue-read-guard.bats::a payload too thin to mint a receipt leaves the update denied" crates/batten/tests/it/board_receipts.rs
//!
//! CHANGED — and four of the five here share ONE cause, which is worth stating
//! once (the fifth is the bypass, and it is row 1's consolidation again): the
//! engine reads the receipt's **mtime**, where the script parsed a stamped epoch
//! out of field 3. Semantically they are the same quantity — the file is written
//! when the read happens — but the suite backdates by rewriting the field, so the
//! engine sees a fresh file and the divergence is in the fixture rather than in
//! the property. So the RECENCY BOUND ITSELF IS NOT LEFT UNASSERTED: it is
//! `a_read_older_than_the_bound_is_refused` below, which backdates the way the
//! engine measures. A `changed` arm over the mechanism is not licence to drop the
//! property, which is the one way this ledger could be used to launder a loss.
//!
// changed: "issue-read-guard.bats::an update from a read older than the bound is denied" crates/batten/tests/it/board_receipts.rs the age is the receipt file's mtime, not a parsed field, so the suite's field-3 arithmetic backdates nothing for the engine; the property is carried in `a_read_older_than_the_bound_is_refused`, which backdates the mtime
// changed: "issue-read-guard.bats::a malformed receipt fails open rather than denying" crates/batten/tests/it/board_receipts.rs the engine parses no field of the receipt, so there is no malformed state to fail open on — `named_validity` answers existence and `max_age` reads the mtime, which is a narrower reader than the one that could half-read a line
// changed: "issue-read-guard.bats::a receipt stamped in the future fails open rather than authorising" crates/batten/tests/it/board_receipts.rs same cause: a stamp is not read at all. A clock that moved shows up as a future mtime, which `older_than` reports as not-older and so still allows — the same direction, reached without parsing
// changed: "issue-read-guard.bats::the bound is configurable, and honoured in both directions" crates/batten/tests/it/board_receipts.rs BATTEN_ISSUE_READ_MAX_AGE is gone: the bound is `max_age` on the row (CLOUD-988), so it is configured where every other property of the row is and a reader finds it without knowing an env var's name. Per-call override is deliberately not carried — an agent that can widen the bound at the call it is being gated on is not gated
// changed: "issue-read-guard.bats::the bypass is honoured" crates/batten/tests/it/guardrail_bypass.rs BATTEN_ISSUE_READ_BYPASS is gone; a mediated deny takes the engine's own hatch, the same consolidation row 1 records one section up
//!
//! ─── CLOUD-909's REPLAY, row 2 ───────────────────────────────────────────────
//!
// replay-call: tests/issue-read-guard.bats 1dbad05 mise-tasks/issue-read-guard.sh an-update-owes-a-recent-read deny=2 allow=0
//!
//! ─── CLOUD-908's MAPPING, the two MINTERS (CLOUD-1024) ───────────────────────
//!
//! The blocks above retire the two GUARDS onto config rows. These retire the two
//! MINTERS onto the engine: `tests/issue-read-check.bats` (twenty cases) and
//! `tests/issue-search-check.bats` (five), whose subject programs are deleted
//! because a receipt now has one writer and it is the boundary.
//!
//! THE SHAPE OF THE MOVE IS DIFFERENT FROM THE GUARD RETIREMENTS, and saying so
//! is what keeps the arms readable. A guard retired onto a row that decides the
//! same question; a minter retires onto a WRITER that takes its input from
//! somewhere else entirely — the tool result rather than stdin. So the cases
//! about the RECORD carry across unchanged, and every case about the STDIN
//! CONTRACT is `changed`, because there is no stdin to have a contract with.
//!
// carried: "issue-read-check.bats::a get_issue payload mints a receipt keyed by the issue" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the receipt records the revision seen and the time it was seen" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the recorded time is when the read happened, so a receipt can actually age" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the receipt records a body hash that tracks the body and nothing else" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::a payload with no description records no baseline, rather than a digest of nothing" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the empty-body digest 8b13789 is never written for an absent description" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::an explicitly null description records no baseline either" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the receipt records the column the read saw" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::a column with a space is one field, not two" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::a payload with no status records no column, rather than one that reads as open" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::an explicitly null status records no column either" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the body baseline and the column arm do not depend on each other" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::a payload carrying only the declared field set is accepted" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::the receipt carries no title and no body" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::a second read replaces the first rather than appending" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::reads of different issues do not authorise each other" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::a payload missing updatedAt is refused rather than minting a receipt that names no revision" crates/batten/tests/it/board_receipts.rs
// carried: "issue-read-check.bats::an id that is not an issue key is refused rather than filed under a made-up name" crates/batten/tests/it/board_receipts.rs
// carried: "issue-search-check.bats::a list_issues payload mints a receipt naming the ids that were seen" crates/batten/tests/it/board_receipts.rs
// carried: "issue-search-check.bats::a search that returned nothing is still a search" crates/batten/tests/it/board_receipts.rs
// carried: "issue-search-check.bats::a payload that is not a search cannot look, and mints nothing" crates/batten/tests/it/board_receipts.rs
// carried: "issue-search-check.bats::a detached HEAD cannot look rather than minting an unkeyed receipt" crates/batten/tests/it/board_receipts.rs
//!
//! CHANGED — the three whose subject was the stdin contract, which no longer
//! exists. Each names what asks the same question on the new input, so the
//! property is relocated rather than dropped — the laundering this ledger exists
//! to refuse.
//!
// changed: "issue-read-check.bats::a single-element array is accepted, so a list payload of one composes" crates/batten/tests/it/board_receipts.rs there is no stdin to normalise: the input is the tool result, and the wrapper that actually arrives is the connector's content-block envelope. `a_content_block_envelope_mints_exactly_as_a_bare_payload_does` is the same property over the shape the host really sends, asserted as equality with the unwrapped mint
// changed: "issue-read-check.bats::stdin that is not a get_issue payload is exit 2, not a silent mint" crates/batten/tests/it/board_receipts.rs the mint has no exit code to give — it runs on an event no host offers a deny channel for — so "not a usable read" is answered by minting NOTHING instead. `a_failed_or_errored_or_empty_result_mints_nothing` and `a_write_response_does_not_mint_a_read_receipt` are the two halves: a result that says nothing, and one that says the right shape from the wrong tool
// changed: "issue-search-check.bats::the {issues: [...]} envelope is accepted as well as a bare array" crates/batten/tests/it/board_receipts.rs only one of the two is a real shape now. Measured against the live connector, a search answers `{issues: [...], hasNextPage, cursor}`; a bare array was the projection a caller piped by hand, and there is no caller. The `requires` path `issues[].id` is what pins the surviving shape
//!
//! ─── CLOUD-908's MAPPING, row 3 ──────────────────────────────────────────────
//!
//! `tests/board-move-guard.bats`, nineteen cases, every one placed. Suite-
//! qualified throughout, for the reason row 2's block gives: this is the THIRD arm
//! over one tool and it shares titles with both its siblings.
//!
// carried: "board-move-guard.bats::a move to In Review with no adjudication is denied, and the denial names graph-check" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::an adjudication that judged OTHER issues does not authorise this one" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::every other column is somebody else's question and is never gated here" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::a save_issue that sets no state at all is not a move" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::the column is read case- and space-insensitively" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::creating an issue is never gated here, even with a state" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::all three live connector spellings are gated identically" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::a tool that does not save an issue is never gated" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::an id that is not an issue key fails open rather than denying" crates/batten/tests/it/board_receipts.rs
// carried: "board-move-guard.bats::the denial carries no payload content" crates/batten/tests/it/board_receipts.rs
//!
//! SUBSUMED — the plumbing became the engine's.
//!
// subsumed: "board-move-guard.bats::an unreadable or nameless payload fails open" crates/batten/tests/it/cli.rs
//!
//! CHANGED — and five of the six are ONE cause, which the receipt's new shape
//! explains once: `graph-check` writes a file per judged id now, where it appended
//! `<epoch> <id> <id> …` to a single file. So there is no line to parse, no
//! substring to anchor, and no stale-line-plus-fresh-line combination to defend
//! against — the set is the set of files, and the age is each file's mtime. Every
//! property those cases asserted is carried below; what is gone is the mechanism
//! they were written against.
//!
// changed: "board-move-guard.bats::a move covered by a fresh adjudication is allowed" crates/batten/tests/it/board_receipts.rs the ALLOW half cannot be expressed on the retiring fixture: the base rev's graph-check mints the aggregate `board-move` file, and the engine reads `board-move.<KEY>`, so a fixture carrying the old shape is a fixture carrying no receipt this row can see. Carried in `a_move_with_no_adjudication_is_refused`, whose second half mints the shape the surviving task now writes
// changed: "board-move-guard.bats::graph-check mints the receipt this guard reads, and only on a coherent board" tests/graph-check.bats same cause on the producing side: this case asserted the two ends agreed on ONE file, and they agree on a file per id now. The seam is asserted where the surviving half lives — `a coherent board records one receipt per id it judged`, which also asserts the aggregate is not left behind
// changed: "board-move-guard.bats::an adjudication older than the bound is denied, and the bound is configurable" crates/batten/tests/it/board_receipts.rs the deny half is carried in `an_adjudication_past_the_bound_is_refused`, which backdates the receipt's mtime; BATTEN_BOARD_MOVE_MAX_AGE is gone and the bound is `max_age` on the row (CLOUD-988), configured where every other property of the row is. Per-call override is deliberately not carried — an agent that can widen the bound at the call it is being gated on is not gated
// changed: "board-move-guard.bats::a stale line naming this issue plus a fresh line naming others is not an authorisation" crates/batten/tests/it/board_receipts.rs there are no lines: one file per id means a fresh adjudication of ANOTHER id cannot appear in this id's receipt at all, so the combination the case defends against is unconstructible rather than defended
// changed: "board-move-guard.bats::an id is matched whole, so a prefix does not authorise a longer key" crates/batten/tests/it/board_receipts.rs the `\b$key\b` anchoring that kept CLOUD-48 from reading as CLOUD-480 is structural now — a filename is matched whole by the filesystem. Carried anyway in `an_adjudication_of_one_row_does_not_authorise_another`, whose second subject is a prefix of the first
// changed: "board-move-guard.bats::a malformed receipt line is not an authorisation" crates/batten/tests/it/board_receipts.rs the engine parses no field of the receipt, so there is no malformed state to judge: `named_validity` answers existence and `max_age` reads the mtime
// changed: "board-move-guard.bats::a receipt stamped in the future fails open rather than authorising" crates/batten/tests/it/board_receipts.rs same cause — a stamp is not read. A clock that moved shows as a future mtime, which `older_than` reports as not-older and so still allows: the same direction, reached without parsing
// changed: "board-move-guard.bats::the bypass is honoured" crates/batten/tests/it/guardrail_bypass.rs BATTEN_BOARD_MOVE_BYPASS is gone; a mediated deny takes the engine's own hatch, the consolidation rows 1 and 2 record above
//!
//! THE SURVIVING SUITE'S OWN RENAMES OWE ARMS TOO, and that is the column working
//! rather than a nuisance: `graph-check.bats` keeps testing the minting side, but
//! three of its case NAMES describe the shape that changed, and a renamed case is
//! a deleted case to anything reading names. Each is `changed` on the same file,
//! because the property is unchanged and only what it is asserted OVER moved.
//!
// changed: "graph-check.bats::a coherent board records which ids it judged" tests/graph-check.bats the receipt is one file per judged id now, so the case asserts a set of files rather than words inside a line; renamed to say so and asserting the aggregate is gone
// changed: "graph-check.bats::runs accumulate rather than overwrite, so an earlier closure stays judged" tests/graph-check.bats accumulation was a property of one shared file. Per-id files give it structurally, and within one id the freshest adjudication must OVERWRITE so the mtime is the age the engine reads — the opposite of accumulate, for the same reason
// changed: "graph-check.bats::the receipt is pointer-only — ids and an epoch, never issue prose" tests/graph-check.bats one id per file rather than many, so the case names the singular; the pointer-only predicate is untouched
//!
//! ─── CLOUD-909's REPLAY, row 3 ───────────────────────────────────────────────
//!
// replay-call: tests/board-move-guard.bats 66d9d8f mise-tasks/board-move-guard.sh a-move-to-in-review-owes-an-adjudication deny=2 allow=0

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

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
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
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
    //
    // `origin/main` WITH THE TASK'S OWN FALLBACK, not `HEAD`. The two agree in
    // this fixture and diverge the moment it grows a local commit, and then a
    // HEAD-based body would be a receipt the real task cannot produce — so the
    // suite would stop exercising the `stale-main` contract while still passing.
    // Caught in review on #680; the spelling is
    // `git rev-parse --verify --quiet origin/main || echo -`.
    let base = common::git_in(repo, &["rev-parse", "--verify", "--quiet", "origin/main"]);
    let base = if base.trim().is_empty() {
        "-".to_owned()
    } else {
        base
    };
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
    // The CALL that mints the receipt is the class's declared route, which
    // CLOUD-1286 moved behind `batten policy explain` — it does not vary
    // between firings, and paying for it on each one was the defect. What must
    // stay inline is the pointer: WHICH receipt is missing, and which row wants
    // it.
    assert!(
        text.contains("issue-search"),
        "the refusal must name the receipt that is absent: {text}"
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

/// CARRIES row 1's "updating an existing issue is never gated" only as far as it
/// is still true: **row 1** does not gate an update.
///
/// The case the retiring script's header calls the one that would get the guard
/// switched off within a day, and the reason row 1 could not be config until
/// CLOUD-987. What changed is that a second row now answers this call, so the
/// discriminating assertion is no longer the exit code — it is WHICH ROW spoke.
/// A bare `Some(2)` here would pass just as well if row 1 had started demanding a
/// search before every edit, which is the exact over-fire this file's header
/// prices.
#[test]
fn an_update_is_not_row_ones_business() {
    let repo = repo("row1-update");
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload(
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","title":"an edit"}"#,
        ),
    );
    let text = stderr(&refusal);
    // THE REFUSING ROW IS THE ONLY ROW ID ON THE LINE, which is what CLOUD-1286
    // changed here and it changed it for the better. This case used to have to
    // read attribution off the `Refused by <id>` PREFIX, because a bare
    // `contains("filing-needs-a-search")` matched row 2's own reason — which
    // ENDS by naming row 1, "Creating an issue is never gated by this row (that
    // is `filing-needs-a-search`)". That cross-reference is prose, so it now
    // lives behind `batten policy explain` with the rest of it, and the id on
    // the emitted line is the engine's own attribution and nothing else. The
    // negative assertion is what keeps that claim honest.
    assert!(
        !text.contains("filing-needs-a-search"),
        "an update names an id, so the row that gates FILING must stay silent: {text}"
    );
    assert!(
        text.contains("an-update-owes-a-recent-read"),
        "and the row that does answer an edit is the one that spoke: {text}"
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

// ─── row 2: an update owes a RECENT read ─────────────────────────────────────

/// Mint the `issue-read` receipt the way `issue-read-check` does, aged by `age`
/// seconds.
///
/// The body is that task's five fields in its own order — `key seen read_at
/// body_hash seen_status` — even though the engine reads none of them, because a
/// fixture that wrote something else would stop being evidence about the file the
/// surviving task actually produces.
///
/// **THE AGE IS THE MTIME**, which is the one place this differs from the retiring
/// suite and the reason four of its cases are `changed` arms above. That suite
/// backdated by rewriting field 3; `older_than` reads the file's modification
/// time, so backdating the field would age nothing and a suite that tried it
/// would assert a bound it never crossed.
fn mint_read_receipt(repo: &Path, key: &str, age: u64) {
    let store = repo.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    let path = store.join(format!("issue-read.{key}"));
    let now = std::time::SystemTime::now();
    let stamped = now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
        - age;
    std::fs::write(
        &path,
        format!("{key} 2026-08-13T04:00:00.000Z {stamped} - todo\n"),
    )
    .expect("mint the read receipt");
    let file = std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("the minted receipt is writable");
    file.set_modified(now - std::time::Duration::from_secs(age))
        .expect("the receipt's mtime is settable");
}

/// CARRIES: "an update with no receipt is denied, and the denial names the fix",
/// and "an update from a fresh read is allowed".
///
/// One case for both, for the reason this file's header gives: a row that refuses
/// every update passes the deny half and is the over-fire the retiring script's
/// own header prices at "switched off within a day".
///
/// The refusing ROW is asserted, not just the code. Two rows select this tool now
/// — complements over one `input-id` — so an exit 2 alone would be satisfied by
/// row 1 firing on an edit, which is the misattribution `replay.sh` calls
/// `denied-by-another-row`.
#[test]
fn an_update_with_no_receipt_is_refused() {
    let repo = repo("row2-update-no-receipt");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", update),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "an update against a row this clone has no recorded read of is refused"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("an-update-owes-a-recent-read"),
        "the row that refused, so a reader can find it in the config: {text}"
    );
    // The CALL that mints the receipt is the class's declared route and is one
    // `batten policy explain` away (CLOUD-1286). It is the same string on every
    // firing, which is exactly what does not belong on a line an agent pays for
    // ~300 times a session.
    assert!(
        !text.contains("Fix: "),
        "the remedy is dereferenced rather than inlined: {text}"
    );
    // THE VERDICT WORDING FOR `ReceiptKey::Named`, pinned because it was missing:
    // `receipt_refusal` had arms for `Branch` and for the commit-keyed default,
    // and a subject-keyed row fell through to the commit one — telling the reader
    // to re-run a per-commit step when what is absent is a read of one row. Found
    // by this row, the key's first consumer.
    // CLOUD-1285 moved the wording into a declared class and its POINTERS, so
    // the sentence this case used to pin no longer exists. What it was actually
    // asserting does: the check name and the KIND of thing the receipt is keyed
    // to both travel, and the keying is `row` rather than `branch`. The negative
    // arm is what keeps this discriminating — a composer that dropped the keying
    // subject entirely would satisfy the first assertion alone.
    assert!(
        text.contains("issue-read"),
        "the verdict must name the check whose receipt is missing: {text}"
    );
    assert!(
        text.contains("row"),
        "and the keying, in this row's own terms: {text}"
    );
    assert!(
        !text.contains("branch"),
        "and not in the branch-keyed terms, which is the neighbouring arm: {text}"
    );

    mint_read_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "the same update, once the read is recorded and recent, is allowed"
    );
}

/// CARRIES: "an update from a read older than the bound is denied" — THE
/// INCIDENT.
///
/// A receipt exists, so an existence gate passes this, and the read behind it is
/// 51 minutes old: CLOUD-508's measurement, where a session planned against a row
/// for that long, another session marked it a duplicate in between, and the write
/// landed anyway.
///
/// Both directions in one case, and the allow arm is what makes the deny arm mean
/// anything: `max_age` deleted from the row would leave a bound-crossing receipt
/// allowed, and `max_age = 0` would leave the fresh one refused.
#[test]
fn a_read_older_than_the_bound_is_refused() {
    let repo = repo("row2-stale-read");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    mint_read_receipt(&repo, "CLOUD-1", 3060);
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", update),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "a receipt past the row's bound is a step that ran, not evidence that still holds"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("an-update-owes-a-recent-read"),
        "the row that refused: {text}"
    );
    assert!(
        text.contains("300s"),
        "and the bound it was measured against, which is what a reader acts on: {text}"
    );

    mint_read_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "and a read inside the bound authorises the same update"
    );
}

/// The clock a `max_age` is read against is SUPPLIED, not taken (CLOUD-1170).
///
/// **This is the case that discriminates the whole row.** The receipt is minted
/// five seconds old, so the boundary's own clock says it is well inside the 300s
/// bound and every other case in this file would allow the update. Handing in an
/// instant a thousand seconds later refuses the same receipt over the same tree —
/// which is only possible if the comparison read the supplied value rather than
/// the clock.
///
/// Nothing else changes between the two runs: same repository, same receipt, same
/// payload, same bound. The instant is the only variable, which is what makes this
/// a statement about where the clock came from rather than about recency.
#[test]
fn a_supplied_instant_decides_recency_rather_than_the_clock() {
    let repo = repo("instant-decides");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    mint_read_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "a five-second-old receipt is inside the bound by the boundary's own clock"
    );
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code", "--instant", &later(1000)],
        &payload("mcp__Linear__save_issue", update),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "and the SAME receipt is past the bound when the caller hands in an instant \
         a thousand seconds later — the comparison read the supplied value"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("an-update-owes-a-recent-read"),
        "the row that refused: {text}"
    );
}

/// Two runs, one instant, one answer (CLOUD-1170).
///
/// §6 asks for byte-stable output, and a `max_age` verdict taken against a clock
/// READ cannot give it: the receipt ages between the two runs, so a bound tight
/// enough to matter flips underneath them. A supplied instant can.
///
/// **Worthless alone**, and its partner is the case below: any constant is
/// byte-identical to itself, so this passes over a build that ignores the flag
/// entirely. The pair is what says the answer depends on the instant AND on
/// nothing else (CLOUD-418).
#[test]
fn the_same_instant_yields_the_same_verdict() {
    let repo = repo("instant-stable");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    mint_read_receipt(&repo, "CLOUD-1", 5);
    let at = later(1000);
    let args = ["hook", "--harness", "exit-code", "--instant", &at];
    let first = run_with_stdin(&repo, &args, &payload("mcp__Linear__save_issue", update));
    let second = run_with_stdin(&repo, &args, &payload("mcp__Linear__save_issue", update));
    assert_eq!(
        first.status.code(),
        second.status.code(),
        "the same instant over the same receipt must reach the same verdict"
    );
    assert_eq!(
        stderr(&first),
        stderr(&second),
        "and say the same thing about it, byte for byte"
    );
}

/// THE ANTI-VACUITY PARTNER (CLOUD-418).
///
/// Without this, the case above is satisfied by a build that never reads
/// `--instant` at all. Two instants either side of the bound, same receipt: one
/// allows and one refuses, so the flag is demonstrably load-bearing.
#[test]
fn a_different_instant_changes_the_verdict() {
    let repo = repo("instant-moves");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    mint_read_receipt(&repo, "CLOUD-1", 5);
    let inside = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code", "--instant", &later(10)],
        &payload("mcp__Linear__save_issue", update),
    );
    let past = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code", "--instant", &later(1000)],
        &payload("mcp__Linear__save_issue", update),
    );
    assert_eq!(
        inside.status.code(),
        Some(0),
        "an instant inside the bound authorises the update"
    );
    assert_eq!(
        past.status.code(),
        Some(2),
        "and one past it does not — identical verdicts across two instants would \
         mean the flag is not reaching the comparison"
    );
}

/// ABSENT MEANS WHAT IT ALWAYS MEANT (CLOUD-1170).
///
/// `Rule::max_age`'s own doc takes this care in these words, and the reason is the
/// same: no committed row may change meaning because a flag arrived. A caller that
/// names no instant gets the boundary clock and today's behaviour exactly, so the
/// flag buys reproducibility for whoever wants it rather than imposing it on
/// every host that fires this hook.
#[test]
fn an_unsupplied_instant_reads_the_boundary_clock() {
    let repo = repo("instant-absent");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    mint_read_receipt(&repo, "CLOUD-1", 3060);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(2),
        "a 51-minute-old read is still refused with no flag in sight"
    );
    mint_read_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "and a fresh one is still allowed — the flag's absence changes nothing"
    );
}

/// A TYPO IS NOT A FALLBACK (CLOUD-1170).
///
/// Degrading an unparseable `--instant` to "read the clock" is the dangerous
/// failure rather than the safe one: the caller believes the verdict is
/// reproducible, the answer still looks right, and nothing says otherwise. So it
/// refuses, as `--rule` and `--since` both do, and the refusal names the flag.
///
/// Exit 1 — a statement about the invocation — never 2, which is a policy verdict
/// this call never reached.
#[test]
fn a_malformed_instant_is_a_usage_error() {
    let repo = repo("instant-malformed");
    let refusal = run_with_stdin(
        &repo,
        &[
            "hook",
            "--harness",
            "exit-code",
            "--instant",
            "half-past-two",
        ],
        &payload(
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","description":"groomed"}"#,
        ),
    );
    assert_eq!(
        refusal.status.code(),
        Some(1),
        "a malformed instant is a usage error, never a policy verdict and never a \
         silent fallback to the clock"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("--instant"),
        "and the refusal names the flag the caller got wrong: {text}"
    );
}

/// An epoch second `offset` seconds after now, as `--instant` takes it.
///
/// Derived from the clock rather than a literal, because the receipt these cases
/// mint is itself aged relative to now: a fixed instant would drift out of every
/// bound the moment the suite outlived its own constant.
fn later(offset: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs();
    (now + offset).to_string()
}

/// CARRIES: "a fresh read of one issue does not authorise an update to a
/// different one".
///
/// This is why the receipt is keyed by ISSUE where `claim-check`'s is keyed by
/// branch, and it is the whole reason `ReceiptKey::Named` exists: a branch
/// legitimately edits several rows, so a branch key would let a fresh read of one
/// authorise a stale write to another.
#[test]
fn a_read_of_one_row_does_not_authorise_a_write_to_another() {
    let repo = repo("row2-wrong-subject");
    mint_read_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","description":"groomed"}"#
        ),
        Some(0),
        "the row that was read is writable"
    );
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-2","description":"groomed"}"#
        ),
        Some(2),
        "the row that was not read is not, however fresh the neighbour's receipt is"
    );
}

/// CARRIES: "an id that is not an issue key fails open rather than denying".
///
/// `key_shape` is the UUID carve-out and it ALLOWS. The `id` parameter accepts a
/// UUID, the receipt namespace is keyed by issue key, and resolving one to the
/// other needs a tracker credential no hook has — a genuine could-not-look, which
/// house-style §7 answers by allowing. Denying would refuse legitimate updates
/// over a spelling the agent is entitled to use, which is the false-positive rate
/// that gets a guard switched off.
#[test]
fn an_id_that_is_not_an_issue_key_allows() {
    let repo = repo("row2-uuid-id");
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"7f3a1b2c-0000-4000-8000-000000000000","description":"groomed"}"#
        ),
        Some(0),
        "a subject the row cannot key is a could-not-look, and could-not-look allows"
    );
}

/// CARRIES: "creating an issue is never gated here, receipt or not".
///
/// The complement's complement, and the arm that keeps the two rows from becoming
/// one over-firing row: a create carries no `id`, so `when_present = "input-id"`
/// excludes it and row 1 answers instead. Asserted by the row that must NOT
/// appear, because a create with no search receipt is refused anyway — reading
/// that exit 2 as this row's would be the same misattribution one direction over.
#[test]
fn a_create_is_not_row_twos_business() {
    let repo = repo("row2-create");
    mint_search_receipt(&repo, "main");
    let output = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", r#"{"title":"a finding"}"#),
    );
    let text = stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a create that asked its question is allowed, with no read receipt anywhere"
    );
    assert!(
        !text.contains("Refused by an-update-owes-a-recent-read"),
        "the row that gates EDITING must stay silent on a filing: {text}"
    );
}

/// CARRIES: "all three live connector spellings are gated identically", and "a
/// tool that does not save an issue is never gated".
///
/// CLOUD-178's measurement, replayed on row 2's arm: one connector exposed as
/// three names across registration episodes, so a rule naming one matched none of
/// the others and the miss was silent. `save_comment` is the negative control the
/// suffix match needs.
#[test]
fn row_two_selects_by_suffix_and_nothing_wider() {
    let repo = repo("row2-spellings");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    for tool in [
        "mcp__Linear__save_issue",
        "mcp__claude_ai_Linear__save_issue",
        "mcp__4db58e41-0000-0000-0000-000000000000__save_issue",
        "save_issue",
    ] {
        assert_eq!(
            verdict(&repo, tool, update),
            Some(2),
            "whatever prefix the host minted, this is the editing verb: {tool}"
        );
    }
    for tool in [
        "mcp__Linear__save_comment",
        "mcp__Linear__list_issues",
        "Bash",
        "Write",
    ] {
        assert_eq!(
            verdict(&repo, tool, update),
            Some(0),
            "this verb edits no row, so it owes no read: {tool}"
        );
    }
}

/// CARRIES: "the denial carries no payload content".
///
/// Non-negotiable rule 4, and the subject is deliberately not named either: the
/// key is read out of the call's own arguments, so echoing it back would put a
/// fragment of the payload in the refusal. The row id and the check name are
/// pointers; everything else here is content somebody was about to write.
#[test]
fn row_twos_refusal_carries_no_byte_of_the_edit() {
    let repo = repo("row2-pointer-only");
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    let output = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload(
            "mcp__Linear__save_issue",
            &format!("{{\"id\":\"CLOUD-1\",\"description\":{encoded}}}"),
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
        "the refusal must not echo what was being written"
    );
    assert!(
        !rendered.contains("CLOUD-1"),
        "nor the subject, which is read from the arguments: {rendered}"
    );
}

/// CARRIES: "a receipt minted from the declared field set alone authorises the
/// update", and SUBSUMES "a payload too thin to mint a receipt leaves the update
/// denied".
///
/// CLOUD-526's seam, and the half that matters here is the consuming end: the
/// narrowed contract is only worth anything if the receipt it mints still opens
/// this gate. `id` and `updatedAt` — two scalars, no body, which is the ~15 KB a
/// model used to re-type to reach exactly this outcome. The refusing end stays
/// `tests/issue-read-check.bats`', because the task that refuses is not retiring;
/// what this asserts is that no receipt means no allow, which is the same state
/// the too-thin payload leaves behind.
#[test]
fn the_declared_field_set_alone_opens_the_gate() {
    let repo = repo("row2-declared-fields");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(2),
        "a payload the check refused mints nothing, so the update is where it started"
    );
    mint_read_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "and the receipt those two fields alone produce is what opens it"
    );
}

// ─── row 3: a move to In Review owes an adjudication ─────────────────────────

/// Mint the `board-move` receipt the way `graph-check` does, aged by `age`
/// seconds.
///
/// One file per judged id, which is the shape CLOUD-312 row 3 moved it to: the
/// engine's `named` key is `<check>.<subject>`, so the set `graph-check` judged is
/// the set of files rather than words inside a line. The body is that task's two
/// fields, and the age is the MTIME for the reason `mint_read_receipt` gives.
fn mint_move_receipt(repo: &Path, key: &str, age: u64) {
    let store = repo.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    let path = store.join(format!("board-move.{key}"));
    let now = std::time::SystemTime::now();
    let stamped = now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
        - age;
    std::fs::write(&path, format!("{stamped} {key}\n")).expect("mint the move receipt");
    let file = std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("the minted receipt is writable");
    file.set_modified(now - std::time::Duration::from_secs(age))
        .expect("the receipt's mtime is settable");
}

/// A move to In Review, as the tracker's `state` parameter spells it.
fn move_to(key: &str, state: &str) -> String {
    let key = serde_json::to_string(key).expect("encodable");
    let state = serde_json::to_string(state).expect("encodable");
    format!("{{\"id\":{key},\"state\":{state}}}")
}

/// CARRIES: "a move to In Review with no adjudication is denied, and the denial
/// names graph-check", and "a move covered by a fresh adjudication is allowed".
///
/// THE MEASURED INCIDENT (CLOUD-512): a bulk sweep after #375 moved fifteen rows
/// to In Review. CLOUD-480 was among them and nothing of it had landed — the only
/// commit naming it carries the key in a `Refs:` trailer as the still-open gap. It
/// sat wrong for 4.5 hours, and `graph-check` refused it in one invocation the
/// moment it was finally asked. The gate was never wrong; it was never consulted.
///
/// Both directions, and the allow half is what stops this becoming a row that
/// demands an adjudication before every edit — the over-fire the retiring guard's
/// own header prices at "switched off within a day".
#[test]
fn a_move_with_no_adjudication_is_refused() {
    let repo = repo("row3-move-no-receipt");
    let input = move_to("CLOUD-1", "In Review");
    // The read receipt row 2 wants, so the row under test is the one answering.
    mint_read_receipt(&repo, "CLOUD-1", 5);
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", &input),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "a move this clone has no adjudication for is refused"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("a-move-to-in-review-owes-an-adjudication"),
        "the row that refused: {text}"
    );
    // The check whose receipt is missing is the pointer and stays inline; the
    // COMMAND that mints it is the class's declared route, which CLOUD-1286
    // moved behind `batten policy explain`. Both halves asserted, because
    // dropping the first would be a real loss and dropping the second is the
    // change.
    assert!(
        text.contains("board-move"),
        "and the check whose receipt is absent: {text}"
    );
    assert!(
        !text.contains("Refused by "),
        "with no prefix restating the class: {text}"
    );

    mint_move_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", &input),
        Some(0),
        "the same move, once the closure is adjudicated, is allowed"
    );
}

/// CARRIES: "an adjudication older than the bound is denied" — the deny half of a
/// `changed` arm, and CARRIES "an id is matched whole" via the second subject.
///
/// The bound is `max_age = 900` on the row now rather than an env var, and the age
/// is the receipt file's mtime rather than a parsed epoch — which is why the arm
/// is `changed` while the property is here. Both directions, because `max_age`
/// deleted would leave a stale adjudication authorising the sweep and `max_age =
/// 0` would refuse a fresh one.
#[test]
fn an_adjudication_past_the_bound_is_refused() {
    let repo = repo("row3-stale-adjudication");
    let input = move_to("CLOUD-1", "In Review");
    mint_read_receipt(&repo, "CLOUD-1", 5);
    mint_move_receipt(&repo, "CLOUD-1", 4000);
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", &input),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "an adjudication past the row's bound is a step that ran, not evidence that still holds"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("a-move-to-in-review-owes-an-adjudication"),
        "the row that refused: {text}"
    );
    // The bound the age was measured against travels as a pointer, because it
    // is the difference between "run it again" and a row nobody can satisfy.
    assert!(text.contains("900s"), "and the bound it crossed: {text}");

    mint_move_receipt(&repo, "CLOUD-1", 5);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", &input),
        Some(0),
        "and an adjudication inside the bound authorises the same move"
    );
}

/// CARRIES: "an adjudication that judged OTHER issues does not authorise this
/// one", and the prefix half of "an id is matched whole".
///
/// The receipt is keyed to the SET because a bare "graph-check ran" receipt is
/// satisfied by judging one clean row and then sweeping fifteen — which is the
/// sweep CLOUD-512 measured. `CLOUD-48` and `CLOUD-480` are deliberate: the
/// retiring guard needed `\b$key\b` to keep the shorter from authorising the
/// longer, and one file per subject makes that the filesystem's problem.
#[test]
fn an_adjudication_of_one_row_does_not_authorise_another() {
    let repo = repo("row3-wrong-subject");
    mint_read_receipt(&repo, "CLOUD-48", 5);
    mint_read_receipt(&repo, "CLOUD-480", 5);
    mint_move_receipt(&repo, "CLOUD-48", 5);
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            &move_to("CLOUD-48", "In Review")
        ),
        Some(0),
        "the row that was adjudicated moves"
    );
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            &move_to("CLOUD-480", "In Review")
        ),
        Some(2),
        "and the row whose key merely CONTAINS it does not"
    );
}

/// CARRIES: "every other column is somebody else's question and is never gated
/// here", "a `save_issue` that sets no state at all is not a move", and "the column
/// is read case- and space-insensitively".
///
/// `when_value` is the whole reason this row is expressible: a row that could only
/// ask whether a `state` was PRESENT would fire on every edit that named any
/// column, which is the over-fire the retiring guard's header prices. In Progress
/// is `claim-check`'s question, Todo promotion is CLOUD-375's — other owners, and
/// this row must not answer for them.
///
/// The three spellings are one move because the tracker's parameter takes a type,
/// a name or an id; the engine folds case and drops spaces, underscores and
/// hyphens.
#[test]
fn only_the_move_to_in_review_is_this_rows_business() {
    let repo = repo("row3-columns");
    mint_read_receipt(&repo, "CLOUD-1", 5);
    for spelling in [
        "In Review",
        "in review",
        "inreview",
        "in_review",
        "IN-REVIEW",
    ] {
        assert_eq!(
            verdict(
                &repo,
                "mcp__Linear__save_issue",
                &move_to("CLOUD-1", spelling)
            ),
            Some(2),
            "however the column is spelled, this is the same move: {spelling}"
        );
    }
    for column in ["Todo", "In Progress", "Done", "Backlog", "Canceled"] {
        assert_eq!(
            verdict(
                &repo,
                "mcp__Linear__save_issue",
                &move_to("CLOUD-1", column)
            ),
            Some(0),
            "this column has a different owner and is not gated here: {column}"
        );
    }
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","description":"an edit"}"#
        ),
        Some(0),
        "and a call that sets no state is not a move at all"
    );
}

/// CARRIES: "creating an issue is never gated here, even with a state", "all three
/// live connector spellings are gated identically", "a tool that does not save an
/// issue is never gated", and "an id that is not an issue key fails open rather
/// than denying".
///
/// The create arm is asserted by the row that must NOT appear rather than by an
/// exit code: a create with no search receipt is refused by row 1 anyway, and
/// reading that 2 as this row's would be the misattribution `replay.sh` calls
/// `denied-by-another-row`.
#[test]
fn row_threes_selectors_are_the_guards() {
    let repo = repo("row3-selectors");
    mint_read_receipt(&repo, "CLOUD-1", 5);
    for tool in [
        "mcp__Linear__save_issue",
        "mcp__claude_ai_Linear__save_issue",
        "mcp__4db58e41-0000-0000-0000-000000000000__save_issue",
        "save_issue",
    ] {
        assert_eq!(
            verdict(&repo, tool, &move_to("CLOUD-1", "In Review")),
            Some(2),
            "whatever prefix the host minted, this is the moving verb: {tool}"
        );
    }
    for tool in [
        "mcp__Linear__save_comment",
        "mcp__Linear__list_issues",
        "Bash",
    ] {
        assert_eq!(
            verdict(&repo, tool, &move_to("CLOUD-1", "In Review")),
            Some(0),
            "this verb moves no row, so it owes no adjudication: {tool}"
        );
    }
    // A UUID is a spelling `id` accepts, and resolving it to a key needs a tracker
    // credential no hook has: a genuine could-not-look, which allows.
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            &move_to("7f3a1b2c-0000-4000-8000-000000000000", "In Review")
        ),
        Some(0),
        "a subject this row cannot key is could-not-look, and could-not-look allows"
    );
    // The create: no `id`, so no subject, so this row is silent.
    let output = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload(
            "mcp__Linear__save_issue",
            r#"{"title":"a finding","state":"In Review"}"#,
        ),
    );
    assert!(
        !stderr(&output).contains("Refused by a-move-to-in-review-owes-an-adjudication"),
        "a create names no row to move, so this row must stay silent: {}",
        stderr(&output)
    );
}

/// CARRIES: "the denial carries no payload content".
///
/// Non-negotiable rule 4. The subject is not named either, for row 2's reason: it
/// is read from the call's own arguments.
#[test]
fn row_threes_refusal_carries_no_byte_of_the_move() {
    let repo = repo("row3-pointer-only");
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    mint_read_receipt(&repo, "CLOUD-1", 5);
    let output = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload(
            "mcp__Linear__save_issue",
            &format!("{{\"id\":\"CLOUD-1\",\"state\":\"In Review\",\"description\":{encoded}}}"),
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
        "the refusal must not echo what was being written"
    );
    assert!(
        !rendered.contains("CLOUD-1"),
        "nor the subject, which is read from the arguments: {rendered}"
    );
}

// ─── CLOUD-1024: the receipts mint themselves ────────────────────────────────
//
// The two rows above DEMAND a receipt; these cases are about who WRITES it. Both
// were minted by a second, hand-piped call carrying a payload the agent
// re-assembled — CLOUD-526's forgery surface, and a toll re-paying a whole issue
// body to record two scalars (measured: one filing plus four board repairs in a
// session, three calls each).
//
// **THE FAILED-CALL CASE IS THE ONE THAT DECIDES WHETHER THIS IS AN IMPROVEMENT.**
// A mint firing on an errored or empty response would forge a read receipt for a
// read that never happened, which is worse than the path it replaces. So it is
// asserted first among the negatives and over three distinct shapes, not one.

/// A post-tool envelope: the event the mint reads, with the host's own result key.
fn post_tool(tool: &str, response: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!(
        "{{\"hook_event_name\":\"PostToolUse\",\"tool_name\":{encoded},\
         \"tool_input\":{{}},\"tool_response\":{response}}}"
    )
}

/// Hand one completed call to the engine, as the host would.
fn completed(repo: &Path, tool: &str, response: &str) {
    // The STATUS is deliberately discarded: a post-tool event carries no verdict —
    // no host offers a deny channel there — so asserting one would be asserting
    // this call's own irrelevance. What the case reads is the receipt store.
    let _ = run_with_stdin(
        repo,
        &["hook", "--harness", "exit-code"],
        &post_tool(tool, response),
    );
}

/// What the receipt store holds for `name`, or `None` when nothing minted.
fn receipt(repo: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(repo.join(".git/batten-receipts").join(name)).ok()
}

/// A `get_issue` result carrying the declared field set and both optional arms.
const READ_RESULT: &str = r#"{"id":"CLOUD-1","updatedAt":"2026-08-25T04:42:01.650Z",
    "description":"hello\n","status":"In Progress"}"#;

#[test]
fn a_read_result_mints_the_receipt_with_no_second_call() {
    // The acceptance clause, end to end and in the order that proves it: the
    // update is REFUSED, one read happens, and the same update is ALLOWED — with
    // no `issue-read-check` in between. Asserting only the file's existence would
    // pass over a receipt the gate cannot actually read.
    let repo = repo("mint-read-authorises-the-write");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(2),
        "the gate denies before anything has read the row"
    );

    completed(&repo, "mcp__Linear__get_issue", READ_RESULT);

    let minted = receipt(&repo, "issue-read.CLOUD-1").expect("the read minted its own receipt");
    let fields: Vec<&str> = minted.trim().split(' ').collect();
    // FIVE, PLUS THE VERDICT (CLOUD-1100). The sixth field is appended rather
    // than inserted, which is what keeps every positional reader of this receipt
    // — `claim-check` at field 4, `finding-sink-check` at field 5 — pointed at
    // the same field it was pointed at before, and keeps the five the hand-run
    // `mise run issue-read-check` writes a receipt every consumer can read.
    assert_eq!(
        fields.len(),
        6,
        "the task's five fields in its order, plus the compiled Ready verdict: {minted}"
    );
    assert_eq!(fields[0], "CLOUD-1");
    assert_eq!(fields[1], "2026-08-25T04:42:01.650Z");
    assert_eq!(
        fields[4], "in-progress",
        "the column is normalised, or a space would split one field into two"
    );
    assert_eq!(
        fields[5], "unready",
        "and the body this fixture sends carries no Ready block at all, which is the \
         verdict the authority gives it"
    );

    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "and reading the row over the connector is now sufficient to authorise the write"
    );
}

#[test]
fn the_recorded_instant_is_the_read_rather_than_a_later_transcription() {
    // The gap the hand-run path concedes: its stamp said when the MINT happened,
    // so a 33-minute-old payload was measured opening a 300-second window. Taken
    // from the result, the two instants collapse — the stamp is within seconds of
    // now rather than of whenever the payload was fetched.
    let repo = repo("mint-read-stamps-the-read");
    completed(&repo, "mcp__Linear__get_issue", READ_RESULT);
    let minted = receipt(&repo, "issue-read.CLOUD-1").expect("minted");
    let stamped: u64 = minted
        .split(' ')
        .nth(2)
        .expect("field three is the clock")
        .parse()
        .expect("the clock is seconds since the epoch");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs();
    assert!(
        now.saturating_sub(stamped) < 60,
        "the receipt records the read, not a transcription: {stamped} vs {now}"
    );
}

#[test]
fn a_failed_or_errored_or_empty_result_mints_nothing() {
    // THE CASE THAT DECIDES THE CHANGE. Three distinct shapes a call that did not
    // succeed actually produces, each asserted rather than one standing in for
    // the others: an error object, a present-but-empty object, and a result the
    // host sent as null. None carries the required projection, and the required
    // projection IS the success predicate here.
    let repo = repo("mint-read-refuses-a-failure");
    for response in [
        r#"{"error":"not found","code":404}"#,
        "{}",
        "null",
        // The half-answer: an id and no revision. `issue-read-check` turns this
        // away BY NAME rather than recording an invented value, and so does this.
        r#"{"id":"CLOUD-1"}"#,
        // And the reverse half, so the conjunction is real rather than a test of
        // `id` alone.
        r#"{"updatedAt":"2026-08-25T04:42:01.650Z"}"#,
    ] {
        completed(&repo, "mcp__Linear__get_issue", response);
        assert!(
            receipt(&repo, "issue-read.CLOUD-1").is_none(),
            "a call that did not succeed must mint nothing; minted from {response}"
        );
    }
}

#[test]
fn a_reconnect_under_another_connector_alias_still_mints() {
    // CLOUD-178's silent miss, on the writing side. One connector was measured
    // exposed under three names across registration episodes, so a mint naming
    // one whole name would stop firing on reconnect and the gate would deny
    // forever with no way to see why.
    let repo = repo("mint-read-survives-an-alias");
    completed(
        &repo,
        "mcp__cc451d34-6c83-4df3-bc3f-13fb7f627544__get_issue",
        READ_RESULT,
    );
    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_some(),
        "the suffix match is what survives the host rotating the server label"
    );
}

#[test]
fn a_write_response_does_not_mint_a_read_receipt() {
    // THE DUCK-TYPING CASE. A write response and a read payload are
    // shape-identical across `id`, `status` and `attachments`, so a mint keyed on
    // field presence would let the later, poorer payload satisfy the gate the
    // write itself is subject to — the row would authorise its own writes.
    // Identification is by TOOL, which is why this response mints nothing despite
    // carrying every required path.
    let repo = repo("mint-read-is-not-duck-typed");
    completed(&repo, "mcp__Linear__save_issue", READ_RESULT);
    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_none(),
        "a write must never mint the receipt that authorises a write"
    );
}

#[test]
fn a_subject_that_is_not_a_safe_component_mints_nothing() {
    // Refused, never rewritten. A rewritten subject would file two different rows
    // under one receipt and let a fresh read of A authorise a stale write to B —
    // precisely the confusion the named keying exists to prevent. The engine's
    // bound is structural (a separator, `.`, `..`, empty, absurdly long) rather
    // than a tracker's identifier shape, which is the consumer's business.
    let repo = repo("mint-read-refuses-a-subject");
    let store = repo.join(".git/batten-receipts");
    for subject in ["../escape", "a/b", "", "."] {
        let encoded = serde_json::to_string(subject).expect("encodable");
        completed(
            &repo,
            "mcp__Linear__get_issue",
            &format!(r#"{{"id":{encoded},"updatedAt":"2026-08-25T04:42:01.650Z"}}"#),
        );
    }
    let minted: Vec<String> = std::fs::read_dir(&store)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("issue-read."))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        minted.is_empty(),
        "an unsafe subject mints nothing rather than a rewritten filename: {minted:?}"
    );
}

#[test]
fn the_body_digest_is_gits_own_and_an_absent_body_records_could_not_look() {
    // The one field with an external contract: `claim-check` compares it against
    // `git hash-object` output, so any other hash is a column that exists and
    // never matches. Cross-checked against git itself rather than against a
    // constant this suite also computes.
    //
    // The `-` half is CLOUD-691's measured forgery: an absent body used to fall
    // through to the empty string, whose digest was a real-looking 40 hex that
    // two bodyless payloads then matched each other on. `-` reads downstream as
    // could-not-look, so sending less makes a later gate louder, never quieter.
    let hashed = repo("mint-read-digest-is-gits");
    completed(&hashed, "mcp__Linear__get_issue", READ_RESULT);
    let minted = receipt(&hashed, "issue-read.CLOUD-1").expect("minted");
    let recorded = minted.split(' ').nth(3).expect("field four is the digest");

    let body = hashed.join("body.txt");
    std::fs::write(&body, "hello\n").expect("write the body git will hash");
    let expected = common::git_in(
        &hashed,
        &["hash-object", body.to_str().expect("a utf-8 path")],
    );
    assert_eq!(
        recorded,
        expected.trim(),
        "the digest must be the one `claim-check` recomputes"
    );

    let absent = repo("mint-read-digest-absent");
    completed(
        &absent,
        "mcp__Linear__get_issue",
        r#"{"id":"CLOUD-2","updatedAt":"2026-08-25T04:42:01.650Z"}"#,
    );
    let bodyless = receipt(&absent, "issue-read.CLOUD-2").expect("minted");
    let fields: Vec<&str> = bodyless.trim().split(' ').collect();
    assert_eq!(
        fields[3], "-",
        "an absent body is could-not-look, never a hash"
    );
    assert_eq!(fields[4], "-", "and so is an absent column");
}

#[test]
fn a_content_block_envelope_mints_exactly_as_a_bare_payload_does() {
    // MEASURED AGAINST THE LIVE HOST, and invisible to every other case here: a
    // connector wraps each response in content blocks, so a reader walking
    // `result.get(...)` directly finds an array with no members it recognises and
    // mints nothing. The bare-object fixtures every case above uses are exactly
    // what hid it — they hand the engine the payload already unwrapped.
    //
    // Asserted as EQUALITY with the unwrapped mint rather than as mere presence,
    // so a decoder that recovers the wrong bytes fails here too.
    let bare = repo("mint-envelope-bare");
    completed(&bare, "mcp__Linear__get_issue", READ_RESULT);
    let expected = receipt(&bare, "issue-read.CLOUD-1").expect("the bare payload mints");

    let wrapped = repo("mint-envelope-wrapped");
    let inner = serde_json::to_string(READ_RESULT).expect("the payload is encodable as text");
    completed(
        &wrapped,
        "mcp__Linear__get_issue",
        &format!(r#"[{{"type":"text","text":{inner}}}]"#),
    );
    let through_envelope = receipt(&wrapped, "issue-read.CLOUD-1")
        .expect("a wrapped payload mints too, or the mechanism is dead in production");

    // Field 3 is the clock and legitimately differs between the two runs; every
    // field the payload decides is compared.
    let fields = |line: &str| -> Vec<String> {
        line.trim()
            .split(' ')
            .enumerate()
            .filter(|(index, _)| *index != 2)
            .map(|(_, field)| field.to_owned())
            .collect()
    };
    assert_eq!(
        fields(&expected),
        fields(&through_envelope),
        "the envelope must decode to the same receipt the bare payload writes"
    );
}

#[test]
fn a_call_mediated_from_a_subdirectory_still_mints_into_the_repository() {
    // THE OTHER LIVE-ONLY DEFECT. `batten hook` is registered once and then
    // mediates calls from wherever the agent is standing, so resolving git
    // against the process CWD passed every fixture — a harness runs the engine AT
    // the repo root — and wrote nothing in production. The anchor falls through
    // to the repository, which is what `capture_response` already relies on and
    // why the capture store kept working while this wrote nothing.
    let repo = repo("mint-from-a-subdirectory");
    let elsewhere = repo.join("crates");
    std::fs::create_dir_all(&elsewhere).expect("a subdirectory to stand in");

    completed(&elsewhere, "mcp__Linear__get_issue", READ_RESULT);

    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_some(),
        "the receipt belongs to the repository, not to whatever directory the call came from"
    );
}

#[test]
fn an_explicitly_null_optional_records_could_not_look_just_as_an_absent_one_does() {
    // The two spellings a tracker uses for "no value" must not diverge: absent
    // and `null` are one answer here, because a caller that projected a field
    // away and one whose row genuinely has none are both saying nothing. Reading
    // `null` as a value would hash the string "null" into the body baseline.
    let repo = repo("mint-read-null-optionals");
    completed(
        &repo,
        "mcp__Linear__get_issue",
        r#"{"id":"CLOUD-1","updatedAt":"2026-08-25T04:42:01.650Z",
            "description":null,"status":null}"#,
    );
    let minted = receipt(&repo, "issue-read.CLOUD-1").expect("minted");
    let fields: Vec<&str> = minted.trim().split(' ').collect();
    assert_eq!(
        fields[3], "-",
        "a null body is could-not-look, never a digest"
    );
    assert_eq!(fields[4], "-", "and a null column is too");
}

#[test]
fn the_receipt_carries_no_title_and_no_body() {
    // Non-negotiable rule 4, on the surface it binds hardest: the receipt
    // outlives the run and is read by a later one, so a byte of the row that
    // leaked here would be a payload nothing can expunge. The body is the
    // richest thing in the result, and the title is the likeliest to look
    // harmless.
    let repo = repo("mint-read-pointer-only");
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    completed(
        &repo,
        "mcp__Linear__get_issue",
        &format!(
            r#"{{"id":"CLOUD-1","updatedAt":"2026-08-25T04:42:01.650Z",
                "title":{encoded},"description":{encoded}}}"#
        ),
    );
    let minted = receipt(&repo, "issue-read.CLOUD-1").expect("minted");
    assert!(
        !minted.contains(secret),
        "neither the title nor the body may reach the receipt: {minted}"
    );
}

#[test]
fn a_second_read_replaces_the_first_rather_than_appending() {
    // `mode = "replace"`, and the distinction decides what the gate reads. This
    // record answers "how old is the NEWEST read", so an append would leave the
    // reader parsing whichever line came first — the stalest — while the freshest
    // sat below it.
    let repo = repo("mint-read-replaces");
    completed(&repo, "mcp__Linear__get_issue", READ_RESULT);
    completed(
        &repo,
        "mcp__Linear__get_issue",
        r#"{"id":"CLOUD-1","updatedAt":"2026-08-26T00:00:00.000Z","status":"Done"}"#,
    );
    let minted = receipt(&repo, "issue-read.CLOUD-1").expect("minted");
    assert_eq!(
        minted.lines().count(),
        1,
        "the freshest read must overwrite the stalest, not queue behind it: {minted}"
    );
    assert!(
        minted.contains("2026-08-26"),
        "and the surviving line is the newer one: {minted}"
    );
}

#[test]
fn a_detached_head_mints_nothing_rather_than_an_unkeyed_receipt() {
    // The branch-keyed half's could-not-look. A detached HEAD has no branch to
    // key on, so there is no honest filename — and inventing one would file this
    // checkout's search under a name a later branch reads as its own, which is a
    // ratchet comparing two different subjects.
    let repo = repo("mint-search-detached");
    let head = common::git_in(&repo, &["rev-parse", "HEAD"]);
    let _ = common::git_in(&repo, &["checkout", "--detach", head.trim()]);

    completed(&repo, "mcp__Linear__list_issues", SEARCH_RESULT);

    let store = repo.join(".git/batten-receipts");
    let minted: Vec<String> = std::fs::read_dir(&store)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("issue-search."))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        minted.is_empty(),
        "a detached HEAD names no branch, so it mints nothing: {minted:?}"
    );
}

/// The measured `list_issues` result shape: a flat object, not a nested page.
const SEARCH_RESULT: &str = r#"{"issues":[{"id":"CLOUD-1"},{"id":"CLOUD-2"}],
    "hasNextPage":true,"cursor":"abc"}"#;

#[test]
fn a_search_result_mints_with_its_base_line() {
    // WITHOUT THE BASE LINE THIS ROW IS SILENTLY UN-PASSABLE, not merely weak:
    // `branch_validity` voids a branch-keyed receipt that cannot say what
    // `origin/main` it was taken against (CLOUD-516), because a branch name
    // outlives the branch it described. So the line is asserted, and then the
    // gate it feeds is asserted through it.
    let repo = repo("mint-search-records-its-base");
    let create = r#"{"title":"a finding"}"#;
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", create),
        Some(2),
        "filing is denied before anything has searched"
    );

    completed(&repo, "mcp__Linear__list_issues", SEARCH_RESULT);

    let branch = common::git_in(&repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let minted = receipt(&repo, &format!("issue-search.{}", branch.trim()))
        .expect("the search minted its own receipt");
    assert!(
        minted.starts_with("CLOUD-1 CLOUD-2\n"),
        "the ids seen, pointer-only: {minted}"
    );
    assert!(
        minted.contains("\nbase "),
        "and the base it was taken against: {minted}"
    );

    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", create),
        Some(0),
        "searching over the connector is now sufficient to authorise the filing"
    );
}

#[test]
fn a_zero_hit_search_still_mints_and_a_read_payload_never_does() {
    // The load-bearing allow: zero hits is the commonest honest outcome of
    // looking before filing something genuinely new, so refusing it would make
    // the gate punish exactly the behaviour it exists to produce.
    let zero_hits = repo("mint-search-zero-hits");
    completed(
        &zero_hits,
        "mcp__Linear__list_issues",
        r#"{"issues":[],"hasNextPage":false}"#,
    );
    let branch = common::git_in(&zero_hits, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let name = format!("issue-search.{}", branch.trim());
    assert!(
        receipt(&zero_hits, &name).is_some(),
        "a search returning nothing is still a search"
    );

    // And the discriminator in the other direction: the page key is what a
    // single-row read does not carry, so a read can never mint a search receipt
    // even though it is the same connector.
    let from_a_read = repo("mint-search-not-from-a-read");
    completed(&from_a_read, "mcp__Linear__list_issues", READ_RESULT);
    assert!(
        receipt(&from_a_read, &name).is_none(),
        "a payload with no page key is not a search result"
    );
}

// ---------------------------------------------------------------------------
// THE INTERCEPTED READ (CLOUD-1147).
//
// A host may refuse to hand over a large tool result, write the bytes to a file
// and substitute a plain-text notice naming it. The notice is prose, so
// `payload_in` cannot parse it and every mint over that call was skipped —
// silently, because a mint's failure is silent by design. Three rows became
// permanently un-updatable that way, each refused with a remedy ("re-read the
// row") that is the operation that fails, and fails BECAUSE the row is large.
//
// Measured 2026-09-01 on the live host: the envelope's `result` is a STRING
// naming an absolute path, and that file holds the complete payload. The bytes
// were never gone; nothing looked.
//
// The negatives below are the load-bearing half. A recovery that fired on a
// notice naming nothing, or on a file that is not a payload, would forge a
// receipt for a read that did not happen — worse than the starvation it fixes,
// and CLOUD-691's recorded class.
// ---------------------------------------------------------------------------

/// The host's notice, in the shape it actually arrives: a sentence naming the
/// file, then the guidance lines that follow it.
fn interception_notice(path: &Path) -> String {
    serde_json::to_string(&format!(
        "Error: result (71,501 characters across 1 line) exceeds maximum allowed \
         tokens. Output has been saved to {}.\nFormat: Plain text\nUse offset and \
         limit parameters to read specific portions of the file.",
        path.display()
    ))
    .expect("a notice is encodable")
}

#[test]
fn an_intercepted_read_recovers_the_spilled_payload_and_mints() {
    let repo = repo("mint-recovers-an-intercepted-read");
    let update = r#"{"id":"CLOUD-1","description":"groomed"}"#;
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(2),
        "the gate denies before anything has read the row"
    );

    // The spill lives OUTSIDE the repository, as the host's own does.
    let spill = common::scratch("mint-spill").join("result.txt");
    std::fs::create_dir_all(spill.parent().expect("a parent")).expect("spill dir");
    std::fs::write(&spill, READ_RESULT).expect("the host wrote the real bytes");

    completed(
        &repo,
        "mcp__Linear__get_issue",
        &interception_notice(&spill),
    );

    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_some(),
        "the payload the host spilled is the payload the server returned, so the \
         receipt it mints attests a read that really happened"
    );
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", update),
        Some(0),
        "and the row is updatable again — the whole point of CLOUD-1147"
    );
}

/// ANTI-VACUITY, and the case that separates a recovery from a forgery: a notice
/// naming a file that is not there mints nothing.
///
/// Without this, the case above is satisfied by a change that mints on any
/// unparseable result, which is precisely the forgery CLOUD-691 records.
#[test]
fn a_notice_naming_a_file_that_is_not_there_mints_nothing() {
    let repo = repo("mint-spill-absent");
    let missing = common::scratch("mint-spill-absent-target").join("gone.txt");
    completed(
        &repo,
        "mcp__Linear__get_issue",
        &interception_notice(&missing),
    );
    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_none(),
        "nothing was read, so nothing may be attested"
    );
}

/// A spilled file that is not a payload mints nothing either — the recovered
/// value goes through the same decode and the same `requires` as any other, so
/// this is the ordinary no-mint path rather than a second rule.
#[test]
fn a_spilled_file_that_is_not_a_payload_mints_nothing() {
    let repo = repo("mint-spill-not-a-payload");
    let spill = common::scratch("mint-spill-garbage").join("result.txt");
    std::fs::create_dir_all(spill.parent().expect("a parent")).expect("spill dir");
    std::fs::write(&spill, "this is not json").expect("write garbage");
    completed(
        &repo,
        "mcp__Linear__get_issue",
        &interception_notice(&spill),
    );
    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_none(),
        "a file that carries no payload is not a read"
    );
}

/// THE ABSOLUTENESS BOUND, pinned on every platform rather than on the one whose
/// spelling the predicate happened to carry.
///
/// A relative path resolves against whatever directory the hook is running in,
/// which is not a thing the notice can have meant — so it recovers nothing even
/// when a file of that name is sitting right there. This case exists because the
/// bound was first written as `starts_with('/')`, which is the Unix spelling of
/// the question rather than the question: `D:\a\_temp\result.txt` failed it, so
/// the recovery was dead on Windows while the positive case above passed green on
/// Linux. Asking `Path::is_absolute` answers it on both, and this is the arm that
/// stays red if the bound is dropped altogether on either.
#[test]
fn a_notice_naming_a_relative_path_recovers_nothing() {
    let repo = repo("mint-spill-relative");
    let spill = repo.join("result.txt");
    std::fs::write(&spill, READ_RESULT).expect("a real payload, in the wrong kind of place");
    completed(
        &repo,
        "mcp__Linear__get_issue",
        &interception_notice(Path::new("result.txt")),
    );
    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_none(),
        "a relative path names no file the notice can have meant, whatever is at it"
    );
}

/// An ordinary unparseable string is untouched. The recovery is keyed on a host
/// naming a path in its own notice, so a tool that simply answered with prose
/// still mints nothing — this is not a blanket amnesty for failed decodes.
#[test]
fn an_unparseable_result_that_names_no_path_is_unchanged() {
    let repo = repo("mint-no-path-in-notice");
    completed(
        &repo,
        "mcp__Linear__get_issue",
        "\"Error: something went wrong and no file was written\"",
    );
    assert!(
        receipt(&repo, "issue-read.CLOUD-1").is_none(),
        "no path, no recovery, no receipt"
    );
}
