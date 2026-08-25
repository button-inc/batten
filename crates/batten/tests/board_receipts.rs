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
// carried: "all three live connector spellings are gated identically" crates/batten/tests/board_receipts.rs
// carried: "a tool that does not create an issue is never gated" crates/batten/tests/board_receipts.rs
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
// changed: "issue-search-guard.bats::creating an issue with a receipt is allowed" crates/batten/tests/board_receipts.rs the engine additionally requires the receipt to record the `origin/main` it was taken against (CLOUD-516); a bare-`git init` fixture has no such ref, so the receipt says `base -` and reads as unproven. Carried in `filing_without_a_search_is_refused_and_with_one_is_allowed`, which mints the base line
// changed: "issue-search-guard.bats::the CLOUD-504 over CLOUD-499 filing is refused, and allowed after the search" crates/batten/tests/board_receipts.rs same cause, same successor shape: the deny half replays, and the allow half needs a base line the fixture's repository cannot produce. Carried in `the_measured_duplicate_is_refused_and_then_allowed`
// changed: "issue-search-guard.bats::the bypass is honoured" crates/batten/tests/guardrail_bypass.rs BATTEN_ISSUE_SEARCH_BYPASS is gone; a mediated deny takes the engine's own hatch, which is the same consolidation CLOUD-442 and CLOUD-444 made when memory-guard and claim-guard retired
// changed: "issue-search-guard.bats::updating an existing issue is never gated, receipt or not" crates/batten/tests/board_receipts.rs the arm was true of row 1 alone and is now false of the config: row 2 below gates exactly that call on a RECENT read (CLOUD-508). The two rows are complements over one tool — `when_absent` and `when_present` on the same `input-id` — so this case's allow survives only where row 2 cannot key the subject, and `an_update_with_no_receipt_is_refused` is where the new answer is asserted
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
// carried: "issue-read-guard.bats::an update with no receipt is denied, and the denial names the fix" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::an update from a fresh read is allowed" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::a fresh read of one issue does not authorise an update to a different one" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::creating an issue is never gated here, receipt or not" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::all three live connector spellings are gated identically" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::a tool that does not save an issue is never gated" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::an id that is not an issue key fails open rather than denying" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::the denial carries no payload content" crates/batten/tests/board_receipts.rs
// carried: "issue-read-guard.bats::a receipt minted from the declared field set alone authorises the update" crates/batten/tests/board_receipts.rs
//!
//! SUBSUMED — the plumbing became the engine's, and one seam became the surviving
//! half's own suite.
//!
// subsumed: "issue-read-guard.bats::an unreadable or nameless payload fails open" crates/batten/tests/cli.rs
// subsumed: "issue-read-guard.bats::a payload too thin to mint a receipt leaves the update denied" crates/batten/tests/board_receipts.rs
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
// changed: "issue-read-guard.bats::an update from a read older than the bound is denied" crates/batten/tests/board_receipts.rs the age is the receipt file's mtime, not a parsed field, so the suite's field-3 arithmetic backdates nothing for the engine; the property is carried in `a_read_older_than_the_bound_is_refused`, which backdates the mtime
// changed: "issue-read-guard.bats::a malformed receipt fails open rather than denying" crates/batten/tests/board_receipts.rs the engine parses no field of the receipt, so there is no malformed state to fail open on — `named_validity` answers existence and `max_age` reads the mtime, which is a narrower reader than the one that could half-read a line
// changed: "issue-read-guard.bats::a receipt stamped in the future fails open rather than authorising" crates/batten/tests/board_receipts.rs same cause: a stamp is not read at all. A clock that moved shows up as a future mtime, which `older_than` reports as not-older and so still allows — the same direction, reached without parsing
// changed: "issue-read-guard.bats::the bound is configurable, and honoured in both directions" crates/batten/tests/board_receipts.rs BATTEN_ISSUE_READ_MAX_AGE is gone: the bound is `max_age` on the row (CLOUD-988), so it is configured where every other property of the row is and a reader finds it without knowing an env var's name. Per-call override is deliberately not carried — an agent that can widen the bound at the call it is being gated on is not gated
// changed: "issue-read-guard.bats::the bypass is honoured" crates/batten/tests/guardrail_bypass.rs BATTEN_ISSUE_READ_BYPASS is gone; a mediated deny takes the engine's own hatch, the same consolidation row 1 records one section up
//!
//! ─── CLOUD-909's REPLAY, row 2 ───────────────────────────────────────────────
//!
// replay-call: tests/issue-read-guard.bats 1dbad05 mise-tasks/issue-read-guard.sh an-update-owes-a-recent-read deny=2 allow=0

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
    // THE REFUSING ROW IS READ FROM THE PREFIX, not by searching the whole
    // refusal for a row id. Measured: a bare `contains("filing-needs-a-search")`
    // fails here, because row 2's own reason ENDS by naming row 1 — "Creating an
    // issue is never gated by this row (that is `filing-needs-a-search`)" — which
    // is exactly the cross-reference the two complements should carry. A substring
    // test over a refusal cannot tell a row that spoke from a row it pointed at;
    // `Refused by <id>` is the engine's own attribution and can.
    assert!(
        !text.contains("Refused by filing-needs-a-search"),
        "an update names an id, so the row that gates FILING must stay silent: {text}"
    );
    assert!(
        text.contains("Refused by an-update-owes-a-recent-read"),
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
    assert!(
        text.contains("issue-read-check"),
        "and the command that mints the receipt, which is the fix: {text}"
    );
    // THE VERDICT WORDING FOR `ReceiptKey::Named`, pinned because it was missing:
    // `receipt_refusal` had arms for `Branch` and for the commit-keyed default,
    // and a subject-keyed row fell through to the commit one — telling the reader
    // to re-run a per-commit step when what is absent is a read of one row. Found
    // by this row, the key's first consumer.
    assert!(
        text.contains("no `issue-read` receipt for the row this call names"),
        "the verdict must name what is missing in this row's own terms: {text}"
    );
    assert!(
        !text.contains("this branch carries no"),
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
