//! A `delta`-keyed receipt is filed under the identity of the branch's CHANGE,
//! and read back under the same one (CLOUD-1547).
//!
//! # Why this tier, and why a unit test over `delta_subject` would prove nothing
//!
//! Stated because the temptation is real: `delta_subject` is a short function and
//! a unit test over it would assert that a filename contains whatever
//! `branch_patch_id` returned. That is not the question. The question is whether
//! the WRITE half and the READ half resolve the SAME subject — the mint files a
//! receipt at the mediated boundary and the receipt row looks one up there, and a
//! defect in either would leave a gate that loads clean and decides nothing.
//! `fact_record_keying.rs` is this suite's sibling for that reason and this one
//! follows its shape: nothing here writes a receipt by hand and nothing inspects
//! a path to decide a case. Every verdict comes from a real `adjudicate` call.
//!
//! # The three properties, and why each needs its own case
//!
//! * **The receipt is found.** A change with a receipt filed under its identity
//!   is allowed. Without this the suite could pass over an engine that refused
//!   everything.
//! * **A rebase does not re-owe it.** This is the whole reason the keying exists.
//!   `land` rebases every lap, and a keying that moved with the rebase would buy
//!   a model call per lap — the cost that gets a gate switched off rather than
//!   satisfied. A `head`-keyed receipt fails this case, which is what makes it
//!   discriminating rather than decorative.
//! * **A content change DOES re-owe it.** The other direction, and the one that
//!   makes the gate worth having: without it a branch reviewed once could push
//!   anything. A `branch`-keyed receipt fails this case.
//!
//! The last two are an anti-vacuity pair in the strict sense — no single keying
//! satisfies both, so a suite carrying only one of them is silently satisfied by
//! the wrong column. That is `fact_record_keying.rs`'s own lesson, one keying
//! over.
//!
//! # The push arm is exercised here and NOT declared in `batten.toml`
//!
//! Worth stating, because a reader who checks the committed config will find one
//! row and two arms here and reasonably suspect drift.
//!
//! The keying is not pattern-specific — a `receipt` row selects on a command and
//! resolves the same subject whichever command that is — and the push arm is what
//! shows that, over this file's own config. What this repository declares is only
//! the ready row, because a committed `push-needs-review` fires on EVERY push:
//! measured over the suite, it denied `forced_push.rs`'s benign fixture push, and
//! 15 test files drive a push that has nothing to do with review. What it wants
//! to refuse is a push to a branch whose PR is already READY, and `forge.rs`
//! carries no draft field, so that narrowing is unsayable today (CLOUD-1446 for
//! the gap, CLOUD-1548 for where it closes).
//!
//! So the arm here proves the mechanism generalises; it does not claim the
//! repository is frozen against a mid-ready push. It is not.

// UNIX-ONLY, for `fact_record_keying.rs`' reason: every case drives real `git`
// against a scratch repository, and a fixture that failed to build would leave
// the receipt absent — which is what the negative arms refuse, so they would pass
// FOR THE WRONG REASON while the allow cases failed.
#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{git_in, run_with_stdin, scratch, stdout, write};

const RECEIPT: &str = "code-review";
const CODE: &str = "crates/batten/src/lib.rs";

/// A fixture carrying both committed rows, keyed as the committed config keys
/// them.
///
/// `key` varies ONLY where a case is establishing that the alternative keyings
/// fail — the discrimination the module doc calls an anti-vacuity pair. Every
/// other case takes the committed `delta`.
fn fixture(name: &str, key: &str) -> PathBuf {
    let dir = scratch(name);
    // `key_base` is refused on any keying but `delta` (`Rule::validate_delta_base`),
    // so the alternative-keying fixtures must omit it — which is the load-time
    // half of the same pair these cases exercise at adjudication.
    let base = if key == "delta" {
        "key_base = \"refs/remotes/origin/main\"\n"
    } else {
        ""
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n\n\
             [[rule]]\nid = \"push-needs-review\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"git push\"\n\
             checks = [\"{RECEIPT}\"]\nkey = \"{key}\"\n{base}\
             reason = \"dispatch the code-review skill\"\n\n\
             [[rule]]\nid = \"ready-needs-review\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr ready\"\n\
             checks = [\"{RECEIPT}\"]\nkey = \"{key}\"\n{base}\
             reason = \"dispatch the code-review skill\"\n"
        ),
    );
    // `git_in` blanks global and system config for CLOUD-282's reason: a
    // contributor's own git settings must not change a verdict here.
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "README.md", "base\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    // The base ref the rows name. A real remote is not needed and would be a
    // network dependency in a gate; what the identity reads is a REF, and a local
    // one resolves identically.
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// Commit a code change, so the branch has an identity at all.
fn change(dir: &Path, body: &str) {
    let path = dir.join(CODE);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the source dir");
    std::fs::write(&path, body).expect("the source");
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "change"]);
}

/// The identity the ENGINE resolves — never one this file computes, or the cases
/// would agree with themselves rather than with the gate.
fn identity(dir: &Path) -> String {
    batten::git::branch_patch_id(dir, "refs/remotes/origin/main")
        .expect("the repository opens")
        .expect("a branch that changed something has an identity")
}

/// File a receipt under `subject`, in the store both halves read.
///
/// Written directly rather than through a `[[mint]]` envelope BECAUSE the mint's
/// own tier already drives that path: what is under test here is the READ side
/// resolving the same subject, and routing through the writer would make a
/// failure ambiguous between the two halves.
fn file_receipt(dir: &Path, subject: &str) {
    let store = dir.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store");
    std::fs::write(store.join(format!("{RECEIPT}.{subject}")), "deadbeef 0\n")
        .expect("write the receipt");
}

fn call(dir: &Path, command: &str) -> Output {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &envelope.to_string(),
    )
}

fn push(dir: &Path) -> Output {
    call(dir, "git push -u origin HEAD")
}

fn ready(dir: &Path) -> Output {
    call(dir, "gh pr ready 999")
}

/// BOTH HELPERS ASSERT THE EXIT STATUS, for `fact_record_keying.rs`' measured
/// reason: the hook prints nothing on an allow and exits 0 either way, so a
/// substring check over an empty string is true — including the empty output of a
/// binary that died before it judged anything.
fn denied(output: &Output) -> String {
    let text = stdout(output);
    assert_eq!(output.status.code(), Some(0), "the hook itself ran: {text}");
    assert!(
        text.contains("\"permissionDecision\":\"deny\""),
        "expected a deny: {text}"
    );
    text
}

fn allowed(output: &Output) {
    let text = stdout(output);
    assert_eq!(output.status.code(), Some(0), "the hook itself ran: {text}");
    assert!(!text.contains("\"deny\""), "expected an allow: {text}");
}

// ---------------------------------------------------------------------------
// THE SUBJECT SEAM: the write and the read resolve one identity.
// ---------------------------------------------------------------------------

/// A change with a receipt under its identity is allowed, and one without is not.
///
/// The pair, in one case, because either alone is satisfied by a broken engine:
/// an engine that never resolved a subject would refuse both, and one that
/// ignored the receipt store would allow both. Declared mutation:
/// `delta-receipt-unread`.
#[test]
fn a_receipt_under_this_change_answers_and_nothing_else_does() {
    let dir = fixture("review-delta-subject", "delta");
    change(&dir, "fn a() {}\n");

    denied(&ready(&dir));
    file_receipt(&dir, &identity(&dir));
    allowed(&ready(&dir));
}

/// A receipt filed under some OTHER identity does not answer.
///
/// The forgery control: without it the row would be satisfied by any receipt in
/// the store, which is `ReceiptKey::Branch` wearing a subject.
#[test]
fn a_receipt_over_another_change_does_not_answer() {
    let dir = fixture("review-delta-other", "delta");
    change(&dir, "fn a() {}\n");
    file_receipt(&dir, "0000000000000000000000000000000000000000");

    let text = denied(&ready(&dir));
    assert!(text.contains("receipt read missing"), "{text}");
}

// ---------------------------------------------------------------------------
// THE ANTI-VACUITY PAIR: no other keying satisfies both of these.
// ---------------------------------------------------------------------------

/// A REBASE THAT CHANGES NO CONTENT DOES NOT RE-OWE THE REVIEW.
///
/// The property the whole keying exists for. `land` rebases every lap, so a
/// keying that moved here would buy a model call per lap — the cost that gets a
/// gate switched off rather than satisfied. A `head`-keyed receipt fails this
/// case, which is what makes it discriminating. Declared mutation:
/// `rebase-repriced`.
#[test]
fn a_rebase_that_changes_no_content_still_answers() {
    let dir = fixture("review-delta-rebase", "delta");
    change(&dir, "fn a() {}\n");
    file_receipt(&dir, &identity(&dir));
    allowed(&ready(&dir));

    // Advance the base and replay onto it. The tree the branch produces is
    // unchanged, so the merge-base diff — and therefore the identity — is too,
    // while every commit SHA on the branch is new.
    let before = common::git_in(&dir, &["rev-parse", "HEAD"]);
    git_in(
        &dir,
        &["checkout", "-q", "-b", "trunk", "refs/remotes/origin/main"],
    );
    write(&dir, "UNRELATED.md", "moved\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "trunk moves"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(&dir, &["checkout", "-q", "main"]);
    git_in(&dir, &["rebase", "-q", "refs/remotes/origin/main"]);
    let after = common::git_in(&dir, &["rev-parse", "HEAD"]);

    assert_ne!(
        before.trim(),
        after.trim(),
        "the rebase must actually move HEAD, or this case asserts nothing"
    );
    allowed(&ready(&dir));
}

/// A CONTENT CHANGE DOES RE-OWE IT.
///
/// The other direction, and the one that makes the gate worth having: without it
/// a branch reviewed once could push anything afterwards. A `branch`-keyed
/// receipt fails this case.
#[test]
fn one_further_code_change_re_owes_the_review() {
    let dir = fixture("review-delta-moved", "delta");
    change(&dir, "fn a() {}\n");
    file_receipt(&dir, &identity(&dir));
    allowed(&ready(&dir));

    change(&dir, "fn a() {}\nfn b() {}\n");
    denied(&ready(&dir));
}

// ---------------------------------------------------------------------------
// THE FREEZE INVARIANT: the push arm is what makes the ready arm sound.
// ---------------------------------------------------------------------------

/// THE KEYING IS NOT PATTERN-SPECIFIC: the same receipt answers at a push.
///
/// Over THIS FILE's config, not the committed one — see the module header for why
/// the repository declares only the ready row. What this establishes is that a
/// consumer who can narrow the push (a declared loop that knows the PR is ready)
/// gets the freeze from the same mechanism, with no second keying.
/// Declared mutation: `push-ungated`.
#[test]
fn a_push_carrying_an_unreviewed_change_is_refused() {
    let dir = fixture("review-delta-push", "delta");
    change(&dir, "fn a() {}\n");

    denied(&push(&dir));
    file_receipt(&dir, &identity(&dir));
    allowed(&push(&dir));

    // And what the freeze would buy a consumer who declares it: once reviewed,
    // a further change cannot reach the remote without its own review.
    change(&dir, "fn a() {}\nfn b() {}\n");
    denied(&push(&dir));
}

// ---------------------------------------------------------------------------
// COULD-NOT-LOOK IS A REFUSAL HERE, DELIBERATELY.
// ---------------------------------------------------------------------------

/// A BRANCH WITH NO IDENTITY IS REFUSED RATHER THAN WAVED THROUGH.
///
/// The opposite of what the `branch` and `named` arms do, and the deliberate
/// half. An unresolvable base or an empty diff means there is no change to have
/// reviewed; answering could-not-look would ALLOW, so a branch whose base does
/// not resolve could push anything. Refusing is loud and cheap to clear.
#[test]
fn a_branch_with_no_change_at_all_is_refused_rather_than_allowed() {
    let dir = fixture("review-delta-empty", "delta");
    // No `change` call: the branch sits at the base, so the merge-base diff is
    // empty and `branch_patch_id` mints no identity.
    denied(&ready(&dir));
}
