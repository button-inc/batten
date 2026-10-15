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

use common::{dispatch_skill as dispatch, git_in, run_with_stdin, stdout, write};

const RECEIPT: &str = "code-review";
const CODE: &str = "crates/batten/src/lib.rs";

/// A fixture carrying both committed rows, keyed as the committed config keys
/// them.
///
/// `key` varies ONLY where a case is establishing that the alternative keyings
/// fail — the discrimination the module doc calls an anti-vacuity pair. Every
/// other case takes the committed `delta`.
fn fixture(name: &str, key: &str) -> PathBuf {
    // `key_base` is refused on any keying but `delta` (`Rule::validate_delta_base`),
    // so the alternative-keying fixtures must omit it — which is the load-time
    // half of the same pair these cases exercise at adjudication.
    let base = if key == "delta" {
        "key_base = \"refs/remotes/origin/main\"\n"
    } else {
        ""
    };
    // THROUGH `common::Fixture`, never a hand-rolled `git init` chain: the builder
    // copies a template rather than forking `git init` (CLOUD-1419 measured 1,819
    // init processes over one run from exactly that habit), and `test fix duplicate`
    // refuses a new copy of it. `base_commit` also pins `refs/remotes/origin/main`,
    // which is the ref these rows name — no remote is needed, because what the
    // identity reads is a REF and a local one resolves identically.
    common::Fixture::new(name)
        .config(&format!(
            "version = 1\n\n\
             [[rule]]\nid = \"push-needs-review\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"git push\"\n\
             checks = [\"{RECEIPT}\"]\nkey = \"{key}\"\n{base}\
             reason = \"dispatch the code-review skill\"\n\n\
             [[rule]]\nid = \"review ask missing\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr ready\"\n\
             checks = [\"{RECEIPT}\"]\nkey = \"{key}\"\n{base}\
             reason = \"dispatch the code-review skill\"\n"
        ))
        .file("README.md", "base\n")
        .git()
        .base_commit()
        .build()
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

/// THE IDENTITY IS RESOLVED AGAINST THE REPO ROOT, NOT THE CWD.
///
/// `batten hook` runs with whatever cwd the harness had, which is routinely a
/// subdirectory. Resolving the patch id from `"."` opens a different repository
/// or none, yields no identity, and — because an absent identity is `Missing`
/// rather than could-not-look here — refuses EVERY call whatever receipt is on
/// disk. Every other case in this file runs at the root and so cannot see it;
/// this one is the whole reason the read side takes `RepoFacts` like its
/// siblings. Declared mutation: `subject-read-from-cwd`.
#[test]
fn the_identity_is_resolved_from_the_repo_root_and_not_the_cwd() {
    let dir = fixture("review-delta-subdir", "delta");
    change(&dir, "fn a() {}\n");
    file_receipt(&dir, &identity(&dir));

    // The receipt answers at the root, so the fixture is sound before the arm
    // that matters runs — otherwise a refusal below would be unattributable.
    allowed(&ready(&dir));

    let nested = dir.join("crates/batten/src");
    assert!(nested.is_dir(), "the change created the nested path");
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "gh pr ready 999"},
    });
    allowed(&run_with_stdin(
        &nested,
        &["adjudicate", "--harness", "claude-code"],
        &envelope.to_string(),
    ));
}

// ---------------------------------------------------------------------------
// DISPATCH IS NOT COMPLETION (CLOUD-2261): the receipt the gate reads is minted
// by the call the review ENDS with, and only over a change it was asked about.
// ---------------------------------------------------------------------------

/// The committed shape: the `Skill` dispatch mints a `code-review-dispatched`
/// record, and the review's closing `ReportFindings` call mints the receipt the
/// ready row reads, `after` that record. Every receipt below is written by the
/// engine through `adjudicate`; nothing here files one by hand.
fn minting_fixture(name: &str) -> PathBuf {
    common::Fixture::new(name)
        .config(&format!(
            "version = 1\n\n\
             [[mint]]\nname = \"{RECEIPT}-dispatched\"\ntool = \"Skill\"\n\
             selects_at = \"skill\"\nselects = \"{RECEIPT}\"\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\nmode = \"replace\"\n\
             body = \"{{git:HEAD}} {{now}}\"\n\n\
             [[mint]]\nname = \"{RECEIPT}\"\ntool = \"ReportFindings\"\n\
             after = \"{RECEIPT}-dispatched\"\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\nmode = \"replace\"\n\
             body = \"{{git:HEAD}} {{now}}\"\n\n\
             [[rule]]\nid = \"review ask missing\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr ready\"\n\
             checks = [\"{RECEIPT}\"]\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\n\
             reason = \"run the code-review skill to completion\"\n"
        ))
        .file("README.md", "base\n")
        .git()
        .base_commit()
        .build()
}

/// The review's closing call, with nothing surviving verification.
fn complete(dir: &Path) {
    common::post_tool(
        dir,
        "ReportFindings",
        &serde_json::json!({"findings": [], "level": "high"}),
        &serde_json::json!("Reported 0 findings"),
    );
}

/// A DISPATCH ALONE DOES NOT ANSWER, and the completion after it does.
///
/// The gap the dispatch-minted receipt left: the ask over these bytes was
/// provable, the finish was not, so `gh pr ready` went through over a review
/// nobody completed.
#[test]
fn a_dispatched_review_answers_only_once_it_completes() {
    let dir = minting_fixture("review-completion");
    change(&dir, "fn a() {}\n");

    dispatch(&dir, RECEIPT);
    denied(&ready(&dir));
    assert_ne!(
        status(&dir, RECEIPT).status.code(),
        Some(0),
        "dispatched, not completed"
    );
    // The record the completion must spend, located before it is spent, so the
    // absence asserted below is not about a path nothing ever wrote.
    let dispatched = dir
        .join(".git/batten-receipts")
        .join(format!("{RECEIPT}-dispatched.{}", identity(&dir)));
    assert!(dispatched.exists(), "the dispatch minted its record");
    complete(&dir);
    allowed(&ready(&dir));
    let answered = status(&dir, RECEIPT);
    assert_eq!(answered.status.code(), Some(0), "{}", stdout(&answered));

    // The dispatch is spent by the completion it admitted, so it cannot answer
    // a second one. Declared mutation: `dispatch-not-spent`.
    assert!(
        !dispatched.exists(),
        "the dispatch record outlived its completion"
    );
}

/// A PREREQUISITE IS WHAT AN EARLIER CALL LEFT, never what this call just wrote
/// (CLOUD-2261). Here the writer and its dependent select the same dispatch,
/// so one call writes the prerequisite and, read live, would satisfy the
/// dependent too. Declared mutation: `prerequisite-read-live`.
#[test]
fn one_call_cannot_satisfy_its_own_prerequisite() {
    let dir = common::Fixture::new("review-completion-same-call")
        .config(&format!(
            "version = 1\n\n\
             [[mint]]\nname = \"{RECEIPT}-dispatched\"\ntool = \"Skill\"\n\
             selects_at = \"skill\"\nselects = \"{RECEIPT}\"\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\nmode = \"replace\"\n\
             body = \"{{now}}\"\n\n\
             [[mint]]\nname = \"{RECEIPT}\"\ntool = \"Skill\"\n\
             selects_at = \"skill\"\nselects = \"{RECEIPT}\"\n\
             after = \"{RECEIPT}-dispatched\"\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\nmode = \"replace\"\n\
             body = \"{{now}}\"\n"
        ))
        .file("README.md", "base\n")
        .git()
        .base_commit()
        .build();
    change(&dir, "fn a() {}\n");

    dispatch(&dir, RECEIPT);
    assert_ne!(
        status(&dir, RECEIPT).status.code(),
        Some(0),
        "one dispatch minted its own completion"
    );
    // Nor a later dispatch, whose prerequisite an earlier call DID leave: this
    // call rewrites it, so it is still this call's own.
    dispatch(&dir, RECEIPT);
    assert_ne!(
        status(&dir, RECEIPT).status.code(),
        Some(0),
        "a second dispatch spent the record it had just rewritten"
    );
}

/// THE ORDER ROWS ARE DECLARED IN DECIDES NOTHING (CLOUD-2261). Here the
/// dependent is declared before its writer, both on the same dispatch: on the
/// second call an earlier record IS on file, and a dependent run first would
/// claim it before this call's writer marked it as this call's own. Declared
/// mutation: `dependent-before-writer`.
#[test]
fn a_dependent_declared_first_still_waits_for_its_writer() {
    let dir = common::Fixture::new("review-completion-order")
        .config(&format!(
            "version = 1\n\n\
             [[mint]]\nname = \"{RECEIPT}\"\ntool = \"Skill\"\n\
             selects_at = \"skill\"\nselects = \"{RECEIPT}\"\n\
             after = \"{RECEIPT}-dispatched\"\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\nmode = \"replace\"\n\
             body = \"{{now}}\"\n\n\
             [[mint]]\nname = \"{RECEIPT}-dispatched\"\ntool = \"Skill\"\n\
             selects_at = \"skill\"\nselects = \"{RECEIPT}\"\nkey = \"delta\"\n\
             key_base = \"refs/remotes/origin/main\"\nmode = \"replace\"\n\
             body = \"{{now}}\"\n"
        ))
        .file("README.md", "base\n")
        .git()
        .base_commit()
        .build();
    change(&dir, "fn a() {}\n");

    dispatch(&dir, RECEIPT);
    dispatch(&dir, RECEIPT);
    assert_ne!(
        status(&dir, RECEIPT).status.code(),
        Some(0),
        "a dependent declared first spent the dispatch an earlier call left"
    );
}

/// A BASE THAT DOES NOT RESOLVE IS THE CHECKOUT'S PROBLEM, NOT A VERDICT
/// (CLOUD-2260). Reading it as `missing` would hand the caller a remedy, review
/// again, that can never clear it. Declared mutation: `delta-base-unchecked`.
#[test]
fn an_unresolvable_base_is_refused_rather_than_read_missing() {
    let dir = minting_fixture("review-status-bad-base");
    change(&dir, "fn a() {}\n");
    let output = run_with_stdin(
        &dir,
        &[
            "receipt",
            "status",
            RECEIPT,
            "--key",
            "delta",
            "--base",
            "refs/remotes/origin/no-such-branch",
        ],
        "",
    );
    let text = stdout(&output);
    let refusal = common::stderr(&output);
    assert_ne!(output.status.code(), Some(0), "{text}{refusal}");
    assert!(text.is_empty(), "a verdict was printed: {text}");
    assert!(
        refusal.contains("--base") && refusal.contains("does not resolve"),
        "the refusal names the base: {refusal}"
    );
}

/// The question `land` asks before it readies (CLOUD-2260): the same receipt,
/// read through the verb rather than the hook.
fn status(dir: &Path, check: &str) -> Output {
    run_with_stdin(
        dir,
        &[
            "receipt",
            "status",
            check,
            "--key",
            "delta",
            "--base",
            "refs/remotes/origin/main",
        ],
        "",
    )
}

/// A COMPLETION NAMES NO CHANGE, so without a dispatch of THIS change on file it
/// mints nothing — neither with no dispatch at all, nor with one taken over an
/// earlier change, nor with one of another skill. Declared mutation:
/// `completion-ignores-dispatch`.
#[test]
fn a_completion_without_a_dispatch_of_this_change_mints_nothing() {
    let dir = minting_fixture("review-completion-orphan");
    change(&dir, "fn a() {}\n");

    complete(&dir);
    denied(&ready(&dir));

    dispatch(&dir, "batten");
    complete(&dir);
    denied(&ready(&dir));

    // Asked over one change, finished over another: the commit between them
    // moved the key, so the earlier ask no longer answers.
    dispatch(&dir, RECEIPT);
    change(&dir, "fn a() {}\nfn b() {}\n");
    complete(&dir);
    denied(&ready(&dir));
}

// ---------------------------------------------------------------------------
// READYING OWES ALL THREE (CLOUD-2293), over the COMMITTED rows: a fixture
// restating them would pass on a `main` that checks `code-review` alone.
// ---------------------------------------------------------------------------

/// The three skills readying owes, in the order the committed row declares them.
const OWED: [&str; 3] = ["simplify", "security-review", "code-review"];

/// The committed `[[mint]]` rows for [`OWED`] and the `review ask missing` row,
/// read out of this repository's `batten.toml` with the base re-pointed at the
/// ref the fixture pins (`common::Fixture::base_commit`).
fn committed_ready_config() -> String {
    let text =
        std::fs::read_to_string(common::at_root("batten.toml")).expect("the committed authority");
    let authority: toml::Table = text.parse().expect("the committed authority parses");
    let rows = |table: &str, field: &str, names: &[&str]| -> Vec<toml::Value> {
        authority[table]
            .as_array()
            .expect("an array of tables")
            .iter()
            .filter(|row| names.contains(&row[field].as_str().unwrap_or_default()))
            .cloned()
            .map(|mut row| {
                if let Some(base) = row.get_mut("key_base") {
                    *base = toml::Value::from("refs/remotes/origin/main");
                }
                row
            })
            .collect()
    };
    let mints = rows("mint", "name", &OWED);
    assert_eq!(mints.len(), OWED.len(), "each owed skill mints a receipt");
    let ready = rows("rule", "id", &["review ask missing"]);
    assert_eq!(ready.len(), 1, "the ready row is committed");
    let mut config = toml::Table::new();
    config.insert("version".into(), toml::Value::from(1));
    config.insert("mint".into(), toml::Value::Array(mints));
    config.insert("rule".into(), toml::Value::Array(ready));
    toml::to_string(&config).expect("the fixture config serialises")
}

fn committed_fixture(name: &str) -> PathBuf {
    common::Fixture::new(name)
        .config(&committed_ready_config())
        .file("README.md", "base\n")
        .git()
        .base_commit()
        .build()
}

/// EACH MISSING SKILL IS NAMED IN TURN, and only all three admit.
///
/// On `main` the committed row checked `code-review` alone, so the ready was
/// admitted with neither `simplify` nor `security-review` on file. Each refusal
/// below comes after every skill before it was minted, so each names a check
/// the row would otherwise not require.
#[test]
fn ready_is_refused_until_simplify_and_both_reviews_are_minted() {
    let dir = committed_fixture("review-owes-three");
    change(&dir, "fn a() {}\n");

    for skill in OWED {
        let text = denied(&ready(&dir));
        // ` at <check>` is the refusal's subject; the bare name is also in the
        // row's reason, which names all three, so it would match vacuously.
        assert!(
            text.contains(&format!(" at {skill}")),
            "the refusal names `{skill}`: {text}"
        );
        dispatch(&dir, skill);
    }
    allowed(&ready(&dir));
}

/// A COMMITTED SIMPLIFICATION RE-OWES ALL THREE, `simplify` included, and
/// re-running only the simplification does not answer the reviews.
///
/// The order the row asks for (simplify, then review) comes from the `delta`
/// key alone: what the reviews attest is the merge-base diff, and the
/// simplification moved it.
#[test]
fn a_committed_simplification_re_owes_all_three() {
    let dir = committed_fixture("review-owes-three-again");
    change(&dir, "fn a() {}\n");
    for skill in OWED {
        dispatch(&dir, skill);
    }
    allowed(&ready(&dir));

    change(&dir, "fn a() {}\n// simplified\n");
    for check in OWED {
        assert_ne!(
            status(&dir, check).status.code(),
            Some(0),
            "`{check}` still answers over the simplified change"
        );
    }

    dispatch(&dir, "simplify");
    let text = denied(&ready(&dir));
    assert!(text.contains(" at security-review"), "{text}");
    for skill in ["security-review", "code-review"] {
        dispatch(&dir, skill);
    }
    allowed(&ready(&dir));
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
