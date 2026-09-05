//! `code-review-dispatched`, over the engine that builds its input (CLOUD-1484).
//!
//! # The seam, and why the module's own suite cannot reach it
//!
//! `policy/code-review-dispatched.rego`'s `test_` rules pin the predicate against
//! a fabricated document. Three questions decide whether the gate is alive, and
//! the module cannot ask any of them:
//!
//! * does the ENGINE project the branch's patch identity at
//!   `input.tree["base-delta"]["patch-id"]`, and the receipt store at
//!   `input.tree.minted`?
//! * is a receipt filed under that identity the one the predicate finds — and one
//!   filed under any other identity NOT found?
//! * does the identity survive a REBASE, which is the property the whole keying
//!   turns on and the one a landing loop would otherwise re-buy every lap?
//!
//! A `with input as` case actively hides all three: it fabricates the map, so it
//! fabricates the keying. Such a suite passes identically over an engine that
//! ignored the subject entirely.
//!
//! # The channel is confirmed by a PAIR, never by one arm
//!
//! `.claude/rules/policy-modules.md` records how CLOUD-1049's dead channel
//! survived two measurements: a probe whose only clause reads the new key cannot
//! tell an empty channel from a module that never ran, because both are silent.
//! Its remedy there is an unconditional `violation`; here the same discrimination
//! comes free from the two arms below, and is worth stating so nobody deletes one
//! of them as redundant.
//!
//! `an_absent_receipt_is_refused_over_the_engines_own_projection` and
//! `a_receipt_under_this_change_reaches_the_predicate_and_is_clean` are the pair.
//! If `input.tree.minted` were never populated, the second would find its subject
//! absent and REFUSE, so it fails. If `base-delta`'s `patch-id` were never
//! projected, `is_string(subject)` would not hold, every arm would abstain, and
//! the first would report clean, so it fails. Neither key can be dead with both
//! green — which is exactly what one arm alone could not establish.

// UNIX-ONLY, for `review_dispatched.rs`' reason one family over: every case here
// drives real `git` against a scratch repository, and a case whose fixture failed
// to build would leave the receipt absent — which is exactly what the negative
// arms refuse, so they would pass FOR THE WRONG REASON while the clean case
// failed. A suite whose negative arms pass because the subject never ran is the
// vacuous pass this family exists to refuse.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

const RULE: &str = "code-review-dispatched";
const RECEIPT: &str = "code-review";
const CODE: &str = "crates/batten/src/lib.rs";

/// A fixture repository whose base carries no code and whose branch adds some.
///
/// THROUGH `common::Fixture`, never a hand-rolled `git init` chain: the builder
/// copies a template rather than forking `git init` (CLOUD-1419 measured 1,819
/// init processes over one run from exactly that habit), and `fixture-forks`
/// refuses a new copy of it.
fn repo(name: &str) -> PathBuf {
    let root = common::Fixture::new(name)
        .config(CONFIG)
        .file("README.md", "base\n")
        .git()
        .base_commit()
        .build();
    install_module(&root);
    write_code(&root, "fn a() {}\n");
    root
}

/// The one config every fixture here writes, so the shape is stated once.
const CONFIG: &str = "version = 1\n";

/// Commit a code change at the path the row's `delta_sources` selects.
fn write_code(root: &Path, body: &str) {
    let path = root.join(CODE);
    fs::create_dir_all(path.parent().expect("a parent")).expect("the source dir");
    fs::write(&path, body).expect("the source");
    common::git_in(root, &["add", "-A"]);
    common::git_in(root, &["commit", "-q", "-m", "change"]);
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/code-review-dispatched.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/code-review-dispatched.rego"))
        .expect("install committed module");
}

/// The identity the ENGINE resolves for this branch — never one this file
/// computes, or the cases would agree with themselves rather than with the gate.
fn identity(root: &Path) -> String {
    batten::git::branch_patch_id(root, "refs/remotes/origin/main")
        .expect("the repository opens")
        .expect("a branch that changed something has an identity")
}

/// File a receipt under `subject`, exactly as the mint boundary writes one.
fn file_receipt(root: &Path, subject: &str) {
    let git_dir = batten::git::git_dir(root).expect("a git dir");
    let store = git_dir.join("batten-receipts");
    fs::create_dir_all(&store).expect("the receipt store");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    fs::write(
        store.join(format!("{RECEIPT}.{subject}")),
        format!("deadbeef {now}\n"),
    )
    .expect("write the receipt");
}

/// The committed row's shape.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": RULE,
        "kind": "policy",
        "scope": "tree",
        "base": "refs/remotes/origin/main",
        "delta_sources": ["crates/**"],
        "module": "policy/code-review-dispatched.rego",
        "severity": "deny",
        "minted": [{
            "id": RECEIPT,
            "mint": RECEIPT,
            "field": 0,
            "recency": 1,
            "max_age_days": 30,
        }],
    }))
    .expect("the loader accepts the committed row's shape")
}

fn verdicts(root: &Path) -> Vec<String> {
    let declared = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &declared,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

// ---------------------------------------------------------------------------
// THE PROJECTION SEAM.
// ---------------------------------------------------------------------------

/// A change with no receipt is refused, over the engine's own projection.
///
/// Without this the module is a `with input as` suite over two keys nothing
/// fills. Declared mutation: `absent-receipt-unread`.
#[test]
fn an_absent_receipt_is_refused_over_the_engines_own_projection() {
    let root = repo("code-review-absent");
    assert_eq!(
        verdicts(&root),
        vec![String::from(RULE)],
        "a branch that changed code with nothing filed under its identity must refuse"
    );
}

/// A receipt filed under this change's identity clears it.
///
/// This is the half that proves the ENGINE resolves the same identity the mint
/// boundary keys by; a fabricated map would pass over an engine that resolved
/// nothing.
#[test]
fn a_receipt_under_this_change_reaches_the_predicate_and_is_clean() {
    let root = repo("code-review-attested");
    let subject = identity(&root);
    file_receipt(&root, &subject);
    assert!(
        verdicts(&root).is_empty(),
        "a receipt filed under this change's own identity must clear the gate"
    );
}

/// THE ANTI-STALENESS HALF. A receipt over other bytes lives under another name.
#[test]
fn a_receipt_over_another_change_does_not_answer() {
    let root = repo("code-review-stale");
    file_receipt(&root, "0000000000000000000000000000000000000000000000000000000000000000");
    assert_eq!(
        verdicts(&root),
        vec![String::from(RULE)],
        "a receipt keyed to bytes this branch does not carry must not answer"
    );
}

/// A FURTHER CODE COMMIT RE-OWES THE REVIEW, which is the same property read
/// forwards: the identity moves, so the record is filed under a name nothing
/// looks up.
#[test]
fn a_further_code_commit_re_owes_the_review() {
    let root = repo("code-review-moved");
    file_receipt(&root, &identity(&root));
    assert!(verdicts(&root).is_empty(), "the fixture starts attested");

    write_code(&root, "fn a() {}\nfn b() {}\n");
    assert_eq!(
        verdicts(&root),
        vec![String::from(RULE)],
        "a commit that moves code must re-owe the review"
    );
}

/// THE PROPERTY THE WHOLE KEYING TURNS ON. `land` rebases every lap, and an
/// identity that moved with the rebase would re-buy the review each time —
/// minutes and tokens per lap, which is the shape that gets a gate switched off
/// rather than satisfied.
///
/// A merge-base diff is what makes this hold, and it is precisely what a
/// `with input as` case cannot check.
#[test]
fn a_rebase_onto_a_moved_base_does_not_re_owe_the_review() {
    let root = repo("code-review-rebase");
    let before = identity(&root);
    file_receipt(&root, &before);
    assert!(verdicts(&root).is_empty(), "the fixture starts attested");

    // Move the base under the branch with a change this branch never made, then
    // rebase onto it — the landing loop's own lap, in miniature.
    common::git_in(&root, &["checkout", "-q", "-b", "trunk", "refs/remotes/origin/main"]);
    fs::write(root.join("NOTES.md"), "trunk moved\n").expect("the trunk file");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-q", "-m", "trunk"]);
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", "trunk"]);
    common::git_in(&root, &["checkout", "-q", "main"]);
    common::git_in(&root, &["rebase", "-q", "refs/remotes/origin/main"]);

    assert_eq!(
        identity(&root),
        before,
        "a rebase relocates the change and must not restate it"
    );
    assert!(
        verdicts(&root).is_empty(),
        "the receipt taken before the rebase must still answer after it"
    );
}

/// A PROSE-ONLY BRANCH OWES NO CODE REVIEW.
///
/// Without this narrowing the gate refuses every fixture and every fresh clone,
/// which is the shape that gets a gate switched off. Declared mutation:
/// `prose-only-priced`.
#[test]
fn a_prose_only_branch_owes_no_code_review() {
    // The base ALREADY CARRIES the code, so the branch's only change is a comment
    // and `code-changed` stays empty. Building it the other way round — base with
    // no file — makes the path read as ADDED and the case would pass for the
    // wrong reason.
    let root = common::Fixture::new("code-review-prose")
        .config(CONFIG)
        .file(CODE, "fn a() {}\n")
        .git()
        .base_commit()
        .build();
    install_module(&root);

    fs::write(root.join(CODE), "// a comment\nfn a() {}\n").expect("the source");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-q", "-m", "comment only"]);

    // THE PREMISE, ASSERTED BEFORE THE CONCLUSION. Without this the case would
    // pass over a fixture whose base carried no file at all, where the path reads
    // as ADDED and `code-changed` is non-empty — green for the wrong reason.
    let delta = batten::git::base_delta(
        &root,
        "refs/remotes/origin/main",
        &[String::from("crates/**")],
    )
    .expect("the repository opens")
    .expect("the base resolves");
    assert!(
        delta.code_changed.is_empty(),
        "a comment-only commit must move no code, but `code-changed` holds {:?}",
        delta.code_changed
    );
    assert!(
        !delta.edited.is_empty(),
        "the fixture must still have EDITED the file, or it tests nothing"
    );
    assert!(
        verdicts(&root).is_empty(),
        "a comment-only commit moves no code and must not re-owe the review"
    );
}

/// A CHANGE WITH NO IDENTITY OWES NO REVIEW.
///
/// An empty diff has nothing to review, and `cumulative_patch_id` refuses to mint
/// an identity for one precisely so two empty changes cannot compare equal.
/// Reading that absence as `unreviewed` would refuse a branch with nothing on it.
/// Declared mutation: `no-identity-priced`.
#[test]
fn a_change_with_no_identity_owes_no_review() {
    // The base already CARRIES the code, and the branch adds nothing on top, so
    // the diff is empty and there is no identity to key a receipt by.
    let root = common::Fixture::new("code-review-empty")
        .config(CONFIG)
        .file(CODE, "fn a() {}\n")
        .git()
        .base_commit()
        .build();
    install_module(&root);

    assert!(
        batten::git::branch_patch_id(&root, "refs/remotes/origin/main")
            .expect("the repository opens")
            .is_none(),
        "the fixture's premise: an empty diff has no identity"
    );
    assert!(
        verdicts(&root).is_empty(),
        "a branch with nothing to review must not be refused for not reviewing it"
    );
}

/// COULD-NOT-LOOK IS NOT A REFUSAL. A checkout whose row declares no receipt
/// projects `null`, and the gate must go quiet rather than refuse the machine.
#[test]
fn an_undeclared_receipt_is_could_not_look_and_never_a_refusal() {
    let root = repo("code-review-undeclared");
    let mut bare = row();
    bare.minted.clear();
    let declared = common::verdicts_in(&root);
    let findings = rules::run_static(
        &[bare],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &declared,
            recorders: &[],
        },
        &root,
    )
    .expect("the read surface runs a policy row")
    .findings;
    assert!(
        findings.is_empty(),
        "a row declaring no receipt projects null, and null is could-not-look"
    );
}
