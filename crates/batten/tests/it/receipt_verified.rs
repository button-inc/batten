//! `batten receipt verified` over the compiled binary — the composed
//! receipt read that retired `mise-tasks/verified.sh` (CLOUD-1148).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! The predecessor was a gate over three reads: a `verify` receipt for this
//! exact HEAD, a `linear-check` receipt, and the `origin/main` that receipt was
//! taken against still being current. Every one of those is `receipt::validity`
//! already, so the port composes rather than reimplements — which is also why
//! the successor is `receipt.rs` rather than a module of its own.

// carried: mise-tasks/verified.sh crates/batten/src/receipt.rs kind:verb crates/batten/tests/it/receipt_verified.rs runs:batten+receipt+verified
// carried: tests/verified.bats crates/batten/src/receipt.rs kind:verb crates/batten/tests/it/receipt_verified.rs

//! # RETIREMENT LEDGER — `tests/verified.bats`, 10 cases
//!
//! **Every title below is the base file's, byte for byte.** The first draft of
//! this block invented them from the brief instead of reading
//! `git show origin/main:tests/verified.bats`, so all ten arms matched nothing
//! and `bats-tests-not-deleted` reported ten unmapped cases — which is the
//! ratchet doing exactly what it exists to do.
//!
//! CARRIED — the predicate moved intact onto the composed verb.

// carried: "a commit with both current receipts is verified" crates/batten/tests/it/receipt_verified.rs
// carried: "a verify receipt alone is not enough — linear-check is a separate claim" crates/batten/tests/it/receipt_verified.rs
// carried: "an amend invalidates the receipt, because it produces a new HEAD" crates/batten/tests/it/receipt_verified.rs
// carried: "a main that moved under the branch invalidates the receipt" crates/batten/tests/it/receipt_verified.rs

//! CHANGED — behaviour that diverges deliberately, with its reason.

// changed: "THE INVERSION: a failed verify whose exit code was swallowed leaves HEAD unverified" crates/batten/tests/it/receipt_verified.rs the predicate is conserved and the WORDING moved: the verb says WHAT is unverified and the `mise` task keeping the `verified` name says what to do about it, because the remedy names `mise run verify` — a consumer task name, which non-negotiable rule 1 forbids in `crates/batten`. The suite asserting the prose therefore asserts it one layer out
// changed: "the failure names what to run, not merely that it refused" crates/batten/tests/it/receipt_verified.rs the same move as the row above, and the same reason: a remedy that names a task cannot live in the repo-agnostic core, so the wrapper emits it
// changed: "an unresolvable origin/main exits 2 — a checkout problem, not a verdict" crates/batten/tests/it/receipt_verified.rs the engine has ONE exit table and no per-verb exception (non-negotiable rule 5): `2` is the policy verdict everywhere and `1`/`3` are the only codes a Batten failure produces. The predecessor spelled an unusable checkout `2` and an unverified head `1`, which is the table inverted. The `mise` task keeping the `verified` name translates, so every caller reads what it always read — the shim shape CLOUD-1170 established
// changed: "outside a git repository it exits 2 rather than claiming unverified" crates/batten/tests/it/receipt_verified.rs the same inversion as the row above, on the other environment arm

//! SUBSUMED — the assertion is a property of a reader the verb now shares.

// subsumed: "a receipt for a different commit does not vouch for this one" crates/batten/tests/it/receipt_verified.rs
// subsumed: "output is a pointer — it names predicates and shas, never run contents" crates/batten/tests/it/receipt_verified.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::Path;

use common::{Fixture, batten, git_in, scratch};

/// A repository with one commit and an `origin/main` pointing at it.
///
/// Built through [`Fixture`] rather than by hand, and that is not style: the
/// scratch tree lives under `target/`, which is INSIDE this repository, so a
/// fixture that only ran `git init` still had this checkout above it — and
/// `repo_facts` answered about the real HEAD. Measured: the first draft of these
/// cases reported this branch's own sha back at them.
fn repo(name: &str) -> std::path::PathBuf {
    // A COMMITTED CONFIG, because a receipt records the policy epoch it was
    // taken under — `receipt record` refuses a tree with no `batten.toml` at
    // HEAD, and rightly: a receipt that named no policy would still be valid
    // after the policy changed underneath it.
    let dir = Fixture::at(scratch(name).join("repo"))
        .config("version = 1\n")
        .file("src.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

fn out_of(dir: &Path, args: &[&str]) -> String {
    git_in(dir, args).trim().to_owned()
}

/// Record the two receipts a verified head carries, THROUGH THE ENGINE'S OWN
/// WRITER.
///
/// Hand-writing the files is what the first draft did, and it failed for the
/// right reason: a receipt is not a sha in a file. `validity` reads a statement
/// that also records WHICH checkout took it, so a hand-rolled one is `Missing`
/// — correctly. Driving `receipt record` makes this a test of the real
/// writer/reader pair rather than of my guess at their format, which is the same
/// argument `land.rs`'s tier makes for driving `land::record`.
fn record(dir: &Path, check: &str) {
    let output = batten()
        .args(["receipt", "record", check])
        .current_dir(dir)
        .output()
        .expect("run batten receipt record");
    assert!(
        output.status.success(),
        "recording {check} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verified(dir: &Path) -> (i32, String) {
    let output = batten()
        .args(["receipt", "verified"])
        .current_dir(dir)
        .output()
        .expect("run batten receipt verified");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().expect("exit code"), text)
}

/// **The discriminating pair: both receipts present is verified, one missing is
/// not.**
///
/// The predecessor existed because a caller acted on a zero that came from a
/// pipe rather than from the gate — `mise run verify 2>&1 | tail -60` exits with
/// `tail`'s status, so a branch `linear-check` had rejected reported success.
/// Composing the two reads into one verb is what makes that unaskable: there is
/// no half of this to answer.
#[test]
fn a_head_carrying_both_receipts_is_verified_and_one_missing_is_not() {
    let dir = repo("receipt-verified-pair");

    record(&dir, "verify");
    record(&dir, "linear-check");
    let (code, text) = verified(&dir);
    assert_eq!(code, 0, "both receipts valid is verified: {text}");

    // The other half, on a fixture that simply never recorded the second
    // receipt. Deleting the file by name is what the first draft did, and it
    // guessed the layout wrong and passed for the wrong reason — the head stayed
    // verified because nothing had been removed. Not recording it cannot guess.
    let half = repo("receipt-verified-half");
    record(&half, "verify");

    let (code, text) = verified(&half);
    assert_eq!(
        code, 2,
        "a missing receipt is a verdict about the tree: {text}"
    );
    assert!(
        text.contains("NOT verified"),
        "the predecessor's wording is conserved because a surviving suite reads for it: {text}"
    );
    assert!(
        text.contains("linear-check"),
        "the refusal names WHICH receipt is missing: {text}"
    );
}

/// A moved trunk expires the linear-check receipt, which is the whole reason
/// that receipt records the trunk it was taken against.
///
/// A head proven linear on a base that has since moved has been proven against
/// something that no longer exists. Without this the pair above passes over a
/// receipt that means nothing.
#[test]
fn a_moved_trunk_expires_the_receipt_taken_against_the_old_one() {
    let dir = repo("receipt-verified-moved-trunk");
    let head = out_of(&dir, &["rev-parse", "HEAD"]);
    record(&dir, "verify");
    record(&dir, "linear-check");
    assert_eq!(verified(&dir).0, 0, "the fixture starts verified");

    // Move trunk on, without touching the branch or its receipts.
    fs::write(dir.join("other.rs"), "fn other() {}\n").expect("seed a second file");
    git_in(&dir, &["add", "other.rs"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: trunk moves"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(&dir, &["reset", "-q", "--hard", &head]);

    let (code, text) = verified(&dir);
    assert_eq!(
        code, 2,
        "a receipt taken against a moved trunk is stale: {text}"
    );
    assert!(text.contains("NOT verified"), "got {text}");
}

/// An amend expires the receipt, because it produces a new HEAD.
///
/// The other half of the keying: the row above moves the TRUNK and this moves
/// the HEAD, and a reader that answered only one of them would vouch for work
/// nobody verified. Cheap to state and the pair is what makes the keying
/// meaningful rather than incidental.
#[test]
fn an_amended_head_expires_the_receipt_taken_against_the_old_one() {
    let dir = repo("receipt-verified-amended");
    record(&dir, "verify");
    record(&dir, "linear-check");
    assert_eq!(verified(&dir).0, 0, "the fixture starts verified");

    let before = out_of(&dir, &["rev-parse", "HEAD"]);
    git_in(&dir, &["commit", "-q", "--amend", "-m", "chore: reworded"]);
    let after = out_of(&dir, &["rev-parse", "HEAD"]);
    assert_ne!(before, after, "the amend minted a new sha");

    let (code, text) = verified(&dir);
    assert_eq!(
        code, 2,
        "a receipt names the commit it validated, and this is not that commit: {text}"
    );
    assert!(text.contains("NOT verified"), "got {text}");
}

/// **The exit table is the engine's, and the inversion is deliberate.**
///
/// The predecessor answered `1` for an unverified head and `2` for a checkout it
/// could not judge. The engine has one table with no per-verb exception: `2` is
/// the policy verdict everywhere, `1`/`3` are the only codes a Batten failure
/// produces. So the two swap, and the `mise` task keeping the old name is what
/// translates for callers that still read the old numbers.
///
/// Anti-vacuity for the pair above: without this, a verb that answered `2` for
/// everything — including a directory that is not a repository — would pass.
#[test]
fn a_checkout_that_cannot_be_judged_is_not_reported_as_an_unverified_head() {
    // OUTSIDE THE REPOSITORY TREE, not merely un-`git init`ed. The scratch tree
    // lives under `target/`, so a directory there still has this checkout above
    // it and `git rev-parse` climbs to it — which is a repository, and the case
    // would then be asserting the opposite of what it says.
    let dir = std::env::temp_dir().join("batten-receipt-verified-not-a-repo");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create the fixture");

    let (code, text) = verified(&dir);
    assert_eq!(
        code, 1,
        "a directory that is not a repository is a usage error, never a verdict: {text}"
    );
    assert_ne!(
        code, 2,
        "exit 2 would report the WORK as unverified when the checkout is what could not be read"
    );
}
