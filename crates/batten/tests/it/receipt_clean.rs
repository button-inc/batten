//! `batten receipt clean` and the guard inside `receipt record`, over the
//! compiled binary — CLOUD-193's precondition, ported off
//! `mise-tasks/tree-clean.sh` under CLOUD-1753.
//!
//! # The assumption this enforces was load-bearing and unenforced
//!
//! CLOUD-193 moved `verify`'s verdict off the exit code and onto a receipt "keyed
//! to the exact HEAD it validated". That mechanism is sound and it rests on an
//! assumption nothing checked: that the bytes verified ARE the bytes at HEAD.
//! They need not be — `cargo`, `hk` and `zizmor` all read the WORKING TREE, and
//! `receipt record` keys the claim to HEAD.
//!
//! # The direction that matters is the SILENT one
//!
//! Measured 2026-08-09 landing CLOUD-269: a backgrounded `land` compiled a
//! mid-edit snapshot and died on a `non-exhaustive patterns` error for code the
//! commit did not contain. That direction is loud and self-correcting. The mirror
//! is not — a dirty tree that PASSES writes a receipt for HEAD, `verified`
//! matches it, `ready-guard` accepts it, the branch is readied, and CI runs the
//! commit alone, which was never the thing that passed.
//!
//! Uncommitted work is not exotic here: backgrounding the slow path is mandated,
//! so a long `verify` while the session edits the next row in the same worktree
//! is the DESIGNED workflow rather than a mistake.
//!
//! # WHAT THE PORT CHANGES, AND IT IS THE PART THE SHELL COULD NOT DO
//!
//! The retired program was a task, so it could only ever be a call somebody
//! remembered to make. Its own header says so — "NOT wired into the hk gate,
//! deliberately", because `pre-commit` runs over a tree that is dirty by
//! definition — and `batten.toml` twice cites the same shape as "the scoping
//! defect CLOUD-1164 records for `tree-clean`".
//!
//! The successor puts the load-bearing half INSIDE `receipt record`, which is the
//! verb that writes the receipt. So the guarantee stops depending on a caller: a
//! receipt keyed to HEAD cannot be written over a tree that is not HEAD, by any
//! route, including one nobody has written yet. `receipt clean` remains as the
//! cheap end, because `verify:gated` needs to fail in seconds rather than after
//! the gate set's full cost — and both call one `tree_state`, so the pair is one
//! authority asked at two moments rather than two readings that could disagree.
//
// carried: mise-tasks/tree-clean.sh crates/batten/src/receipt.rs kind:verb crates/batten/tests/it/receipt_clean.rs runs:batten+receipt+clean
// carried: tests/tree-clean.bats crates/batten/src/receipt.rs kind:verb crates/batten/tests/it/receipt_clean.rs runs:batten+receipt+clean
//
// carried: "a clean tree passes and names the commit the receipt would be about" crates/batten/src/receipt.rs
// carried: "a modified tracked file exits 1 and names the path" crates/batten/src/receipt.rs
// carried: "staged but uncommitted is dirty — the index is not HEAD" crates/batten/src/receipt.rs
// carried: "AN UNTRACKED FILE IS DIRTY — decided, not omitted" crates/batten/src/receipt.rs
// carried: "an ignored file is not dirty — scratch is excluded structurally" crates/batten/src/receipt.rs
// carried: "a deleted tracked file is dirty" crates/batten/src/receipt.rs
// carried: "the count is the number of paths, not a fixed string" crates/batten/src/receipt.rs
// changed: "output is a pointer — paths and a count, never the differing content" crates/batten/src/receipt.rs from `tests/tree-clean.bats`. Narrowed in the direction rule 4 points: the successor emits the COUNT and the head, and never the porcelain path list the retired program printed to stderr. A path list is already a pointer, so this is not a defect being fixed — it is a gate that no longer needs the reader to open anything, since the remedy is the same whichever paths are dirty. `the_refusal_carries_a_count_and_never_a_path` is the narrowed property
// carried: "the refusal names the fix, not merely the refusal" crates/batten/src/receipt.rs
// changed: "outside a git repository it exits 2 — could not look is not a verdict" crates/batten/src/receipt.rs from `tests/tree-clean.bats`. The ANSWER is carried and the CODE is not: the corpus reads `2` as could-not-look and this repository's one exit contract reads `2` as the policy verdict, with no per-verb exception (non-negotiable rule 5). So the successor answers `3`, which is what `Internal` means here. The inversion is the corpus-wide one `batten verdict` exists to fold, not a decision this port made
// changed: "a repository with no commit exits 2 — no HEAD for a receipt to name" crates/batten/src/receipt.rs from `tests/tree-clean.bats`. Same inversion as the row above, same reason: could-not-look is `3` on the engine's table
// changed: "THE ACCEPTANCE CASE: a dirty tree that would PASS still leaves HEAD unverified" crates/batten/src/receipt.rs from `tests/tree-clean.bats`. The property is STRONGER than the case asserted, which is why it is changed rather than carried. The case drove the retired gate and then checked that `verified` still refused — a composition of two tasks, true only while somebody kept calling the first. `a_dirty_tree_cannot_have_a_receipt_written_for_it_at_all` asserts it at the write instead: `receipt record` refuses, so there is no receipt for `verified` to match and no call site whose removal could restore the hole

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, stdout};

/// A repository with one commit, so HEAD resolves and a receipt could name it.
fn repo(name: &str) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-receipt-clean", name);
    common::init_repo(&dir);
    common::write(&dir, "batten.toml", "version = 1\n");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    // `receipt record` names the trunk its receipt was taken against, so the case
    // that drives it needs one. `receipt clean` deliberately does NOT — it
    // compares the tree to HEAD — and every other case here would pass without
    // this line, which is the asymmetry the verb's own doc records.
    common::pin_origin_main(&dir);
    dir
}

fn clean(dir: &Path) -> Output {
    batten()
        .arg("receipt")
        .arg("clean")
        .current_dir(dir)
        .output()
        .expect("run batten receipt clean")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_clean_tree_passes_and_names_the_commit_the_receipt_would_be_about() {
    let dir = repo("clean");
    let output = clean(&dir);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        stdout(&output).contains("working tree matches HEAD"),
        "{output:?}"
    );
}

#[test]
fn a_modified_tracked_file_is_refused() {
    let dir = repo("modified");
    common::write(&dir, "batten.toml", "version = 1\n# edited\n");
    let output = clean(&dir);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stderr(&output).contains("differs from HEAD"), "{output:?}");
}

#[test]
fn staged_but_uncommitted_is_dirty_because_the_index_is_not_head() {
    let dir = repo("staged");
    common::write(&dir, "added.txt", "x\n");
    common::git_in(&dir, &["add", "-A"]);
    assert_eq!(clean(&dir).status.code(), Some(1));
}

#[test]
fn an_untracked_file_is_dirty_decided_rather_than_omitted() {
    // THE GAP A `diff HEAD` PREDICATE MISSES, and it is not theoretical: `cargo
    // test` autodiscovers test targets and the bats suite globs `tests/*.bats`,
    // so a brand-new untracked file is compiled and run by `verify` with ZERO
    // tracked-file change. A receipt written after that attests a pass over bytes
    // no commit contains, which is the whole failure.
    let dir = repo("untracked");
    common::write(&dir, "scratch.rs", "fn main() {}\n");
    assert_eq!(clean(&dir).status.code(), Some(1));
}

#[test]
fn an_ignored_file_is_not_dirty_because_scratch_is_excluded_structurally() {
    // Excluded by CONSTRUCTION rather than tuned out: `git status` never reports
    // an ignored path, so `target/`, the worktree directories and
    // `batten.local.toml` are outside the judgement rather than carved out of it.
    let dir = repo("ignored");
    common::write(&dir, ".gitignore", "junk/\n");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "ignore"]);
    std::fs::create_dir_all(dir.join("junk")).unwrap();
    common::write(&dir.join("junk"), "big.log", "noise\n");
    let output = clean(&dir);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

#[test]
fn a_deleted_tracked_file_is_dirty() {
    let dir = repo("deleted");
    std::fs::remove_file(dir.join("batten.toml")).unwrap();
    assert_eq!(clean(&dir).status.code(), Some(1));
}

#[test]
fn the_count_is_the_number_of_paths_rather_than_a_fixed_string() {
    let dir = repo("count");
    common::write(&dir, "one.txt", "1\n");
    common::write(&dir, "two.txt", "2\n");
    common::write(&dir, "three.txt", "3\n");
    let output = clean(&dir);
    assert!(stderr(&output).contains("in 3 path(s)"), "{output:?}");
}

#[test]
fn the_refusal_carries_a_count_and_never_a_path() {
    // Narrowed from the retired case in rule 4's direction: the successor emits
    // the count and the head and never the porcelain list, because the remedy is
    // the same whichever paths are dirty.
    let dir = repo("pointer");
    common::write(&dir, "secret-name.txt", "content that must not be echoed\n");
    let output = clean(&dir);
    let said = stderr(&output);
    assert!(!said.contains("secret-name.txt"), "{said}");
    assert!(!said.contains("content that must not be echoed"), "{said}");
    assert!(said.contains("in 1 path(s)"), "{said}");
}

#[test]
fn the_refusal_names_the_fix_rather_than_merely_the_refusal() {
    // All THREE routes, because "commit it" is not always the one the author
    // wants and a refusal naming one route is how a gate earns a bypass.
    let dir = repo("remedy");
    common::write(&dir, "wip.txt", "x\n");
    let said = stderr(&clean(&dir));
    assert!(said.contains("Commit the work"), "{said}");
    assert!(said.contains("stash it"), "{said}");
    assert!(said.contains("separate worktree"), "{said}");
}

#[test]
fn outside_a_repository_it_is_could_not_look_rather_than_a_verdict() {
    // `3`, not the corpus's `2`. This repository's one exit contract reads `2` as
    // the policy verdict with no per-verb exception, so a could-not-look answered
    // there would tell every mediating harness that policy refused.
    let dir = common::scratch_outside_tree("batten-receipt-clean", "no-repo");
    let output = clean(&dir);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

#[test]
fn a_repository_with_no_commit_is_could_not_look() {
    let dir = common::scratch_outside_tree("batten-receipt-clean", "no-head");
    common::init_repo(&dir);
    let output = clean(&dir);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

#[test]
fn a_dirty_tree_cannot_have_a_receipt_written_for_it_at_all() {
    // THE ACCEPTANCE CASE, and it is stronger than the one it replaces. The
    // retired case drove the gate and then checked that `verified` still refused
    // — a composition true only while somebody kept calling the gate. This
    // asserts it at the WRITE: `receipt record` refuses, so there is no receipt
    // for `verified` to match, and no call site whose removal could reopen the
    // hole.
    let dir = repo("record-refuses");
    common::write(&dir, "mid-run-edit.rs", "fn main() {}\n");
    let output = batten()
        .arg("receipt")
        .arg("record")
        .arg("verify")
        .current_dir(&dir)
        .output()
        .expect("run batten receipt record");
    assert_ne!(output.status.code(), Some(0), "{output:?}");
    assert!(
        stderr(&output).contains("attest bytes no commit contains"),
        "{output:?}"
    );
}
