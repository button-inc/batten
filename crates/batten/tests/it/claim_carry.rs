//! `batten claim carry` over the compiled binary (CLOUD-1295).
//!
//! # Why this tier and not only the unit one
//!
//! `carry::judge` is pure and `src/carry.rs` drives every refusal against
//! strings. What it cannot see is whether the ENGINE builds the inputs that
//! predicate reads — the merge base, the table on each side, the set of other
//! changed paths. A dead reader and a clean branch are byte-identical on the
//! decision surface, which is the failure `.claude/rules/policy-modules.md`
//! records for exactly this shape.
//!
//! So these cases build real repositories and run the real verb.
//!
//! # The premise case is not decoration
//!
//! `a_branch_carrying_one_row_forward_mints_the_receipt` is what the refusals
//! below are refusals *against*. Without it a verb that refused everything would
//! satisfy all of them, which is CLOUD-418's vacuity.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common::{Fixture, git_in, run, stderr, stdout, write};

/// The licence table's path, as the engine names it.
const TABLE: &str = "mise-tasks/sbom-actions.tsv";

/// A base table with two mapped repos and a comment the parser must skip.
const BASE: &str = "# how each row was sourced\n\
jdx/mise-action@aaa\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n\
taiki-e/install-action@bbb\tApache-2.0 OR MIT\tNONE\n";

/// A repository whose `origin/main` carries [`BASE`], with `head` then written
/// over the table and committed as the branch's own work.
///
/// `origin/main` is pinned by [`Fixture::base_commit`], so the merge base the
/// verb resolves is a real one rather than a fixture-only convention.
fn carry_branch(name: &str, head: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config("version = 1\n")
        .file(TABLE, BASE)
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", "sbom-actions/carry-probe"]);
    write(&dir, TABLE, head);
    git_in(&dir, &["add", "-A"]);
    // `--allow-empty` for `Fixture::work_commit`'s reason: a branch that changes
    // nothing is a case the verb must still judge, and it has nothing to commit.
    // Without it `a_branch_that_changed_nothing_earns_no_receipt` dies in setup
    // rather than reaching the assertion it exists for.
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "ci(deps): carry"],
    );
    dir
}

/// `batten claim carry` as (exit code, stdout, stderr).
fn carry(dir: &Path) -> (Option<i32>, String, String) {
    let output = run(dir, &["claim", "carry"]);
    (output.status.code(), stdout(&output), stderr(&output))
}

/// Whether the receipt the verb writes is on disk under the branch's name.
fn receipt(dir: &Path) -> Option<String> {
    let path = dir
        .join(".git")
        .join("batten-receipts")
        .join("carry.sbom-actions-carry-probe");
    std::fs::read_to_string(path).ok()
}

/// THE PREMISE. Every refusal below is a refusal against this.
#[test]
fn a_branch_carrying_one_row_forward_mints_the_receipt() {
    let head = format!(
        "{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
    );
    let dir = carry_branch("carry-happy", &head);
    let (code, _, err) = carry(&dir);
    assert_eq!(code, Some(0), "a derivable branch is admitted: {err}");
    let recorded = receipt(&dir).expect("the receipt is written");
    assert!(recorded.contains("carry 1 row(s)"), "{recorded}");
    // The base line is what gives this receipt CLOUD-516's staleness rule, the
    // same way `bot.<branch>` gets it. A receipt without one is trusted forever.
    assert!(recorded.contains("\nbase "), "records its base: {recorded}");
}

/// Pointer-only (rule 4): the receipt records a count and a path, never a
/// licence or a holder — those are the bytes the table exists to hold.
#[test]
fn the_receipt_records_no_licence_and_no_holder() {
    let head = format!(
        "{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
    );
    let dir = carry_branch("carry-pointer", &head);
    assert_eq!(carry(&dir).0, Some(0));
    let recorded = receipt(&dir).expect("the receipt is written");
    assert!(!recorded.contains("MIT"), "no licence: {recorded}");
    assert!(!recorded.contains("GitHub, Inc."), "no holder: {recorded}");
}

/// A second changed path is refused and NAMED, so an author knows which.
#[test]
fn a_branch_touching_a_second_path_is_refused() {
    let head = format!(
        "{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
    );
    let dir = carry_branch("carry-second-path", &head);
    write(&dir, "notes.md", "an unrelated edit\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "ci(deps): and a note"]);

    let (code, report, _) = carry(&dir);
    assert_eq!(code, Some(2), "a second path is not a carry");
    assert!(report.contains("notes.md"), "names the path: {report}");
    assert!(receipt(&dir).is_none(), "and mints nothing");
}

/// The case that makes this more than a diff-size check: a repo with no recorded
/// verdict has nothing to carry, so admitting it would ASSERT a licence.
#[test]
fn a_row_for_an_unmapped_repo_is_refused_over_the_binary() {
    let head = format!("{BASE}brand/new-action@ddd\tMIT\tCopyright (c) 2026 Somebody\n");
    let dir = carry_branch("carry-unmapped", &head);
    let (code, report, _) = carry(&dir);
    assert_eq!(code, Some(2));
    assert!(report.contains("no-prior-row"), "{report}");
    assert!(
        report.contains("brand/new-action"),
        "names the repo: {report}"
    );
    assert!(receipt(&dir).is_none());
}

/// A carry changes the sha and nothing else; a moved licence is a new claim.
#[test]
fn a_row_whose_licence_moved_is_refused_over_the_binary() {
    let head = format!(
        "{BASE}jdx/mise-action@ccc\tGPL-3.0\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
    );
    let dir = carry_branch("carry-relicensed", &head);
    let (code, report, _) = carry(&dir);
    assert_eq!(code, Some(2));
    assert!(report.contains("verdict-changed"), "{report}");
    // Pointer-only: the refusal names the repo, never the licence it compared.
    assert!(
        !report.contains("GPL-3.0"),
        "no licence in the line: {report}"
    );
    assert!(receipt(&dir).is_none());
}

/// Rewriting an existing row must not read as an addition — the prefix
/// comparison is what makes that true, and this drives it over the binary.
#[test]
fn rewriting_a_row_in_place_is_refused_over_the_binary() {
    let head = "# how each row was sourced\n\
jdx/mise-action@aaa\tGPL-3.0\tCopyright (c) 2018 GitHub, Inc. and contributors\n\
taiki-e/install-action@bbb\tApache-2.0 OR MIT\tNONE\n";
    let dir = carry_branch("carry-rewrite", head);
    let (code, report, _) = carry(&dir);
    assert_eq!(code, Some(2));
    assert!(report.contains("not-append-only"), "{report}");
    assert!(receipt(&dir).is_none());
}

/// A branch that changed nothing has nothing to attest. Without this, any branch
/// touching no tracked file would earn a receipt — which is the branch-name
/// exemption arriving by another door.
#[test]
fn a_branch_that_changed_nothing_earns_no_receipt() {
    let dir = carry_branch("carry-empty", BASE);
    let (code, report, _) = carry(&dir);
    assert_eq!(code, Some(2), "nothing carried is not a carry: {report}");
    assert!(report.contains("nothing-carried"), "{report}");
    assert!(receipt(&dir).is_none());
}
