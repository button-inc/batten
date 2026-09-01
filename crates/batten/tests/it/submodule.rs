//! Both halves of a selection agree over a submodule (CLOUD-328).
//!
//! A ratchet compares a count at a base rev against a count in the working
//! tree. The base half reads `git ls-tree -r`, which reports a submodule as one
//! gitlink and does not recurse; the working half reads
//! [`batten::rules::tree_files`], which used to walk a submodule like any other
//! directory. A `non_decreasing` row spanning one therefore sat permanently
//! above its base — measured on this repository as base 637 against working
//! 1404, a fixed `+767` — so no deletion could pull it back under and **the
//! gate could not fail**. That is the defect class Batten exists to catch,
//! arriving inside the mechanism built to catch it.
//!
//! The resolution is stated once, on `tree_files`: the selection stops at a
//! nested repository. These tests assert it from both sides — **directly** on
//! the walker, so its contract is pinned rather than inferred from a ratchet's
//! arithmetic, and as set equality against the base-rev listing, which is the
//! exact comparison the two halves' agreement means.
//!
//! **The fixture needs no network.** Its submodule is added from a local path,
//! which git only permits when `protocol.file.allow` says so — passed per
//! invocation, never written into the fixture's config, so nothing else in the
//! fixture inherits a relaxed transport policy.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use batten::rules::tree_files;
use common::{Fixture, git_in, run, stdout};

/// Where the submodule is mounted in every fixture below — the same path
/// consumer #1 uses, so the case under test is the measured one.
const SUBMODULE: &str = "tests/bats";

/// A bats file's marker, and the ratchet token these fixtures count.
const TOKEN: &str = "@test \"";

/// One `@test` case, as a bats file carries it.
fn bats(name: &str) -> String {
    format!("{TOKEN}{name}\" {{\n  true\n}}\n")
}

/// A ratchet row over every `.bats` file at any depth — the glob that spans the
/// submodule, which is the whole point.
const SPANNING_CONFIG: &str = "version = 1\n\n[[rule]]\nid = \"bats-tests-not-deleted\"\nkind = \"ratchet\"\nglob = \"tests/**/*.bats\"\npattern = \"@test \\\"\"\ndirection = \"non_decreasing\"\nbase = \"main\"\nseverity = \"deny\"\n";

/// A superproject with `config`, two of its own bats suites, and a real
/// submodule at [`SUBMODULE`] carrying three more.
///
/// The submodule's own count (3) is deliberately different from the
/// superproject's (2), so a walk that leaked into it could not coincidentally
/// agree with one that did not.
fn repo_with_submodule(name: &str, config: &str) -> PathBuf {
    // The submodule's source repository, beside the superproject rather than
    // inside it: a nested source would itself be walked.
    let inner = Fixture::new(&format!("{name}-inner"))
        .file("one.bats", &bats("inner one"))
        .file("two.bats", &bats("inner two"))
        .file("nested/three.bats", &bats("inner three"))
        .git()
        .build();
    git_in(&inner, &["add", "-A"]);
    git_in(&inner, &["commit", "-q", "-m", "the vendored suite"]);

    let dir = Fixture::new(name)
        .config(config)
        .file("tests/own.bats", &bats("own one"))
        .file("tests/suite/deep.bats", &bats("own two"))
        .git()
        .build();
    git_in(
        &dir,
        &[
            // Per invocation, not `git config`: a local-path submodule is the
            // only reason this fixture needs the permission, and leaving it in
            // the fixture's config would hand it to every later git call.
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            inner.to_str().unwrap(),
            SUBMODULE,
        ],
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

/// The paths `git ls-tree -r` reports at `HEAD`, gitlinks removed — the base
/// half's selection, computed here from git's own output rather than from the
/// crate, so the comparison below is between two independent answers.
fn base_paths(dir: &Path) -> BTreeSet<String> {
    git_in(dir, &["ls-tree", "-r", "HEAD"])
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(meta, _)| meta.split_whitespace().next() != Some("160000"))
        .map(|(_, path)| path.to_owned())
        .collect()
}

#[test]
fn tree_files_stops_at_a_nested_repository_boundary() {
    // The direct assertion the acceptance list demands: whatever the walker
    // decides about submodules is pinned HERE, on the walker, so no later
    // reading has to be inferred from a ratchet's arithmetic.
    let dir = repo_with_submodule("submodule-walk", SPANNING_CONFIG);

    // The premise, asserted before the conclusion: the vendored files must
    // actually be ON DISK, or "the walk yielded none of them" passes for a
    // fixture whose submodule was never checked out. A case that cannot fail is
    // not evidence (`.claude/rules/rust.md`).
    for vendored in ["one.bats", "two.bats", "nested/three.bats"] {
        assert!(
            dir.join(SUBMODULE).join(vendored).is_file(),
            "{vendored} must exist inside the submodule for the skip to mean anything"
        );
    }

    let files: BTreeSet<String> = tree_files(&dir)
        .expect("walk the tree")
        .into_iter()
        .collect();

    let inside: Vec<&String> = files
        .iter()
        .filter(|path| path.starts_with(&format!("{SUBMODULE}/")))
        .collect();
    assert!(
        inside.is_empty(),
        "the walk must not enter a nested repository: {inside:?}"
    );
    // The submodule's own `.git` is a FILE, not a directory, so the name-based
    // skip never saw it and the pointer itself was offered as policy input.
    assert!(
        !files.contains(&format!("{SUBMODULE}/.git")),
        "the gitlink pointer is not policy input either"
    );

    // And the superproject is still fully walked — a boundary that swallowed
    // its own tree would agree with the base half by making both empty.
    for own in ["batten.toml", "tests/own.bats", "tests/suite/deep.bats"] {
        assert!(
            files.contains(own),
            "{own} must still be selected: {files:?}"
        );
    }
    assert!(
        files.contains(".gitmodules"),
        "the superproject's own record of the submodule is its file, not the submodule's"
    );
}

#[test]
fn both_halves_select_the_same_set_over_a_submodule() {
    // Set equality, exactly — the computable predicate the issue states. Not a
    // count comparison: two different sets can share a size, and it is the
    // *sets* that must agree for the gate to be honest for every glob.
    let dir = repo_with_submodule("submodule-parity", SPANNING_CONFIG);
    let walked: BTreeSet<String> = tree_files(&dir)
        .expect("walk the tree")
        .into_iter()
        .collect();

    assert_eq!(
        walked,
        base_paths(&dir),
        "the working-tree walk and the base-rev listing must select the same files"
    );
}

#[test]
fn a_ratchet_spanning_a_submodule_is_at_parity_when_nothing_changed() {
    // The headline acceptance: nothing has changed, so the row is silent. Before
    // the fix the working half counted the submodule's three cases on top of the
    // superproject's two while the base half counted two, and the row sat
    // permanently and unfailably above its base.
    let dir = repo_with_submodule("submodule-ratchet", SPANNING_CONFIG);
    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an unchanged tree is parity, not a skew: {}",
        stdout(&output)
    );
    assert!(output.stdout.is_empty(), "a ratchet that held says nothing");
}

#[test]
fn deleting_a_matched_file_outside_the_submodule_still_fires() {
    // Parity must not be bought by making the gate inert. The counts name the
    // superproject's two cases falling to one — the submodule's three appear on
    // neither side.
    let dir = repo_with_submodule("submodule-deletion", SPANNING_CONFIG);
    std::fs::remove_file(dir.join("tests/suite/deep.bats")).expect("delete one own suite");

    let output = run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(2), "a deletion is a verdict");
    let text = stdout(&output);
    assert!(
        text.contains("2->1"),
        "both counts are the superproject's alone: {text:?}"
    );
    assert!(
        text.contains("bats-tests-not-deleted"),
        "the finding names the rule: {text:?}"
    );
}

#[test]
fn changing_a_file_inside_the_submodule_moves_neither_count() {
    // The mirror, pinning the contract from the other side: a vendored tree is
    // not this repository's to judge, so gutting it is not this repository's
    // violation — and, just as importantly, not a way to inflate the count past
    // a real deletion.
    let dir = repo_with_submodule("submodule-vendored-edit", SPANNING_CONFIG);
    common::write(&dir, &format!("{SUBMODULE}/one.bats"), "");
    common::write(&dir, &format!("{SUBMODULE}/two.bats"), "");
    common::write(&dir, &format!("{SUBMODULE}/nested/three.bats"), "");
    common::write(
        &dir,
        &format!("{SUBMODULE}/added.bats"),
        &bats("vendored new"),
    );

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the vendored suite is on neither side of the comparison: {}",
        stdout(&output)
    );
}
