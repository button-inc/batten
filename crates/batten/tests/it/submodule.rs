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
const SPANNING_CONFIG: &str = "version = 1\n\n[[rule]]\nid = \"bats count dropped\"\nkind = \"ratchet\"\nglob = \"tests/**/*.bats\"\npattern = \"@test \\\"\"\ndirection = \"non_decreasing\"\nbase = \"main\"\nseverity = \"deny\"\n";

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

/// A LINKED WORKTREE counts its OWN files, not the main checkout's
/// (CLOUD-1753).
///
/// `git::repo_root` answers with the common dir's parent on purpose, so every
/// linked worktree resolves to one store (CLOUD-164). The working-tree walk used
/// that as the directory to read files FROM, which compares this checkout's
/// index against the other checkout's bytes. Measured: a worktree whose branch
/// had committed a different `batten.toml` reported that file as uncommitted on
/// a tree `git status` called clean, and the count fell to zero the moment the
/// main checkout's copy was made to match — which is the tell that the wrong
/// file was being read.
///
/// The fixture makes the two checkouts DISAGREE on a tracked file, because a
/// worktree whose content matches the main one cannot distinguish the two
/// readings at all.
#[test]
fn a_linked_worktree_counts_its_own_files_rather_than_the_main_checkouts() {
    let main = Fixture::new("worktree-own-files")
        .file("shared.txt", "main's own text\n")
        .git()
        .build();
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "base"]);
    git_in(&main, &["branch", "sibling"]);

    let linked = main.join("..").join("worktree-own-files-linked");
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            linked.to_str().expect("a utf-8 fixture path"),
            "sibling",
        ],
    );
    std::fs::write(linked.join("shared.txt"), "the branch's own text\n").unwrap();
    git_in(&linked, &["add", "-A"]);
    git_in(&linked, &["commit", "-q", "-m", "this branch's own text"]);

    // The premise: the two checkouts must actually differ, or the walk cannot
    // tell which one it read.
    assert_ne!(
        std::fs::read_to_string(main.join("shared.txt")).unwrap(),
        std::fs::read_to_string(linked.join("shared.txt")).unwrap(),
        "the fixture must make the two checkouts disagree"
    );
    assert_eq!(
        git_in(&linked, &["status", "--porcelain"]).trim(),
        "",
        "and the linked worktree must be clean before the count is asked for"
    );

    assert_eq!(
        batten::git::uncommitted(&linked).expect("count the uncommitted paths"),
        0,
        "a linked worktree is judged by its own files"
    );
}

/// A clean superproject carrying a submodule has NO uncommitted paths
/// (CLOUD-1753).
///
/// The walk behind `uncommitted` compares each index entry against the bytes on
/// disk. A gitlink's entry records a commit id in another repository and its
/// path on disk is a DIRECTORY, so the read fails and the deletion arm claims a
/// change that no git command reports. This asserts the superproject reads as
/// clean, and then that the same walk still SEES an ordinary edit — because a
/// walk that skipped too much would pass the first half by answering nothing.
#[test]
fn a_submodule_is_not_counted_as_an_uncommitted_path() {
    let dir = repo_with_submodule("submodule-uncommitted", SPANNING_CONFIG);

    // The premise: the gitlink must actually be an index entry, or "no
    // uncommitted paths" is true for a fixture with no submodule in it.
    let staged = git_in(&dir, &["ls-files", "-s", SUBMODULE]);
    assert!(
        staged.starts_with("160000"),
        "{SUBMODULE} must be a gitlink for this case to mean anything; got {staged:?}"
    );
    // And git itself must agree the tree is clean, so the assertion below is a
    // disagreement with git rather than a second opinion about real work.
    assert_eq!(
        git_in(&dir, &["status", "--porcelain"]).trim(),
        "",
        "the fixture must be clean before the count is asked for"
    );

    assert_eq!(
        batten::git::uncommitted(&dir).expect("count the uncommitted paths"),
        0,
        "a checked-out submodule is not uncommitted work"
    );

    // The other direction, so the skip is narrow rather than a blanket silence.
    std::fs::write(dir.join("tests/own.bats"), bats("own one edited")).unwrap();
    assert_eq!(
        batten::git::uncommitted(&dir).expect("count the uncommitted paths"),
        1,
        "an ordinary unstaged edit is still counted"
    );
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
    // not evidence (`rules/rust.md`).
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
        text.contains("bats count dropped"),
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
