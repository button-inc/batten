//! A stranded worktree registration is a finding (CLOUD-1424).
//!
//! # Why this tier exists at all
//!
//! `policy/worktree-registration.rego`'s own `test_` rules pin the predicate and
//! cannot pin the ENGINE. Every one of them supplies `input` by hand, so all six
//! pass over a `git-worktrees` key nothing fills — which is the class
//! `.claude/rules/policy-modules.md` opens with and the one both live instances in
//! this repository were found by adding a tier like this one, not by reading.
//!
//! So this suite installs **the module's real bytes**, read off the checkout at
//! test time, and drives the compiled binary over a real repository with a real
//! linked worktree. Nothing here fabricates a fact.
//!
//! # What each case is for
//!
//! * **Both ways over one registration.** The live arm and the stranded arm are
//!   the same repository, seconds apart, with only the directory's existence
//!   differing. A suite that only ever saw a stranded row would pass against a
//!   fact that reported every registration, and one that only ever saw a live row
//!   would pass against a fact that reported none.
//! * **The commonest input is silence.** A repository with only its main checkout
//!   keeps no registration at all, and a gate that fired there would be switched
//!   off within a day.
//! * **The pointer is the id and never the path.** A linked worktree may live
//!   anywhere on the machine, so the finding naming its absolute path would put a
//!   developer's home directory into CI output — non-negotiable rule 4, asserted
//!   over the rendered line rather than trusted to the fact's shape.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, stdout};

/// The rule id under test, and the string a case reads its verdict off.
const RULE: &str = "worktree-registration-live";

/// The module's real bytes, from this checkout.
///
/// READ RATHER THAN RETYPED, which is the whole point of the tier: a copy in this
/// file would be a second predicate that agrees with the first only while somebody
/// keeps them in step, and the defect this suite exists to catch is exactly a
/// predicate that agrees with its own fixture and with nothing else.
fn module() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy/worktree-registration.rego");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The row that loads it, plus the two verdict classes it raises.
///
/// The `[[verdict]]` rows are not optional decoration — the loader refuses a
/// module raising a token no row declares, so a fixture omitting them would fail
/// to load and every negative case here would pass for the wrong reason.
fn config() -> String {
    "version = 1\n\
     \n\
     [[rule]]\n\
     id = \"worktree-registration-live\"\n\
     kind = \"policy\"\n\
     scope = \"tree\"\n\
     git = [\"worktrees\"]\n\
     module = \"policy/worktree-registration.rego\"\n\
     severity = \"deny\"\n\
     \n\
     [[verdict]]\n\
     id = \"worktree name absent\"\n\
     gloss = \"a worktree registration names a directory that is no longer there\"\n\
     class = \"The registry keeps a row nothing on disk answers for, and it \
     refuses in a later command over a path no reader recognises.\"\n\
     \n\
     [[verdict.route]]\n\
     id = \"patch run first\"\n\
     kind = \"command\"\n\
     target = \"git worktree prune\"\n\
     \n\
     [[verdict]]\n\
     id = \"worktree list unread\"\n\
     gloss = \"the worktree registry could not be read, so nothing about it was established\"\n\
     class = \"The row declares the read, so a null fact is the engine having \
     asked and failed rather than nobody having asked.\"\n\
     \n\
     [[verdict.route]]\n\
     id = \"module read first\"\n\
     kind = \"document\"\n\
     target = \"policy/worktree-registration.rego\"\n"
        .to_owned()
}

/// A repository carrying the real row and the real module.
fn repo(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config())
        .file("policy/worktree-registration.rego", &module())
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build()
}

/// Where a linked worktree for `dir` goes.
///
/// A SIBLING of the fixture, never a subdirectory. A checkout nested inside the
/// tree under test would be walked by `check` as ordinary files, so a case could
/// pass or fail on the walker's reading of a second `.git` rather than on the
/// registry — and the whole subject here is a registration that outlives its
/// directory, which is much easier to reason about when the directory was never
/// part of the tree being judged.
/// Cleared first, because a sibling is outside what `Fixture` resets and a run
/// that fails between creating this directory and removing it leaves one behind —
/// after which every later run of the case fails at `worktree add` with `already
/// exists`, which is a different failure from the one being asserted. Measured
/// while proving the declared mutation: the mutant reddens the first assertion,
/// so the case never reached its own cleanup, and the next honest run went red
/// for the leftover instead of green.
fn linked_at(dir: &Path) -> PathBuf {
    let name = dir.file_name().unwrap().to_str().unwrap();
    let linked = dir.parent().unwrap().join(format!("{name}-linked"));
    // `remove_dir_all` on an absent path is an error, not a no-op, so the
    // existence test is the guard rather than a race to lose.
    if linked.exists() {
        std::fs::remove_dir_all(&linked).unwrap();
    }
    linked
}

/// `check`'s stdout, with the run asserted to have decided.
///
/// THE EXIT STATUS IS READ FIRST, and the order is load-bearing: the absence of
/// the rule id is evidence only if the run reached policy evaluation. A run that
/// died at config load prints nothing and would satisfy every negative case here
/// for exactly the wrong reason. A `deny` row makes the two codes `0` and `2`.
fn decided(dir: &Path) -> String {
    let output = run(dir, &["check"]);
    let text = stdout(&output);
    let code = output.status.code();
    assert!(
        code == Some(0) || code == Some(2),
        "the run has to reach a verdict for its silence to mean anything \
         (exit {code:?}): {text}"
    );
    text
}

#[test]
fn a_live_worktree_is_not_a_finding_and_a_stranded_one_is() {
    // THE CASE THE DECLARED MUTATION NAMES, and it carries both arms in one
    // repository on purpose. The mutation flips the presence conjunct, so under
    // it the live arm fires and the stranded arm goes quiet — a case asserting
    // only "some finding appears" would pass under the mutant, since it still
    // produces exactly one.
    let dir = repo("worktree-registration-both-ways");
    let linked = linked_at(&dir);
    git_in(
        &dir,
        &[
            "worktree",
            "add",
            "--detach",
            "-q",
            linked.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(
        linked.is_dir(),
        "the linked worktree was created at {}",
        linked.display()
    );
    assert!(
        !decided(&dir).contains(RULE),
        "a live extra worktree is legitimate and must not be refused"
    );

    // Only the directory goes. The registration under the common dir's
    // `worktrees/` stays — which is the whole defect, and is what
    // `mise.toml`'s baseline scratch leaves behind when its `trap ... EXIT`
    // never runs because the process was killed.
    std::fs::remove_dir_all(&linked).unwrap();
    assert!(
        decided(&dir).contains(RULE),
        "the registration outlived its directory and nothing said so"
    );
}

#[test]
fn a_repository_with_no_linked_worktrees_is_silent() {
    // THE COMMONEST INPUT BY FAR, and the one that decides whether this gate can
    // stay switched on. The main checkout keeps no registration, so the registry
    // is read and holds nothing — an answer, and a different one from the null
    // the could-not-look arm refuses over.
    let dir = repo("worktree-registration-none");
    assert!(
        !decided(&dir).contains(RULE),
        "no linked worktrees: the registry was read and is empty"
    );
}

#[test]
fn a_locked_registration_is_left_alone_when_its_directory_is_gone() {
    // A lock is the recorded statement that this checkout is deliberately
    // unavailable — git's own documented case is removable storage — so an absent
    // directory under one is an answer somebody already gave. Without this arm
    // the gate would refuse a state its own operator declared.
    let dir = repo("worktree-registration-locked");
    let linked = linked_at(&dir);
    let path = linked.to_str().unwrap().to_owned();
    git_in(&dir, &["worktree", "add", "--detach", "-q", &path, "HEAD"]);
    git_in(&dir, &["worktree", "lock", &path]);
    std::fs::remove_dir_all(&linked).unwrap();
    assert!(
        !decided(&dir).contains(RULE),
        "a locked registration with no directory is declared, not stranded"
    );
}

#[test]
fn the_finding_names_the_registration_and_never_its_path() {
    // Non-negotiable rule 4, asserted over the RENDERED LINE rather than over the
    // fact's shape. A linked worktree may live anywhere on the machine, so a
    // finding carrying its absolute path puts a developer's home directory into
    // whatever CI log reads this — and the fact is built with no path field
    // precisely so that no consumer can put one back.
    let dir = repo("worktree-registration-pointer");
    let linked = linked_at(&dir);
    let path = linked.to_str().unwrap().to_owned();
    git_in(&dir, &["worktree", "add", "--detach", "-q", &path, "HEAD"]);
    std::fs::remove_dir_all(&linked).unwrap();

    let text = decided(&dir);
    assert!(text.contains(RULE), "the finding fired: {text}");
    // The registration's id is the directory's basename, which is what
    // `git worktree list` shows and what the remedy clears.
    let id = linked.file_name().unwrap().to_str().unwrap();
    assert!(text.contains(id), "the id is the pointer: {text}");
    assert!(
        !text.contains(linked.parent().unwrap().to_str().unwrap()),
        "the registration's directory reached the output: {text}"
    );
}

#[test]
fn outside_a_repository_the_registry_is_null_and_the_gate_says_so() {
    // THE COULD-NOT-LOOK ARM, DRIVEN BY THE ENGINE. The module's own `test_` rule
    // for this supplies `{"git-worktrees": null}` by hand and therefore proves
    // only that the clause parses; this proves the projection actually produces
    // that null, which is the half CLOUD-1049 spent three revisions being wrong
    // about in both directions.
    //
    // `scratch_outside_tree`, not `Fixture::new`: `target/tmp/` is inside THIS
    // repository, so discovery walks up and finds the real checkout — the case
    // would judge batten's own tree and pass for the wrong reason.
    let outside = common::scratch_outside_tree("batten-worktree-registration", "no-repo");
    let dir = Fixture::at(outside)
        .config(&config())
        .file("policy/worktree-registration.rego", &module())
        .file("src/lib.rs", "fn main() {}\n")
        .build();
    assert!(
        decided(&dir).contains(RULE),
        "with no repository the registry cannot be read, and silence there would \
         be a gate reporting clean over something it never looked at"
    );
}
