//! A protected write carries its articulation in the commit message
//! (CLOUD-1278).
//!
//! # What this tier is for
//!
//! `path write refused`'s override route made a protected write admissible: the
//! guarded party articulates, an admission is issued and spent, the write goes
//! through. That much landed and it produced nothing anyone could read. The record
//! lives under the OS data directory, which in this repository is a container the
//! platform reclaims — so the reasoning an override cost was legible only inside
//! the session that wrote it, and only until that session ended. There was not
//! even a read verb: `override` offered `request` and `spend` and nothing that
//! could show a record back.
//!
//! A forcing function whose product nobody can read is a toll. This is the half
//! that makes it an audit trail.
//!
//! # Over the compiled binary, and that is the whole discriminator
//!
//! `rules/policy-modules.md`'s second tier, one surface over: the unit
//! tests in `commit.rs` pin the predicate over a `CommitWrite` a test constructed,
//! and cannot see whether `git::writes_in_range` builds one. Both halves of this
//! clause failed exactly there in development — a fixture whose protected glob
//! selected nothing yields no paths, so every case passes for the wrong reason and
//! the gate is absent rather than green.
//!
//! `an_unarticulated_protected_write_is_refused` is the premise case that closes
//! it: without a case asserting the REFUSAL happens, the admitting cases are
//! satisfied by a clause that never fired.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, stdout, write};

/// The protected path under test, and one that is not.
const GUARDED: &str = "guarded.toml";
const ORDINARY: &str = "notes.md";

/// A protected path that ALSO has a `[[redirect]]` naming its sanctioned
/// mutation — the CLOUD-1303 set.
const SURFACED: &str = "memories/note.md";

/// A fixture protecting one path, with a base commit that predates every case.
///
/// `[commit]` is present because `commit check` refuses a config without one
/// before it reaches either clause — a fixture omitting it would exit 1 and every
/// case would read that as its own verdict.
fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            "version = 1\nprotected = [\"{GUARDED}\"]\n\n\
             [commit]\nsubject_pattern = \"^(feat|fix|chore)(\\\\(.+\\\\))?!?: .+\"\n"
        ))
        .file(GUARDED, "original = 1\n")
        .file(ORDINARY, "just notes\n")
        .git()
        .base_commit()
        .build()
}

/// The same fixture, plus a second protected path that a `[[redirect]]` speaks
/// for (CLOUD-1303).
///
/// **BOTH paths are protected and only one is redirected**, which is what makes
/// the third case below able to fail. A fixture where the redirect covered the
/// whole protected set would pass an implementation that dropped the demand
/// entirely.
fn fixture_with_redirect(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            "version = 1\nprotected = [\"{GUARDED}\", \"memories/**\"]\n\n\
             [[redirect]]\nglob = \"memories/**\"\n\
             mutation = \"use the memory tools\"\n\n\
             [commit]\nsubject_pattern = \"^(feat|fix|chore)(\\\\(.+\\\\))?!?: .+\"\n"
        ))
        .file(GUARDED, "original = 1\n")
        .file(SURFACED, "original\n")
        .file(ORDINARY, "just notes\n")
        .git()
        .base_commit()
        .build()
}

/// Commit everything staged in `dir` with `message`, and return the range that
/// covers exactly that commit.
///
/// `--no-verify` is not passed and does not need to be: a fixture repository has
/// no hooks installed, so the commit under test is created without this clause
/// having a say. That is the point — the case judges it afterwards, the way the
/// range tier in CI does.
fn commit(dir: &Path, message: &str) -> String {
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", message]);
    "HEAD~1..HEAD".to_owned()
}

/// `batten commit check <range>`, as (exit code, stdout).
fn check(dir: &Path, range: &str) -> (Option<i32>, String) {
    let output = run(dir, &["commit", "check", range]);
    (output.status.code(), stdout(&output))
}

/// A block that verifies, built by asking the binary for one.
///
/// **Issued and spent through the real verbs rather than assembled here.** A block
/// this file hand-wrote would have to reproduce `address`'s canonicalization, which
/// is the second implementation the whole scheme exists to avoid — and it would
/// keep verifying after a change to the protocol that broke every real one.
fn articulate(dir: &Path, subject: &str) -> String {
    let issued = run_with_answers(
        dir,
        &[
            "override",
            "request",
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            subject,
        ],
        "precondition=the owning surface cannot express it\n\
         lost=nothing\n\
         rejected-route=restoring it would undo the change\n",
    );
    let address = issued.trim().to_owned();
    let spent = run(
        dir,
        &[
            "override",
            "spend",
            "--admission",
            &address,
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            subject,
        ],
    );
    assert_eq!(spent.status.code(), Some(0), "spend: {}", stdout(&spent));
    // Everything after the pointer line is the block, which `spend` prints for
    // exactly this purpose: it is what a caller pastes into the message.
    //
    // Split at the first newline rather than re-joining `lines()`: the block's
    // bytes are what the address was computed over, so a round trip through a
    // line iterator is a chance to change them.
    stdout(&spent)
        .split_once('\n')
        .map(|(_, block)| block.to_owned())
        .unwrap_or_default()
}

fn run_with_answers(dir: &Path, args: &[&str], answers: &str) -> String {
    let output = common::run_with_stdin(dir, args, answers);
    assert_eq!(
        output.status.code(),
        Some(0),
        "request: {}",
        common::stderr(&output)
    );
    stdout(&output)
}

#[test]
fn an_unarticulated_protected_write_is_refused() {
    // THE PREMISE. Every other case here is about a clause that fired; if the
    // fixture's protected glob selected nothing this would pass and take the rest
    // with it, green over a gate that is absent.
    let dir = fixture("commit-admits-missing");
    write(&dir, GUARDED, "original = 2\n");
    let range = commit(&dir, "fix(config): change the guarded file");
    let (code, report) = check(&dir, &range);
    assert_eq!(
        code,
        Some(2),
        "an unarticulated protected write must refuse"
    );
    assert!(
        report.contains(&format!("admits {GUARDED}")),
        "the finding must name the path the author owes an articulation for: {report}"
    );
}

#[test]
fn an_articulated_protected_write_passes() {
    let dir = fixture("commit-admits-present");
    write(&dir, GUARDED, "original = 2\n");
    let block = articulate(&dir, GUARDED);
    let range = commit(
        &dir,
        &format!("fix(config): change the guarded file\n\n{block}"),
    );
    let (code, report) = check(&dir, &range);
    assert_eq!(
        code,
        Some(0),
        "a verifying block admits the write: {report}"
    );
}

#[test]
fn a_write_that_touches_no_protected_path_needs_nothing() {
    // The clause must not toll an ordinary commit. Without this case the safe
    // implementation is "refuse every commit", which would pass the premise case
    // above.
    let dir = fixture("commit-admits-ordinary");
    write(&dir, ORDINARY, "more notes\n");
    let range = commit(&dir, "chore: write some notes");
    let (code, report) = check(&dir, &range);
    assert_eq!(code, Some(0), "an ordinary write owes nothing: {report}");
}

#[test]
fn an_edited_block_is_reported_as_tampered_not_as_missing() {
    // The graver finding, and the reason it is a separate field. Rolling both into
    // "missing" would let a doctored articulation read as an honest omission —
    // which is the one failure mode a content-addressed record exists to expose.
    let dir = fixture("commit-admits-tampered");
    write(&dir, GUARDED, "original = 2\n");
    let block = articulate(&dir, GUARDED);
    let doctored = block.replace(
        "the owning surface cannot express it",
        "a reason nobody articulated",
    );
    assert_ne!(doctored, block, "the case must actually change the answer");
    let range = commit(
        &dir,
        &format!("fix(config): change the guarded file\n\n{doctored}"),
    );
    let (code, report) = check(&dir, &range);
    assert_eq!(code, Some(2), "an edited block must not admit: {report}");
    assert!(
        report.contains(&format!("admits-tampered {GUARDED}")),
        "an edited block is tampered, never merely missing: {report}"
    );
}

#[test]
fn a_block_bound_to_another_path_does_not_admit_this_one() {
    // The binding, from the commit-message side. An articulation is for ONE
    // subject; a block naming a different path is not an answer about this one,
    // and reading it as one would make a single override cover every protected
    // write in the commit.
    let dir = fixture("commit-admits-wrong-subject");
    write(&dir, GUARDED, "original = 2\n");
    let block = articulate(&dir, ORDINARY);
    let range = commit(
        &dir,
        &format!("fix(config): change the guarded file\n\n{block}"),
    );
    let (code, report) = check(&dir, &range);
    assert_eq!(code, Some(2), "a block for another path must not admit");
    assert!(
        report.contains(&format!("admits {GUARDED}")),
        "the unadmitted path is the one the finding names: {report}"
    );
}

#[test]
fn a_deleted_protected_path_owes_an_articulation_too() {
    // Deleting a protected file is as much a write to it as editing one, and a
    // clause that compared only present paths would make deletion the way through.
    let dir = fixture("commit-admits-deleted");
    std::fs::remove_file(dir.join(GUARDED)).unwrap();
    let range = commit(&dir, "fix(config): remove the guarded file");
    let (code, report) = check(&dir, &range);
    assert_eq!(
        code,
        Some(2),
        "a deleted protected path is a write: {report}"
    );
    assert!(
        report.contains(&format!("admits {GUARDED}")),
        "the deleted path is named: {report}"
    );
}

#[test]
fn a_protected_path_with_a_sanctioned_mutation_owes_no_block() {
    // CLOUD-1303, and the whole of it. A write through the surface the class
    // declares is refused by nothing, so no admission is issued and there is
    // nothing to articulate — while the override route's own precondition says it
    // exists for when "writing the protected path directly is the only route
    // left". Demanding a block here leaves an honest author a choice between a
    // false articulation and not committing.
    let dir = fixture_with_redirect("commit-admits-surfaced");
    write(&dir, SURFACED, "changed\n");
    let range = commit(&dir, "chore(memory): record something");
    let (code, report) = check(&dir, &range);
    assert_eq!(
        code,
        Some(0),
        "a path with a declared mutation surface owes no articulation: {report}"
    );
}

#[test]
fn a_tampered_block_on_a_redirected_path_is_still_refused() {
    // THE HALF THE SUPERSEDED FIX DROPPED, and the reason CLOUD-1303 refuted it.
    // Exempting the path before inspecting it loses `admits-tampered` for exactly
    // the exempted set: a doctored block on a memory would go unexamined. The
    // redirect answers only the ABSENCE case; a block that claims the path is
    // still verified.
    let dir = fixture_with_redirect("commit-admits-surfaced-tampered");
    write(&dir, SURFACED, "changed\n");
    let block = articulate(&dir, SURFACED);
    let doctored = block.replace(
        "the owning surface cannot express it",
        "a reason nobody articulated",
    );
    assert_ne!(doctored, block, "the case must actually change the answer");
    let range = commit(
        &dir,
        &format!("chore(memory): record something\n\n{doctored}"),
    );
    let (code, report) = check(&dir, &range);
    assert_eq!(
        code,
        Some(2),
        "a doctored block is refused whether or not the path has a surface: {report}"
    );
    assert!(
        report.contains(&format!("admits-tampered {SURFACED}")),
        "the tampered finding keeps its whole subject set: {report}"
    );
}

#[test]
fn a_redirect_for_one_path_does_not_excuse_another() {
    // Without this, an implementation that dropped the demand for every protected
    // path the moment ANY redirect was declared would pass the case above, and the
    // clause would be off. The commit writes both; only the redirected one is
    // excused.
    let dir = fixture_with_redirect("commit-admits-surfaced-narrow");
    write(&dir, SURFACED, "changed\n");
    write(&dir, GUARDED, "original = 2\n");
    let range = commit(&dir, "chore(config): change both");
    let (code, report) = check(&dir, &range);
    assert_eq!(code, Some(2), "the unredirected path still owes: {report}");
    assert!(
        report.contains(&format!("admits {GUARDED}")),
        "the finding names the path with no sanctioned surface: {report}"
    );
    assert!(
        !report.contains(SURFACED),
        "the redirected path is not reported: {report}"
    );
}

#[test]
fn the_clause_needs_no_store_to_decide() {
    // THE PROPERTY THAT MAKES THIS A CI TIER RATHER THAN A LOCAL ONE. The block
    // spells every binding field out, so `recomputes` is a pure function of the
    // message — a runner that has never seen the store decides identically. A
    // clause that consulted the store would pass here and abstain in CI, which is
    // the shape of a gate that is not there.
    let dir = fixture("commit-admits-storeless");
    write(&dir, GUARDED, "original = 2\n");
    let block = articulate(&dir, GUARDED);
    let range = commit(
        &dir,
        &format!("fix(config): change the guarded file\n\n{block}"),
    );
    let store = batten::admission::store_dir(&dir).expect("the store resolves");
    std::fs::remove_dir_all(&store).expect("the store is removable");
    assert!(
        !store.exists(),
        "the store must be gone for this to mean anything"
    );
    let (code, report) = check(&dir, &range);
    assert_eq!(
        code,
        Some(0),
        "the block verifies with the store deleted: {report}"
    );
}
