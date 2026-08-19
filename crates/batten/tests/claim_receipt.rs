//! The claim gate over the compiled binary, in real checkouts (CLOUD-444).
//!
//! This is `tests/claim-guard.bats` translated into the surface that now decides
//! it: a `receipt` row with `trigger = "write"` and `key = "branch"`. The bash
//! guard is deleted in the same change, so this file is what keeps the deletion
//! honest — without it, retiring the guard would take its corpus along and
//! nothing would notice a shape that stopped being refused.
//!
//! **The allows are the load-bearing half, and that is not a style preference.**
//! Every exclusion here is what keeps the gate's false-positive rate survivable:
//! a rule that refused a git-ignored path, a path outside the repository, a write
//! under `.git`, or an edit during a rebase conflict would refuse most writes in
//! a working container and be switched off within the hour — and a bypassed gate
//! enforces nothing. A suite that asserted only the deny would pass on exactly
//! that rule.
//!
//! Fixture repositories rather than the checkout this runs in, because every
//! predicate under test is a property of a real one: an ignore file, a branch, a
//! detached HEAD, a receipt beside the branch. A separate target rather than more
//! of `tests/cli.rs`, on `tests/advisory_drain.rs`'s precedent — that file is the
//! exit-code and output-contract suite.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run_with_stdin, stderr, write};

/// The policy under test: the committed row's shape, with nothing else declared.
///
/// Written here rather than read from the repository's own `batten.toml` because
/// these cases are about the *kind* — the committed row is pinned by the census
/// in `tests/cli.rs`, and a fixture that inherited real policy would be
/// adjudicating this repo's protected paths as well.
const POLICY: &str = r#"version = 1

[[rule]]
id = "claim-needs-receipt"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
trigger = "write"
checks = ["claim"]
key = "branch"
reason = "pipe the issue payload to `mise run claim-check`"
"#;

/// A repository on a feature branch, with one committed file and one ignored
/// directory.
fn repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(POLICY)
        .file(".gitignore", "scratch/\n")
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", "user/cloud-444-slug"]);
    dir
}

/// Mint the branch-keyed receipt the way `claim-check` does: one file under the
/// git dir, named for the check and the branch with separators replaced, and
/// carrying the `origin/main` the claim was made against.
///
/// **The base line is not optional here** (CLOUD-516). `claim-check` records it,
/// and a receipt without one is void by design so that receipts predating that
/// change cannot grandfather themselves in — so a helper that omitted it would
/// mint a receipt no real claim resembles and would test the wrong thing.
fn mint(dir: &Path, branch: &str) {
    mint_against(
        dir,
        branch,
        git_in(dir, &["rev-parse", "origin/main"]).trim(),
    );
}

/// Mint a receipt naming a base of the caller's choosing, for the cases that are
/// about the base having moved.
fn mint_against(dir: &Path, branch: &str, base: &str) {
    let git_dir = git_in(dir, &["rev-parse", "--absolute-git-dir"]);
    let receipts = PathBuf::from(git_dir.trim()).join("batten-receipts");
    std::fs::create_dir_all(&receipts).expect("create the receipt store");
    std::fs::write(
        receipts.join(format!("claim.{}", branch.replace('/', "-"))),
        format!("CLOUD-444\nready-lint pass\nbase {base}\n"),
    )
    .expect("mint the receipt");
}

fn write_payload(path: &str) -> String {
    let encoded = serde_json::to_string(path).expect("a path is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Write\",\
         \"tool_input\":{{\"file_path\":{encoded}}}}}"
    )
}

fn verdict(dir: &Path, path: &str) -> Option<i32> {
    run_with_stdin(
        dir,
        &["hook", "--harness", "exit-code"],
        &write_payload(path),
    )
    .status
    .code()
}

fn assert_denied(dir: &Path, path: &str) {
    assert_eq!(
        verdict(dir, path),
        Some(2),
        "must refuse the write to {path}"
    );
}

fn assert_allowed(dir: &Path, path: &str) {
    assert_eq!(
        verdict(dir, path),
        Some(0),
        "must allow the write to {path}"
    );
}

#[test]
fn a_write_with_no_claim_receipt_is_refused() {
    // The gap CLOUD-444 closes, and the reason it is a write trigger rather than
    // a command shape: nothing sat between *discovering* work and *editing files*
    // for it, because the first guard in the path fired at `gh pr create`.
    let dir = repo("claim-deny");
    assert_denied(&dir, "src/tracked.rs");
    // An untracked-but-not-ignored file is judged too — opening a new feature
    // file is the first edit this exists to catch, and exempting untracked paths
    // would leave the hole open in its commonest form.
    assert_denied(&dir, "src/brand_new.rs");
    // Both spellings of the same target, since a relative path left unjudged is
    // the whole gate with one extra keystroke.
    let absolute = dir.join("src/tracked.rs");
    assert_denied(&dir, absolute.to_str().expect("utf-8 fixture path"));
}

#[test]
fn the_refusal_names_the_route_and_the_keying() {
    let dir = repo("claim-refusal");
    let refusal = stderr(&run_with_stdin(
        &dir,
        &["hook", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    ));
    assert!(
        refusal.contains("claim-needs-receipt"),
        "names the rule: {refusal}"
    );
    assert!(refusal.contains("branch"), "names the keying: {refusal}");
    assert!(
        refusal.contains("claim-check"),
        "names the route rather than only refusing: {refusal}"
    );
    // The wrong pointer this avoids: a per-commit remedy for a branch-wide claim.
    assert!(
        !refusal.contains("this commit"),
        "a branch-keyed refusal must not send the reader after a commit: {refusal}"
    );
}

#[test]
fn the_receipt_allows_the_write_and_survives_a_commit() {
    // The whole reason for the second keying. A HEAD-keyed receipt expires the
    // moment a commit lands, which for a claim would mean a re-claim per commit —
    // the false-positive rate that gets a guard bypassed.
    let dir = repo("claim-allow");
    mint(&dir, "user/cloud-444-slug");
    assert_allowed(&dir, "src/tracked.rs");
    write(&dir, "src/tracked.rs", "// edited\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "work"]);
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn a_receipt_for_another_branch_does_not_vouch_for_this_one() {
    let dir = repo("claim-other-branch");
    mint(&dir, "user/some-other-branch");
    assert_denied(&dir, "src/tracked.rs");
    // And the branch it WAS minted for is allowed, so the negative above is
    // about the keying rather than about an unreadable store.
    git_in(&dir, &["checkout", "-q", "-b", "user/some-other-branch"]);
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn a_branch_restarted_after_its_pr_merged_carries_no_usable_claim() {
    // CLOUD-516, end to end through the real hook rather than the predicate. A
    // merged PR's documented remedy is `git checkout -B <name> origin/main`,
    // which repoints the name at a new base and discards the commits that were
    // the branch — while the receipt, keyed by the name, survives. Measured
    // 2026-08-13: a receipt naming CLOUD-230 authorised every edit behind four
    // unrelated stories and reported nothing.
    let dir = repo("claim-restarted");
    mint(&dir, "user/cloud-444-slug");
    assert_allowed(&dir, "src/tracked.rs");
    // The branch does some work and lands; `origin/main` advances past the base
    // the claim was made against.
    write(&dir, "src/tracked.rs", "// landed\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "landed work"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    // The restart: same name, new base, nothing of its own. The receipt is still
    // on disk and still names the same issue.
    git_in(
        &dir,
        &["checkout", "-q", "-B", "user/cloud-444-slug", "origin/main"],
    );
    assert_denied(&dir, "src/tracked.rs");
}

#[test]
fn a_lap_that_rebases_onto_newer_main_is_never_asked_to_re_claim() {
    // The row a careless fix breaks, and the reason the predicate is a
    // conjunction. `land` rebases onto the current `origin/main` every lap, so
    // the recorded base is stale on every lap after the first — voiding on that
    // alone would demand a re-claim per lap, which is the false-positive rate
    // that gets a guard bypassed.
    let dir = repo("claim-lap");
    let stale = git_in(&dir, &["rev-parse", "origin/main"]);
    mint_against(&dir, "user/cloud-444-slug", stale.trim());
    write(&dir, "src/tracked.rs", "// in flight\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "work in flight"]);
    // main moves under the branch, which still carries its own commit.
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "someone else landed"],
    );
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD~1"]);
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn a_git_ignored_path_is_never_judged() {
    // The scratch-work half, closed by asking git rather than by guessing which
    // paths are scratch.
    let dir = repo("claim-ignored");
    assert_allowed(&dir, "scratch/notes.md");
    assert_allowed(&dir, "scratch/nested/deeper.md");
}

#[test]
fn a_path_outside_the_repository_is_never_judged() {
    // Not this repository's policy to enforce.
    let dir = repo("claim-outside");
    assert_allowed(&dir, "/tmp/elsewhere.md");
    assert_allowed(&dir, "../sibling.md");
}

#[test]
fn a_write_under_the_git_directory_is_never_judged() {
    // Receipts, hooks and index state are the machinery, not the work — and the
    // receipt this gate reads lives there, so judging it would be circular.
    let dir = repo("claim-git-dir");
    assert_allowed(&dir, ".git/config");
    assert_allowed(&dir, ".git/batten-receipts/claim.anything");
}

#[test]
fn a_detached_head_fails_open() {
    // A detached HEAD has no branch to key a claim on. Refusing here would deny
    // every edit during a rebase conflict resolution — the one moment the
    // workflow contract says a human decision is required.
    let dir = repo("claim-detached");
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    git_in(&dir, &["checkout", "-q", "--detach", head.trim()]);
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn a_command_is_not_judged_by_a_write_triggered_row() {
    // The two triggers select disjointly. A row added for writes must not start
    // charging every mediated command a receipt lookup it never asked for.
    let dir = repo("claim-command");
    let payload = "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
                   \"tool_input\":{\"command\":\"gh pr ready 42\"}}";
    let output = run_with_stdin(&dir, &["hook", "--harness", "exit-code"], payload);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a write-triggered row must not judge a command"
    );
}

#[test]
fn a_repository_declaring_no_claim_row_judges_nothing() {
    // The cost half: the exclusions above are only cheap because the lookup does
    // not happen at all where no row asked for one.
    let dir = Fixture::new("claim-no-row")
        .config("version = 1\n")
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    assert_allowed(&dir, "src/tracked.rs");
}
