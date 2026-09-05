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

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, run_with_stdin, stderr, stdout, write};

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
        &["adjudicate", "--harness", "exit-code"],
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
fn the_refusal_names_the_check_and_the_keying() {
    let dir = repo("claim-refusal");
    let refusal = stderr(&run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    ));
    assert!(
        refusal.contains("claim-needs-receipt"),
        "names the rule: {refusal}"
    );
    assert!(refusal.contains("branch"), "names the keying: {refusal}");
    // The ROUTE (`mise run claim-check`) is the class's declared remedy and is
    // one `batten policy explain` away since CLOUD-1286: it is the same string
    // on every firing, so inlining it was pure repetition. The CHECK whose
    // receipt is missing does vary, so it stays — and it is what turns "refused"
    // into something a reader can act on.
    assert!(
        refusal.contains("claim"),
        "names the check rather than only refusing: {refusal}"
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
    let output = run_with_stdin(&dir, &["adjudicate", "--harness", "exit-code"], payload);
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

// --- the same predicate, reached from the tree surface (CLOUD-741) -----------
//
// Everything above asks the ENGINE, through `batten hook`. `verify` cannot ask
// that way: `RuleKind::scopes` pins `RuleKind::Receipt` to the mediated call, so
// `batten check` can never evaluate a receipt row, and the tree surface had
// re-implemented the question in shell as `[ -f "$claim_receipt" ]`.
//
// A presence test is strictly weaker than the engine's reader, so the restart
// case above — the very incident CLOUD-516 was filed for — passed `verify` while
// the hook refused it. And because that hook can be unloaded (CLOUD-187), the one
// scenario the shell check existed for was also the one where nothing could see
// staleness at all.
//
// These rows are what stops the two coming apart again: they drive `receipt
// status --key branch` over the SAME fixtures as the hook cases and assert the
// two readers reach the same verdict. Written as a pair per state rather than
// asserting the CLI alone, because "they agree" is the property, not "the CLI
// answers".

/// The pointer line and exit code of `receipt status --key branch` in `dir`.
fn branch_status(dir: &Path) -> (Option<i32>, String) {
    let output = run(dir, &["receipt", "status", "claim", "--key", "branch"]);
    (output.status.code(), stdout(&output))
}

#[test]
fn the_tree_surface_reads_the_same_receipt_the_hook_does() {
    let dir = repo("status-valid");
    mint(&dir, "user/cloud-444-slug");
    let (code, line) = branch_status(&dir);
    assert_eq!(code, Some(0), "a valid claim exits clean: {line}");
    assert!(line.contains("valid"), "names the verdict: {line}");
    assert!(
        line.contains("user/cloud-444-slug"),
        "the subject is the BRANCH under this keying, not a SHA: {line}"
    );
    // And the hook agrees, which is the whole point of the row.
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn an_absent_claim_is_a_violation_on_the_tree_surface_too() {
    let dir = repo("status-missing");
    let (code, line) = branch_status(&dir);
    assert_eq!(code, Some(2), "no receipt is a policy verdict: {line}");
    assert!(
        line.contains("missing"),
        "`missing` is the remedy 'mint one', distinct from `stale-main`: {line}"
    );
    assert_denied(&dir, "src/tracked.rs");
}

#[test]
fn the_restart_that_used_to_pass_verify_is_now_refused_by_it() {
    // THE ROW THIS ISSUE EXISTS FOR. Identical setup to
    // `a_branch_restarted_after_its_pr_merged_carries_no_usable_claim`, asked of
    // the surface `verify` actually calls. Before CLOUD-741 the shell check saw a
    // file on disk and passed, so a restarted branch could be verified, readied
    // and landed carrying a claim for an unrelated issue.
    let dir = repo("status-restarted");
    mint(&dir, "user/cloud-444-slug");
    write(&dir, "src/tracked.rs", "// landed\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "landed work"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(
        &dir,
        &["checkout", "-q", "-B", "user/cloud-444-slug", "origin/main"],
    );

    let (code, line) = branch_status(&dir);
    assert_eq!(code, Some(2), "the restart is refused: {line}");
    assert!(
        line.contains("stale-main"),
        "`stale-main` is what tells a re-claim apart from a first claim: {line}"
    );
    assert!(
        !line.contains("missing"),
        "the receipt EXISTS; reporting it absent would send the reader to the wrong remedy: {line}"
    );
    assert_denied(&dir, "src/tracked.rs");
}

#[test]
fn a_lap_that_rebases_onto_newer_main_still_passes_the_tree_surface() {
    // The false-positive direction, and the one a careless fix breaks: `land`
    // rebases every lap, so voiding on a moved base alone would demand a
    // re-claim per lap and get the gate bypassed. Asserted on both surfaces for
    // the same reason the deny is.
    let dir = repo("status-lap");
    let stale = git_in(&dir, &["rev-parse", "origin/main"]);
    mint_against(&dir, "user/cloud-444-slug", stale.trim());
    write(&dir, "src/tracked.rs", "// in flight\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "work in flight"]);
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "someone else landed"],
    );
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD~1"]);

    let (code, line) = branch_status(&dir);
    assert_eq!(code, Some(0), "a rebase lap is not a re-claim: {line}");
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn the_sha_keying_is_untouched_by_the_new_flag() {
    // `--key` was added to an existing verb, so the contract that matters most is
    // the one for callers who supply nothing. `receipt record`/`status` without a
    // key must judge the SHA-keyed receipt exactly as before, and the subject it
    // names must still be a commit.
    let dir = repo("status-head-default");
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    let output = run(&dir, &["receipt", "status", "verify"]);
    let line = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "no SHA-keyed receipt was recorded: {line}"
    );
    assert!(
        line.contains(head.trim()),
        "the default keying still names HEAD: {line}"
    );
}

#[test]
fn a_detached_head_cannot_answer_and_says_so_rather_than_refusing() {
    // `branch_facts` returns "could not look", and the CLI must not launder that
    // into a verdict: a rebase detaches, so answering `missing` here would make
    // every rebase read as an unclaimed branch and stop `land` on its own loop.
    // Exit 3 is the engine's internal code — distinct from the 2 a real refusal
    // carries, which is what lets `verify` map the two differently.
    let dir = repo("status-detached");
    mint(&dir, "user/cloud-444-slug");
    git_in(&dir, &["checkout", "-q", "--detach", "HEAD"]);
    let output = run(&dir, &["receipt", "status", "claim", "--key", "branch"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "could not look is not a verdict: {}",
        stderr(&output)
    );
    // And the hook's own carve-out is unchanged.
    assert_allowed(&dir, "src/tracked.rs");
}

// --- the alternation (CLOUD-1297) -------------------------------------------

/// The same row, spelled as an alternation instead of a conjunction.
///
/// A SEPARATE POLICY CONSTANT rather than a mutation of [`POLICY`], because the
/// two spellings must both keep working: every case above drives the conjunction
/// and every case below drives the alternation, and folding them into one
/// fixture would leave whichever spelling the fixture did not use untested.
const ALTERNATION: &str = r#"version = 1

[[rule]]
id = "claim-needs-receipt"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
trigger = "write"
checks_any = ["claim", "bot", "carry"]
key = "branch"
reason = "pipe the issue payload to `mise run claim-check`"
"#;

/// [`repo`]'s twin over [`ALTERNATION`], identical in every other respect.
fn alternation_repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(ALTERNATION)
        .file(".gitignore", "scratch/\n")
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", "user/cloud-444-slug"]);
    dir
}

/// [`mint_against`] over an arbitrary receipt KIND, which is the axis these
/// cases vary.
fn mint_kind(dir: &Path, kind: &str, branch: &str) {
    let git_dir = git_in(dir, &["rev-parse", "--absolute-git-dir"]);
    let receipts = PathBuf::from(git_dir.trim()).join("batten-receipts");
    std::fs::create_dir_all(&receipts).expect("create the receipt store");
    let base = git_in(dir, &["rev-parse", "origin/main"]);
    std::fs::write(
        receipts.join(format!("{kind}.{}", branch.replace('/', "-"))),
        format!("CLOUD-1297\nready-lint pass\nbase {}\n", base.trim()),
    )
    .expect("mint the receipt");
}

#[test]
fn any_one_of_the_alternatives_vouches_for_the_branch() {
    // The defect CLOUD-1297 closes, driven once per alternative. `bot` and
    // `carry` are the two that were denied while valid: `verify` accepted them
    // all along and this row accepted only `claim`, so an agent on a bot branch
    // met a refusal holding a real attestation.
    //
    // ALL THREE ARE DRIVEN, including `claim`. The alternation must not merely
    // admit the new kinds — it must still admit the one the conjunction
    // admitted, and a suite that checked only the additions would pass over a
    // column that had silently replaced the original.
    for kind in ["claim", "bot", "carry"] {
        let dir = alternation_repo(&format!("alternation-{kind}"));
        mint_kind(&dir, kind, "user/cloud-444-slug");
        assert_allowed(&dir, "src/tracked.rs");
    }
}

#[test]
fn an_alternation_with_no_receipt_at_all_is_still_refused() {
    // THE VACUITY CASE, and the one this column most needs. An alternation is
    // satisfied by any member, so the way it fails is by being satisfied by
    // nothing at all — an allow wearing a gate's name. The row must deny a
    // branch carrying none of the three exactly as the conjunction did.
    let dir = alternation_repo("alternation-vacuity");
    assert_denied(&dir, "src/tracked.rs");
}

#[test]
fn a_receipt_of_a_kind_the_alternation_does_not_name_does_not_vouch() {
    // The other half of the vacuity question: the alternation admits the kinds
    // it NAMES, not any receipt that happens to sit in the store. Without this,
    // a bug that read "some receipt exists" would pass every case above.
    let dir = alternation_repo("alternation-unnamed-kind");
    mint_kind(&dir, "verify", "user/cloud-444-slug");
    assert_denied(&dir, "src/tracked.rs");
    // And a named kind on the same branch IS admitted, so the refusal above is
    // about which kind was minted rather than about an unreadable store.
    mint_kind(&dir, "carry", "user/cloud-444-slug");
    assert_allowed(&dir, "src/tracked.rs");
}

#[test]
fn an_alternative_minted_for_another_branch_does_not_vouch_for_this_one() {
    // The keying still applies to every member. An alternation that dropped the
    // branch check for its new kinds would be a wider hole than the false
    // positive it was added to close.
    let dir = alternation_repo("alternation-other-branch");
    mint_kind(&dir, "bot", "user/some-other-branch");
    assert_denied(&dir, "src/tracked.rs");
}

#[test]
fn the_alternations_refusal_names_every_alternative_and_its_verdict() {
    // A failed conjunction has one thing to go and do; a failed alternation has
    // several, any of which clears it. A refusal naming only the first would
    // send a reader to mint a `claim` on a branch where minting a `carry` was
    // the right move and half the work.
    let dir = alternation_repo("alternation-refusal");
    let refusal = stderr(&run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    ));
    for kind in ["claim", "bot", "carry"] {
        assert!(
            refusal.contains(kind),
            "names the `{kind}` alternative: {refusal}"
        );
    }
    assert!(
        refusal.contains("missing"),
        "names each alternative's verdict: {refusal}"
    );
    // Pointer-only (non-negotiable rule 4): a receipt's contents never reach the
    // refusal, and the fixture plants a distinctive one to prove it.
    assert!(
        !refusal.contains("CLOUD-1297"),
        "a refusal must not echo a receipt's contents: {refusal}"
    );
}
