//! The tracker-key gate over the compiled binary, in real checkouts (CLOUD-446).
//!
//! This is the naming half of `tests/issue-guard.bats`, translated into the
//! surface that now decides it: a `shape` row carrying `requires_key`. The guard
//! itself is **not** deleted by this change — it still carries the duplicate-claim
//! half, which needs a network call no mediated rule kind can make — so this file
//! is not yet that suite's replacement, only its port of the half that moved.
//!
//! **The allows are the load-bearing half.** Three evidence sources each
//! correspond to a way real work legitimately carries its key: typed into the
//! command, in the branch name the tracker generated, or in a commit written
//! along the way. A rule that recognised only one of the three would refuse most
//! honest publishing and be bypassed inside a day — and a bypassed gate enforces
//! nothing. So would one that refused outside a checkout, where the hook has no
//! evidence to read at all. A suite asserting only the deny passes on every one
//! of those rules.
//!
//! Fixture repositories rather than the checkout this runs in, because every
//! evidence source is a property of a real one: a branch, a commit range, an
//! `origin/main` to read it since. A separate target rather than more of
//! `tests/cli.rs`, on `tests/claim_receipt.rs`'s precedent.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, run_with_stdin, scratch_outside_tree, stderr};

/// The policy under test: the committed rows' shape, with nothing else declared.
///
/// Written here rather than read from the repository's own `batten.toml` for
/// `claim_receipt.rs`'s reason — these cases are about the *modifier*, and a
/// fixture inheriting real policy would be adjudicating this repo's protected
/// paths alongside them. The committed rows are pinned by the census in
/// `tests/cli.rs`.
///
/// The expression is the consumer's, and this fixture proves it: `TEST-<n>` is
/// nothing the crate has heard of, and it gates exactly as `CLOUD-<n>` does in
/// `batten.toml`. A crate that had baked in one tracker's vocabulary would fail
/// every case below (non-negotiable rule 1).
const POLICY: &str = r#"version = 1

[[rule]]
id = "pr-names-an-issue"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr create"
requires_key = '(?i)\bTEST-[0-9]+\b'
base = "origin/main"
reason = "name the issue in the branch, a commit, or the body"

[[rule]]
id = "ready-names-an-issue"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr ready"
requires_key = '(?i)\bTEST-[0-9]+\b'
base = "origin/main"
reason = "name the issue in the branch or a commit before readying"
"#;

/// A repository whose base commit carries the policy, on a branch named `branch`
/// with one commit whose subject is `subject`.
///
/// The base commit is deliberately outside the range: `origin/main` points at it,
/// so a key that appeared only there would be evidence about somebody else's
/// work. Every fixture below relies on that — the branch's commits are the only
/// ones the gate reads.
fn repo(name: &str, branch: &str, subject: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(POLICY)
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", branch]);
    git_in(&dir, &["commit", "-q", "--allow-empty", "-m", subject]);
    dir
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

fn verdict(dir: &Path, command: &str) -> Option<i32> {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload(command),
    )
    .status
    .code()
}

fn assert_denied(dir: &Path, command: &str) {
    assert_eq!(verdict(dir, command), Some(2), "must refuse: {command}");
}

fn assert_allowed(dir: &Path, command: &str) {
    assert_eq!(verdict(dir, command), Some(0), "must allow: {command}");
}

#[test]
fn work_naming_no_key_anywhere_is_refused() {
    // The predicate itself: a branch, a commit and a command that between them
    // mention no tracker key at all.
    let dir = repo("key-deny", "user/some-slug", "chore: tidy up");
    assert_denied(&dir, "gh pr create --title 'tidy up' --body 'no key here'");
}

#[test]
fn readying_work_naming_no_key_is_refused_too() {
    // The second publishing moment, and the one the bash guard reached only by
    // reading the PR over the network: `gh pr ready` carries no body of its own,
    // so the branch and the commits are all the evidence there is.
    let dir = repo("ready-deny", "user/some-slug", "chore: tidy up");
    assert_denied(&dir, "gh pr ready");
}

#[test]
fn a_key_in_the_branch_alone_allows() {
    // The commonest honest shape by far: the tracker generates the branch name,
    // and neither the commit subject nor the command repeats it.
    //
    // LOWER CASE, and that is the case that matters rather than an incidental
    // choice: `gitBranchName` produces `user/test-123-...`, so an expression
    // without `(?i)` leaves this source dead for every branch anyone actually
    // has — a gate that loads, matches, and refuses honest work. `issue-guard`
    // matched case-insensitively for the same reason.
    let dir = repo("key-branch", "user/test-123-the-slug", "chore: tidy up");
    assert_allowed(&dir, "gh pr create --title 'tidy up' --body 'no key here'");
    assert_allowed(&dir, "gh pr ready");
}

#[test]
fn a_key_in_a_commit_alone_allows() {
    // Work committed under a Conventional-Commits subject that cites the issue,
    // on a branch named for the change rather than the ticket.
    let dir = repo("key-commit", "user/some-slug", "fix(hook): close TEST-123");
    assert_allowed(&dir, "gh pr create --title 'tidy up' --body 'no key here'");
    assert_allowed(&dir, "gh pr ready");
}

#[test]
fn a_key_in_the_command_alone_allows() {
    // The evidence source that needs no checkout read at all — and the one that
    // answers for the case the bash guard used `gh pr view` to reach.
    let dir = repo("key-command", "user/some-slug", "chore: tidy up");
    assert_allowed(
        &dir,
        "gh pr create --title 'tidy up' --body 'Closes TEST-9'",
    );
}

#[test]
fn a_key_only_on_the_base_commit_does_not_count() {
    // The narrowing `base` exists for. `origin/main` is full of other people's
    // keys; reading the whole history would allow every PR forever, which is a
    // gate that loads, matches, and decides nothing.
    let dir = Fixture::new("key-base-only")
        .config(POLICY)
        .file("src/tracked.rs", "// committed\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(
        &dir,
        &["commit", "-q", "-m", "feat: land TEST-1 on the trunk"],
    );
    git_in(&dir, &["branch", "-M", "main"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(&dir, &["checkout", "-q", "-b", "user/some-slug"]);
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "chore: tidy"],
    );
    assert_denied(&dir, "gh pr create --title 'tidy' --body 'no key'");
}

#[test]
fn a_command_the_row_does_not_select_is_untouched() {
    // The selection half is unchanged by the modifier: these are not `gh pr
    // create` or `gh pr ready`, so no amount of missing key makes them a
    // refusal. Read-only `gh` is what an agent uses to FIND the issue it is
    // being asked to name, so denying it would make the remedy unreachable.
    let dir = repo("key-unselected", "user/some-slug", "chore: tidy up");
    for command in [
        "gh pr view 42",
        "gh pr list --state open",
        "gh issue list",
        "git commit -m 'chore: tidy up'",
    ] {
        assert_allowed(&dir, command);
    }
}

#[test]
fn outside_a_checkout_the_gate_allows() {
    // Could not look, so no answer — the fail-open posture every retiring guard
    // has. A hook registered once and then run in whatever directory the agent
    // is in must not become the reason a call cannot proceed where it governs
    // nothing.
    //
    // Outside this repository's tree, because `target/` is inside it: a fixture
    // under `target/tmp` has a repository root — this one — and the gate would
    // correctly read its branch and commits. That is the hook working, not the
    // case under test.
    let dir = Fixture::at(scratch_outside_tree("batten-issue-key", "no-checkout"))
        .config(POLICY)
        .build();
    assert_allowed(&dir, "gh pr create --title 'tidy' --body 'no key'");
}

#[test]
fn an_unresolvable_base_allows() {
    // Same reading, different cause: a repository with no `origin/main` has no
    // range to read commit evidence over. Falling back to the branch name alone
    // would be a narrowing nobody wrote, and refusing would make a fresh clone
    // un-publishable.
    let dir = Fixture::new("key-no-base")
        .config(POLICY)
        .file("src/tracked.rs", "// committed\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: tidy up"]);
    git_in(&dir, &["checkout", "-q", "-b", "user/some-slug"]);
    assert_allowed(&dir, "gh pr create --title 'tidy' --body 'no key'");
}

#[test]
fn a_detached_head_still_reads_its_commits() {
    // A detached HEAD loses one evidence source, not all of them: there is no
    // branch name, and the commits on the range still answer. Treating the
    // missing branch as "could not look" would switch the gate off for every
    // rebase and bisect.
    let dir = repo("key-detached", "user/some-slug", "fix(hook): close TEST-7");
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    git_in(&dir, &["checkout", "-q", "--detach", head.trim()]);
    assert_allowed(&dir, "gh pr create --title 'tidy' --body 'no key'");

    let unkeyed = repo("key-detached-unkeyed", "user/some-slug", "chore: tidy up");
    let head = git_in(&unkeyed, &["rev-parse", "HEAD"]);
    git_in(&unkeyed, &["checkout", "-q", "--detach", head.trim()]);
    assert_denied(&unkeyed, "gh pr create --title 'tidy' --body 'no key'");
}

#[test]
fn a_shallow_clone_cannot_answer_and_therefore_allows() {
    // THE CASE CI MEASURED, and the reason it is a regression test rather than a
    // completeness case. `ci.yml` fetches its ratchet base with `git fetch
    // --depth=1 origin main` and `actions/checkout` takes the head at the same
    // depth, so `origin/main..HEAD` there holds a synthetic commit and none of
    // the branch's own. The first version of this rule read that view as "the
    // work names no key" and refused every PR in CI — a confident answer from a
    // partial fetch, which is the failure mode the whole `None` = could-not-look
    // posture exists to prevent.
    //
    // The source repository is deliberately keyless AND its clone shallow, so a
    // rule that lost only the truncation check would still deny here.
    let source = repo("key-shallow-source", "user/some-slug", "chore: tidy up");
    let dir = scratch_outside_tree("batten-issue-key", "shallow");
    std::fs::remove_dir_all(&dir).expect("clear the clone target");
    let url = format!("file://{}", source.to_str().expect("utf-8 fixture path"));
    git_in(
        source.parent().expect("fixture has a parent"),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &url,
            dir.to_str().expect("utf-8 clone path"),
        ],
    );
    // The base has to resolve, or the allow would come from the unresolvable-base
    // path and prove nothing about truncation.
    git_in(&dir, &["fetch", "-q", "--depth", "1", "origin", "main"]);
    git_in(
        &dir,
        &["update-ref", "refs/remotes/origin/main", "FETCH_HEAD"],
    );
    assert_eq!(
        git_in(&dir, &["rev-parse", "--is-shallow-repository"]).trim(),
        "true",
        "the fixture must actually be shallow, or this asserts nothing"
    );
    assert_allowed(&dir, "gh pr create --title 'tidy' --body 'no key'");
}

#[test]
fn the_refusal_names_the_route_and_leaks_no_evidence() {
    let dir = repo(
        "key-refusal",
        "user/some-slug",
        "chore: tidy up the widget factory",
    );
    let refusal = stderr(&run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload("gh pr create --title 'tidy' --body 'no key'"),
    ));
    assert!(
        refusal.contains("pr-names-an-issue"),
        "names the rule: {refusal}"
    );
    // WHAT IS MISSING IS THE CLASS (CLOUD-1286): `issue name missing` says the
    // key is absent rather than that the shape is banned, in three words, and it
    // is a name a reader can look up. The sentence that used to say it, and the
    // places to put a key, are what `batten policy explain` prints.
    assert!(
        refusal.contains("issue name missing"),
        "says what is missing rather than that the shape is banned: {refusal}"
    );
    let explained = run(&dir, &["policy", "explain", "pr-names-an-issue"]);
    assert_eq!(explained.status.code(), Some(0), "the row resolves");
    assert!(
        String::from_utf8_lossy(&explained.stdout).contains("branch"),
        "and the hop names a place to put one"
    );
    // CLOUD-403 measured that the bash guard's deny text advertised no reachable
    // hatch, and CLOUD-437 that advertising one on every deny was itself the
    // defect. CLOUD-1286 settles it: the hatch is not advertised at all, because
    // the sentence was byte-identical on every firing of every row.
    assert!(
        !refusal.contains("Bypass with"),
        "and the hatch sentence is off the hot path: {refusal}"
    );
    // Pointer-only (non-negotiable rule 4). The gate read the branch name and
    // every commit message on the range; the refusal must quote none of them.
    assert!(
        !refusal.contains("widget factory"),
        "a commit message must not reach the refusal: {refusal}"
    );
    assert!(
        !refusal.contains("user/some-slug"),
        "the branch NAME is evidence too, and is not the pointer: {refusal}"
    );
}

#[test]
fn a_requires_key_row_without_a_base_is_a_load_error() {
    // The column pair is validated at load rather than discovered at
    // adjudication, because a row missing `base` would silently fall back to the
    // branch name alone — a narrowing nobody wrote, reached by omission.
    let dir = Fixture::new("key-no-base-column")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"pr-names-an-issue\"\n\
             kind = \"shape\"\n\
             scope = \"mediated_call\"\n\
             severity = \"deny\"\n\
             pattern = \"gh pr create\"\n\
             requires_key = '(?i)\\bTEST-[0-9]+\\b'\n\
             reason = \"name the issue\"\n",
        )
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    let output = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload("gh pr create --title 'tidy' --body 'no key'"),
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a malformed row is a usage error, never a deny: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("requires `base`"),
        "the refusal names the missing column: {}",
        stderr(&output)
    );
}
