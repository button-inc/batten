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
//!
//! # The conformance fixture every retirement tier imports (CLOUD-761)
//!
//! CLOUD-1142 landed the DEFINITION — `ready::Grammar::key_of` and `keys_in`,
//! the three axes decided (case sensitive, the explicit character-class
//! boundary, the project prefix mandatory). What it could not land is the
//! obligation: nineteen governed shell consumers still re-derive the key, each
//! retires whole under CLOUD-1164, and its successor's tier has to be held to
//! the same seven examples rather than to whichever ones its author remembered.
//!
//! [`conformance`] is that set, exported so a successor tier IMPORTS it. A tier
//! that re-types the examples is a twentieth derivation wearing a test's
//! clothes: it can drift from this one silently, and the drift is invisible
//! precisely because both files are green.
//!
//! **The reader under test is the engine's, resolved from the COMMITTED table**
//! (`Grammar::resolve(&common::committed_patterns())`), never a fixture
//! expression. `Grammar::committed()` states the reason for the in-crate half
//! and it holds here: a fixture would let the `[[pattern]] ready-issue-key` row
//! change while every case below kept passing, which is the drift one definition
//! exists to remove.
//!
//! # The declared mutation, and why the row is in THIS file
//!
//! `obligations-bound` binds a §7 obligation by reading the declared file's
//! lines for a row beginning `#MUTANT <slug>|`, and its `line_sources` covers
//! `crates/batten/tests/**` and not `crates/batten/src/**` — so the row lives
//! here even though the expression it applies belongs to `ready.rs`'s reader.
//! It is a block comment because the match is on a line PREFIX and Rust has no
//! line comment starting with `#`. The same row is declared beside the reader in
//! `crates/batten/src/ready.rs`, where `engine-ready` resolves it, so
//! `mise run mutant` APPLIES it rather than only binding it — the gap
//! `crates/batten/tests/it/commit_arm_sequencing.rs` records for its own row.

/*
#MUTANT-SUITE crates/batten/tests/it/issue_key.rs
#MUTANT case-insensitive-key-accepted|s@^            Regex::new(&row.regex)@            Regex::new(\&format!("(?i){}", row.regex))@|the_committed_reader_refuses_the_lowercase_spelling
*/
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
    run_with_stdin(dir, &["hook", "--harness", "exit-code"], &payload(command))
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
        &["hook", "--harness", "exit-code"],
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
        &["hook", "--harness", "exit-code"],
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

/// One conformance example: a subject, whether the WHOLE of it is a key, and how
/// many keys the subject CONTAINS.
///
/// Both questions, because they are different ones and the four shell `case`
/// globs conflate them. `<PREFIX>-1x` is not a key and carries one; a glob
/// answering "is this a key" by matching a prefix cannot tell those apart, which
/// is why it accepts the string outright.
pub(crate) struct KeyExample {
    /// The text the reader is asked about.
    pub subject: String,
    /// Whether `key_of` resolves the whole subject.
    pub whole_key: bool,
    /// How many keys `keys_in` finds in it.
    pub contains: usize,
}

/// The consumer's own key, spelled from parts so this file carries no derivation
/// of the token.
///
/// `no-tracker-key-in-core` refuses one anywhere under `crates/**`, and a test is
/// not exempt from the rule it is testing — the same dodge `tests/it/cli.rs`
/// uses to seed the banned shapes it asserts on.
pub(crate) fn key(n: u32) -> String {
    format!("{}-{n}", "CL".to_owned() + "OUD")
}

/// The committed grammar, resolved the way a consumer's run resolves it.
///
/// `Grammar::committed()` is `#[cfg(test)]` and therefore unreachable from this
/// target, so the route is the public one over the committed `[[pattern]]`
/// table. That is not a workaround: reading the shipped table is what makes a
/// registry row's drift red HERE rather than only in the crate's own unit tests.
pub(crate) fn committed_grammar() -> batten::ready::Grammar {
    batten::ready::Grammar::resolve(&common::committed_patterns())
        .expect("the committed pattern table resolves a ready grammar")
}

/// CLOUD-761's fixed example set, exported for the retirement tiers that succeed
/// the nineteen shell consumers.
///
/// Each row is a site that behaves DIFFERENTLY today: the four `case` globs
/// (`[A-Z]*-[0-9]*`) accept `AB-1`, `Z-9` and `A-1foo`; five sites match
/// case-insensitively and normalise up, which is the shipped defect — a body
/// writing the lowercase spelling is accepted by one gate and invisible to two
/// others; and two landed sites commented the short-key-inside-a-long-one case
/// by name while spelling the boundary two different ways.
///
/// A successor tier imports this rather than re-typing it. Re-typing is how a
/// twentieth derivation arrives, and it arrives green.
pub(crate) fn conformance() -> Vec<KeyExample> {
    vec![
        // The positive arm, first: without it every refusal below is satisfied
        // by a definition that refuses everything.
        KeyExample {
            subject: key(757),
            whole_key: true,
            contains: 1,
        },
        // CASE: SENSITIVE. Refused rather than normalised.
        KeyExample {
            subject: key(757).to_lowercase(),
            whole_key: false,
            contains: 0,
        },
        // PROJECT PREFIX: MANDATORY. All three are accepted by a glob, which
        // cannot anchor.
        KeyExample {
            subject: "AB-1".to_owned(),
            whole_key: false,
            contains: 0,
        },
        KeyExample {
            subject: "Z-9".to_owned(),
            whole_key: false,
            contains: 0,
        },
        KeyExample {
            subject: "A-1foo".to_owned(),
            whole_key: false,
            contains: 0,
        },
        // Not a key, and it CONTAINS one — the pair a glob collapses.
        KeyExample {
            subject: format!("{}x", key(1)),
            whole_key: false,
            contains: 1,
        },
        // BOUNDARY: the greedy match takes the whole number, so the short key
        // never appears inside the long one.
        KeyExample {
            subject: key(179),
            whole_key: true,
            contains: 1,
        },
    ]
}

#[test]
fn the_committed_reader_decides_every_conformance_example() {
    // The whole set through the engine's own reader, in one case, because the
    // obligation a successor tier inherits is the SET rather than any one arm.
    let grammar = committed_grammar();
    for example in conformance() {
        assert_eq!(
            grammar.key_of(&example.subject).is_some(),
            example.whole_key,
            "`key_of` disagrees about {}",
            example.subject
        );
        assert_eq!(
            grammar.keys_in(&example.subject).len(),
            example.contains,
            "`keys_in` disagrees about {}",
            example.subject
        );
    }
}

#[test]
fn the_committed_reader_refuses_the_lowercase_spelling() {
    // THE DECLARED MUTATION'S CASE. Stated on its own rather than left inside
    // the loop above: `mutate` selects a case by substring, so the arm the
    // mutation must redden has to be nameable.
    //
    // The shipped defect CLOUD-761 measured is exactly this spelling — one gate
    // accepts it, two others cannot find it, and nothing says so.
    let grammar = committed_grammar();
    assert!(
        grammar.key_of(&key(757).to_lowercase()).is_none(),
        "the lowercase spelling is refused, never normalised"
    );
    assert!(
        grammar.keys_in(&key(757).to_lowercase()).is_empty(),
        "and it is not found inside a span either"
    );
    // ANTI-VACUITY, in the same case: a reader that refused everything would
    // satisfy the assertions above. The mutation must leave this green.
    assert!(
        grammar.key_of(&key(757)).is_some(),
        "the consumer's own key still parses"
    );
}

#[test]
fn a_shorter_key_is_not_found_inside_a_longer_one() {
    // The case two landed sites commented on by name, and the one the exported
    // set can only express as a count. A successor tier asking "does this text
    // carry key K" compares against `keys_in` rather than searching again — the
    // derivation this definition removes rather than adds.
    let grammar = committed_grammar();
    let found = grammar.keys_in(&key(179));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].as_str(), key(179));
    assert!(
        !found.iter().any(|k| k.as_str() == key(17)),
        "the short key is not inside the long one"
    );
}
