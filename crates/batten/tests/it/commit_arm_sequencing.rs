//! An escape hatch is not spent by the commit that creates it (CLOUD-1402).
//!
//! # What this tier is for
//!
//! `[rule.conserves]`'s arms are the ledger a ratchet decrease has to satisfy,
//! and two of them are optional — `withdrawn` (CLOUD-1080) and `ported`
//! (CLOUD-1268). Adding one widens what a deletion may claim, which is exactly
//! the kind of change that wants an independent reader.
//!
//! It did not get one. `65757c86` both added `withdrawn` to `batten.toml` and
//! *spent* it, in the same commit, on the deletion it wanted to make. An escape
//! hatch created and consumed at once is self-authorizing: the thing that would
//! have refused the deletion was authored by the same change. That first use
//! shipped a partly-wrong deletion — it retired the `NO_PROXY` fencing on the
//! reasoning that honouring the environment's CA bundle made it unnecessary,
//! which conflates TLS re-termination with the proxy's injected-token 403 — and
//! the reasoning stood unrefuted in the history for a week (CLOUD-1399).
//!
//! # Over the compiled binary, and that is the whole discriminator
//!
//! `.claude/rules/policy-modules.md`'s second tier, one surface over. The unit
//! tests in `commit.rs` pin the predicate over two sets a test constructed, and
//! cannot see whether the resolver builds them: whether the config at a commit's
//! PARENT is read at all, whether `[rule.conserves]` survives that parse, and
//! whether a ledger line the commit added is distinguished from one that was
//! already there. Every one of those is a shape a `with input as` equivalent
//! would fabricate.
//!
//! `a_commit_that_adds_an_arm_and_spends_it_is_refused` is the premise case that
//! closes it: without a case asserting the refusal happens, the four admitting
//! cases are satisfied by a clause that never fired.
//!
//! # The real commit, replayed — and why it is not a case here
//!
//! `BASE_SHA='65757c86^' HEAD_SHA=65757c86 mise run commit-check` reports
//! `65757c86 arm-self-authorized bats-tests-not-deleted.withdrawn`, which is
//! CLOUD-1402's Done clause satisfied over this repository's own history rather
//! than over a fixture.
//!
//! It stays a recorded measurement instead of a case, because a case naming a
//! SHA asserts how deep the clone is. `linear-check` deepens a shallow clone and
//! nothing else promises to, so such a case would pass locally and fail — or
//! worse, could-not-look green — on a runner that fetched less history. The
//! fixtures below pin the predicate; that command is the evidence it reaches the
//! commit it was written for.
//!
//! # The declared mutation, and why the row is in THIS file
//!
//! `obligations-bound` binds a §7 obligation by reading the declared file's lines
//! for a row beginning `#MUTANT <slug>|`. Its `line_sources` covers
//! `crates/batten/tests/**` and not `crates/batten/src/**`, so the row has to be
//! here even though the expression it applies belongs to `commit.rs`'s predicate
//! — the same split `.rego` modules already have, where `#MUTANT-SUITE` names a
//! suite somewhere else entirely.
//!
//! It is a block comment because the match is on a line PREFIX and Rust has no
//! line comment that starts with `#`. Written first as a prose mention in this
//! header, it did not bind and `obligation-unbound` fired — correctly.
//!
//! **What the row does NOT yet buy is the sweep, and saying so is the point.**
//! `mutate`'s `Gate::name` resolves sources from a task name, a module stem or a
//! preset name; there is no arm for a Rust source, so `mutate sweep` never
//! applies this. CLOUD-1369 owes that arm, and `crates/batten/src/pinned.rs`
//! records the identical gap. Until it lands the named case is proven by
//! `verify` rather than by a survivor.

/*
#MUTANT same-commit-spend-passes|s@                .any(|line| line.trim_start().starts_with(token.as_str()))@                .any(|_unread| false)@|a_commit_that_adds_an_arm_and_spends_it_is_refused
*/
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, stdout, write};

/// The file under the ledger's `declared_in` glob, where an arm row is written.
const LEDGER: &str = "successors/alpha.rs";

/// A suite under the ratchet's own glob, so the fixture's rule is not vacuous.
const SUITE: &str = "suites/alpha.t";

/// The pointer the refusal names: the rule id and the arm, as a config path.
const POINTER: &str = "arm-self-authorized suites-not-gutted.withdrawn";

/// The arm token this suite introduces and spends.
///
/// The real spelling rather than a placeholder: the whole predicate is a prefix
/// match on what the config declares, so a token that looked nothing like a
/// comment would pass for a reason no consumer shares.
const ARM_TOKEN: &str = "// withdrawn:";

/// A ledger row spending the arm.
const ARM_ROW: &str = "// withdrawn: \"one\" the subject is gone\n";

/// The fixture's config, with `withdrawn` present only when asked for.
///
/// `[commit]` is present because `commit check` refuses a config without one
/// before it reaches any clause — a fixture omitting it would exit 1 and every
/// case would read that as its own verdict.
///
/// `conserves` requires `retires_with`, which requires `base`, so all three are
/// here: a rule that admits no decrease has no deletion to map, and the loader
/// says so rather than accepting a table that decides nothing.
fn config(withdrawn: bool) -> String {
    let arm = if withdrawn {
        format!("withdrawn = \"{ARM_TOKEN}\"\n")
    } else {
        String::new()
    };
    format!(
        "version = 1\n\n\
         [commit]\nsubject_pattern = \"^(feat|fix|chore)(\\\\(.+\\\\))?!?: .+\"\n\n\
         [[rule]]\n\
         id = \"suites-not-gutted\"\n\
         kind = \"ratchet\"\n\
         glob = \"suites/**/*.t\"\n\
         pattern = \"@case \"\n\
         direction = \"non_decreasing\"\n\
         base = \"main\"\n\
         severity = \"deny\"\n\
         retires_with = \"# subject:\"\n\n\
         [rule.conserves]\n\
         case = \"@case \\\"\"\n\
         close = \"\\\"\"\n\
         carried = \"// carried:\"\n\
         subsumed = \"// subsumed:\"\n\
         changed = \"// changed:\"\n\
         declared_in = \"successors/*.rs\"\n\
         {arm}"
    )
}

/// A fixture whose base commit carries `withdrawn` or does not, and one ledger
/// file already tracked so a later commit EDITS it rather than creating it.
fn fixture(name: &str, withdrawn: bool) -> PathBuf {
    Fixture::new(name)
        .config(&config(withdrawn))
        .files(&[
            (SUITE, "# subject: programs/alpha\n@case \"one\" {\n"),
            (LEDGER, "// the successors of the alpha suite\n"),
        ])
        .git()
        .base_commit()
        .build()
}

/// Commit everything staged in `dir` with `message`.
///
/// No `--no-verify` is needed: a fixture repository has no hooks installed, so
/// the commit under test is created without this clause having a say. That is the
/// point — the case judges it afterwards, the way the range tier in CI does.
fn commit(dir: &Path, message: &str) {
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", message]);
}

/// `batten commit check <range>`, as (exit code, stdout).
fn check(dir: &Path, range: &str) -> (Option<i32>, String) {
    let output = run(dir, &["commit", "check", range]);
    (output.status.code(), stdout(&output))
}

// ---------------------------------------------------------------------------
// The premise: the refusal happens.
// ---------------------------------------------------------------------------

#[test]
fn a_commit_that_adds_an_arm_and_spends_it_is_refused() {
    // THE REGRESSION THIS CLAUSE EXISTS FOR, replayed in miniature: one commit
    // that declares the hatch and consumes it. Every admitting case below is
    // satisfied by a clause that never fires, so this one is what makes them mean
    // anything.
    let dir = fixture("arm-same-commit", false);
    write(&dir, "batten.toml", &config(true));
    write(
        &dir,
        LEDGER,
        &format!("// the successors of the alpha suite\n{ARM_ROW}"),
    );
    commit(&dir, "feat(config): add the withdrawn arm and use it");
    let (code, report) = check(&dir, "HEAD~1..HEAD");
    assert_eq!(
        code,
        Some(2),
        "an arm introduced and spent at once must refuse: {report}"
    );
    assert!(
        report.contains(POINTER),
        "the finding names the config path a reader should open: {report}"
    );
}

// ---------------------------------------------------------------------------
// The admitting arms. Each one is a shape the predicate must stay silent over.
// ---------------------------------------------------------------------------

#[test]
fn the_same_pair_split_across_two_commits_passes() {
    // THE REMEDY, and it has to actually work or the clause is a wall rather than
    // a sequencing rule. Judged over a range covering BOTH commits, because that
    // is what CI walks: the arm arrives in one and is spent in the next, and
    // neither commit alone carries both halves.
    let dir = fixture("arm-two-commits", false);
    write(&dir, "batten.toml", &config(true));
    commit(&dir, "feat(config): add the withdrawn arm");
    write(
        &dir,
        LEDGER,
        &format!("// the successors of the alpha suite\n{ARM_ROW}"),
    );
    commit(&dir, "chore(tests): withdraw the alpha case");
    let (code, report) = check(&dir, "HEAD~2..HEAD");
    assert_eq!(
        code,
        Some(0),
        "landing the arm before spending it is the remedy: {report}"
    );
}

#[test]
fn a_commit_that_spends_an_arm_the_tree_already_carried_passes() {
    // THE DISCRIMINATING CASE. A predicate keyed only on "this commit spends an
    // arm" would refuse this, and that would refuse every honest use of the
    // ledger — the false-positive rate that gets a guard switched off.
    let dir = fixture("arm-already-declared", true);
    write(
        &dir,
        LEDGER,
        &format!("// the successors of the alpha suite\n{ARM_ROW}"),
    );
    commit(&dir, "chore(tests): withdraw the alpha case");
    let (code, report) = check(&dir, "HEAD~1..HEAD");
    assert_eq!(
        code,
        Some(0),
        "an arm the tree already carried is not self-authorized: {report}"
    );
}

#[test]
fn a_commit_that_only_declares_the_arm_passes() {
    // Declaring without spending is the whole shape the remedy asks for, so it
    // must be free. The config side alone is not the refusal.
    let dir = fixture("arm-declared-only", false);
    write(&dir, "batten.toml", &config(true));
    commit(&dir, "feat(config): add the withdrawn arm");
    let (code, report) = check(&dir, "HEAD~1..HEAD");
    assert_eq!(
        code,
        Some(0),
        "declaring an arm is not spending it: {report}"
    );
}

#[test]
fn a_ledger_line_the_commit_did_not_add_does_not_count() {
    // The other half of the same question, and the reason the spend side is a set
    // DIFFERENCE rather than a scan of the head text. A successor file can carry
    // the token as ordinary prose before the arm is declared at all — it is only
    // a comment — and a clause that read the head text would refuse the commit
    // that declares the arm for a row somebody else wrote.
    let dir = fixture("arm-preexisting-line", false);
    write(
        &dir,
        LEDGER,
        &format!("// the successors of the alpha suite\n{ARM_ROW}"),
    );
    commit(&dir, "chore(tests): note the withdrawal in prose");
    write(&dir, "batten.toml", &config(true));
    commit(&dir, "feat(config): add the withdrawn arm");
    let (code, report) = check(&dir, "HEAD~1..HEAD");
    assert_eq!(
        code,
        Some(0),
        "a line this commit did not write is not its spend: {report}"
    );
}

#[test]
fn a_commit_that_edits_the_config_without_adding_an_arm_passes() {
    // The clause must not toll an ordinary config edit, which is the commit shape
    // this repository produces most. Without this case the implementation that
    // passes the premise is "refuse every commit that touches the config".
    let dir = fixture("arm-ordinary-config-edit", true);
    // A whole second rule, appended: a bare key written after `[rule.conserves]`
    // would land INSIDE that table, and a retired top-level key would be refused
    // at load — exit 1, which every case here would read as its own verdict.
    write(
        &dir,
        "batten.toml",
        &format!(
            "{}\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\n\
             glob = \"**/*.t\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
            config(true)
        ),
    );
    write(
        &dir,
        LEDGER,
        &format!("// the successors of the alpha suite\n{ARM_ROW}"),
    );
    commit(&dir, "chore(config): raise the pileup threshold");
    let (code, report) = check(&dir, "HEAD~1..HEAD");
    assert_eq!(
        code,
        Some(0),
        "an edit that introduces no arm owes nothing: {report}"
    );
}

// ---------------------------------------------------------------------------
// The pending mode, which is a different resolver and would otherwise be dead.
// ---------------------------------------------------------------------------

#[test]
fn the_staged_pair_is_refused_before_the_commit_exists() {
    // THE EARLIEST COMPUTABLE MOMENT, and a separate code path: the index is the
    // commit-to-be and `HEAD` is its parent. Without this case the `--message`
    // half could read the working tree, or nothing at all, and the range tier
    // above would stay green over it — a gate that is absent where a contributor
    // actually meets it.
    let dir = fixture("arm-staged", false);
    write(&dir, "batten.toml", &config(true));
    write(
        &dir,
        LEDGER,
        &format!("// the successors of the alpha suite\n{ARM_ROW}"),
    );
    git_in(&dir, &["add", "-A"]);
    let message = dir.join("COMMIT_EDITMSG_UNDER_TEST");
    std::fs::write(&message, "feat(config): add the withdrawn arm and use it\n").unwrap();
    let output = run(
        &dir,
        &["commit", "check", "--message", message.to_str().unwrap()],
    );
    let report = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a staged self-authorization must refuse: {report}"
    );
    assert!(
        report.contains("pending arm-self-authorized suites-not-gutted.withdrawn"),
        "the pending finding carries the same pointer under the `pending` label: {report}"
    );
}
