//! End-to-end tests for the `ratchet` rule kind (CLOUD-55).
//!
//! The property: a count over a declared token may only move one way between a
//! base rev and the working tree. What makes it worth a kind of its own is that
//! the test suite cannot be a protected path — tests are edited every day — so
//! the computable guard is *direction of change*, not immutability.
//!
//! Every fixture below carries real git history, because the base half of the
//! comparison reads `ls-tree`/`show` at a rev and a fake would prove nothing
//! about the plumbing. Exit assertions use **2** for the verdict: the shell
//! tasks' inverted convention must not be carried in (`mem:toolchain-and-hooks`
//! records ported bats cases that passed while asserting the wrong claim).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

/// Two `#[test]` functions in one file, committed as the base.
const BASE_SRC: &str =
    "#[test]\nfn one() {\n    assert!(true);\n}\n\n#[test]\nfn two() {\n    assert!(true);\n}\n";

/// A config carrying one ratchet row over `src/**/*.rs`.
fn ratchet_config(pattern: &str, direction: &str, severity: &str) -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"tests-not-deleted\"\nkind = \"ratchet\"\nglob = \"src/**/*.rs\"\npattern = \"{pattern}\"\ndirection = \"{direction}\"\nbase = \"main\"\nseverity = \"{severity}\"\n"
    )
}

/// A repo whose base commit carries [`BASE_SRC`], with `config` committed.
///
/// `base = "main"` rather than a remote-tracking ref: the fixtures carry no
/// origin literal (`no-origin-literal-in-fixtures`), and a local branch proves
/// the same plumbing.
fn ratchet_repo(name: &str, config: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(config)
        .file("src/lib.rs", BASE_SRC)
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check"])
}

#[test]
fn deleting_a_test_is_a_violation_naming_the_two_counts() {
    // The headline case: the working tree drops one of the two `#[test]` fns.
    let dir = ratchet_repo(
        "ratchet-deleted",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    common::write(
        &dir,
        "src/lib.rs",
        "#[test]\nfn one() {\n    assert!(true);\n}\n",
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a deletion is a policy verdict"
    );
    let text = stdout(&output);
    assert!(
        text.contains("tests-not-deleted"),
        "the finding names the rule: {text:?}"
    );
    assert!(
        text.contains("2->1"),
        "and carries both counts, so the reader knows how far it moved: {text:?}"
    );
    assert!(
        !text.contains("fn two"),
        "pointer-only: the deleted test's text is payload and never appears: {text:?}"
    );
    assert_eq!(
        text.lines().count(),
        1,
        "one aggregate finding, not one per file: {text:?}"
    );
}

#[test]
fn an_unchanged_count_is_silent() {
    let dir = ratchet_repo(
        "ratchet-unchanged",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "a ratchet that held says nothing");
}

#[test]
fn adding_a_test_is_never_a_violation_of_a_non_decreasing_row() {
    let dir = ratchet_repo(
        "ratchet-added",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    common::write(
        &dir,
        "src/lib.rs",
        &format!("{BASE_SRC}\n#[test]\nfn three() {{\n    assert!(true);\n}}\n"),
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn a_test_moved_between_files_is_clean_without_rename_tracking() {
    // The reason the count is aggregate per rule rather than per file. A
    // per-file count would read this consolidation as a deletion and a magic
    // appearance, and the fix would be rename tracking nobody needs.
    let dir = ratchet_repo(
        "ratchet-moved",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    common::write(
        &dir,
        "src/lib.rs",
        "#[test]\nfn one() {\n    assert!(true);\n}\n",
    );
    common::write(
        &dir,
        "src/moved.rs",
        "#[test]\nfn two() {\n    assert!(true);\n}\n",
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the suite is intact, so nothing moved: {}",
        stdout(&output)
    );
}

#[test]
fn deleting_every_matched_file_is_caught_rather_than_skipped() {
    // The case an empty-match early return would have made silent — and the
    // worst one to be silent about. Every other kind treats "the glob matched
    // nothing" as nothing to inspect; for a ratchet it is the maximal deletion.
    let dir = ratchet_repo(
        "ratchet-emptied",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    fs::remove_file(dir.join("src/lib.rs")).expect("delete the only matched file");

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("2->0"));
}

#[test]
fn a_non_increasing_row_catches_a_newly_added_token() {
    // The mirror direction — the `#[ignore]` guard, where adding is the danger.
    let dir = ratchet_repo(
        "ratchet-ignore",
        &ratchet_config("#[ignore]", "non_increasing", "deny"),
    );
    common::write(
        &dir,
        "src/lib.rs",
        &format!("{BASE_SRC}\n#[ignore]\n#[test]\nfn skipped() {{}}\n"),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("0->1"));
}

#[test]
fn a_warn_row_reports_without_failing_until_promoted() {
    // The advisory tier: assertions thinning out is worth saying, and worth
    // saying without blocking, until the run asks for strictness.
    let dir = ratchet_repo(
        "ratchet-warn",
        &ratchet_config("assert", "non_decreasing", "warn"),
    );
    // Same `#[test]` count, fewer assertions — the gutting shape.
    common::write(
        &dir,
        "src/lib.rs",
        "#[test]\nfn one() {}\n\n#[test]\nfn two() {}\n",
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a warn row reports without failing"
    );
    assert!(
        stdout(&output).contains("tests-not-deleted"),
        "and it does report: {}",
        stdout(&output)
    );

    let promoted = run(&dir, &["--fail-on-warning", "check"]);
    assert_eq!(
        promoted.status.code(),
        Some(2),
        "promotion is what makes it block"
    );
}

#[test]
fn an_unresolvable_base_is_a_usage_error_naming_the_rev() {
    // Never a pass: a ratchet that cannot see its baseline has not established
    // that the count held, and reporting zero would read as "nothing was
    // deleted" having looked at nothing.
    let dir = ratchet_repo(
        "ratchet-bad-base",
        "version = 1\n\n[[rule]]\nid = \"tests-not-deleted\"\nkind = \"ratchet\"\nglob = \"src/**/*.rs\"\npattern = \"#[test]\"\ndirection = \"non_decreasing\"\nbase = \"no-such-rev\"\nseverity = \"deny\"\n",
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config error, not a verdict"
    );
    assert!(
        common::stderr(&output).contains("no-such-rev"),
        "the message names the rev: {}",
        common::stderr(&output)
    );
}

// ---------------------------------------------------------------------------
// The count is taken at the MERGE BASE, not at the declared ref's tip
// (CLOUD-405).
//
// Every case above leaves HEAD on `main`, where the merge base and the tip are
// the same commit — which is why they say nothing about this and why the three
// below have to diverge the branch from its base explicitly.
// ---------------------------------------------------------------------------

/// A branch that left `main` at the base commit, with `main` free to move on.
///
/// Returns the repo. The caller writes the working tree afterwards, exactly as
/// the fixtures above do.
fn diverged(name: &str, config: &str) -> PathBuf {
    let dir = ratchet_repo(name, config);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    dir
}

/// Commit `src/lib.rs` as `text` on `main`, then return to `work`.
///
/// This is the fleet's ordinary condition rather than an exotic one: under land
/// contention a branch is routinely a few commits behind by the time CI reads
/// its base.
fn main_moves_to(dir: &Path, text: &str) {
    git_in(dir, &["checkout", "-q", "main"]);
    common::write(dir, "src/lib.rs", text);
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "main moves"]);
    git_in(dir, &["checkout", "-q", "work"]);
}

#[test]
fn a_branch_that_touched_nothing_is_clean_however_far_the_base_has_moved() {
    // THE MEASURED CASE (CLOUD-122, 2026-08-11), and it is red against a binary
    // that counts at the tip: `verify` green locally, CI red on the same commit,
    // on a branch touching no matched file at all. `main` gained a test while the
    // branch waited; nothing was deleted.
    let dir = diverged(
        "ratchet-base-moved",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    main_moves_to(
        &dir,
        &format!("{BASE_SRC}\n#[test]\nfn three() {{\n    assert!(true);\n}}\n"),
    );

    // The branch's own tree is untouched — the same two tests it left with.
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a branch that deleted nothing must be clean; the base moving is not this \
         branch's doing: {}",
        stdout(&output)
    );
}

#[test]
fn a_real_deletion_is_still_refused_with_both_counts_after_the_base_moves() {
    // The direction a careless fix breaks. Moving the count to the merge base
    // must not buy a branch a free deletion, and the pointer must still carry the
    // two counts the reader needs — measured against the MERGE BASE's two, not
    // the tip's three.
    let dir = diverged(
        "ratchet-base-moved-deleted",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    main_moves_to(
        &dir,
        &format!("{BASE_SRC}\n#[test]\nfn three() {{\n    assert!(true);\n}}\n"),
    );
    common::write(
        &dir,
        "src/lib.rs",
        "#[test]\nfn one() {\n    assert!(true);\n}\n",
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a deletion is still a verdict"
    );
    let text = stdout(&output);
    assert!(
        text.contains("2->1"),
        "the counts are the merge base's and the working tree's, never the tip's: {text:?}"
    );
    assert!(
        !text.contains("3->1"),
        "counting at the tip would blame the branch for what landed on the base: {text:?}"
    );
}

#[test]
fn a_deletion_on_the_base_cannot_mask_one_on_the_branch() {
    // THE MASKING CASE, and the reason the merge base is chosen over merely
    // tolerating drift. Both sides drop one test, so the tip reading sees 1
    // against 1 and reports clean — the branch's own deletion vanishes inside the
    // aggregate. This is the refusal the tip reading LOSES, so it is red against
    // the current binary in the opposite direction from the first case.
    let one_test = "#[test]\nfn one() {\n    assert!(true);\n}\n";
    let dir = diverged(
        "ratchet-base-masks",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    main_moves_to(&dir, one_test);
    common::write(&dir, "src/lib.rs", one_test);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the branch deleted a test and the base deleting one too must not hide it: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("2->1"),
        "against the merge base's count, not the tip's: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_waiver_suppresses_a_ratchet_and_a_lapsed_one_does_not() {
    // The designed hatch for a legitimate reduction — with a reason and an
    // expiry, never `severity = "allow"`, which switches the rule off forever
    // and tells nobody.
    let with_expiry = |expires: &str| {
        format!(
            "{}\n[[waiver]]\nrule = \"tests-not-deleted\"\nreason = \"tracked in CLOUD-1; the suite is being consolidated\"\nexpires = \"{expires}\"\n",
            ratchet_config("#[test]", "non_decreasing", "deny")
        )
    };

    let live = ratchet_repo("ratchet-waived", &with_expiry("2999-01-01"));
    common::write(
        &live,
        "src/lib.rs",
        "#[test]\nfn one() {\n    assert!(true);\n}\n",
    );
    assert_eq!(
        check(&live).status.code(),
        Some(0),
        "a live waiver suppresses the finding like any other"
    );

    let lapsed = ratchet_repo("ratchet-lapsed", &with_expiry("2020-01-01"));
    common::write(
        &lapsed,
        "src/lib.rs",
        "#[test]\nfn one() {\n    assert!(true);\n}\n",
    );
    assert_eq!(
        check(&lapsed).status.code(),
        Some(2),
        "an expired waiver stops suppressing with nobody acting"
    );
}

#[test]
fn an_allow_severity_switches_the_row_off() {
    let dir = ratchet_repo(
        "ratchet-allow",
        &ratchet_config("#[test]", "non_decreasing", "allow"),
    );
    common::write(&dir, "src/lib.rs", "");
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn the_report_is_byte_stable_across_runs_in_both_channels() {
    let dir = ratchet_repo(
        "ratchet-stable",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    common::write(&dir, "src/lib.rs", "#[test]\nfn one() {}\n");

    for args in [&["check"][..], &["check", "-J"][..]] {
        let first = run(&dir, args);
        let second = run(&dir, args);
        assert_eq!(
            first.stdout, second.stdout,
            "identical state must produce identical bytes"
        );
        assert_eq!(first.status.code(), Some(2));
    }
}

#[test]
fn a_ratchet_also_evaluates_under_enforce() {
    // Both surfaces, because the kind reaches no configured command: it is
    // admitted by `check`'s read effect and is not enforce-only.
    let dir = ratchet_repo(
        "ratchet-enforce",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    common::write(&dir, "src/lib.rs", "#[test]\nfn one() {}\n");
    assert_eq!(run(&dir, &["enforce"]).status.code(), Some(2));
}

// --- the base and worktree halves must count the same paths (CLOUD-749) ------
//
// CLOUD-328 established the shape: a ratchet whose two halves select different
// path sets produces a gate that cannot fail. That was the submodule axis. This
// is the second axis on the same function — path *quoting*.
//
// `count_at_rev` reads `ls-tree` through plain `query`, so quoting is whatever
// the host's `git config` says. Under git's default `core.quotePath=true` a
// non-ASCII path arrives as `"caf\303\251.rs"` — literal quotes, octal escapes —
// and the glob silently fails to match it. The working-tree half walks with
// `ignore` and gets the real path, so it matches. The two halves disagree about
// which files exist, and the delta they report is fiction.

/// A ratchet repo whose base carries a non-ASCII path inside the glob.
fn accented_repo(name: &str, config: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(config)
        // Two matching files, one of them named in a way git will quote.
        .file("src/lib.rs", BASE_SRC)
        .file("src/café.rs", BASE_SRC)
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

#[test]
fn a_non_ascii_path_is_counted_on_the_base_side_too() {
    // The base carries four `#[test]` across two files; the working tree deletes
    // one of the two in the ACCENTED file. If the base side cannot see that file
    // it counts 2 where the tree counts 3 — an increase — and a `non_decreasing`
    // ratchet reports clean while a test was deleted. The gate cannot fail.
    let dir = accented_repo(
        "ratchet-non-ascii",
        &ratchet_config("#[test]", "non_decreasing", "deny"),
    );
    common::write(
        &dir,
        "src/café.rs",
        "#[test]\nfn one() {\n    assert!(true);\n}\n",
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the base side must see the accented file, or a deletion inside it is \
         invisible. stdout: {:?}",
        stdout(&output)
    );
    let text = stdout(&output);
    assert!(
        text.contains("4->3"),
        "both halves counted the same file set, so the counts are 4 and 3: {text:?}"
    );
}

#[test]
fn the_base_count_does_not_move_with_the_hosts_quote_path_setting() {
    // The property that makes the count host-independent. `core.quotePath` is a
    // legal local setting, so two developers must not get different verdicts for
    // the same commit — which is what reading a quoting-dependent format through
    // an unpinned `query` buys.
    let mut verdicts = Vec::new();
    for (name, setting) in [("ratchet-quote-on", "true"), ("ratchet-quote-off", "false")] {
        let dir = accented_repo(name, &ratchet_config("#[test]", "non_decreasing", "deny"));
        git_in(&dir, &["config", "core.quotePath", setting]);
        common::write(
            &dir,
            "src/café.rs",
            "#[test]\nfn one() {\n    assert!(true);\n}\n",
        );
        verdicts.push((setting, check(&dir).status.code(), stdout(&check(&dir))));
    }
    let [
        (on_setting, on_code, on_text),
        (off_setting, off_code, off_text),
    ] = <[_; 2]>::try_from(verdicts).expect("two runs");
    assert_eq!(
        on_code, off_code,
        "core.quotePath={on_setting} and ={off_setting} must reach the same verdict"
    );
    assert_eq!(
        on_text, off_text,
        "and report the same counts — a host setting must not move a ratchet"
    );
}

// --- `retires_with`: a decrease admitted exactly when the subject died -------
//
// CLOUD-807. Before this column the only hatch for a legitimate reduction was a
// `[[waiver]]`, which expires and which cannot say WHICH reductions are
// legitimate — so a suite quietly gutted and a suite retired with its subject
// were indistinguishable. The negative case below is the one a blanket waiver
// cannot express, and asserting only the happy path would pass against a rule
// that admits everything.

/// Two cases in one suite that declares its subject, plus the subject itself.
const ALPHA_SUITE: &str = "# subject: programs/alpha\n@case one\n@case two\n";

/// A second suite, so a fixture can retire the first without emptying the glob.
const BETA_SUITE: &str = "# subject: programs/beta\n@case only\n";

/// A ratchet over the suites, keyed to a declared subject.
fn retirement_config(retires_with: Option<&str>) -> String {
    let column = match retires_with {
        None => String::new(),
        Some(token) => format!("retires_with = \"{token}\"\n"),
    };
    format!(
        "version = 1\n\n[[rule]]\nid = \"suites-not-gutted\"\nkind = \"ratchet\"\nglob = \"suites/**/*.t\"\npattern = \"@case \"\ndirection = \"non_decreasing\"\nbase = \"main\"\nseverity = \"deny\"\n{column}"
    )
}

/// A repo with two declared suites and the two programs they name.
fn retirement_repo(name: &str, retires_with: Option<&str>) -> PathBuf {
    retirement_repo_declaring(name, retires_with, ALPHA_SUITE)
}

/// The same, with `alpha` declaring whatever the caller needs **at base**.
///
/// The base state is the FIRST commit rather than a second one plus a moved
/// branch: git refuses to force a branch that is checked out, which is the same
/// defect `no-branch-f-main` gates on the bats corpus.
fn retirement_repo_declaring(name: &str, retires_with: Option<&str>, alpha: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&retirement_config(retires_with))
        .files(&[
            ("suites/alpha.t", alpha),
            ("suites/beta.t", BETA_SUITE),
            ("programs/alpha", "alpha\n"),
            ("programs/beta", "beta\n"),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

#[test]
fn a_retirement_that_takes_its_subject_with_it_is_admitted() {
    // Row (a). The suite and the program it declares die in the same change, so
    // what falls is the case count and not the coverage.
    let dir = retirement_repo("retires-with-subject", Some("# subject:"));
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
    fs::remove_file(dir.join("programs/alpha")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a decrease whose subject died is admitted: {:?}",
        stdout(&output)
    );
}

#[test]
fn deleting_cases_while_the_subject_lives_still_denies() {
    // Row (b), and the load-bearing one: this is what the blanket waiver could
    // not express, and what a happy-path-only assertion would miss entirely.
    let dir = retirement_repo("retires-subject-alive", Some("# subject:"));
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the subject is still there, so nothing bought the decrease"
    );
    let text = stdout(&output);
    assert!(
        text.contains("suites-not-gutted"),
        "the finding names the rule: {text:?}"
    );
    assert!(
        text.contains("3->1"),
        "the finding names the two counts: {text:?}"
    );
    assert!(
        text.contains("subject-alive programs/alpha"),
        "the finding names the subject that did not die: {text:?}"
    );
}

#[test]
fn a_subject_that_dies_under_a_surviving_suite_is_a_finding_at_the_declaration() {
    // Row (c): the ratchet itself is clean — no case was deleted — and the
    // header has rotted into a lie. Caught by the obligation half, which is why
    // that half exists rather than only checking the files a change touched.
    let dir = retirement_repo("retires-dead-subject", Some("# subject:"));
    fs::remove_file(dir.join("programs/alpha")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a suite outliving its subject is a finding"
    );
    let text = stdout(&output);
    assert!(
        text.contains("suites/alpha.t:1"),
        "the pointer lands on the declaration itself: {text:?}"
    );
}

#[test]
fn a_suite_with_no_declared_subject_is_refused() {
    // Row (d). The header cannot rot into a lie if a missing one is already red,
    // and this is what stops the admission resting on a header nobody checks.
    let dir = retirement_repo("retires-undeclared", Some("# subject:"));
    common::write(&dir, "suites/gamma.t", "@case fresh\n");

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a suite declaring no subject is refused even though the count ROSE"
    );
    let text = stdout(&output);
    assert!(
        text.contains("suites/gamma.t:1"),
        "the pointer names the file owing a header: {text:?}"
    );
}

#[test]
fn a_multi_path_subject_needs_every_path_to_die() {
    // The too-narrow-subject hole, asserted directly: a suite covering two
    // programs is not retirable while either still has work to do. Union
    // semantics are the refusing direction, deliberately.
    let dir = retirement_repo_declaring(
        "retires-multi",
        Some("# subject:"),
        "# subject: programs/alpha programs/beta\n@case one\n@case two\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
    fs::remove_file(dir.join("programs/alpha")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "one of the two declared programs survives, so the suite still covers something"
    );
    assert!(
        stdout(&output).contains("subject-alive programs/beta"),
        "the finding names the survivor: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_change_cannot_rewrite_its_own_permission() {
    // The header is read from the BASE tree. Rewriting it in the same commit
    // that spends it would make the permission self-issued — the shape
    // `claim-check` refuses one level up, in the rule engine.
    let dir = retirement_repo("retires-self-authorised", Some("# subject:"));
    // The working copy now claims a subject that is already gone...
    common::write(
        &dir,
        "suites/alpha.t",
        "# subject: programs/never\n@case one\n",
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the base header names programs/alpha, which is still alive"
    );
    assert!(
        stdout(&output).contains("subject-alive programs/alpha"),
        "the BASE subject decides, not the rewritten one: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_subject_that_never_existed_admits_nothing() {
    // The anti-rot term. Without alive-at-base, a header naming a path that was
    // never there reports "absent from the working tree" and admits the very
    // deletion it was supposed to justify — a gate that reads as present and
    // denies nothing.
    let dir = retirement_repo_declaring(
        "retires-phantom",
        Some("# subject:"),
        "# subject: programs/never\n@case one\n@case two\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a subject that was never a blob at base cannot have died"
    );
    assert!(
        stdout(&output).contains("subject-never-existed programs/never"),
        "the finding says which way the header is a lie: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_ratchet_without_the_column_is_unchanged() {
    // The compatibility property, asserted rather than assumed: the same
    // deletion that row (a) admits is refused by a row that declares no header,
    // and no header obligation is imposed on its files.
    let dir = retirement_repo("retires-absent-column", None);
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
    fs::remove_file(dir.join("programs/alpha")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "without the column a decrease is a decrease, exactly as before"
    );
    let text = stdout(&output);
    assert!(
        text.contains("3->1"),
        "the finding is the plain count pair: {text:?}"
    );
    assert!(
        !text.contains("subject-"),
        "no subject reasoning rides on a row that declared none: {text:?}"
    );
}

// --- the mapping: conserving LOGIC rather than files (CLOUD-908) -------------
//
// `retires_with` above admits a decrease when the subject died. That conserves
// FILES. These cover the obligation inside that admission: every named case in
// the decrease is claimed, in the head tree, by exactly one arm naming something
// that resolves. The measured defect is a real one — the campaign's single
// completed port deleted 22 named cases and six of them have no successor
// anything in the tree can name.

/// Two named cases in a declaring suite. Quoted, because a case name is prose
/// and the delimiter is what makes it readable at all.
const NAMED_SUITE: &str = "# subject: programs/alpha\n@case \"one\" {\n@case \"two\" {\n";

/// A second suite, so retiring the first does not empty the glob.
const NAMED_BETA: &str = "# subject: programs/beta\n@case \"only\" {\n";

/// A ratchet whose decrease also owes a per-case mapping.
///
/// `declared_in` is `successors/*.rs` rather than the rule's own glob for the
/// reason the column refuses a default: a retired suite's successors are by
/// definition not under the glob the suite was.
fn mapping_config() -> String {
    "version = 1\n\n[[rule]]\nid = \"suites-not-gutted\"\nkind = \"ratchet\"\nglob = \"suites/**/*.t\"\npattern = \"@case \"\ndirection = \"non_decreasing\"\nbase = \"main\"\nseverity = \"deny\"\nretires_with = \"# subject:\"\n\n[rule.conserves]\ncase = \"@case \\\"\"\nclose = \"\\\"\"\ncarried = \"// carried:\"\nsubsumed = \"// subsumed:\"\nchanged = \"// changed:\"\ndeclared_in = \"successors/*.rs\"\n".to_string()
}

/// A repo whose head tree carries `arms` as its successor file.
fn mapping_repo(name: &str, arms: &str) -> PathBuf {
    mapping_repo_declaring(name, arms, NAMED_SUITE)
}

/// The same, with `alpha` carrying whatever the caller needs **at base**.
fn mapping_repo_declaring(name: &str, arms: &str, alpha: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&mapping_config())
        .files(&[
            ("suites/alpha.t", alpha),
            ("suites/beta.t", NAMED_BETA),
            ("programs/alpha", "alpha\n"),
            ("programs/beta", "beta\n"),
            ("successors/alpha.rs", "// the new home\n"),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    // Written AFTER the base commit: the arms are the head tree's claim about a
    // deletion this change is making, so they belong to the working tree.
    common::write(&dir, "successors/alpha.rs", arms);
    dir
}

/// Retire `suites/alpha.t` and the program it declares, the way row (a) does.
fn retire_alpha(dir: &Path) {
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
    fs::remove_file(dir.join("programs/alpha")).unwrap();
}

#[test]
fn a_fully_mapped_retirement_is_admitted() {
    // Arm (d), the positive one. Without the four reds below this would be a
    // rule that admits everything, which is precisely what `retires_with` alone
    // already was.
    let dir = mapping_repo(
        "conserves-mapped",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"two\" programs/beta\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "every deleted case is claimed by exactly one arm naming a live target: {:?}",
        stdout(&output)
    );
}

#[test]
fn an_unmapped_case_refuses_the_deletion() {
    // Arm (a), and the whole reason the column exists: this is the deletion
    // `retires_with` admits in silence. "two" is claimed by nothing.
    let dir = mapping_repo(
        "conserves-unmapped",
        "// carried: \"one\" successors/alpha.rs\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a case nothing claims refuses the deletion that dropped it"
    );
    let text = stdout(&output);
    assert!(
        text.contains("suites/alpha.t:3"),
        "the pointer lands on the unmapped case's own line at base: {text:?}"
    );
    assert!(
        !text.contains("\"two\""),
        "the case body never travels — pointer only (rule 4): {text:?}"
    );
}

#[test]
fn an_arm_naming_a_target_this_tree_lacks_is_refused() {
    // Arm (b). A mapping whose successor does not exist records a migration that
    // did not happen, and it is the shape a copied-and-edited arm takes.
    let dir = mapping_repo(
        "conserves-phantom-target",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"two\" successors/gone.rs\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an arm naming nothing resolvable does not discharge its case"
    );
    assert!(
        stdout(&output).contains("successors/alpha.rs:2"),
        "the pointer lands on the ARM, because that is where the fix goes: {:?}",
        stdout(&output)
    );
}

#[test]
fn one_case_claimed_by_two_arms_is_refused() {
    // Arm (c). "Exactly one" is the predicate; two arms means the author has not
    // decided whether the assertion moved or was subsumed, and a mapping that
    // takes either is not evidence.
    let dir = mapping_repo(
        "conserves-double-claim",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"one\" programs/beta\n// carried: \"two\" successors/alpha.rs\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a case claimed twice is refused rather than resolved by precedence"
    );
    let text = stdout(&output);
    assert!(
        text.contains("successors/alpha.rs:2"),
        "the pointer lands on the SECOND claim, not the one to keep: {text:?}"
    );
}

#[test]
fn a_changed_arm_with_no_reason_is_refused() {
    // The `changed` arm's whole obligation. A deliberate divergence with no
    // reason is indistinguishable from an accident, which is the untracked-file
    // case the calibration found: defensible, and marked by nothing.
    let dir = mapping_repo(
        "conserves-unexplained-change",
        "// carried: \"one\" successors/alpha.rs\n// changed: \"two\" successors/alpha.rs\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a `changed` arm owes a reason, and an empty one discharges nothing"
    );
    assert!(
        stdout(&output).contains("successors/alpha.rs:2"),
        "the pointer lands on the arm missing its reason: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_changed_arm_carrying_its_reason_is_admitted() {
    // The other half of the pair: without this, the assertion above would be
    // satisfied by a rule that refuses every `changed` arm.
    let dir = mapping_repo(
        "conserves-explained-change",
        "// carried: \"one\" successors/alpha.rs\n// changed: \"two\" successors/alpha.rs the tracked list cannot see a file that postdates it\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a declared divergence with its reason discharges the case: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_complete_mapping_is_the_second_admission_for_a_decrease() {
    // WHAT CHANGED UNDER CLOUD-1050, and why it is a repair rather than a
    // weakening.
    //
    // Arm (e) used to read: a complete mapping is NOT a second way to buy a
    // decrease, the subject still has to die. That composition is unsatisfiable
    // for the case CLOUD-1059 creates. A Bats suite whose subject is a LIVE
    // `.rego` module cannot be edited in place — `shell-retirement` refuses
    // exactly that — and its subject is not dying, because the module is what
    // the migration keeps. So the only two doors were both shut, and a rule with
    // no open door is not a ratchet, it is a wall.
    //
    // The repair is a SECOND admission, not a wider one: `retires_with` admits a
    // decrease on subject death OR on a complete CLOUD-908 ledger. Both are
    // evidence that the logic survived; neither is a promise. Arm (e)'s real
    // content — an UNMAPPED decrease answers to the subject — is unchanged and
    // is asserted by `an_unmapped_case_refuses_the_deletion` and by
    // `a_partial_deletion_still_owes_an_arm_for_the_case_it_dropped`, which
    // reads the `subject-alive` pointer this case used to.
    // AND WHAT CHANGED UNDER CLOUD-1130, which is the fixture rather than the
    // claim. The arms used to name `programs/beta` — a successor with no relation
    // to this suite's subject — so the case read as "any complete ledger admits a
    // decrease whose subject lives", which is the hole rather than the admission:
    // it is byte-identical to deleting a suite and leaving the program it tested
    // alive and untested. The arm CLOUD-1050 bought is the one below: the cases
    // were subsumed INTO the live subject, so the ledger accounts for the survivor
    // as well as for the cases. Naming it is what the mapping is now asked for.
    let dir = mapping_repo(
        "conserves-subject-alive",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"two\" programs/alpha\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a complete ledger admits the decrease without the subject dying: {:?}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("subject-alive programs/alpha"),
        "the subject clause does not fire over a fully mapped path: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_ledger_that_never_names_the_surviving_subject_is_refused() {
    // CLOUD-1130, and it is the discriminating half of the case above: without it
    // the mapped-successor arm admits the exploit it was never meant to cover.
    //
    // THE EXPLOIT, PRECISELY. Delete a suite whole, leave the program it tested
    // standing, and write one well-formed arm per case naming successors that
    // exist. Every other question the column asks is answered — the cases resolve,
    // the targets are in the tree, exactly one arm each — and the thing under test
    // is now untested with nothing recording it. Measured green on the tree as it
    // stood before this row.
    //
    // The only difference from the fixture above is WHICH path the second arm
    // names, which is what makes this pair discriminate rather than merely differ.
    let dir = mapping_repo(
        "conserves-subject-unnamed",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"two\" programs/beta\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();

    let output = check(&dir);
    let text = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a ledger accounts for the cases and never for the subject: {text:?}"
    );
    assert!(
        text.contains("subject-alive programs/alpha"),
        "the refusal names the surviving subject, which is where the fix goes: {text:?}"
    );
}

#[test]
fn a_mapped_deletion_whose_declared_subject_never_existed_is_refused() {
    // The third question the mapped arm owes, and the one the `fully_mapped`
    // filter hid before CLOUD-1130 rewrote this arm: a subject that the BASE tree
    // never carried is not a subject that died.
    //
    // `# subject: programs/ghost` plus a complete ledger reads as "the thing this
    // suite tested is gone", when what it actually says is that the header names
    // nothing checkable — so the claim is unverifiable rather than satisfied, and
    // the same fabricated header would buy the deletion under any marker. The
    // unmapped path has refused this since `retires_with` landed; the mapped path
    // never reached the check, which is why it is asserted here.
    //
    // PRE-EXISTING rather than opened by CLOUD-1130: the filter this arm replaced
    // skipped a fully mapped path before either question was asked. Closed here
    // because it is one conjunct of the arm being rewritten.
    let dir = mapping_repo_declaring(
        "conserves-ghost-subject",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"two\" programs/alpha\n",
        "# subject: programs/ghost\n@case \"one\" {\n@case \"two\" {\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();

    let output = check(&dir);
    let text = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a header naming nothing the base tree carried is not a death: {text:?}"
    );
    assert!(
        text.contains("subject-never-existed programs/ghost"),
        "and the refusal names the subject that cannot be checked: {text:?}"
    );
}

#[test]
fn a_dying_suite_that_declares_no_subject_is_not_newly_refused() {
    // The bound on the row above, and the direction it must not break: a suite
    // carrying no `# subject:` header at all answers to the ledger and to nothing
    // else. 19 of this repository's 142 bats suites are in that position, and a
    // fix that read the filename as a subject would refuse every one of them.
    let dir = mapping_repo_declaring(
        "conserves-no-subject",
        "// carried: \"one\" successors/alpha.rs\n// subsumed: \"two\" programs/beta\n",
        "@case \"one\" {\n@case \"two\" {\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an undeclared subject is the ledger's question alone: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_case_whose_name_never_closes_is_reported_at_the_case() {
    // Could-not-look, kept distinct from unmapped. A name with no delimiter
    // cannot be claimed by anything, because no arm could spell it — so reading
    // it as "unmapped" would blame the mapping for a defect in the dying file.
    // The malformed case has to sit in a file whose count FELL: the mapping asks
    // its question of a decrease, so a malformed name in a file nobody deleted is
    // correctly none of this column's business.
    let dir = mapping_repo_declaring(
        "conserves-unreadable-case",
        "// carried: \"one\" successors/alpha.rs\n",
        "# subject: programs/alpha\n@case \"one\" {\n@case \"unterminated\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unreadable case name is a finding rather than a silent pass"
    );
    assert!(
        stdout(&output).contains("suites/alpha.t:3"),
        "the pointer lands on the malformed declaration: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_partial_deletion_owes_an_arm_only_for_what_it_dropped() {
    // The defect this covers was real and my own: the mapping read the BASE text
    // and asked about every case in it, so a suite that lost one case of two owed
    // arms for both — including the one still standing. A gate that cannot be
    // satisfied gets switched off, which is coverage evaporation by a second
    // route than the one this column closes.
    //
    // ASSERTED ON THE FINDINGS RATHER THAN THE EXIT CODE. What discriminates
    // this column is WHICH findings appear — the first version of this test
    // asserted the code, passed for the wrong reason on a fixture that had
    // deleted the program out from under a surviving suite, and had to be
    // rewritten.
    //
    // WHAT CHANGED UNDER CLOUD-1050, because this comment used to say the
    // opposite. It read: "a partial deletion leaves the suite alive, so its
    // subject is alive too, so `retires_with` refuses the decrease no matter how
    // perfect the mapping is." That was true while subject death was the ONLY
    // admission. The mapped-successor arm is the second one, and a complete
    // ledger is strictly more evidence than a dead subject: it says where every
    // dropped case went, which subject death asks nothing about. So a perfect
    // mapping now admits, and `an_unmapped_partial_deletion_is_still_refused`
    // below is the discriminating half — without it this case would be satisfied
    // by an arm that admitted everything.
    let dir = mapping_repo(
        "conserves-partial",
        "// carried: \"two\" successors/alpha.rs\n",
    );
    common::write(
        &dir,
        "suites/alpha.t",
        "# subject: programs/alpha\n@case \"one\" {\n",
    );

    let output = check(&dir);
    let text = stdout(&output);
    assert!(
        !text.contains("subject-alive programs/alpha"),
        "a complete ledger admits the decrease without the subject dying: {text:?}"
    );
    assert!(
        !text.contains("suites/alpha.t:2"),
        "the SURVIVING case is never asked to have moved: {text:?}"
    );
    assert!(
        !text.contains("suites/alpha.t:3"),
        "and the dropped case is claimed, so it raises nothing either: {text:?}"
    );
}

#[test]
fn a_partial_deletion_still_owes_an_arm_for_the_case_it_dropped() {
    // The other half. Without it, the two silences above would be satisfied by a
    // mapping that asks nothing of a partial deletion at all — which is what the
    // fix for the defect could easily have shipped.
    let dir = mapping_repo("conserves-partial-unmapped", "// the new home\n");
    common::write(
        &dir,
        "suites/alpha.t",
        "# subject: programs/alpha\n@case \"one\" {\n",
    );

    let output = check(&dir);
    let text = stdout(&output);
    assert!(
        text.contains("suites/alpha.t:3"),
        "the DROPPED case is still owed an arm, at its line in the base text: {text:?}"
    );
    assert!(
        !text.contains("suites/alpha.t:2"),
        "and only the dropped one: {text:?}"
    );
    // AND THE MAPPED-SUCCESSOR ARM DOES NOT ADMIT IT (CLOUD-1050). An unmapped
    // dropped case leaves the path un-conserved, so the aggregate admission
    // falls back to asking whether the subject died — and it did not. Without
    // this the new arm would be a hole rather than an admission: any decrease
    // would pass on a ledger that claimed nothing.
    assert!(
        text.contains("subject-alive programs/alpha"),
        "an unmapped decrease still answers to the subject: {text:?}"
    );
}

#[test]
fn a_renamed_case_owes_an_arm_even_though_no_count_moved() {
    // THE EVASION THE COUNTS COULD NOT SEE (CLOUD-480, found reviewing #660).
    // The mapping used to run only when the AGGREGATE fell, and the obvious
    // repair — run it when a FILE's count falls — is still blind here: renaming
    // `"two"` to `"three"` leaves both totals exactly where they were. A rename
    // is a deletion plus an addition, and the deletion half owes an arm like any
    // other, so the pass compares case NAMES and counts nothing.
    let dir = mapping_repo("conserves-renamed", "// the new home\n");
    common::write(
        &dir,
        "suites/alpha.t",
        "# subject: programs/alpha\n@case \"one\" {\n@case \"three\" {\n",
    );

    let output = check(&dir);
    let text = stdout(&output);
    assert!(
        text.contains("suites/alpha.t:3"),
        "the case that vanished under the rename is owed an arm: {text:?}"
    );
    assert!(
        !text.contains("suites/alpha.t:2"),
        "and the untouched case is not: {text:?}"
    );
}

#[test]
fn a_renamed_case_whose_arm_names_it_is_admitted() {
    // The guard on the case above: without it, the finding could be satisfied by
    // a pass that refuses every rename, which would make the column unusable for
    // the ordinary edit it is most likely to meet.
    let dir = mapping_repo(
        "conserves-renamed-claimed",
        "// carried: \"two\" successors/alpha.rs\n",
    );
    common::write(
        &dir,
        "suites/alpha.t",
        "# subject: programs/alpha\n@case \"one\" {\n@case \"three\" {\n",
    );

    let output = check(&dir);
    let text = stdout(&output);
    assert!(
        !text.contains("suites/alpha.t:3"),
        "a rename whose dropped name is carried raises nothing: {text:?}"
    );
}

#[test]
fn a_file_whose_case_names_are_unchanged_raises_nothing() {
    // The pass now asks EVERY file the base carried rather than only the ones
    // whose count fell, so this is the property that keeps that affordable and
    // quiet: an untouched suite answers in a set comparison and says nothing.
    let dir = mapping_repo("conserves-untouched", "// the new home\n");

    let output = check(&dir);
    let text = stdout(&output);
    assert!(
        !text.contains("case-unmapped"),
        "no case moved, so nothing is owed: {text:?}"
    );
}

#[test]
fn a_retirement_row_without_the_mapping_column_is_unchanged() {
    // The compatibility property, one level in from
    // `a_ratchet_without_the_column_is_unchanged`: a `retires_with` row that
    // declares no mapping behaves exactly as it did before this column existed,
    // and imposes no per-case obligation on anything.
    let dir = retirement_repo("conserves-absent-column", Some("# subject:"));
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
    fs::remove_file(dir.join("programs/alpha")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the dead subject alone still buys the decrease: {:?}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("case-"),
        "no mapping reasoning rides on a row that declared none: {:?}",
        stdout(&output)
    );
}

// --- `admits_with`: an increase admitted exactly when the growth declared why -
//
// CLOUD-929. The mirror of `retires_with`, and deliberately the weaker half: a
// file absent from `base` has no base copy to read, so the declaration is read
// from the WORKING tree and a change can therefore write its own permission.
// That is a declaration a reviewer reads, not a proof — so the cases below fix
// what it DOES decide, and the per-file case is the one that keeps it honest.

/// A program carrying the counted token and declaring nothing.
const BARE_PROGRAM: &str = "#TASK one\nbody\n";

/// The same program, declaring why it cannot migrate.
const DECLARED_PROGRAM: &str = "#TASK one\n# stays-bash: ISSUE-1 forge bucket\nbody\n";

/// A `non_increasing` ratchet over the programs, optionally carrying the column.
fn growth_config(admits_with: Option<&str>) -> String {
    let column = match admits_with {
        None => String::new(),
        Some(token) => format!("admits_with = \"{token}\"\n"),
    };
    format!(
        "version = 1\n\n[[rule]]\nid = \"surface-not-growing\"\nkind = \"ratchet\"\nglob = \"programs/**\"\npattern = \"#TASK \"\ndirection = \"non_increasing\"\nbase = \"main\"\nseverity = \"deny\"\n{column}"
    )
}

/// A repo whose base carries two undeclared programs.
fn growth_repo(name: &str, admits_with: Option<&str>) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&growth_config(admits_with))
        .files(&[
            ("programs/alpha", BARE_PROGRAM),
            ("programs/beta", BARE_PROGRAM),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

#[test]
fn a_new_program_that_declares_nothing_denies() {
    // Direction (a). The surface grew and nothing said why.
    let dir = growth_repo("admits-undeclared", Some("# stays-bash:"));
    common::write(&dir, "programs/gamma", BARE_PROGRAM);

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("2->3"), "{:?}", stdout(&output));
    assert!(
        stdout(&output).contains("growth-undeclared programs/gamma"),
        "the refusal names the file that grew: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_new_program_that_declares_why_is_admitted() {
    // Direction (b), and the proof the marker is read from the WORKING tree:
    // `gamma` does not exist at base at all, so there is nowhere else to read it.
    let dir = growth_repo("admits-declared", Some("# stays-bash:"));
    common::write(&dir, "programs/gamma", DECLARED_PROGRAM);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a declared increase is admitted: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_deletion_never_violates_a_non_increasing_row() {
    // Direction (c). The column must not turn a shrinking surface into a finding.
    let dir = growth_repo("admits-deletion", Some("# stays-bash:"));
    fs::remove_file(dir.join("programs/alpha")).unwrap();

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a decrease is not what this row refuses: {:?}",
        stdout(&output)
    );
}

#[test]
fn one_declaration_does_not_pay_for_an_undeclared_sibling() {
    // THE DISCRIMINATING CASE. The admission is per file, so a change that adds
    // two programs and declares one has not declared the increase. Summed over
    // the aggregate instead, the declared file would buy the silent one and the
    // column would be worth less than nothing — it would read as a permission
    // while admitting exactly what it exists to surface.
    let dir = growth_repo("admits-partial", Some("# stays-bash:"));
    common::write(&dir, "programs/gamma", DECLARED_PROGRAM);
    common::write(&dir, "programs/delta", BARE_PROGRAM);

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let report = stdout(&output);
    assert!(
        report.contains("growth-undeclared programs/delta"),
        "the undeclared sibling is named: {report:?}"
    );
    assert!(
        !report.contains("growth-undeclared programs/gamma"),
        "the declared one is not: {report:?}"
    );
}

#[test]
fn a_row_without_the_column_denies_the_same_increase() {
    // Optional is the whole of its compatibility story: without the column the
    // row behaves exactly as it did before the column existed, and the marker
    // text is inert. Asserting this is what stops the happy path above passing
    // against an engine that admits every increase.
    let dir = growth_repo("admits-absent", None);
    common::write(&dir, "programs/gamma", DECLARED_PROGRAM);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the declaration decides nothing on a row that never opted in: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_blank_admits_with_is_refused_at_load() {
    // An empty prefix matches at the start of every line, so every file would
    // "declare" a reason and the column would admit every increase silently —
    // strictly worse than not having it, because it reads as a configured
    // permission while deciding nothing. A config fault, not a policy verdict.
    let dir = growth_repo("admits-blank", Some(""));
    common::write(&dir, "programs/gamma", BARE_PROGRAM);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a blank token is a config fault: {:?}",
        stdout(&output)
    );
}

#[test]
fn admits_with_on_the_opposite_direction_is_refused_at_load() {
    // Found by review of #694, and a refusal rather than a note because the
    // column does not merely go inert on the wrong row — it switches the row
    // OFF. `undeclared_growth` inspects only the files whose count ROSE, so on a
    // `non_decreasing` row it collects nothing, the blocker set stays empty, and
    // the evaluator returns clean over exactly the DELETION that row exists to
    // refuse. That is the blank token's failure reached by the other axis, so it
    // is refused in the same place and at the same exit code.
    //
    // A local config rather than `growth_config`, whose direction is fixed: the
    // point of this case is the pairing, so the direction has to be the variable.
    let dir = Fixture::new("admits-wrong-direction")
        .config(
            "version = 1\n\n[[rule]]\nid = \"surface-not-shrinking\"\nkind = \"ratchet\"\nglob = \"programs/**\"\npattern = \"#TASK \"\ndirection = \"non_decreasing\"\nbase = \"main\"\nseverity = \"deny\"\nadmits_with = \"# stays-bash:\"\n",
        )
        .files(&[
            ("programs/alpha", BARE_PROGRAM),
            ("programs/beta", BARE_PROGRAM),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    // The decrease this row refuses, which the mispaired column would have
    // admitted in silence.
    std::fs::remove_file(dir.join("programs/beta")).expect("remove a counted file");

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a column paired with the direction it cannot govern is a config fault, not a clean tree: {:?}",
        stdout(&output)
    );
}

// --- the fourth arm: a WITHDRAWAL has no successor (CLOUD-1080) --------------
//
// The three arms above all name a successor, because they were written for a suite
// migrating into another mechanism. A withdrawal — the subject deleted because the
// feature should not exist — has none, so the only routes past the column were a
// false `subsumed` (a ledger entry that lies to pass) or a `[[waiver]]`, which
// `config-lint` refuses as `waiver-added` unless the weakening was groomed onto the
// issue before the work. No honest path existed, which is a defect and not a verdict.
//
// The arm is admissible ONLY where the dying file's declared subject died too, and
// `a_withdrawal_over_a_live_subject_refuses` is the case that makes that real. It is
// the discriminating one: without it this arm is a waiver with better manners, and
// the positive case below would pass against a rule that admits every deletion.

/// The same rule, with the fourth arm declared.
fn withdrawing_config() -> String {
    mapping_config().replace(
        "changed = \"// changed:\"\n",
        "changed = \"// changed:\"\nwithdrawn = \"// withdrawn:\"\n",
    )
}

/// A repo that declares the fourth arm, otherwise `mapping_repo`'s shape.
fn withdrawing_repo(name: &str, arms: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&withdrawing_config())
        .files(&[
            ("suites/alpha.t", NAMED_SUITE),
            ("suites/beta.t", NAMED_BETA),
            ("programs/alpha", "alpha\n"),
            ("programs/beta", "beta\n"),
            ("successors/alpha.rs", "// the new home\n"),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    common::write(&dir, "successors/alpha.rs", arms);
    dir
}

#[test]
fn a_withdrawal_is_admitted_when_the_subject_died_with_it() {
    // The positive arm. Neither case names a successor, and there is none to name:
    // `programs/alpha` goes in the same change.
    let dir = withdrawing_repo(
        "conserves-withdrawn",
        "// withdrawn: \"one\" the feature is gone\n// withdrawn: \"two\" the feature is gone\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a withdrawal whose subject died owes no successor: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_withdrawal_over_a_live_subject_refuses() {
    // THE DISCRIMINATING CASE, and the reason this arm is narrower than the waiver
    // it replaces. `programs/alpha` is left STANDING while its suite's cases are
    // deleted and claimed as withdrawn — which is a suite being gutted with a note
    // attached, exactly what the column exists to refuse. A fourth verb without
    // this condition would admit it.
    let dir = withdrawing_repo(
        "conserves-withdrawn-live",
        "// withdrawn: \"one\" the feature is gone\n// withdrawn: \"two\" the feature is gone\n",
    );
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
    // `programs/alpha` deliberately NOT removed.

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a withdrawal cannot excuse deleting cases whose subject still stands: {:?}",
        stdout(&output)
    );
    // Asserted at the ARM'S OWN LINE rather than on a reason string, which is both
    // this suite's convention and the sharper discriminator: the aggregate
    // `subject-alive` blocker fires with or without this arm, so a case keyed on it
    // would pass against an arm that honoured every withdrawal. A finding AT the arm
    // is what only the condition produces.
    let text = stdout(&output);
    assert!(
        text.contains("successors/alpha.rs:1") && text.contains("successors/alpha.rs:2"),
        "each withdrawn arm is refused at its own line: {text:?}"
    );
}

// --- the fifth arm: a PORT whose subject SURVIVES (CLOUD-1268) ---------------
//
// The exact mirror of the fourth. `withdrawn` is admissible only where the dying
// file's declared subject DIED; `ported` only where it LIVES. Between them the two
// answers to "what happened to the subject" both have a spelling.
//
// The class it exists for is measured: 16 of this repository's suites declare a
// `# subject:` the CLOUD-843 campaign never retires, `SubjectFacts::died` is
// `.all()`, so those suites were undeletable BY CONSTRUCTION — 217.9s of a 1097.1s
// corpus, in a lane whose makespan cannot fall below its longest suite. Neither
// obvious route is landable: re-subjecting a suite EDITS a governed `.bats`, and so
// does an in-file marker.
//
// THE DISCRIMINATING PAIR IS THE WHOLE ARM, and it is the two cases below rather
// than the positive one: a deletion with a COMPLETE port arm passes, and the SAME
// deletion with one case unported still refuses. Without the second this is a hole
// and CLOUD-908's finding — "conserves files, not logic" — recurs by design.

/// The same rule, with the fifth arm declared.
fn porting_config() -> String {
    mapping_config().replace(
        "changed = \"// changed:\"\n",
        "changed = \"// changed:\"\nported = \"// ported:\"\n",
    )
}

/// A repo that declares the fifth arm, otherwise `mapping_repo`'s shape.
fn porting_repo(name: &str, arms: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&porting_config())
        .files(&[
            ("suites/alpha.t", NAMED_SUITE),
            ("suites/beta.t", NAMED_BETA),
            ("programs/alpha", "alpha\n"),
            ("programs/beta", "beta\n"),
            ("successors/alpha.rs", "// the new home\n"),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    common::write(&dir, "successors/alpha.rs", arms);
    dir
}

/// Delete the suite and LEAVE its subject standing — the port-without-retirement
/// shape, and the one `retire_alpha` above deliberately is not.
fn port_alpha(dir: &Path) {
    fs::remove_file(dir.join("suites/alpha.t")).unwrap();
}

#[test]
fn a_complete_port_over_a_surviving_subject_is_admitted() {
    // THE POSITIVE HALF. Both cases moved to a home the tree carries, and both
    // rows name the survivor `programs/alpha` — which is what clears the aggregate
    // subject-alive term, by ACCOUNTING for it rather than by a `carried` row
    // falsely claiming a case moved into the program.
    let dir = porting_repo(
        "conserves-ported",
        "// ported: \"one\" successors/alpha.rs subject:programs/alpha\n// ported: \"two\" successors/alpha.rs subject:programs/alpha\n",
    );
    port_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a suite whose every case names a new home and whose survivor is named is accounted for: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_same_port_with_one_case_unported_still_refuses() {
    // THE DISCRIMINATING CASE, and the whole reason the arm above is not a hole.
    // Byte-identical to the admitted fixture except that `"two"` has no arm. It
    // refuses twice over, which is the design rather than an accident: the
    // unmapped case is refused at the suite, and because the path is then not
    // fully mapped, the aggregate subject-alive blocker fires for `programs/alpha`
    // as well. A spelling that admitted this would be CLOUD-908's finding —
    // "six cases have no successor anything in the tree can name" — by design.
    let dir = porting_repo(
        "conserves-ported-partial",
        "// ported: \"one\" successors/alpha.rs subject:programs/alpha\n",
    );
    port_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a port is complete or it is not a port: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_port_over_a_subject_that_died_refuses() {
    // THE MIRROR OF `a_withdrawal_over_a_live_subject_refuses`, and what keeps the
    // two arms from describing one event two ways. Here `programs/alpha` goes with
    // the suite, so this is a plain retirement — `carried` already spells it, with
    // less — and admitting it under both markers would make the ledger record the
    // same fact in two vocabularies.
    let dir = porting_repo(
        "conserves-ported-dead",
        "// ported: \"one\" successors/alpha.rs subject:programs/alpha\n// ported: \"two\" successors/alpha.rs subject:programs/alpha\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a port whose subject died is a retirement, and `carried` is its spelling: {:?}",
        stdout(&output)
    );
    // At the ARM'S OWN LINE, for `a_withdrawal_over_a_live_subject_refuses`'s
    // reason: a subject that died clears the aggregate blocker, so a case keyed on
    // the exit code alone would pass against an arm that honoured every port.
    let text = stdout(&output);
    assert!(
        text.contains("successors/alpha.rs:1") && text.contains("successors/alpha.rs:2"),
        "each ported arm is refused at its own line: {text:?}"
    );
}

#[test]
fn a_port_naming_no_surviving_subject_refuses() {
    // WITHOUT THE FIELD THIS IS `carried` UNDER ANOTHER WORD, and it would clear
    // the subject-alive term while accounting for nothing — CLOUD-1130's exploit
    // re-opened by a fifth marker. So the field is owed rather than optional.
    let dir = porting_repo(
        "conserves-ported-unnamed",
        "// ported: \"one\" successors/alpha.rs\n// ported: \"two\" successors/alpha.rs subject:programs/alpha\n",
    );
    port_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a port that names no survivor accounts for nothing: {:?}",
        stdout(&output)
    );
    // Only the arm that named nothing is refused, which is what makes this about
    // the field rather than about ports in general.
    let text = stdout(&output);
    assert!(
        text.contains("successors/alpha.rs:1") && !text.contains("successors/alpha.rs:2"),
        "only the arm missing its subject is refused: {text:?}"
    );
}

#[test]
fn a_port_naming_a_subject_the_suite_never_declared_refuses() {
    // THE ANTI-FABRICATION TERM. `programs/beta` is a real, surviving path — but it
    // is not what `suites/alpha.t` declared, so naming it would let an author buy
    // the deletion with a convenient survivor. The subject is the one the DYING
    // FILE declared, read out of the base text, never chosen on the row.
    let dir = porting_repo(
        "conserves-ported-fabricated",
        "// ported: \"one\" successors/alpha.rs subject:programs/beta\n// ported: \"two\" successors/alpha.rs subject:programs/beta\n",
    );
    port_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a subject the dying file never declared is not its subject: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_carried_arm_over_a_live_subject_still_refuses() {
    // THE ANTI-VACUITY MIRROR FOR CLOUD-1130, and the case that proves this row is
    // additive. The fifth arm is declared, so the vocabulary is the new one — and
    // the SAME deletion spelled `carried`, which names no survivor, is refused
    // exactly as it was before this arm existed. A change that made `carried`
    // tolerate a live subject would have reopened CLOUD-1130, and this is what
    // would go red if it did.
    let dir = porting_repo(
        "conserves-ported-carried-live",
        "// carried: \"one\" successors/alpha.rs\n// carried: \"two\" successors/alpha.rs\n",
    );
    port_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "naming where the cases went never answered what happened to the subject: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_withdrawal_owes_a_reason_since_it_names_no_target() {
    // It names no target, so the reason is the only thing a reader can check the
    // claim against. An arm with neither is a case deleted with a marker on it.
    let dir = withdrawing_repo(
        "conserves-withdrawn-bare",
        "// withdrawn: \"one\"\n// withdrawn: \"two\" the feature is gone\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a bare withdrawal claims without saying anything: {:?}",
        stdout(&output)
    );
    // The BARE arm is refused and the explained one is not, which is what makes
    // this about the reason rather than about withdrawals in general.
    let text = stdout(&output);
    assert!(
        text.contains("successors/alpha.rs:1") && !text.contains("successors/alpha.rs:2"),
        "only the arm that said nothing is refused: {text:?}"
    );
}

#[test]
fn the_fourth_arm_is_inert_where_a_row_does_not_declare_it() {
    // A row without the column reads exactly the three tokens it always did, so a
    // `withdrawn:` line is not an arm and the case it meant to claim is unmapped.
    // This is what makes the column's absence byte-identical to before it existed.
    let dir = mapping_repo(
        "conserves-withdrawn-undeclared",
        "// carried: \"one\" successors/alpha.rs\n// withdrawn: \"two\" the feature is gone\n",
    );
    retire_alpha(&dir);

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an undeclared arm claims nothing: {:?}",
        stdout(&output)
    );
}

// --- growth INSIDE one already-tracked file, on a single-file glob (CLOUD-1137) -
//
// The `admits_with` block above only ever grows the surface by adding a FILE, so
// every case there reads `was == 0`. CLOUD-1137's rows glob `mise.toml` — one
// file, whose count rises in place — and its Ready block recorded that direction
// as UNVERIFIED, to be resolved before the rows chose whether to carry the column
// at all. These cases are that resolution, fixed as behaviour rather than left as
// a reading of `undeclared_growth`.
//
// They also pin the two-literal split those rows ship with. A ratchet `pattern` is
// a literal substring and the kind has no `regex` column (CLOUD-1058), while TOML
// spells a multiline body two ways — so one literal leaves a live false negative,
// and `a_body_in_the_other_quoting_is_invisible_to_the_first_row` is the case that
// would go green if somebody merged the two rows back into one.

/// A manifest carrying two `'''` bodies and one `"""` body — the shape
/// `mise.toml` actually has.
const BASE_MANIFEST: &str = "[tasks.a]\nrun = '''\nbody\n'''\n\n[tasks.b]\nrun = '''\nbody\n'''\n\n[tasks.c]\nrun = \"\"\"\nbody\n\"\"\"\n";

/// The two rows CLOUD-1137 ships over one file, optionally carrying the column.
///
/// `pattern` is single-quoted in the emitted TOML for the `'''` row and
/// double-quoted for the `\"\"\"` row, because each literal contains the other's
/// delimiter — the same reason the shipped rows are spelled that way.
fn manifest_config(admits_with: Option<&str>) -> String {
    let column = match admits_with {
        None => String::new(),
        Some(token) => format!("admits_with = \"{token}\"\n"),
    };
    format!(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"inline-bodies\"\n\
         kind = \"ratchet\"\n\
         glob = \"manifest.toml\"\n\
         pattern = \"run = '''\"\n\
         direction = \"non_increasing\"\n\
         base = \"main\"\n\
         severity = \"deny\"\n\
         {column}\n\
         [[rule]]\n\
         id = \"inline-bodies-basic\"\n\
         kind = \"ratchet\"\n\
         glob = \"manifest.toml\"\n\
         pattern = 'run = \"\"\"'\n\
         direction = \"non_increasing\"\n\
         base = \"main\"\n\
         severity = \"deny\"\n\
         {column}"
    )
}

/// A repo whose base commit carries [`BASE_MANIFEST`].
fn manifest_repo(name: &str, admits_with: Option<&str>) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&manifest_config(admits_with))
        .file("manifest.toml", BASE_MANIFEST)
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

#[test]
fn a_tracked_file_that_grows_in_place_is_a_violation() {
    // THE CASE THE EXISTING BLOCK DOES NOT COVER: no file is added, and the row
    // still fires. `2->3` is the assertion that matters — it says the engine
    // counted OCCURRENCES in one file rather than files matching the glob.
    let dir = manifest_repo("ratchet-inplace-growth", None);
    common::write(
        &dir,
        "manifest.toml",
        &format!("{BASE_MANIFEST}\n[tasks.d]\nrun = '''\nbody\n'''\n"),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("2->3"),
        "the finding names the two counts: {:?}",
        stdout(&output)
    );
}

#[test]
fn in_place_growth_is_admitted_when_the_file_declares_why() {
    // The resolution of CLOUD-1137's open question, stated as behaviour: the
    // column DOES reach an increase inside a file that already existed at base.
    // `undeclared_growth` compares `now > was` per path, and a newly added file is
    // only the `was == 0` case of that — so this is the same admission, not a
    // second one.
    //
    // The shipped `mise.toml` rows nonetheless carry NO `admits_with`, and this
    // case is why the reason had to be cardinality rather than capability: the
    // declaration is a per-FILE boolean, so on a glob selecting one file the first
    // author to write the marker admits every later increase too. That is a
    // property of the glob, not of the column, and it is not expressible as a
    // fixture — hence the waiver, and hence this comment.
    let dir = manifest_repo("ratchet-inplace-declared", Some("# stays-inline:"));
    common::write(
        &dir,
        "manifest.toml",
        &format!(
            "# stays-inline: ISSUE-1 forge bucket\n{BASE_MANIFEST}\n[tasks.d]\nrun = '''\nbody\n'''\n"
        ),
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a declared in-place increase is admitted: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_body_in_the_other_quoting_is_invisible_to_the_first_row() {
    // THE DISCRIMINATING CASE FOR THE TWO-ROW SPLIT. A `"""` body added to the
    // manifest must leave the `'''` row silent and turn the `"""` row red. Merge
    // the two rows into one literal and this goes green while real inline shell
    // lands — the false negative the split exists to close.
    let dir = manifest_repo("ratchet-other-quoting", None);
    common::write(
        &dir,
        "manifest.toml",
        &format!("{BASE_MANIFEST}\n[tasks.d]\nrun = \"\"\"\nbody\n\"\"\"\n"),
    );

    let first = run(&dir, &["check", "--rule", "inline-bodies"]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "the `'''` row does not see a `\"\"\"` body: {:?}",
        stdout(&first)
    );

    let second = run(&dir, &["check", "--rule", "inline-bodies-basic"]);
    assert_eq!(second.status.code(), Some(2));
    assert!(
        stdout(&second).contains("1->2"),
        "the sibling row counts the other spelling: {:?}",
        stdout(&second)
    );
}

#[test]
fn removing_an_inline_body_never_violates_either_row() {
    // Both rows are `non_increasing`, so the direction the campaign wants is
    // silent. Asserted rather than assumed: a row that fired on a REDUCTION would
    // penalise every migration it exists to encourage.
    let dir = manifest_repo("ratchet-inline-shrink", None);
    common::write(&dir, "manifest.toml", "[tasks.a]\nrun = '''\nbody\n'''\n");

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a shrinking inline surface is clean: {:?}",
        stdout(&output)
    );
}

// --- the ledger for a WITHDRAWAL: `.claude/container-setup.sh` (CLOUD-1080) ---
//
// WHY THIS BLOCK IS HERE RATHER THAN BESIDE A SUCCESSOR. Every other block in the
// tree sits on the retired suite's primary successor, because a migration has one.
// This retirement has none: that is what makes it a withdrawal, and what the
// `withdrawn` arm exists to say. So the block sits with the mechanism that admits
// it, and the arms below are the record of which of the eight cases had a successor
// and which did not.
//
// THE HISTORY, because a ledger nobody can check is a ledger nobody should trust.
// `.claude/container-setup.sh` was a Claude-cloud-specific bootstrap: it fetched
// and verified `install.sh` from a release, then ran it, so the binary would be on
// PATH before the `SessionStart` registration of `batten hook` fired. It was added
// and withdrawn inside one session, because the install path it wrapped is meant to
// be harness-agnostic — a single line, every environment — and honouring the CA
// bundle the environment already declares (`CURL_CA_BUNDLE`, else `SSL_CERT_FILE`)
// turned out to be sufficient on its own. Measured: with the bundle honoured the
// one-liner installs straight through an agent proxy that re-terminates TLS, with
// no `NO_PROXY` fencing at all. The wrapper was solving a problem it had misread.
//
// Two cases had real successors and are mapped as such. Six described the wrapper's
// OWN existence — which script to prefer, what to fetch, what to verify about the
// fetched bytes — and have no successor because they should have no subject.

// THE FILE-LEVEL ARM, which is the same ledger one granularity up. `shell-retirement`
// reads these same markers keyed on the retired PATH rather than on a quoted case, so
// the suite owes a row here as well as the eight case rows below — 908 conserves the
// cases, 1059 conserves the file, and a withdrawal has to be spellable at both or the
// honest deletion has no landable form at either.
// withdrawn: tests/container-setup.bats .claude/container-setup.sh the wrapper it covered is withdrawn in this same change and nothing replaced it — there is no policy surface and no compiled-binary test to name, which is what makes this a withdrawal rather than a port

// subsumed: "a binary installed off PATH is refused, not reported ready" tests/install.bats
// changed: "the GitHub hosts are fenced in NO_PROXY before anything is fetched" tests/install.bats the proxy is handled by honouring the declared CA bundle now, not by fencing NO_PROXY — same problem, different and narrower mechanism, covered by three cases there
// withdrawn: "THE DEFAULT: a checkout beside it is NOT used, the release is" the wrapper chose between a checked-out and a fetched install.sh; with no wrapper there is no choice to make
// withdrawn: "the checkout is usable only by opting in, for an unreleased change" the opt-in existed only to override the wrapper's own default
// withdrawn: "the opt-in with no checkout to opt into is could-not-look, not a silent fetch" an error path of that opt-in, which is gone with it
// withdrawn: "an install.sh that refuses is not reported as ready" the wrapper propagated install.sh's exit status; with nothing between the caller and install.sh there is no propagation to assert
// withdrawn: "THE REFUSAL: with no checkout, a script the manifest disagrees with is not run" install.sh deliberately does NOT verify its own bytes — a one-liner cannot, and its trust is TLS plus the release digest it checks on the BINARY
// withdrawn: "with no checkout and no install.sh asset, the gate that should have caught it is named" the wrapper's fetch fallback is gone; `release-assets-check` still demands the asset, which is that obligation's real home

// --- the ledger for a WITHDRAWAL: `hook-latency-drift` (CLOUD-1270) ---
//
// Beside the block above for the same reason it is here at all: a withdrawal has
// no successor to sit with. CLOUD-1270's decided disposition 3 moves the
// measurement into `.github/workflows/hook-latency-drift.yml` as an inline step —
// ungoverned, no task, no verb, no record — so there is no policy surface and no
// compiled-binary tier to name, which is exactly what makes this a withdrawal
// rather than a port.
//
// WHAT THE SUITE ACTUALLY PINNED, stated plainly because the arms below are all
// withdrawals and a reader is entitled to know what that costs. Every case drove
// a `sleep`-based `hk` stub and asserted the ARITHMETIC over it: median of N
// samples, a `BUDGET + SLACK` ceiling, a `BUDGET / LOOSE_FACTOR` floor, and the
// three verdicts those produce. That arithmetic survives verbatim in the step's
// own body, and the four numbers it reads are now `env:` entries beside it rather
// than shell defaults — but nothing re-asserts them, because a workflow step is
// not drivable from `crates/batten/tests/**` and inventing a fixture that re-ran
// the same shell in a test would be a second implementation of the thing under
// test rather than coverage of it.
//
// SO THE COVERAGE LOSS IS REAL AND IS THE PRICE THE ROW PRICED: 24.3s of a corpus
// against six cases over a reporter that decides nothing and gates no commit. The
// one property worth more than the arithmetic — `hk` absent must fail rather than
// pass — is preserved by construction instead of by assertion, because the step
// runs under `set -euo pipefail` and exits 1 on that branch, where the retired
// program exited 2 into a task runner that discarded it on a schedule.
//
// The two file arms name each other as the path this same delta retires, which is
// what `withdrawn_subjects` demands and what stops a row excusing its own deletion.
// withdrawn: mise-tasks/hook-latency-drift.sh tests/hook-latency-drift.bats the successor is an inline step of the scheduled workflow, not a mechanism — nothing enters `crates/batten` and no `policy/*.rego` decides it, so there is no surface to name; CLOUD-1270 disposition 3
// withdrawn: tests/hook-latency-drift.bats mise-tasks/hook-latency-drift.sh the subject died in this same delta and the successor is a workflow step no test target can drive, so the cases have nowhere to go rather than somewhere unnamed; CLOUD-1270 disposition 3
// withdrawn: "a tier inside its budget passes" the in-budget arm is the step's own final `echo` on the path where neither comparison fires; there is no runner-independent way to assert a wall clock from a test target
// withdrawn: "a tier over budget plus slack is drift-tight" the `median > BUDGET + SLACK` comparison moves verbatim into the step, with the tokens `drift-tight` and the two numbers still in the message; nothing re-asserts it because the step is not drivable from a test
// withdrawn: "slack absorbs a small overshoot rather than crying wolf" this pinned that SLACK is added to the ceiling rather than ignored — the same single `ceiling=$((BUDGET_SECONDS + SLACK_SECONDS))` line, now data in the step's `env:` block
// withdrawn: "a tier far under budget is drift-loose, not a silent pass" the ratchet direction, preserved as the `elif` on `median < BUDGET / LOOSE_FACTOR`; it is the arm most likely to rot unnoticed and that is stated here rather than hidden
// withdrawn: "a red gate is still timed, because cost is not correctness" preserved as the `|| true` on the `hk check` line, which is now load-bearing without a case behind it
// withdrawn: "no hk on PATH is could-not-look, never a verdict" the one property that must not collapse into a pass; preserved structurally — `command -v hk` failing exits 1 under `set -e` — rather than by assertion

// --- the ledger for a WITHDRAWAL: `replay` (CLOUD-1163 unit 11) ---
//
// A THIRD WITHDRAWAL BLOCK, AND THE FIRST WHOSE SUBJECT NEVER DECIDED ANYTHING.
// The two above retire a mechanism onto something else — a workflow step, a
// module — and price the arms against that successor. This one has no successor
// at either end, because `replay` was never reachable: a pattern scan of
// `mise.toml`, `hk.pkl`, `.claude/settings.json` and `.github/workflows/` at
// `9e7a9a91` finds the word only in prose, and the sole caller of
// `replay-pointers.py` was `replay.sh:80` itself.
//
// CLOUD-1115 IS THE ARGUMENT FOR THE DELETION RATHER THAN AGAINST IT, and that
// inversion is the whole of why this unit was reachable when the row first read
// as blocked. That issue's title is that `replay`'s tree arm "has never run
// against a real gate and cannot pass it", and its §8 opens "Blockers. None, in
// either direction." A gate off the landing path, invoked by nothing, whose one
// live arm cannot pass, is a gate deciding nothing — and CLOUD-909's own header
// says as much in the present tense: "THIS HARNESS HAS NO LIVE CONSUMER YET."
//
// WHAT IS ACTUALLY LOST, and it is not the fidelity property. `replay` was to be
// the evidence that a migrated gate answers the way the bash it replaced did.
// That property is UNESTABLISHED either way: the harness never ran against a real
// migration, so deleting it removes an unexercised instrument rather than a
// result. What the fifteen cases below pinned is the instrument's own
// discrimination — that it refuses a vacuous pass, refuses an identity
// translation, and reports a divergence instead of admitting one. Those are good
// properties of a thing nobody built a consumer for, and they die with it.
//
// THE ONE FINDING WORTH CARRYING FORWARD, because it cost a measurement and would
// be re-derived by whoever revives this: `batten check` renders `path:line rule`
// for a tree-scoped row and no remedy at all, because rule 4 IS its output
// contract — so a fidelity harness that greps refusal output for remedy prose
// reports every faithful migration of a tree gate as having lost one. The remedy
// has to be read from the DECLARATION (a `forbid` row's column, a policy module's
// own text), never from the refusal. That is recorded here rather than in a
// deleted file.
//
// The two file arms name each other, as `withdrawn_subjects` demands.
// `mise-tasks/replay-pointers.py` needs no arm and gets none: `governed_when_deleted`
// excludes `.py`, so it is simply deleted — and it is still named as the suite's
// co-subject, which dies in this same delta, so `SubjectFacts::died` holds.
// withdrawn: mise-tasks/replay.sh tests/replay.bats the harness has no successor at either end — nothing in `crates/batten` decides it, no `policy/*.rego` replaces it, and no task, hook or workflow ever invoked it; CLOUD-1163 unit 11, on CLOUD-1115's own measurement
// withdrawn: tests/replay.bats mise-tasks/replay.sh both declared subjects die in this same delta and no instrument replaces them, so the cases have nowhere to go rather than somewhere unnamed; CLOUD-1163 unit 11
// withdrawn: "a faithful migration replays green across every carried case" the green arm of an instrument that never ran against a real migration; there is nothing left to be green
// withdrawn: "a module whose pointer set differs is reported, naming the case" the per-case divergence report, which is the harness's whole output surface and dies with it
// withdrawn: "the refusal does not print the two pointer sets side by side" rule 4 over the harness's own output; the rule still binds every gate that exists, this pinned it for one that no longer does
// withdrawn: "a translation declared as an identity is refused" the anti-carry-over arm — `1=1` is the naive `assert_equal $status 1` written down — and it guarded a declaration format nothing now reads
// withdrawn: "0=0 is the one identity that is not a carry-over" the carve-out for the exit code both contracts spell the same; meaningless without the translation it qualified
// withdrawn: "an exit code the translation does not name is a refusal, never a pass" fail-closed on an undeclared status, over a declaration surface this delta removes
// withdrawn: "a divergence on a case marked changed passes, and the same one otherwise fails" the arm that made the harness consume CLOUD-908's `carried`/`changed` markers rather than a second list; the markers survive and their consumer does not
// withdrawn: "a migrated refusal that dropped its remedy is reported" the remedy-preservation check; its finding is carried in the prose above rather than in a case, because there is no program left to assert it against
// withdrawn: "an unreadable head answer is could-not-look, not an empty pointer set" could-not-look over the extractor's input, distinguishing a shape it cannot read from an answer of nothing
// withdrawn: "a document with no findings key is could-not-look too" the same distinction on a well-formed document missing the key, which is the half that fails silently
// withdrawn: "the extractor reports only the rule it was asked about" the filter standing in for a `check --rule` flag; without it every migration read as divergent, and the flag it stood in for now exists on the binary
// withdrawn: "the remedy is read from the declaration, and a policy row from its module" the case behind the finding above, covering both shapes a migration produces
// withdrawn: "a rule the head config does not carry is could-not-look" a broken declaration read as could-not-look rather than blamed on the migration
// withdrawn: "a suite that never invokes the program is a refusal, not a silent pass" the vacuous-pass refusal, and the one this repository has measured four times elsewhere; it is refused here by an instrument that is itself now gone
// withdrawn: "no declared replay at all is not a failure" the mid-campaign carve-out that kept the task useful before its first consumer existed — a consumer that never arrived, which is this withdrawal's premise
