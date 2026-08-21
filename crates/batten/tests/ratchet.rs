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

mod common;

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
