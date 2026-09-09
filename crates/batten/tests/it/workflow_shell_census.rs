//! `.github/workflows/**` is counted, over the compiled binary (CLOUD-1709).
//!
//! **What these cases are for, and what `ratchet.rs` next door already covers.**
//! That tier proves the ratchet KIND: direction, counts, base movement, waivers,
//! byte stability. Nothing there is about this surface. What is decidable only
//! here is that the two literals this row picked actually count what a workflow
//! spells — and, more importantly, that they do NOT count what a workflow spells
//! that is not shell.
//!
//! **The anchoring is the case worth having.** `run:` unanchored also matches
//! `workflow_run:` and `check_run:`, which are trigger declarations rather than
//! steps; there are 15 of them in the tree today. A row that counted those would
//! report a rise whenever a workflow gained a trigger, and would report a fall
//! when one lost it — a census moving on something that is not shell at all.
//! `a_trigger_declaration_is_not_a_shell_step` is the discriminating case, and it
//! is the one a naive `pattern = "run:"` fails.
//!
//! The exit assertion is **2** throughout. The retiring shell corpus spells a
//! violation `1`; carrying that inversion in is the defect CLOUD-1718 names.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

/// The row as `batten.toml` declares it, minus the origin ref.
///
/// `base = "main"` rather than `origin/main`: the fixtures carry no origin
/// literal (`no-origin-literal-in-fixtures`), and a local branch proves the same
/// plumbing. Both spellings are declared together because the pair is the
/// predicate — one row alone is a census with a hole in it, which is the whole
/// reason there are two.
fn census_config(admits: bool) -> String {
    let permit = if admits {
        "admits_with = \"# workflow-shell:\"\n"
    } else {
        ""
    };
    format!(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"workflow-shell-not-growing\"\n\
         kind = \"ratchet\"\n\
         glob = \".github/workflows/**\"\n\
         pattern = \"\\n        run:\"\n\
         direction = \"non_increasing\"\n\
         base = \"main\"\n\
         {permit}\
         severity = \"deny\"\n\
         scope = \"tree\"\n\n\
         [[rule]]\n\
         id = \"workflow-shell-not-growing-bare\"\n\
         kind = \"ratchet\"\n\
         glob = \".github/workflows/**\"\n\
         pattern = \"\\n      - run:\"\n\
         direction = \"non_increasing\"\n\
         base = \"main\"\n\
         {permit}\
         severity = \"deny\"\n\
         scope = \"tree\"\n"
    )
}

/// A workflow carrying one of each spelling, plus a trigger that is not a step.
///
/// The `workflow_run:` trigger is in the BASE rather than added by a case,
/// because the property is that it is never counted — in either half of the
/// comparison. A fixture that only added one would leave the base side untested.
const BASE_WORKFLOW: &str = "\
name: ci
on:
  workflow_run:
    workflows: [other]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: named step
        run: echo one
      - run: echo two
";

fn census_repo(name: &str, admits: bool) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&census_config(admits))
        .file(".github/workflows/ci.yml", BASE_WORKFLOW)
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
fn a_tree_at_the_ceiling_passes() {
    let dir = census_repo("workflow-census-held", false);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(
        output.stdout.is_empty(),
        "a ratchet that held says nothing: {}",
        stdout(&output)
    );
}

#[test]
fn one_named_step_over_the_ceiling_fails() {
    // The 8-space spelling: a `run:` key under a `- name:`.
    let dir = census_repo("workflow-census-named-over", false);
    common::write(
        &dir,
        ".github/workflows/ci.yml",
        &format!("{BASE_WORKFLOW}      - name: added\n        run: echo three\n"),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("workflow-shell-not-growing"),
        "the finding names the rule: {text:?}"
    );
    assert!(
        text.contains("1->2"),
        "and carries both counts, so a reader sees how far it moved: {text:?}"
    );
    assert!(
        !text.contains("echo three"),
        "pointer-only: the step's body is payload and never appears: {text:?}"
    );
}

#[test]
fn one_bare_step_over_the_ceiling_fails_the_other_row() {
    // The 6-space `- run:` spelling. A separate case rather than a second
    // assertion, because the whole reason there are two rows is that one literal
    // cannot see the other — so a case that only exercised the first would pass
    // over a census with a live hole in it.
    let dir = census_repo("workflow-census-bare-over", false);
    common::write(
        &dir,
        ".github/workflows/ci.yml",
        &format!("{BASE_WORKFLOW}      - run: echo three\n"),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("workflow-shell-not-growing-bare"),
        "the bare spelling is the OTHER row's, and it must be the one that fires: {text:?}"
    );
}

#[test]
fn a_trigger_declaration_is_not_a_shell_step() {
    // DISCRIMINATING, and the case a naive `pattern = "run:"` fails. Adding a
    // `workflow_run:` trigger adds no shell, so neither row may move. Without the
    // newline anchor both would count it and the census would report growth on a
    // change that added no bash at all.
    let dir = census_repo("workflow-census-trigger", false);
    common::write(
        &dir,
        ".github/workflows/ci.yml",
        &BASE_WORKFLOW.replace(
            "    types: [completed]\n",
            "    types: [completed]\n  check_run:\n    types: [created]\n",
        ),
    );

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a trigger is not shell and must not move the census: {}",
        stdout(&output)
    );
}

#[test]
fn a_declared_increase_is_admitted_and_an_undeclared_one_is_not() {
    // The `admits_with` half, which is why the row carries the permit at all: a
    // retirement that lands a `run: batten <verb>` step raises this count while
    // lowering real bash, and that firing is the campaign succeeding rather than
    // a defect. Both halves in one case because the permit means nothing unless
    // the same edit without it still fails.
    let added = format!("{BASE_WORKFLOW}      - name: added\n        run: echo three\n");

    let undeclared = census_repo("workflow-census-permit-absent", true);
    common::write(&undeclared, ".github/workflows/ci.yml", &added);
    assert_eq!(
        check(&undeclared).status.code(),
        Some(2),
        "an undeclared increase is still refused when the column exists"
    );

    let declared = census_repo("workflow-census-permit-present", true);
    common::write(
        &declared,
        ".github/workflows/ci.yml",
        &format!(
            "# workflow-shell: CLOUD-1709 the step invokes a retired program's successor\n{added}"
        ),
    );
    let output = check(&declared);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a declared increase is owned rather than refused: {}",
        stdout(&output)
    );
}
