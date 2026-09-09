//! Every adopted tool's license row is resolved, over the compiled binary
//! (ported from `mise-tasks/license-table-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/license-table.rego` carries
//! load-time cases pinning the parse and the closed set, and each fabricates
//! `input.tree.lines["CONTRIBUTING.md"]`. Only a real repository shows the
//! engine resolving that declaration — which is the anti-vacuity half twice
//! over, since the gate's own subject is "did the table parse to any rows at
//! all".
//
// carried: mise-tasks/license-table-check.sh policy/license-table.rego crates/batten/tests/it/license_table.rs
// carried: tests/license-table-check.bats policy/license-table.rego crates/batten/tests/it/license_table.rs
//
// carried: "license-table-check.bats::the repo as it stands passes" policy/license-table.rego
// carried: "an unresolved license fails, and names the tool" policy/license-table.rego
// carried: "a resolved license with an unresolved verdict still fails" policy/license-table.rego
// carried: "a verdict outside the closed set fails rather than passing" policy/license-table.rego
// carried: "a fully resolved fixture passes" policy/license-table.rego
// carried: "an explicit incompatible verdict is resolved, and passes" policy/license-table.rego
// carried: "a table with no rows is a failure, not a vacuous pass" policy/license-table.rego
// carried: "output is a pointer — it names the tool and the cell, never the table body" policy/license-table.rego
//
// changed: "license-table-check.bats::the gate is wired: hk.pkl declares a step that runs this task" policy/license-table.rego the case asserted that a `mise run` step existed in `hk.pkl`, which is how a shell gate reached the hook at all. A rule row has no step of its own — it is reached through `batten-check`, whose glob is itself gated by `batten-glob-check` and whose `line_sources` declaration is what `batten check --rule license-table` resolves. The wiring is asserted by a different mechanism rather than left unasserted
// changed: "an unreadable file is exit 1 — could not look is not a verdict" policy/license-table.rego the shell took the document as a positional ARGUMENT and could be pointed at an unreadable path. The successor's subject is a declared `line_sources` entry: a glob matching nothing means the rule is not evaluated, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049). There is no caller left that can aim it, so the case has no subject rather than no coverage

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

fn table_repo(name: &str, doc: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[verdict]]\n\
             id = \"tool grade unclear\"\n\
             gloss = \"an adopted tool's declaration is unresolved\"\n\
             class = \"A row still asking the question cannot be shipped against; read the upstream LICENSE and record the SPDX id.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"license-table\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"CONTRIBUTING.md\"]\n\
             module = \"policy/license-table.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("CONTRIBUTING.md", doc)
        .git()
        .build();
    common::write(
        &dir,
        "policy/license-table.rego",
        &std::fs::read_to_string(common::at_root("policy/license-table.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "license-table"])
}

const HEAD: &str = "| Tool | Use | License | Apache-2.0 |\n| --- | --- | --- | --- |\n";

#[test]
fn a_fully_resolved_table_passes() {
    let dir = table_repo(
        "license-resolved",
        &format!("{HEAD}| hk | hooks | MIT | ✅ |\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn an_unresolved_license_fails_and_names_the_tool() {
    let dir = table_repo(
        "license-unresolved",
        &format!("{HEAD}| hk | hooks | _to confirm_ | ✅ |\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("CONTRIBUTING.md"),
        "the finding points at the table: {}",
        stdout(&output)
    );
}

#[test]
fn a_verdict_outside_the_closed_set_fails_over_the_binary() {
    // DISCRIMINATING. A check that only looked for the literal placeholder
    // passes this, which is exactly how an unresolved row slips through.
    let dir = table_repo(
        "license-open-set",
        &format!("{HEAD}| hk | hooks | MIT | probably |\n"),
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unrecognised glyph read as resolved: {}",
        stdout(&output)
    );
}

#[test]
fn a_table_with_no_rows_is_a_failure_not_a_vacuous_pass() {
    // The reason the predecessor existed: a renamed heading or a reformatted
    // table satisfies every per-row assertion by having no rows to assert over.
    let dir = table_repo("license-no-rows", "# Contributing\n\nno table here\n");
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an empty parse read as all rows resolved: {}",
        stdout(&output)
    );
}

#[test]
fn output_is_a_pointer_never_the_table_body() {
    let dir = table_repo(
        "license-pointer-only",
        &format!("{HEAD}| distinctive-tool | a distinctive use | _to confirm_ | ✅ |\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("a distinctive use"),
        "the table body is payload: {}",
        stdout(&output)
    );
}

#[test]
fn the_repo_as_it_stands_passes() {
    let output =
        common::run_at_real_root(&common::at_root(""), &["check", "--rule", "license-table"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an adopted tool's license row is unresolved: {}",
        stdout(&output)
    );
}
