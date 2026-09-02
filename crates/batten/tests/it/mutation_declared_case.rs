//! `mutation-declared-case`, over the engine that builds its input (CLOUD-1355).
//!
//! # The seam, and why the module's own suite cannot reach it
//!
//! `policy/mutation-declared-case.rego`'s `test_` rules pin the predicate
//! against a fabricated `input.tree.lines`. The question that decides whether
//! this gate is alive is a different one: does the ENGINE put BOTH SIDES —
//! the declaring file AND the suite it names — under `input.tree.lines`, keyed
//! the way the predicate spells them?
//!
//! It has a specific way to fail silently, and it is the `line_sources` glob. A
//! set holding the declarations and not the suites resolves every suite to
//! nothing, `suite_read` never holds, and the rule reports a clean tree over a
//! declaration it never checked — indistinguishable, on the decision surface,
//! from a tree with no stale declarations at all. A `with input as` case cannot
//! see that, because it supplies both sides itself.
//!
//! The committed row's globs are therefore reproduced in [`row`] rather than
//! narrowed for the fixture: a suite path outside them is the defect this file
//! exists to catch, and a fixture that widened them would hide it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// A fixture repository carrying a declaring file and, optionally, the suite it
/// names.
///
/// Every file is written BEFORE the commit, because the engine acquires a
/// declared document from the tracked set: a suite added afterwards would be
/// absent for a reason that has nothing to do with the predicate.
fn repo(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", "work"]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    for (path, body) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).expect("parent");
        fs::write(full, body).expect("write the fixture file");
    }
    install_module(&root);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    root
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/mutation-declared-case.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/mutation-declared-case.rego"))
        .expect("install committed module");
}

/// The committed row's shape, globs included — the field this suite exists to
/// keep honest.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "mutation-declared-case",
        "kind": "policy",
        "scope": "tree",
        "line_sources": [
            "crates/batten/tests/**/*.rs",
            "crates/batten/src/policy/presets/**/*.rego",
            "policy/*.rego",
            "tests/**/*.bats",
            "mise-tasks/**",
        ],
        "module": "policy/mutation-declared-case.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn verdicts(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

const UNDEFINED: &str = "mutation-declared-case";

/// The declaring file, as a module carrying a suite declaration and one row.
fn declaring(suite: &str, case: &str) -> String {
    format!("#MUTANT-SUITE {suite}\n#MUTANT slug|s@a@b@|{case}\n")
}

// ---------------------------------------------------------------------------
// THE READ SEAM.
// ---------------------------------------------------------------------------

/// A resolvable declaration is silent, and this is the case that proves the
/// ENGINE reaches BOTH sides. If the suite's lines resolved to nothing this
/// would pass for the wrong reason — so the refusal below is what gives it
/// meaning, and it is what gives the refusal its own.
#[test]
fn a_declaration_whose_case_its_suite_has_is_silent() {
    let root = repo(
        "mutation-case-clean",
        &[
            (
                "policy/subject.rego",
                &declaring("crates/batten/tests/it/subject.rs", "a_case_that_exists"),
            ),
            (
                "crates/batten/tests/it/subject.rs",
                "#[test]\nfn a_case_that_exists() {}\n",
            ),
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the suite carries the case the declaration names: {:?}",
        verdicts(&root)
    );
}

#[test]
fn a_declaration_naming_a_case_its_suite_lacks_is_refused() {
    let root = repo(
        "mutation-case-missing",
        &[
            (
                "policy/subject.rego",
                &declaring("crates/batten/tests/it/subject.rs", "a_case_nobody_wrote"),
            ),
            (
                "crates/batten/tests/it/subject.rs",
                "#[test]\nfn a_case_that_exists() {}\n",
            ),
        ],
    );
    assert_eq!(verdicts(&root), vec![UNDEFINED.to_owned()]);
}

/// The bats spelling over the engine, and it is not the case above repeated: a
/// `.bats` suite matched with the Rust needle would pass vacuously, so the two
/// needles need one live case each.
#[test]
fn a_bats_title_the_suite_carries_is_silent_over_the_engine() {
    let root = repo(
        "mutation-case-bats-clean",
        &[
            (
                "mise-tasks/subject.sh",
                &declaring("tests/subject.bats", "a case that exists"),
            ),
            ("tests/subject.bats", "@test \"a case that exists\" {\n}\n"),
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the bats suite carries the title: {:?}",
        verdicts(&root)
    );
}

#[test]
fn a_bats_title_the_suite_lacks_is_refused_over_the_engine() {
    let root = repo(
        "mutation-case-bats-missing",
        &[
            (
                "mise-tasks/subject.sh",
                &declaring("tests/subject.bats", "a case nobody wrote"),
            ),
            ("tests/subject.bats", "@test \"a case that exists\" {\n}\n"),
        ],
    );
    assert_eq!(verdicts(&root), vec![UNDEFINED.to_owned()]);
}

/// COULD-NOT-LOOK, and it is the case the `line_sources` glob decides. The
/// suite is real and tracked and sits outside the declared set, so the engine
/// never reads it — and the rule must abstain rather than report the case
/// missing, which would be a verdict about this row's globs spoken as a verdict
/// about the declaration.
#[test]
fn a_suite_outside_the_declared_globs_is_not_reported_as_missing() {
    let root = repo(
        "mutation-case-unread-suite",
        &[
            (
                "policy/subject.rego",
                &declaring("elsewhere/subject.rs", "a_case_nobody_wrote"),
            ),
            ("elsewhere/subject.rs", "fn a_case_that_exists() {}\n"),
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a suite this run did not read is could-not-look, not a finding: {:?}",
        verdicts(&root)
    );
}

/// THE SCOPE NARROWING, over the engine: a file declaring no suite contributes
/// no declaration, so `mutate.rs`'s default mapping stays the sweep's and is
/// never re-derived here.
#[test]
fn a_declaration_whose_file_names_no_suite_is_not_judged() {
    let root = repo(
        "mutation-case-no-suite-declared",
        &[
            (
                "mise-tasks/subject.sh",
                "#MUTANT slug|s@a@b@|a case nobody wrote\n",
            ),
            ("tests/subject.bats", "@test \"a case that exists\" {\n}\n"),
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a file naming no suite is the sweep's to judge: {:?}",
        verdicts(&root)
    );
}

// THE LIVE CORPUS IS GATED, AND NOT FROM HERE. A case running this row over
// this repository was written and removed rather than left passing for the
// wrong reason: `run_static` with ONE row loads the whole verdict registry and
// `check_registry_is_exhausted` then refuses, because ~170 declared classes go
// unraised when a single module is the only one running. The failure is about
// the harness rather than about the tree, and a case that cannot distinguish
// those is worse than no case.
//
// What gates the real corpus is the committed `[[rule]]` row itself: `batten
// check` runs every row, `verify` runs `batten check`, and the `hk` gate runs it
// on the way to a commit. So a case name that goes stale under a rename is
// refused where a contributor sees it, which is the whole of CLOUD-1355 — this
// file's job is to prove the ENGINE feeds the predicate both sides, which is
// what the fixtures above do.
