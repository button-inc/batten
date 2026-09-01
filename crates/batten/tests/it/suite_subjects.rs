//! `policy/suite-subject-retirable.rego` decides over the compiled engine
//! (CLOUD-1156).
//!
//! # Why this tier and not the module's own rules
//!
//! The module's `test_` cases hand themselves a `lines` object, so they are green
//! over a shape the engine may never build. Everything this rule decides rests on
//! one key — `input.tree.lines` populated for a `tests/*.bats` glob — and if the
//! engine does not fill it, `suites` is empty, every arm is vacuously satisfied,
//! and a dead gate is byte-identical to a clean corpus on the decision surface
//! (CLOUD-845). A `with input as` case fabricates exactly the key that would be
//! missing, so it cannot tell the two apart. This tier can.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout, which is
//! what holds the exemption table to the corpus it claims to describe. Every
//! other case here is a shape written to fail; that one is the shape that has to
//! keep passing, and it is what turns the table from a list into a claim.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "suite-subject-retirable",
        "kind": "policy",
        "scope": "tree",
        "line_sources": ["tests/*.bats", "tests/**/*.bats"],
        "module": "policy/suite-subject-retirable.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken — and the
/// exemption table lives inside it, so a restated copy would also be asserting
/// against a table nobody ships.
fn install_module(root: &Path) {
    let source = common::at_root("policy/suite-subject-retirable.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/suite-subject-retirable.rego"))
        .expect("install committed module");
}

/// A scratch tree carrying the named suites, plus the committed module.
fn tree(name: &str, suites: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(&format!("suite-subjects-{name}"));
    for (path, body) in suites {
        common::write(&root, path, body);
    }
    install_module(&root);
    root
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary: registry equality runs in BOTH directions, so collecting the
    // real checkout's tokens would refuse the load for every token nothing here
    // emits. That refusal is correct, so the vocabulary is scoped rather than the
    // assertion loosened.
    findings_declared_by(root, root)
}

fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<(String, Option<usize>)> {
    let verdicts = common::verdicts_in(vocabulary_root);
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
    .map(|finding| (finding.path, finding.line))
    .collect()
}

const GOVERNED: &str =
    "#!/usr/bin/env bats\n# subject: mise-tasks/probe.sh\n\n@test 'a' {\n  true\n}\n";

const IMMORTAL: &str = "#!/usr/bin/env bats\n# subject: mise.toml\n\n@test 'a' {\n  true\n}\n";

/// THE CASE THE LOAD-TIME TIER CANNOT MAKE. Everything else rests on the engine
/// filling `input.tree.lines` for a `tests/*.bats` glob; if it does not, `suites`
/// is empty and this reports nothing while looking exactly like a clean tree.
#[test]
fn the_engine_reads_a_bats_header_and_the_rule_fires() {
    let root = tree("immortal", &[("tests/probe.bats", IMMORTAL)]);
    let found = findings(&root);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "tests/probe.bats", "{found:?}");
}

/// THE ANTI-VACUITY MIRROR. Without it the case above is satisfied by a rule that
/// reports every suite in the corpus, which is a gate nobody would leave on.
#[test]
fn a_suite_subjecting_only_governed_programs_is_clean() {
    let root = tree("governed", &[("tests/probe.bats", GOVERNED)]);
    assert!(findings(&root).is_empty(), "{:?}", findings(&root));
}

/// A suite naming one retirable subject and one immortal one is reported — the
/// `.all()` semantics this row exists for, rather than "any subject will do".
#[test]
fn one_immortal_subject_among_several_is_reported() {
    let root = tree(
        "mixed",
        &[(
            "tests/probe.bats",
            "#!/usr/bin/env bats\n# subject: mise-tasks/probe.sh hk.pkl\n",
        )],
    );
    assert_eq!(findings(&root).len(), 1, "{:?}", findings(&root));
}

/// Deleting the header would otherwise be the way OUT of this gate: the
/// immortal-subject arm quantifies over declared subjects, and a suite with none
/// satisfies it trivially.
#[test]
fn a_suite_declaring_no_subject_is_not_a_clean_suite() {
    let root = tree(
        "headerless",
        &[(
            "tests/probe.bats",
            "#!/usr/bin/env bats\n\n@test 'a' {\n  true\n}\n",
        )],
    );
    assert_eq!(findings(&root).len(), 1, "{:?}", findings(&root));
}

/// A tree that is not this corpus is not judged against the exemption table —
/// the bound arm C's comment records, and the reason the absent-suite half was
/// removed. Without this, the rule would refuse every fixture inheriting the
/// config, which is the regression #770 measured on `prebuilt-lint`.
#[test]
fn a_tree_that_is_not_this_corpus_is_not_judged_against_the_table() {
    let root = tree("foreign", &[]);
    assert!(findings(&root).is_empty(), "{:?}", findings(&root));
}

/// THE CASE THAT HOLDS THE TABLE TO THE CORPUS IT DESCRIBES. Every immortal
/// subject in this checkout is either declared or this goes red, and an exemption
/// for a suite whose subjects have all become retirable goes red too.
#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings` states; the scratch name is this case's own, because
    // nextest runs each case in its own process and a shared name is a wipe under
    // another process's read.
    let only = common::scratch("suite-subjects-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed corpus should satisfy its own exemption table: {found:?}"
    );
}
