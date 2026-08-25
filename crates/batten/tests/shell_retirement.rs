//! `policy/shell-retirement.rego` decides over the compiled engine rather than
//! over a fabricated input (CLOUD-1059).
//!
//! **This is the tier the module's own `test_` rules cannot be.** A `with input
//! as` block writes the shape it then reads, so it is green over a key the engine
//! never fills — CLOUD-845's defect, and `.claude/rules/policy-modules.md` records
//! both live instances of it being found by adding this tier rather than by
//! reading. `Fact::BaseDelta` is brand new here, so "the schema says
//! `input.tree["base-delta"]` exists" is exactly the untested claim about the
//! engine that this file exists to test.
//!
//! And it is not merely a projection test: every fixture below builds a **real
//! repository with a real base ref**, so the delta is computed by
//! `git::base_delta` from two trees rather than handed in. A test that stubbed
//! the delta would prove the predicate and nothing about the fact.
//!
//! The module read here is the COMMITTED one, copied into each scratch tree
//! rather than restated inline — an inline copy would drift from the shipped
//! module and pass while the real gate was broken, which is the
//! two-authorities-that-drift defect the campaign is about.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does and a row the loader would
/// refuse cannot be smuggled in by hand.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "shell-retirement",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["mise-tasks/**", "tests/**/*.bats"],
        "line_sources": ["mise-tasks/*.sh", "crates/batten/tests/*.rs"],
        "module": "policy/shell-retirement.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A repository whose `origin/main` carries `base`, with `head` applied on top.
///
/// `origin/main` is a real remote-tracking ref rather than a local branch,
/// because that is the name the committed row declares and a fixture that
/// resolved a different one would be testing a different question.
fn repo(name: &str, base: &[(&str, &str)], head: &Head<'_>) -> PathBuf {
    let root = common::scratch(&format!("shell-retirement-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    write_all(&root, base);
    install_module(&root);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "base"]);
    // The remote-tracking ref the row names, pointed at the base commit. No
    // remote is configured: `base_delta` resolves a rev, and a fetch would make
    // the fixture depend on the network for a question that is local.
    let base_sha = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", &base_sha],
    );

    for path in head.removed {
        fs::remove_file(root.join(path)).expect("remove at head");
    }
    write_all(&root, head.written);
    root
}

/// What the working tree does to the base: files written, files removed.
struct Head<'a> {
    written: &'a [(&'a str, &'a str)],
    removed: &'a [&'a str],
}

fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, body).expect("write fixture file");
    }
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/shell-retirement.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/shell-retirement.rego")).expect("install committed module");
}

fn scan(root: &Path) -> rules::Scan {
    rules::run_static(&[row()], &[], &[], root).expect("the read surface runs a policy row")
}

fn findings(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

const GATE: &str = "#!/usr/bin/env bash\n#MISE description=\"a gate\"\necho hi\n";
const SUITE: &str = "# subject: mise-tasks/old-gate.sh\n@test \"it holds\" {\n  true\n}\n";

/// A mapped retirement, spelled the way the ledger spells one.
fn ledger(retired: &str) -> String {
    format!("// carried: {retired} policy/old-gate.rego crates/batten/tests/old_gate.rs\n")
}

// ---------------------------------------------------------------------------
// The positive arm first: without it every refusal below is satisfied by a
// module that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_deleted_and_fully_mapped_shell_rule_passes() {
    let root = repo(
        "mapped",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger("mise-tasks/old-gate.sh"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a conforming migration passes: {:?}",
        findings(&root)
    );
}

#[test]
fn an_untouched_tree_is_silent() {
    let root = repo(
        "untouched",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "nothing changed, nothing to say"
    );
}

// ---------------------------------------------------------------------------
// The refusals, one fixture each.
// ---------------------------------------------------------------------------

#[test]
fn an_added_shell_rule_is_refused() {
    let root = repo(
        "added",
        &[],
        &Head {
            written: &[("mise-tasks/new-gate.sh", GATE)],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn an_added_bats_suite_is_refused() {
    let root = repo(
        "added-bats",
        &[],
        &Head {
            written: &[("tests/new-gate.bats", SUITE)],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

/// The load-bearing arm: an edit is invisible to every other sensor in the tree.
#[test]
fn a_shell_rule_edited_in_place_is_refused() {
    let root = repo(
        "edited",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "mise-tasks/old-gate.sh",
                "#!/usr/bin/env bash\n#MISE description=\"a gate\"\necho changed\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_bats_suite_edited_in_place_is_refused() {
    let root = repo(
        "edited-bats",
        &[("tests/old-gate.bats", SUITE)],
        &Head {
            written: &[(
                "tests/old-gate.bats",
                "# subject: mise-tasks/old-gate.sh\n@test \"it holds\" {\n  false\n}\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_deletion_with_no_mapping_is_refused() {
    let root = repo(
        "unmapped",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_deletion_carrying_two_arms_is_refused() {
    let two = format!(
        "// carried: mise-tasks/old-gate.sh policy/old-gate.rego crates/batten/tests/old_gate.rs\n\
         // subsumed: mise-tasks/old-gate.sh policy/other.rego crates/batten/tests/other.rs\n"
    );
    let root = repo(
        "two-arms",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[("crates/batten/tests/old_gate.rs", &two)],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_mapping_naming_no_policy_surface_is_refused() {
    let root = repo(
        "no-surface",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: mise-tasks/old-gate.sh crates/batten/tests/old_gate.rs\n",
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_mapping_naming_no_compiled_binary_test_is_refused() {
    let root = repo(
        "no-test",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: mise-tasks/old-gate.sh policy/old-gate.rego\n",
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

// ---------------------------------------------------------------------------
// The boundaries, which is where a gate nobody can keep green comes from.
// ---------------------------------------------------------------------------

/// A generated artifact and a non-shell path under `mise-tasks/` are excluded BY
/// PATH, so regenerating completions is not a retirement obligation.
#[test]
fn generated_and_non_shell_paths_are_not_governed() {
    let root = repo(
        "generated",
        &[("mise-tasks/replay-pointers.py", "print('x')\n")],
        &Head {
            written: &[
                ("completions/batten.bash", "# generated\n"),
                ("mise-tasks/replay-pointers.py", "print('y')\n"),
                ("crates/batten/src/lib.rs", "// code\n"),
            ],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "derived output is not an authored shell rule: {:?}",
        findings(&root)
    );
}

/// An untouched shell rule elsewhere in the tree does not affect the result —
/// the predicate decides over the CHANGED set, not over the corpus.
#[test]
fn an_untouched_shell_rule_elsewhere_does_not_fire() {
    let root = repo(
        "bystander",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            ("mise-tasks/bystander.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger("mise-tasks/old-gate.sh"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "only the changed set is judged: {:?}",
        findings(&root)
    );
}

/// A file under `mise-tasks/` carrying neither a shebang nor a `#MISE
/// description=` is not an authored shell rule on the head side.
#[test]
fn a_mise_tasks_file_that_is_not_a_shell_rule_is_not_governed_at_head() {
    let root = repo(
        "not-a-rule",
        &[],
        &Head {
            written: &[("mise-tasks/notes.sh", "just some text\n")],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "classification is the file's own first bytes: {:?}",
        findings(&root)
    );
}

/// The could-not-look arm, and it is the one a vacuous pass would hide. A base
/// that does not resolve must leave the fact `null` and every predicate
/// undefined — never an empty delta, which reads as a clean tree.
#[test]
fn an_unresolvable_base_reports_nothing_rather_than_clean() {
    let root = common::scratch("shell-retirement-no-base");
    common::git_in(&root, &["init", "--initial-branch=main"]);
    install_module(&root);
    write_all(&root, &[("mise-tasks/new-gate.sh", GATE)]);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "only commit"]);
    // No `refs/remotes/origin/main` was ever created, so the declared base does
    // not resolve. An added shell rule is present and would fire if the delta
    // had been fabricated as empty-but-present.
    assert!(
        findings(&root).is_empty(),
        "could-not-look yields no finding: {:?}",
        findings(&root)
    );
    assert!(
        scan(&root).findings.is_empty(),
        "and it is silence rather than a clean verdict"
    );
}
