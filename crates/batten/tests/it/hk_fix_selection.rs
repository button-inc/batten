//! `policy/hk-fix-selection.rego` decides over the compiled engine (CLOUD-681).
//!
//! # Why this tier
//!
//! The module's `test_` cases hand themselves a `lines` array and a `documents`
//! object, so they are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading. Two things
//! here can only be proved against the real boundary: that a file the boundary
//! does NOT parse (`hk.pkl` is Pkl) still reaches a module through
//! `input.tree.lines`, and that `mise.toml`'s task table arrives as a keyed
//! object, so the unrouted-fixer class derives its subject from the repository's
//! own tasks rather than restating a list of tool names.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says the committed config and the
//! committed prose still agree rather than that a fixture of them would.
//!
//! # What this row does NOT decide, and where that half lives
//!
//! Whether hk's `fix` hook selects exactly the gate's fixer-bearing steps is
//! `fix-selection-complete`'s, a `command` row running `mise run
//! fix-selection-check`. It is not answerable from lines: it needs the config
//! evaluated, and evaluation is where the surprise was — the derived spelling
//! evaluates correctly under `pkl` while hk's own evaluator reads it as EMPTY.
//!
//! # The measurement behind the row
//!
//! Before the change, `hk fix --all --plan` on this checkout included 58 steps,
//! of which 7 declared a fixer: `test:bats`, the cargo `test` build,
//! `batten-check`, `policy-test`, `sbom-check` and `token-bench-check` all ran
//! under a task two authorities call the formatters-only subset. hk does not
//! no-op a step with no fixer under `fix`; it runs the step's check. Measured
//! end to end on one machine, `mise run fmt` went from **931s to 2s**.

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
        "id": "hk-fix-selection",
        "kind": "policy",
        "scope": "tree",
        "sources": ["mise.toml"],
        "line_sources": ["hk.pkl", ".claude/rules/toolchain.md"],
        "module": "policy/hk-fix-selection.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a hook config, a manifest and the rules file, plus
/// the committed module.
fn tree(name: &str, config: &str, manifest: &str, rules_doc: &str) -> PathBuf {
    let root = common::scratch(&format!("hk-fix-selection-{name}"));
    common::write(&root, "hk.pkl", config);
    common::write(&root, "mise.toml", manifest);
    common::write(&root, ".claude/rules/toolchain.md", rules_doc);
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/hk-fix-selection.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/hk-fix-selection.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary. The real checkout is not: `verdicts_in` would collect every
    // module's tokens while only this row is loaded, and registry equality runs
    // in BOTH directions — the load is refused for the tokens nothing here emits.
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

/// A hook config whose `fix` hook selects the gate's fixer-bearing steps.
///
/// Assembled from the shipped config's own markers rather than copied wholesale:
/// a fixture that pasted the real 1100-line `hk.pkl` would be re-asserting the
/// file under test, and every edit to it would be a fixture edit too.
const SOUND_CONFIG: &str = r#"
local gate = new Mapping<String, Step> {
  ["deno-fmt"] {
    check = "mise run lint:deno"
    fix = "mise run fmt:deno"
  }
  ["rego"] {
    check = "mise run lint:rego"
    fix = "mise run fmt:rego"
  }
  ["test:bats"] {
    check = "mise run test:bats"
  }
}
local fixers = new Mapping<String, Step> {
  ["deno-fmt"] = gate["deno-fmt"]
  ["rego"] = gate["rego"]
}
hooks {
  ["pre-commit"] {
    steps = gate
  }
  ["fix"] {
    fix = true
    steps = fixers
  }
}
"#;

const SOUND_MANIFEST: &str = r#"
[tasks.fmt]
description = "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list"
run = "hk fix --all"

[tasks."fmt:rego"]
run = "opa fmt -w"

[tasks."fmt:deno"]
run = "deno fmt"
"#;

const SOUND_RULES: &str = "`fmt` remains the formatters-only subset.\n";

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings` states; the scratch name is this case's own, because
    // nextest runs each case in its own process and a shared name is a wipe under
    // another process's read.
    let only = common::scratch("hk-fix-selection-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed hook config should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("sound", SOUND_CONFIG, SOUND_MANIFEST, SOUND_RULES);
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The prose, which is this row's half. What the config DOES is
// `fix-selection-complete`'s, and it is a command rather than a line scan.
// ---------------------------------------------------------------------------

#[test]
fn a_task_description_that_names_the_gate_is_refused() {
    // Exactly one of the two sides was allowed to move; if a later change widens
    // `fmt` back to the gate, this is what obliges the description to be
    // corrected in the same commit rather than left describing something else.
    let manifest = SOUND_MANIFEST.replace(
        r#"description = "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list""#,
        r#"description = "Run the whole hk gate over the tree""#,
    );
    let root = tree("described-as-gate", SOUND_CONFIG, &manifest, SOUND_RULES);
    let found = findings(&root);
    assert!(
        found.iter().any(|(path, _)| path == "mise.toml"),
        "the manifest should be named as the place to fix it: {found:?}"
    );
}

#[test]
fn a_rules_file_that_dropped_the_clause_is_refused() {
    // Both authorities are asserted, because the defect is that they DISAGREE and
    // it does not matter which of them is the one that lied.
    let root = tree(
        "clause-dropped",
        SOUND_CONFIG,
        SOUND_MANIFEST,
        "`fmt` runs the whole gate.\n",
    );
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".claude/rules/toolchain.md"),
        "the rules file should be named as the place to fix it: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// The silent half: a fixer nobody routes.
// ---------------------------------------------------------------------------

#[test]
fn a_fixer_task_no_step_routes_is_refused() {
    // CLOUD-681's second defect, in the shape it actually had: `fmt:deno` existed
    // to be written and no step routed `mise run fmt` to it, so the one formatter
    // the task description promised was the one it could not perform. A fixer
    // nobody routes is indistinguishable from a tree that needs no fixing, which
    // is why no other sensor in this tree could see it.
    //
    // THIS IS THE CASE THAT NEEDS THE PARSED MANIFEST. The routed set is derived
    // from `mise.toml`'s own `fmt:*` task keys, so this passes only if the engine
    // hands the module a keyed task table — not lines it would have to scan.
    let config = SOUND_CONFIG.replace(
        r#"    fix = "mise run fmt:deno"
"#,
        "",
    );
    let root = tree("unrouted", &config, SOUND_MANIFEST, SOUND_RULES);
    let found = findings(&root);
    assert!(
        found.iter().any(|(path, _)| path == "hk.pkl"),
        "an unrouted fixer should be refused against the config: {found:?}"
    );
}

#[test]
fn a_manifest_with_no_fixer_tasks_leaves_the_config_alone() {
    // The half that pays for the class: a repository whose linters have no fixer
    // halves declares no `fmt:*` task, and nothing here is its business. Without
    // this the class would read as "every hk config must route something".
    let manifest = r#"
[tasks.fmt]
description = "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list"
run = "hk fix --all"
"#;
    let config = SOUND_CONFIG
        .replace(
            r#"    fix = "mise run fmt:deno"
"#,
            "",
        )
        .replace(
            r#"    fix = "mise run fmt:rego"
"#,
            "",
        );
    let root = tree("no-fixer-tasks", &config, manifest, SOUND_RULES);
    assert!(
        findings(&root).is_empty(),
        "a tree that declares no fixer task routes nothing: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// Not-applicable is not a pass, and is not a refusal either.
// ---------------------------------------------------------------------------

#[test]
fn a_tree_with_no_hook_config_is_not_judged() {
    // `command-task-defined`'s measured lesson, one row over: an unguarded module
    // reported seven findings against a fixture that copies this config without
    // its subject. A repository that runs no hk hooks has no selection to judge.
    let root = common::scratch("hk-fix-selection-foreign");
    common::write(&root, "mise.toml", SOUND_MANIFEST);
    common::write(&root, ".claude/rules/toolchain.md", SOUND_RULES);
    install_module(&root);
    assert!(
        findings(&root).is_empty(),
        "a tree with no hk config is answering for nothing: {:?}",
        findings(&root)
    );
}
