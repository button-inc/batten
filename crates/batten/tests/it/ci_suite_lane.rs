//! `policy/ci-suite-lane.rego` decides over the compiled engine (CLOUD-1140).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading. This row
//! reads deeper into a parsed document than any of its neighbours: not a top
//! level key but `jobs.<name>.steps[].env.HK_SKIP_STEPS`, a mapping inside a
//! sequence inside a mapping. Whether YAML of that depth survives the boundary
//! at all is exactly the class a `with input as` case cannot answer, because it
//! fabricates the very structure in question.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says the `ci` job's carve-out and the
//! `bats` job that answers it are still paired — the live property, not a
//! fixture of it.
//!
//! # What this row does NOT decide, and where that half lives
//!
//! Whether the `slow` tier still runs under `hk check` at all is
//! `hook-profile-check`'s, over the hk plan. This row is deliberately blind to
//! the plan: its whole subject is what a workflow CALLER passes, which is the
//! half a plan cannot see and the reason the two are not one gate.
//!
//! Whether the surviving job installs what the suite needs is
//! `bats-invocation`'s, whose `install_args` clause derives the job from the
//! same `mise run test:bats` reading this file exercises.
//!
//! # The measurement behind the row
//!
//! On run 33244045030 the `ci` job was 1983s of a 1992s CI run — the entire
//! critical path, with `perf` finishing at 9.2 min and idling for 24 more.
//! `mise run ci` was 1832s of the job and `test:bats` ~83% of that. CLOUD-386
//! swept the worker count at the runner's real width and found every direction
//! worse, because each point redistributes workers inside one saturated 2-core
//! box; its point D measured the suite alone with the box to itself at 623s
//! against 829s contended. The carve-out this row guards is what turns the
//! gate's wall clock from a sum of the two chains into a max.

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
        "id": "ci-suite-lane",
        "kind": "policy",
        "scope": "tree",
        "sources": [".github/workflows/ci.yml"],
        "module": "policy/ci-suite-lane.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying one workflow and the committed module.
fn tree(name: &str, workflow: &str) -> PathBuf {
    let root = common::scratch(&format!("ci-suite-lane-{name}"));
    common::write(&root, ".github/workflows/ci.yml", workflow);
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/ci-suite-lane.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/ci-suite-lane.rego")).expect("install committed module");
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

/// The shape this repository actually ships, reduced to the two jobs the row is
/// about.
///
/// Assembled from the real workflow's own markers rather than copied wholesale:
/// a fixture that pasted the shipped 600-line `ci.yml` would be re-asserting the
/// file under test, and every edit to it would be a fixture edit too.
const PAIRED: &str = r"
name: CI
on:
  pull_request:
    types: [opened]
jobs:
  ci:
    name: ci
    runs-on: ubuntu-latest
    steps:
      - run: mise run ci
        env:
          DOCTOR_TARGETS: ''
          HK_SKIP_STEPS: test:bats
  bats:
    name: bats
    runs-on: ubuntu-latest
    steps:
      - run: mise run test:bats
        env:
          DOCTOR_TARGETS: ''
";

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
    // nextest runs each case in its own process and a shared name is a wipe
    // under another process's read.
    let only = common::scratch("ci-suite-lane-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed workflow should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("paired", PAIRED);
    assert!(
        findings(&root).is_empty(),
        "the paired fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The defect itself.
// ---------------------------------------------------------------------------

#[test]
fn a_carved_out_step_no_job_runs_is_refused() {
    // THE FALSE GREEN THIS ROW EXISTS FOR. The `ci` job still hands hk the step
    // to skip and the job that answered it is gone, so the suite runs on no
    // runner at all. `hook-profile-check` is green here — the hk plan is
    // unchanged by an env var — and so is every other gate in the tree.
    let orphaned = PAIRED
        .split_once("  bats:")
        .expect("the fixture carries the bats job")
        .0;
    let root = tree("orphaned", orphaned);
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".github/workflows/ci.yml"),
        "the workflow should be named as the place to fix it: {found:?}"
    );
}

#[test]
fn the_engine_reads_a_job_level_carve_out_too() {
    // The variable is honoured at either level, so a reading that reached only
    // into `steps[].env` would answer "nothing is skipped" about a workflow that
    // skips — a silent pass, which is the one direction this row must not have.
    // It is also a second, shallower path through the parsed document, so it
    // says the boundary builds `jobs.<name>.env` and not merely the step list.
    let job_level = r"
name: CI
on:
  pull_request:
    types: [opened]
jobs:
  ci:
    name: ci
    runs-on: ubuntu-latest
    env:
      HK_SKIP_STEPS: test:bats
    steps:
      - run: mise run ci
";
    let root = tree("job-level", job_level);
    assert!(
        !findings(&root).is_empty(),
        "a job-level carve-out nothing answers should be refused"
    );
}

#[test]
fn a_second_name_cannot_ride_in_on_the_first_ones_coverage() {
    // The variable takes a list, so coverage has to be decided per name. Asserted
    // over the compiled binary rather than only in the module because the split
    // happens on a value the boundary hands over, and a YAML scalar that arrived
    // quoted, folded or coerced would split differently than the fixture's does.
    let two = PAIRED.replace(
        "HK_SKIP_STEPS: test:bats",
        "HK_SKIP_STEPS: test:bats,sbom-check",
    );
    let root = tree("two-names", &two);
    assert!(
        !findings(&root).is_empty(),
        "the uncovered name of the list should still be refused"
    );
}

// ---------------------------------------------------------------------------
// The two ways of being silent, and they must not be spelled the same.
// ---------------------------------------------------------------------------

#[test]
fn a_workflow_that_carves_nothing_out_is_clean() {
    // ANTI-VACUITY'S OTHER HALF. A workflow with no carve-out has nothing to
    // answer for, and reading that as a pass earned by coverage would let the
    // row report green over a tree where the mechanism does not exist.
    let plain = PAIRED.replace("          HK_SKIP_STEPS: test:bats\n", "");
    let root = tree("no-carve-out", &plain);
    assert!(
        findings(&root).is_empty(),
        "a workflow that skips nothing should be clean: {:?}",
        findings(&root)
    );
}

#[test]
fn a_tree_with_no_such_workflow_is_not_this_rows_business() {
    let root = common::scratch("ci-suite-lane-absent");
    install_module(&root);
    assert!(
        findings(&root).is_empty(),
        "absent is not-applicable, never a finding: {:?}",
        findings(&root)
    );
}
