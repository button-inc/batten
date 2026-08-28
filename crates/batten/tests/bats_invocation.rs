//! `policy/bats-invocation.rego` decides over the compiled engine (CLOUD-386,
//! retired under CLOUD-1059).
//!
//! # Where this came from
//!
//! The successor to `tests/test-bats-parallel.bats`, whose subject is
//! `mise.toml`'s `[tasks."test:bats"]`. The suite was an authored bats file, so
//! `shell-retirement`'s arm B refused maintaining it in place; the predicate
//! moved into the module and the classification of the task body moved into fact
//! acquisition, which is the same split `command-task-defined` already makes.
//!
//! # Why this tier and not the module's own rules
//!
//! The module's `test_` cases hand themselves a `documents` object, so they are
//! green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading. Two things
//! here can only be proved against the real boundary: that the manifest's
//! `[tasks."test:bats"].run` reaches a module as a parsed string at all, and that
//! `.github/workflows/ci.yml` parses into `jobs.ci.steps[].with.install_args`
//! rather than into lines the module would have to scan.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what would have caught the retired suite's own
//! vacuity risk — a gate whose subject moved out from under it reports nothing
//! and looks identical to a gate that passed.

// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). Its grammar is disjoint from
// CLOUD-908's case arms below by construction: a case arm's first field after the
// marker is a QUOTED case name, and a file arm's is a path.
//
// carried: tests/test-bats-parallel.bats policy/bats-invocation.rego crates/batten/tests/bats_invocation.rs

// CLOUD-908's case arms: every `@test` the retired suite declared, and where its
// predicate now lives. Twelve carried and one changed — the change is stated
// rather than smuggled, because a suite that asserted its own subject exists
// cannot port to a module that treats an absent subject as not-applicable.
//
// carried: "the suite runs in parallel — a silent revert to serial is this gate's whole purpose" policy/bats-invocation.rego
// carried: "the job count is derived from the machine, never a hand-typed number that outlives its runner" policy/bats-invocation.rego
// carried: "the job count is not capped below the machine — that was measured, and it is a large regression" policy/bats-invocation.rego
// carried: "the run asserts how many cases it executed, not merely that none failed" policy/bats-invocation.rego
// carried: "the suites are SELECTED, and the count is taken over the same list" policy/bats-invocation.rego
// carried: "a selector that answers nothing runs everything rather than narrowing" policy/bats-invocation.rego
// carried: "the report survives the run, or the cost corpus has no source" policy/bats-invocation.rego
// carried: "a jobs count of 1 is refused — that is serial wearing the flag's costume" policy/bats-invocation.rego
// carried: "tests are parallelised across files only, never within one" policy/bats-invocation.rego
// carried: "the parallel backend is named explicitly rather than left to bats' default probe" policy/bats-invocation.rego
// carried: "the parallel backend is a pinned tool, so the fast path cannot depend on the host" policy/bats-invocation.rego
// carried: "CI installs the parallel backend — an absent rush is a missing TOOL, not a slow suite" policy/bats-invocation.rego
// changed: "the test:bats invocation was found at all — this suite is not passing vacuously" crates/batten/tests/bats_invocation.rs the suite asserted its own subject exists, which a module cannot: a tree with no `test:bats` task is not-applicable rather than in violation, or the row fires on every fixture that copies this config (`command-task-defined` measured seven such findings). The property survives as `this_repository_is_clean_today` plus `a_tree_with_no_such_task_is_not_judged`, which together say the same thing about THIS tree without claiming it about every tree

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "bats-invocation",
        "kind": "policy",
        "scope": "tree",
        "sources": ["mise.toml", ".github/workflows/ci.yml"],
        "line_sources": ["mise.toml", ".github/workflows/ci.yml"],
        "module": "policy/bats-invocation.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a manifest and a workflow, plus the committed module.
fn tree(name: &str, manifest: &str, workflow: &str) -> PathBuf {
    let root = common::scratch(&format!("bats-invocation-{name}"));
    common::write(&root, "mise.toml", manifest);
    common::write(&root, ".github/workflows/ci.yml", workflow);
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/bats-invocation.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/bats-invocation.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary. The real checkout is not: `verdicts_in` would collect every
    // module's tokens while only this row is loaded, and registry equality runs
    // in BOTH directions — the load is refused for the tokens nothing here emits.
    // That refusal is correct (a class no gate reaches reads as coverage), so the
    // vocabulary is scoped rather than the assertion loosened.
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

/// A manifest whose `test:bats` body carries every conjunct the row wants.
///
/// Assembled from the shipped body's own markers rather than copied wholesale:
/// a fixture that pasted the real 40-line body would be re-asserting the file
/// under test, and every edit to it would be a fixture edit too.
fn sound_manifest() -> String {
    format!(
        r#"
# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)
[tools]
"aqua:shenwei356/rush" = "0.6.0"

[tasks."test:bats"]
run = '''
{}
'''
"#,
        sound_body()
    )
}

fn sound_body() -> String {
    [
        r#"suites=$(./mise-tasks/suite-select.sh) || suites="""#,
        r#"if [ -z "$suites" ]; then suites=$(git ls-files); fi"#,
        r#"expected=$(awk '/^@test /{n++} END{print n+0}' $suites)"#,
        "workers=$(nproc)",
        "report=./target/bats-report",
        "started=$(date +%s)",
        r#"bats --parallel-binary-name rush --jobs "$workers" --no-parallelize-within-files --report-formatter junit --output "$report" $suites"#,
        "elapsed=$(($(date +%s) - started))",
        r#"if [ "$ran" != "$expected" ]; then echo "of $expected cases reported by the runner"; fi"#,
        "recorded=$(awk -f - bench/suites/RESULTS.md)",
        r#"if [ "$recorded" = "-" ]; then :; fi"#,
        r#"if [ "$elapsed" -ge "$recorded" ]; then echo "::error:: slower"; fi"#,
        r#"echo "${elapsed}s wall vs ${recorded}s recorded serial""#,
    ]
    .join("\n")
}

const SOUND_WORKFLOW: &str = r#"
jobs:
  ci:
    timeout-minutes: 87 # budget: p95=1730s x3 measured=2026-08-28
    steps:
      - uses: jdx/mise-action@v4
        with:
          install_args: rust hk aqua:shenwei356/rush
"#;

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
    let only = common::scratch("bats-invocation-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed invocation should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("sound", &sound_manifest(), SOUND_WORKFLOW);
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The speed-up, and the two ways it goes away.
// ---------------------------------------------------------------------------

#[test]
fn a_body_that_lost_the_worker_flag_is_refused() {
    let manifest = sound_manifest().replace(r#"--jobs "$workers""#, "");
    let root = tree("no-jobs", &manifest, SOUND_WORKFLOW);
    let found = findings(&root);
    assert!(
        found.iter().any(|(path, _)| path == "mise.toml"),
        "a dropped --jobs should be refused against the manifest: {found:?}"
    );
}

#[test]
fn a_worker_count_capped_below_the_machine_is_refused() {
    let manifest = sound_manifest().replace("workers=$(nproc)", "workers=$(($(nproc) / 2))");
    let root = tree("capped", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "capping the count below the machine should be refused"
    );
}

#[test]
fn a_workflow_that_does_not_install_the_backend_is_refused() {
    // The half `ci-tools-check` structurally cannot answer: it holds names in the
    // workflow to being declared in the manifest, never a tool the gate needs to
    // being installed. bats aborts rather than falling back when the named
    // parallel binary is absent, so the omission is a failed gate, not a slow one.
    let workflow = SOUND_WORKFLOW.replace(" aqua:shenwei356/rush", "");
    let root = tree("no-rush", &sound_manifest(), &workflow);
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".github/workflows/ci.yml"),
        "the workflow should be named as the place to fix it: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// The count, and the cost.
// ---------------------------------------------------------------------------

#[test]
fn a_run_that_asserts_no_count_is_refused() {
    let manifest = sound_manifest().replace(r#""$ran" != "$expected""#, "false");
    let root = tree("uncounted", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "a run that cannot say how many cases it executed should be refused"
    );
}

#[test]
fn a_run_that_compares_no_wall_clock_is_refused() {
    let manifest = sound_manifest().replace(r#"[ "$elapsed" -ge "$recorded" ]"#, "false");
    let root = tree("uncosted", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "a run that measures nothing against the corpus should be refused"
    );
}

#[test]
fn a_budget_measured_before_the_sweep_is_refused() {
    // CLOUD-386's third predicate, and the one that needs both files at once: the
    // sweep's date lives in a manifest COMMENT and the budget's in a workflow
    // comment, so neither is visible to a parsed document and both come from
    // `line_sources`. This case is what proves the engine fills that key for two
    // paths in one row.
    let workflow = SOUND_WORKFLOW.replace(
        "timeout-minutes: 87 # budget: p95=1730s x3 measured=2026-08-28",
        "timeout-minutes: 36 # budget: p95=701s x3 measured=2026-08-14",
    );
    let root = tree("stale-budget", &sound_manifest(), &workflow);
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, line)| path == ".github/workflows/ci.yml" && line.is_some()),
        "the stale budget line should be pointed at: {found:?}"
    );
}

#[test]
fn a_sweep_that_names_no_hardware_is_refused() {
    // The defect that produced the predicate: the recorded optimum was measured on
    // a 4-core box and the runner has 2, so the table read as a live instruction
    // about hardware CI does not have.
    let manifest = sound_manifest().replace(
        "# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)",
        "# the sweep says four is best",
    );
    let root = tree("no-hardware", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "a sweep table that cannot say what it was taken on should be refused"
    );
}

// ---------------------------------------------------------------------------
// Not-applicable is not a pass, and is not a refusal either.
// ---------------------------------------------------------------------------

#[test]
fn a_tree_with_no_such_task_is_not_judged() {
    // `command-task-defined`'s measured lesson, one row over: an unguarded module
    // reported seven findings against a fixture that copies this config without a
    // task namespace, including against a case named "this repository is clean
    // today".
    let manifest = "[tasks.other]\nrun = \"true\"\n";
    let root = tree("foreign", manifest, SOUND_WORKFLOW);
    assert!(
        findings(&root).is_empty(),
        "a tree with no pole is answering for nothing: {:?}",
        findings(&root)
    );
}
