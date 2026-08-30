//! `policy/ci-parity.rego` decides over the compiled engine (CLOUD-1161).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading.
//!
//! This row reads FOUR document formats at once — YAML workflows, the TOML
//! manifest, a TOML release config and a JSON5 bot config — plus the `lines`
//! fact over two shell programs and `tracked` for a file that must be ABSENT.
//! Whether every one of those resolves, and resolves to the shape the predicates
//! expect, is exactly what a `with input as` case cannot answer, because it
//! fabricates the very structure in question.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says the roster still names exactly the
//! pull-request jobs, the release PR still opens as a draft, the retired second
//! bot has not come back, the surviving one still carries its five bounds, and
//! the fan-in is still wired end to end.
//!
//! # What this row does NOT decide
//!
//! What a run COSTS — the draft guard, superseding, the concurrency group, the
//! ready subscription — is the `ci-hygiene` preset's, because it is true of the
//! practice rather than of this repository. `crates/batten/tests/ci_hygiene.rs`
//! is that half's tier.
//!
//! Whether the foreign-runner cargo invocation still matches the task's own is
//! neither's: it needs mise's answer about mise's task graph, which no policy
//! module can ask for. It stays a mise task.

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
        "id": "ci-parity",
        "kind": "policy",
        "scope": "tree",
        "sources": [
            ".github/workflows/*.yml",
            "mise.toml",
            "release-plz.toml",
            "renovate.json5",
        ],
        "line_sources": ["mise-tasks/abandon-matrix.sh", "mise-tasks/land.sh"],
        "module": "policy/ci-parity.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/ci-parity.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/ci-parity.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    findings_declared_by(root, root)
}

fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary. The real checkout is not: `verdicts_in` would collect every
    // module's tokens while only this row is loaded, and registry equality runs
    // in BOTH directions — the load is refused for the tokens nothing here emits.
    let verdicts = common::verdicts_in(vocabulary_root);
    // The one `[[pattern]]` row this module reads, declared here as the config
    // declares it. An inline regex in the module is refused at LOAD, so the row
    // has to exist for the bundle to compile at all — which is the registry
    // doing its job rather than a fixture detail.
    let patterns = [batten::pattern::NamedPattern {
        id: "mise-run-task".to_owned(),
        regex: "mise run [a-z][a-z0-9:_-]*".to_owned(),
    }];
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
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

// ---------------------------------------------------------------------------
// A sound fixture tree, assembled from the shipped shapes rather than copied.
// ---------------------------------------------------------------------------

const WORKFLOW: &str = r"
name: CI
on:
  pull_request:
    types: [opened, ready_for_review]
jobs:
  ci:
    name: ci
    runs-on: ubuntu-latest
    steps:
      - run: mise run lint
  final:
    name: final
    runs-on: ubuntu-latest
    steps:
      - run: echo done
";

const MANIFEST: &str = r#"
[env]
CI_REQUIRED_CHECKS = "ci,final"
CI_FANIN_CHECK = "final"
CI_FANIN_WORKFLOW = ".github/workflows/ci.yml"

[tasks.verify]
run = "mise run verify:gated"

[tasks."verify:gated"]
run = "mise run lint"
"#;

const RENOVATE: &str = r#"{
  draftPR: true,
  rebaseWhen: "behind-base-branch",
  prConcurrentLimit: 1,
  minimumReleaseAge: "3 days",
  vulnerabilityAlerts: { enabled: true },
  enabledManagers: ["cargo", "github-actions", "mise"],
  packageRules: [{ semanticCommitType: "ci" }],
}
"#;

fn sound(name: &str) -> PathBuf {
    let root = common::scratch(&format!("ci-parity-{name}"));
    common::write(&root, ".github/workflows/ci.yml", WORKFLOW);
    common::write(&root, "mise.toml", MANIFEST);
    common::write(&root, "renovate.json5", RENOVATE);
    common::write(&root, "release-plz.toml", "[pr]\npr_draft = true\n");
    common::write(
        &root,
        "mise-tasks/abandon-matrix.sh",
        "#!/usr/bin/env bash\nrun=\"$CI_FANIN_WORKFLOW\"\n",
    );
    common::write(
        &root,
        "mise-tasks/land.sh",
        "#!/usr/bin/env bash\nmise run abandon-matrix\n",
    );
    install_module(&root);
    root
}

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings_declared_by` states; the scratch name is this case's own,
    // because nextest runs each case in its own process and a shared name is a
    // wipe under another process's read.
    let only = common::scratch("ci-parity-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed wiring should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = sound("sound");
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The defects, each shown able to fail (CLOUD-418).
// ---------------------------------------------------------------------------

#[test]
fn a_ci_task_verify_does_not_run_is_refused() {
    let root = sound("task-parity");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace("- run: mise run lint", "- run: mise run smoke"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a task CI runs that verify does not should be refused"
    );
}

#[test]
fn a_foreign_runner_may_run_a_task_verify_does_not() {
    // There is no local Windows, so the premise "a free local run would have
    // caught it" is false there and the property becomes a prohibition on
    // cross-OS jobs rather than a parity check.
    let root = sound("foreign-runner");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW
            .replace("- run: mise run lint", "- run: mise run smoke")
            .replace(
                "    runs-on: ubuntu-latest\n    steps:\n      - run: mise run smoke",
                "    runs-on: windows-latest\n    steps:\n      - run: mise run smoke",
            ),
    );
    assert!(
        findings(&root).is_empty(),
        "a foreign runner is exempt from task parity: {:?}",
        findings(&root)
    );
}

#[test]
fn a_pull_request_job_missing_from_the_roster_is_refused() {
    // CLOUD-327's false green arriving through the roster: the job is not waited
    // on, so a commit reports green without its verdict.
    let root = sound("job-unrequired");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "  final:",
            "  extra:\n    name: extra\n    runs-on: ubuntu-latest\n    steps:\n      - run: mise run lint\n  final:",
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a pull_request job missing from the roster should be refused"
    );
}

#[test]
fn a_roster_name_matching_no_job_is_refused() {
    let root = sound("roster-ghost");
    common::write(
        &root,
        "mise.toml",
        &MANIFEST.replace(r#""ci,final""#, r#""ci,final,ghost""#),
    );
    assert!(
        !findings(&root).is_empty(),
        "a required name no job creates should be refused"
    );
}

#[test]
fn a_release_config_that_does_not_open_a_draft_is_refused() {
    let root = sound("release-ready");
    common::write(&root, "release-plz.toml", "[pr]\npr_draft = false\n");
    assert!(
        !findings(&root).is_empty(),
        "a release PR that opens ready should be refused"
    );
}

#[test]
fn a_returned_dependabot_config_is_refused() {
    // The property INVERTED rather than being deleted: from the commit that
    // removed the file it asserts the file is not there, so a second updater
    // cannot quietly come back on ecosystems the survivor already owns.
    let root = sound("dependabot");
    common::write(&root, ".github/dependabot.yml", "version: 2\n");
    // `tracked` is a git fact, so the fixture has to be a repository for the
    // file to be visible to the predicate at all.
    common::git_in(&root, &["init", "-q"]);
    common::git_in(&root, &["add", "-A"]);
    assert!(
        !findings(&root).is_empty(),
        "a returned dependabot config should be refused"
    );
}

#[test]
fn each_renovate_bound_dropped_is_refused() {
    // All five, because each is the mechanism rather than a preference and
    // dropping any one changes what the lane spends or what it covers.
    for key in [
        "draftPR: true,",
        r#"rebaseWhen: "behind-base-branch","#,
        "prConcurrentLimit: 1,",
        r#"minimumReleaseAge: "3 days","#,
        "vulnerabilityAlerts: { enabled: true },",
    ] {
        let root = sound("renovate-bound");
        common::write(&root, "renovate.json5", &RENOVATE.replace(key, ""));
        assert!(
            !findings(&root).is_empty(),
            "dropping `{key}` should be refused"
        );
    }
}

#[test]
fn a_zero_concurrent_limit_is_not_a_bound() {
    // Renovate reads 0 as UNLIMITED, so the bound and its own negation differ by
    // a single character. Matching the key without its value would pass here.
    let root = sound("renovate-zero");
    common::write(
        &root,
        "renovate.json5",
        &RENOVATE.replace("prConcurrentLimit: 1,", "prConcurrentLimit: 0,"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a zero concurrency limit is unlimited, not a bound"
    );
}

#[test]
fn a_top_level_commit_type_does_not_satisfy_the_scoped_one() {
    // THE MEASURED DEFECT: a top-level key is silently outranked by the
    // recommended preset's catch-all package rule, so the config asserts an
    // intent the tool overrode.
    let root = sound("commit-type");
    common::write(
        &root,
        "renovate.json5",
        &RENOVATE.replace(
            r#"packageRules: [{ semanticCommitType: "ci" }],"#,
            r#"semanticCommitType: "ci","#,
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a top-level commit type should not satisfy the scoped property"
    );
}

#[test]
fn an_unserved_ecosystem_is_refused() {
    let root = sound("ecosystem");
    common::write(
        &root,
        "renovate.json5",
        &RENOVATE.replace(r#"["cargo", "github-actions", "mise"]"#, r#"["cargo"]"#),
    );
    assert!(
        !findings(&root).is_empty(),
        "an ecosystem nothing proposes updates for should be refused"
    );
}

#[test]
fn a_fanin_outside_the_required_roster_is_refused() {
    let root = sound("fanin-unrequired");
    common::write(
        &root,
        "mise.toml",
        &MANIFEST.replace(
            r#"CI_FANIN_CHECK = "final""#,
            r#"CI_FANIN_CHECK = "nowhere""#,
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a fan-in the landing path does not wait for should be refused"
    );
}

#[test]
fn a_fanin_workflow_declaring_no_such_job_is_refused() {
    let root = sound("fanin-homeless");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace("    name: final", "    name: closing"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a fan-in whose declared home does not carry it should be refused"
    );
}

#[test]
fn an_abandon_that_restates_the_path_is_refused() {
    let root = sound("abandon-literal");
    common::write(
        &root,
        "mise-tasks/abandon-matrix.sh",
        "#!/usr/bin/env bash\nrun=.github/workflows/ci.yml\n",
    );
    assert!(
        !findings(&root).is_empty(),
        "an abandon that restates the path rather than reading the declaration \
         should be refused"
    );
}

#[test]
fn a_lander_that_never_abandons_is_refused() {
    // THE ANTI-VACUITY TERM. Every other fan-in clause makes the abandon SAFE;
    // none of them notices it is never called.
    let root = sound("abandon-uncalled");
    common::write(
        &root,
        "mise-tasks/land.sh",
        "#!/usr/bin/env bash\nmise run ci-wait\n",
    );
    assert!(
        !findings(&root).is_empty(),
        "a lander that never calls the abandon should be refused"
    );
}

// ---------------------------------------------------------------------------
// Not-applicable, never a vacuous pass pretending to be a verdict.
// ---------------------------------------------------------------------------

#[test]
fn a_tree_with_no_verify_task_is_not_this_rows_business() {
    let root = common::scratch("ci-parity-absent");
    install_module(&root);
    assert!(
        findings(&root).is_empty(),
        "absent is not-applicable, never a finding: {:?}",
        findings(&root)
    );
}
