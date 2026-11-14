//! `policy/release-trigger-independent.rego` decides over the compiled engine
//! (CLOUD-2741).
//!
//! The module's own `test_` rules pin the PREDICATE with `with input as`, which
//! fabricates the very shape the engine may be unable to produce: whether
//! `input.tree.documents` carries a workflow path at all, and whether `on:`
//! parses as the string key rather than YAML 1.1's boolean `true`. Every case
//! here goes in through `batten check` over a real workflow file with a real
//! `on:` key, and reads the verdict a caller would read.
//!
//! Each workflow is inlined. No committed workflow runs the release-asset check
//! today, so reading the tree's own would assert nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The step that makes a workflow the watcher.
const WATCHES: &str = "      - run: mise run release-assets-check \"$TAG\"\n";

/// A step that watches nothing.
const BUILDS: &str = "      - run: mise run ci\n";

/// A throwaway repository carrying the committed module, the row that enables
/// it, the class it raises, and one workflow built from a trigger block and a
/// step.
fn fixture(name: &str, triggers: &str, step: &str) -> PathBuf {
    let root = common::scratch(&format!("release-trigger-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::create_dir_all(root.join(".github/workflows")).expect("scratch workflows dir");
    let module = common::at_root("policy/release-trigger-independent.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(module, root.join("policy/release-trigger-independent.rego"))
        .expect("install committed module");
    fs::write(
        root.join(".github/workflows/release-assets.yml"),
        format!(
            "name: release-assets\non:\n{triggers}jobs:\n  release-assets:\n    \
             runs-on: ubuntu-latest\n    steps:\n{step}"
        ),
    )
    .expect("write the workflow");
    fs::write(
        root.join("batten.toml"),
        concat!(
            "version = 1\n\n",
            "[[rule]]\n",
            "id = \"release watch late\"\n",
            "kind = \"policy\"\n",
            "scope = \"tree\"\n",
            "sources = [\".github/workflows/*.yml\"]\n",
            "module = \"policy/release-trigger-independent.rego\"\n",
            "severity = \"deny\"\n\n",
            "[[verdict]]\n",
            "id = \"release watch late\"\n",
            "gloss = \"the release gate is reachable only through the event that silences it\"\n",
            "class = \"\"\"\n",
            "A gate must not share a trigger with the failure it watches.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"workflow read first\"\n",
            "kind = \"document\"\n",
            "target = \".github/workflows\"\n",
        ),
    )
    .expect("write the fixture authority");
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    root
}

/// The exit contract, asserted by name (`rules/rust.md`): the policy verdict,
/// with the class on stdout.
fn refused(root: &Path) {
    let output = common::run(root, &["check"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "expected the policy verdict: {text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("release watch late"),
        "the finding names the class: {text}"
    );
}

fn clean(root: &Path) {
    let output = common::run(root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "expected a clean tree: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The shape that shipped a release with one asset of eighteen: a watcher on a
/// clock and a dispatch, and nothing that fires per release.
#[test]
fn the_engine_refuses_a_clock_alone() {
    let root = fixture(
        "clock-alone",
        "  schedule:\n    - cron: \"30 6 * * 1\"\n  workflow_dispatch: {}\n",
        WATCHES,
    );
    refused(&root);
}

#[test]
fn the_engine_reads_a_push_trigger_as_independent() {
    let root = fixture("push", "  push:\n    branches: [main]\n", WATCHES);
    clean(&root);
}

#[test]
fn the_engine_reads_a_workflow_run_trigger_as_independent() {
    let root = fixture(
        "workflow-run",
        "  workflow_run:\n    workflows: [release-plz]\n    types: [completed]\n",
        WATCHES,
    );
    clean(&root);
}

/// ANTI-VACUITY. A workflow on a clock alone that watches no release is not the
/// gate's subject; a predicate that fired on every workflow would refuse it.
#[test]
fn the_engine_leaves_a_workflow_watching_nothing_untouched() {
    let root = fixture(
        "watches-nothing",
        "  schedule:\n    - cron: \"0 5 * * *\"\n",
        BUILDS,
    );
    clean(&root);
}
