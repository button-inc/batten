//! The Rust workflow's `paths:` filter honours its own claims, over the compiled
//! binary (CLOUD-398, ported from `mise-tasks/rust-paths-check.sh` under
//! CLOUD-843).
//!
//! **What is decidable only here.** `policy/rust-paths-check.rego` carries
//! load-time cases pinning the matcher and the two probe sets, and every one of
//! them supplies the workflow's lines with `with input as`. That fabricates the
//! very shape the engine may be unable to produce (CLOUD-845), and it matters more
//! than usual for this rule: its whole subject is a filter that decides whether a
//! JOB RUNS, and its dangerous failure is silent. A module whose suite only
//! fabricated the file would stay green over an engine that resolved the path to
//! nothing — which is the state where the rule is not evaluated at all, and where
//! a narrowed filter would sail through exactly as it did before the gate existed.
//!
//! The self-consumption case is the one the retiring suite opened on: the
//! committed filter honours every probe, checked rather than asserted.
//
// carried: mise-tasks/rust-paths-check.sh policy/rust-paths-check.rego crates/batten/tests/it/rust_paths_check.rs
// carried: tests/rust-paths-check.bats policy/rust-paths-check.rego crates/batten/tests/it/rust_paths_check.rs
//
// carried: "the committed rust.yml filter honours every probe" policy/rust-paths-check.rego
// carried: "the full filter selects every declared input and no docs path" policy/rust-paths-check.rego
// carried: "a directory glob selects a file below it" policy/rust-paths-check.rego
// carried: "dropping mise.toml is refused, because the jobs run mise tasks" policy/rust-paths-check.rego
// carried: "dropping Cargo.lock is refused" policy/rust-paths-check.rego
// carried: "a whole-repository glob is refused" policy/rust-paths-check.rego
// carried: "selecting the memories tree is refused" policy/rust-paths-check.rego
// carried: "a workflow with no paths filter is exit 2, not a pass" policy/rust-paths-check.rego
// carried: "a pattern the matcher cannot decide is exit 2, not a guess" policy/rust-paths-check.rego
// changed: "a missing workflow is exit 2, not a pass" policy/rust-paths-check.rego the shell took the workflow as an argument and refused a path it could not open; the successor declares it as a `line_sources` path and the ENGINE decides this earlier — a rule whose declared path matches nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). What the case protected survives as the present-but-filterless arm: a workflow that resolves and declares no `paths:` block is still a refusal, never a pass

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn paths_repo(name: &str, entries: &[&str]) -> PathBuf {
    let mut listed = String::new();
    for entry in entries {
        writeln!(listed, "      - \"{entry}\"").unwrap();
    }
    let workflow = format!(
        "on:\n  pull_request:\n    paths:\n{listed}jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    );
    workflow_repo(name, &workflow)
}

fn workflow_repo(name: &str, workflow: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[verdict]]\n\
             id = \"input select missing\"\n\
             gloss = \"the filter does not select an input its jobs read\"\n\
             class = \"A job left absent is accepted by design, so the regression lands green.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[verdict]]\n\
             id = \"input select loose\"\n\
             gloss = \"the filter selects a diff its jobs cannot be affected by\"\n\
             class = \"Every widening is invisible except as a bill.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[verdict]]\n\
             id = \"workflow read unclear\"\n\
             gloss = \"the filter could not be read, or carries a shape this cannot decide\"\n\
             class = \"A guessed selection here is the silent false-absent the gate exists to stop.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"rust-paths-check\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\".github/workflows/rust.yml\"]\n\
             module = \"policy/rust-paths-check.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file(".github/workflows/rust.yml", workflow)
        .git()
        .build();
    common::write(
        &dir,
        "policy/rust-paths-check.rego",
        &std::fs::read_to_string(common::at_root("policy/rust-paths-check.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "rust-paths-check"])
}

/// Every declared input, and nothing a docs-only diff touches.
const HONEST: &[&str] = &[
    "crates/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "deny.toml",
    "mise.toml",
    "mise.lock",
    ".github/workflows/rust.yml",
];

#[test]
fn the_full_filter_selects_every_input_and_no_docs_path() {
    let dir = paths_repo("paths-honest", HONEST);
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_directory_glob_selects_a_file_below_it() {
    // `crates/**` standing for `crates/batten/src/lib.rs` is the reason the
    // filter can stay short at all.
    let dir = paths_repo("paths-directory-glob", HONEST);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_dropped_input_is_refused() {
    // THE SILENT DIRECTION: the jobs run tasks the manifest defines, so a filter
    // written from "the Rust tree" misses it and the jobs go absent.
    let without_manifest: Vec<&str> = HONEST
        .iter()
        .copied()
        .filter(|e| *e != "mise.toml")
        .collect();
    let dir = paths_repo("paths-dropped-manifest", &without_manifest);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("mise.toml"),
        "the finding names the unselected probe: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_dropped_lockfile_is_refused_too() {
    let without_lock: Vec<&str> = HONEST
        .iter()
        .copied()
        .filter(|e| *e != "Cargo.lock")
        .collect();
    let dir = paths_repo("paths-dropped-lock", &without_lock);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_whole_repository_glob_is_refused() {
    // A bare `**` strips to an EMPTY prefix, which a "did the strip change
    // anything" test reads as matching nothing — so a filter selecting the whole
    // repository would pass as narrow.
    let dir = paths_repo("paths-whole-repo", &["**"]);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn selecting_the_memories_tree_is_refused() {
    let mut wide: Vec<&str> = HONEST.to_vec();
    wide.push(".serena/**");
    let dir = paths_repo("paths-memories", &wide);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_workflow_with_no_paths_filter_is_not_a_pass() {
    let dir = workflow_repo(
        "paths-no-filter",
        "on:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_pattern_the_matcher_cannot_decide_is_not_a_guess() {
    let mut with_negation: Vec<&str> = HONEST.to_vec();
    with_negation.push("!docs/**");
    let dir = paths_repo("paths-undecidable", &with_negation);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = workflow_repo(
        "paths-pointer-only",
        "on:\n  pull_request:\n    paths:\n      - \"**\"\njobs:\n  build:\n    runs-on: a-distinctive-runner\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("a-distinctive-runner"),
        "the workflow's content is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_committed_filter_honours_every_probe() {
    // The self-consumption case the retiring suite opened on.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "rust-paths-check"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "the committed paths filter does not honour its own claims: {}",
        stdout(&output)
    );
}
