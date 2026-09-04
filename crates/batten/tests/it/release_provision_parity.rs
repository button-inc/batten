//! `policy/release-provision-parity.rego` decides over the compiled engine
//! (CLOUD-1431).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading.
//!
//! This row is the one in the tree that reads TWO documents of different formats
//! and different depths to reach one verdict: a `strategy.matrix.include[].target`
//! out of parsed YAML, and a `[[provision]]` row's `platforms` table KEYS out of
//! parsed TOML. Whether the boundary builds both from one rule's `sources` is
//! precisely what a `with input as` case cannot answer, because it fabricates
//! the structures in question.
//!
//! The second thing only this tier settles is the platform table's shape. A TOML
//! `[provision.platforms.linux-x86_64]` sub-table arrives as a nested map whose
//! KEYS are the platform names, and the predicate reads the keys rather than the
//! values. A module that read the values, or expected a list, would be green in
//! its own suite over a fabricated object and dead over real config.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout, and it is
//! the only case that can say the declared gaps still match the tree. Every
//! other fixture is a shape somebody wrote to fail.
//!
//! # The measurement behind the row
//!
//! Job 100903936005, the first arm64 run of `batten-check`:
//! `provision ripsecrets: no artifact for linux-aarch64; the entry pins
//! linux-x86_64, macos-aarch64, macos-x86_64`. Upstream publishes three binaries
//! and has since v0.1.2 — `aarch64-apple-darwin`, `x86_64-apple-darwin`,
//! `x86_64-unknown-linux-gnu` — so `linux-aarch64` cannot be pinned, and
//! `no-source-built-tool` forbids compiling one. Building the mapping surfaced a
//! second instance nobody had found: `x86_64-pc-windows-gnu` has been in exactly
//! the same state for its whole life, with no runner to reveal it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "release-provision-parity",
        "kind": "policy",
        "scope": "tree",
        "sources": [".github/workflows/release-artifacts.yml", "batten.toml"],
        "module": "policy/release-provision-parity.rego",
        "severity": "deny",
        "no_fix_reason": "a platform a provisioned tool cannot reach is not fixable in this tree: either the upstream artifact exists and the row should pin it, or it does not and the gap is declared with its consequence — and which of the two is a supply-chain decision, not a rewrite",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a release workflow, a config, and the committed
/// module.
fn tree(name: &str, targets: &[&str], platforms: &[&str]) -> PathBuf {
    let root = common::scratch(&format!("release-provision-parity-{name}"));
    let mut matrix = String::new();
    for target in targets {
        write!(
            matrix,
            "          - target: {target}\n            build-tool: cross\n"
        )
        .expect("writing to a String cannot fail");
    }
    common::write(
        &root,
        ".github/workflows/release-artifacts.yml",
        &format!(
            "name: release-artifacts\non:\n  workflow_dispatch:\njobs:\n  dist:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        include:\n{matrix}"
        ),
    );
    let mut table = String::new();
    for key in platforms {
        write!(
            table,
            "[provision.platforms.{key}]\nurl = \"https://example.invalid/a.tar.gz\"\nsha256 = \"0\"\n\n"
        )
        .expect("writing to a String cannot fail");
    }
    common::write(
        &root,
        "batten.toml",
        &format!(
            "[[provision]]\nname = \"scanner\"\nversion = \"1\"\nunpack = \"tar_gz\"\nbinary = \"scanner\"\n\n{table}"
        ),
    );
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/release-provision-parity.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/release-provision-parity.rego"))
        .expect("install committed module");
}

fn findings(root: &Path) -> Vec<String> {
    findings_declared_by(root, root)
}

fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<String> {
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
    .map(|finding| finding.path)
    .collect()
}

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

/// Every target `release-artifacts.yml` publishes is either pinned by the
/// `[[provision]]` table or a declared gap — over the real documents, read by
/// the real boundary.
///
/// This is the case that goes red when somebody adds a release target, adds a
/// provisioned tool, or narrows a platform table. That is the whole point of the
/// row: the pairing gets decided on the change that makes it, rather than on a
/// consumer's machine months later.
#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // THE VOCABULARY IS A DIRECTORY HOLDING ONLY THIS MODULE, and that is forced
    // rather than tidy. `verdicts_in` collects the tokens the `.rego` files under
    // a root RAISE — it never reads a config — and registry equality runs in both
    // directions: the real checkout over-declares, because it would collect every
    // module's tokens while only this row is loaded, and an empty directory
    // under-declares, so this module's own token reaches nothing and the load is
    // refused. Measured both ways while writing this case.
    //
    // The scratch name is this case's own: nextest runs each case in its own
    // process, and a shared name is a wipe under another process's read.
    let only = common::scratch("release-provision-parity-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "every published target is pinned or a declared gap: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// The refusals.
// ---------------------------------------------------------------------------

/// A published target whose platform nothing pins and no row declares.
///
/// `#MUTANT gap-may-go-undeclared` names this case: dropping the `declared_gap`
/// conjunct makes the rule refuse the tree's own declared gaps, and this case is
/// where that shows up as a changed verdict rather than as a changed count.
#[test]
fn an_undeclared_platform_gap_is_refused() {
    // darwin-x86_64 is a real target and a real gap, and it is NOT in the
    // module's declared set — so it must refuse.
    let root = tree("undeclared", &["x86_64-apple-darwin"], &["linux-x86_64"]);
    assert!(
        !findings(&root).is_empty(),
        "a published target no provision row can serve is the defect this row owns"
    );
}

/// A triple the mapping does not name is could-not-look, and could-not-look
/// refuses rather than passing.
///
/// The direction matters: reading an unknown triple as covered is the dead-gate
/// shape, so a NEW release target reddens here until the map names it.
#[test]
fn a_target_the_mapping_does_not_name_is_refused() {
    let root = tree(
        "unmapped",
        &["riscv64gc-unknown-linux-gnu"],
        &["linux-x86_64"],
    );
    assert!(
        !findings(&root).is_empty(),
        "a triple with no platform key is a question this rule cannot answer"
    );
}

/// A declared source that will not parse reaches the could-not-look channel
/// rather than leaving the finding set empty.
#[test]
fn an_unparsed_release_workflow_is_reported() {
    let root = common::scratch("release-provision-parity-unparsed");
    common::write(
        &root,
        ".github/workflows/release-artifacts.yml",
        "name: [unterminated\n  - : :\n",
    );
    install_module(&root);
    assert!(
        !findings(&root).is_empty(),
        "a source the boundary could not read must be said, not abstained on"
    );
}

// ---------------------------------------------------------------------------
// The silences, which are the load-bearing half.
// ---------------------------------------------------------------------------

/// A pinned platform is clean — the anti-vacuity mirror for every refusal above.
#[test]
fn a_pinned_target_is_clean() {
    let root = tree("pinned", &["x86_64-unknown-linux-gnu"], &["linux-x86_64"]);
    assert!(
        findings(&root).is_empty(),
        "a target the table pins is not a finding: {:?}",
        findings(&root)
    );
}

/// `-musl` and `-gnu` are one platform to a downloaded binary's URL table, so
/// pinning one covers both.
///
/// `#MUTANT musl-may-not-map` names this case: deleting the musl row from the
/// mapping makes this triple unmapped, which the could-not-look arm then
/// refuses — so the mutation turns this silence into a finding.
#[test]
fn a_musl_triple_maps_to_the_same_platform_key_as_gnu() {
    let root = tree("musl", &["x86_64-unknown-linux-musl"], &["linux-x86_64"]);
    assert!(
        findings(&root).is_empty(),
        "platform keys carry no libc flavour, so the gnu pin serves musl: {:?}",
        findings(&root)
    );
}

/// A declared gap is silent, and this case is the one a reviewer should distrust
/// most: it is the only thing standing between this gate and a red tree.
#[test]
fn a_declared_gap_is_silent() {
    let root = tree(
        "declared",
        &["aarch64-unknown-linux-gnu"],
        &["linux-x86_64"],
    );
    assert!(
        findings(&root).is_empty(),
        "linux-aarch64 is declared unavailable with its reason: {:?}",
        findings(&root)
    );
}
