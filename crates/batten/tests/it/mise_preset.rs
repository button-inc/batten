//! The `mise` preset's TREE half decides over the compiled engine (CLOUD-1672).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding a tier like this rather than by reading.
//!
//! Here the hazard is sharper than usual, because this predicate reads **two
//! documents of different formats** and compares them. The workflow is YAML and
//! the pin table is TOML, and the module joins them by shape rather than by
//! filename — so what a fabricated `documents` object cannot show is whether the
//! engine actually delivers both. If it delivers only the workflows, the pin is
//! absent, the module abstains BY DESIGN, and the gate reports clean over every
//! tree forever. That failure is invisible to the load-time suite, invisible in
//! the output, and is precisely the drift the row exists to catch.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the preset over this checkout, where
//! all 24 committed workflows declare the version the `[[provision]]` row pins.
//! `a_drifted_version_in_this_repository_is_refused` is its discriminating twin:
//! it takes the same real tree, moves one workflow's version, and requires a
//! finding. Together they say the rule passes the tree it should and fails the
//! tree it should — which a fixture pair alone cannot, because a fixture
//! supplies its own pin document and so proves nothing about the glob.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
///
/// `sources` carries `batten.toml` BESIDE the workflow globs, and that is the
/// column this whole file exists to hold. Drop it and every case below still
/// compiles, the suite still runs, and the deny cases silently stop denying.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "task table other",
        "kind": "policy",
        "scope": "tree",
        "preset": "mise",
        "sources": [
            "batten.toml",
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
        ],
        "line_sources": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying one workflow and one pin table.
///
/// No module is installed: a preset ships INSIDE the binary, so unlike an
/// in-repo module there is nothing to copy into the fixture. That is also what
/// makes this tier the only place the vendored bytes are exercised at all.
fn tree(name: &str, pins: &str, workflow: &str) -> PathBuf {
    let root = common::scratch(&format!("mise-preset-{name}"));
    common::write(&root, "batten.toml", pins);
    common::write(&root, ".github/workflows/ci.yml", workflow);
    root
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // The empty vocabulary is what a consumer hands a preset, and it is the
    // point rather than a shortcut. A preset's verdicts are the binary's own
    // vendored table; its `[[pattern]]` lookups would resolve to undefined for
    // every real consumer, so a harness that declared any id would supply input
    // no consumer supplies and the deny cases below would pass for the wrong
    // reason — how `job spelling wrong` once shipped two dead predicates under a green
    // `batten policy test` reporting 330 passed.
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &[],
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

/// The pin, reduced to the one row the predicate reads.
const PINS: &str = r#"
[[provision]]
name = "mise"
version = "2026.9.1"
"#;

/// A pin table naming some other tool, so the mise row is genuinely absent.
const OTHER_PIN: &str = r#"
[[provision]]
name = "ripsecrets"
version = "0.1.11"
"#;

fn workflow(step: &str) -> String {
    format!(
        r"
name: CI
on:
  pull_request:
jobs:
  build:
    name: build
    runs-on: ubuntu-latest
    steps:
{step}
"
    )
}

/// The action declaring a version.
fn declaring(version: &str) -> String {
    workflow(&format!(
        "      - uses: jdx/mise-action@3c2e0cf8\n        with:\n          version: {version}"
    ))
}

/// The action declaring none — the shape that produced the incident.
fn bare() -> String {
    workflow("      - uses: jdx/mise-action@3c2e0cf8")
}

// ---------------------------------------------------------------------------
// The tree this preset actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "every committed workflow should install the version batten.toml pins: {found:?}"
    );
}

#[test]
fn a_drifted_version_in_this_repository_is_refused() {
    // THE DISCRIMINATING TWIN OF THE CASE ABOVE, and the only case in this file
    // that can fail if the `sources` glob stops delivering `batten.toml`. Every
    // other deny case writes its own pin table into a scratch tree, so it would
    // keep passing over a row that never reads the consumer's. This one copies
    // the real checkout's workflows and real pin table, moves ONE version, and
    // requires the finding.
    let real = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let root = common::scratch("mise-preset-real-drift");
    let pins = std::fs::read_to_string(real.join("batten.toml")).expect("the committed authority");
    common::write(&root, "batten.toml", &pins);

    let from = real.join(".github/workflows/ci.yml");
    let workflow = std::fs::read_to_string(&from).expect("the committed workflow");
    // The pin the sweep landed, moved to a version the provision row does not
    // name. Asserted rather than assumed: if the committed spelling ever
    // changes, this case must fail loudly rather than silently replacing nothing
    // and then passing because the tree is clean.
    assert!(
        workflow.contains("version: 2026.9.1"),
        "the committed workflow should carry the pinned version"
    );
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &workflow.replacen("version: 2026.9.1", "version: 2026.9.3", 1),
    );

    let found = findings(&root);
    assert!(
        !found.is_empty(),
        "a workflow installing a version the pin table does not name is refused"
    );
}

// ---------------------------------------------------------------------------
// The two directions, over the engine.
// ---------------------------------------------------------------------------

#[test]
fn a_step_declaring_another_version_is_refused() {
    let root = tree("other", PINS, &declaring("2026.9.3"));
    assert!(
        !findings(&root).is_empty(),
        "a declared version that disagrees with the pin is refused"
    );
}

#[test]
fn a_step_declaring_no_version_is_refused() {
    let root = tree("bare", PINS, &bare());
    assert!(
        !findings(&root).is_empty(),
        "an absent version hands the choice to the installer and is refused"
    );
}

#[test]
fn a_matching_version_is_clean() {
    // Without this the two cases above could both be produced by a rule that
    // refuses every workflow carrying this action, which looks identical to one
    // that compares.
    let root = tree("match", PINS, &declaring("2026.9.1"));
    let found = findings(&root);
    assert!(found.is_empty(), "the pinned version is clean: {found:?}");
}

#[test]
fn an_unpinned_tool_is_not_this_rules_business() {
    // ANTI-VACUITY. With no `[[provision]]` row for the tool there is nothing to
    // disagree with, so the same bare step that is refused above is clean here.
    // A consumer who pins no toolchain is not told to match a version that does
    // not exist.
    let root = tree("unpinned", OTHER_PIN, &bare());
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "a tool the tree does not pin is outside this rule: {found:?}"
    );
}

#[test]
fn the_engine_reads_the_version_as_written() {
    // A SHAPE QUESTION THE FIXTURES CANNOT ASK, and the class `ci_hygiene.rs`
    // records for `cancel-in-progress`. A version like `2026.9.1` is a STRING to
    // the YAML parser, but an unquoted `2026.9` would resolve to a float and a
    // comparison against a TOML string would then never hold — refusing nothing,
    // green suite. Driving the real parser is the only way to see which arrives.
    let root = tree("quoted", PINS, &declaring("\"2026.9.1\""));
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "a quoted version is the same version: {found:?}"
    );
}
