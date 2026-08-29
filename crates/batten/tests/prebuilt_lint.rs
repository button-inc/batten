//! Never compile a third-party tool from source (CLOUD-86), as consumer #1's own
//! policy rather than an engine feature.
//!
//! The rules under test are two `[[rule]]` rows in this repository's `batten.toml`,
//! so the subject is the CONFIG, not the crate. That is what makes
//! [`this_repository_is_clean_today`] the load-bearing case: a gate is only a gate
//! if it is green on the tree it governs *and* red on the mistake it names, and a
//! config-only rule can lose either half without a single Rust test changing.
//!
//! # Retired from `tests/prebuilt-lint.bats` (CLOUD-1137)
//!
//! The bats suite stood the WHOLE shipped config up in a fixture — symlinked
//! manifest and sources, a copied `batten.toml`, a copied `AGENTS.md` for
//! `[budget.instructions]`, a `.serena/project.yml` for `[[embedded]]`, a
//! provisioned ripsecrets stub for `no-secrets`, a resolvable `origin/main` for the
//! `ratchet` rows, and a task namespace synthesised from every `mise run <task>` in
//! the config so `command-task-defined` would not fire. Every one of those was a
//! precondition of running the config, not of testing these two rows.
//!
//! These cases run the two rows and nothing else, so none of that is owed. That is
//! not only cheaper — 71.6s, 5.8% of the whole bats wall clock — it is what makes
//! the suite stable under a growing config: the fixture's base commit was empty, so
//! it counted every copied-in file as growth from zero, and the first `ratchet` row
//! to glob `mise.toml` made its "both sides of every ratchet count zero" invariant
//! false. A one-row rule set has no such invariant to break.
//!
//! The rows are deserialized from JSON rather than struct-literalled, so they go
//! through the same `deny_unknown_fields` column census a consumer's config does.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// `no-source-built-tool` as `batten.toml` declares it.
fn no_source_built_tool() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "no-source-built-tool",
        "kind": "forbid",
        "glob": "mise.toml",
        "pattern": "\"cargo:",
        "severity": "deny",
        "scope": "tree",
        "no_fix_reason": "pin an attested binary in mise.toml instead; what to pin is a supply-chain decision, not a rewrite",
    }))
    .expect("the row batten.toml declares")
}

/// `no-cargo-install-in-ci` as `batten.toml` declares it.
fn no_cargo_install_in_ci() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "no-cargo-install-in-ci",
        "kind": "forbid",
        "glob": ".github/workflows/*.yml",
        "pattern": "cargo install",
        "severity": "deny",
        "scope": "tree",
        "no_fix_reason": "pin the tool in mise.toml so CI installs exactly what the lockfile names",
    }))
    .expect("the row batten.toml declares")
}

/// Both rows over `root`, as `<path>:<line> <rule>` — the pointer shape the
/// retired suite asserted on, and pointer-only per non-negotiable rule 4.
///
/// The vocabulary is empty because a `forbid` row raises no verdict token: it has
/// no module to declare one, so there is nothing for the registry to balance.
fn findings(root: &Path) -> Vec<String> {
    rules::run_static(
        &[no_source_built_tool(), no_cargo_install_in_ci()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &[],
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs two forbid rows")
    .findings
    .into_iter()
    .map(|finding| match finding.line {
        Some(line) => format!("{}:{} {}", finding.path, line, finding.rule),
        None => format!("{} {}", finding.path, finding.rule),
    })
    .collect()
}

/// A scratch tree holding a `[tools]` table with `line` appended.
fn tools_with(name: &str, line: &str) -> PathBuf {
    let root = common::scratch(&format!("prebuilt-lint-{name}"));
    common::write(
        &root,
        "mise.toml",
        &format!("[tools]\nrust = \"1.85.0\"\n{line}\n"),
    );
    root
}

/// A workflow in `root` whose one step runs `step`.
fn workflow_with(root: &Path, step: &str) {
    common::write(
        root,
        ".github/workflows/t.yml",
        &format!(
            "name: t\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {step}\n"
        ),
    );
}

// ---------------------------------------------------------------------------
// The tree these rows actually defend.
// ---------------------------------------------------------------------------

// The arm that names the surviving SUBJECT (CLOUD-1130). `tests/prebuilt-lint.bats`
// declared `# subject: batten.toml`, and that file outlives this retirement, so the
// ledger has to name it or the deletion reads as a program left alive and untested.
// The successor file is named in the reason rather than the target, because a case
// may carry exactly one arm.
//
// carried: "this repository is clean today — the rule is green on the tree it governs" batten.toml the two rows now run over this checkout from crates/batten/tests/prebuilt_lint.rs, one rule set at a time rather than the whole config in a fixture
#[test]
fn this_repository_is_clean_today() {
    // The half that a narrowed pattern, or a rule matching nothing, would also
    // satisfy — which is why every case below exists too.
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "the committed build config should satisfy its own rows: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// `no-source-built-tool`: the mistake, and the shape that is not it.
// ---------------------------------------------------------------------------

// carried: "a cargo: backend in mise.toml is a violation, named and located" crates/batten/tests/prebuilt_lint.rs
#[test]
fn a_cargo_backend_in_the_manifest_is_a_violation_named_and_located() {
    let root = tools_with("cargo-backend", "\"cargo:cargo-hack\" = \"0.6\"");
    assert_eq!(findings(&root), vec!["mise.toml:3 no-source-built-tool"]);
}

// carried: "a prebuilt backend is not a violation — the rule bans compiling, not installing" crates/batten/tests/prebuilt_lint.rs
#[test]
fn a_prebuilt_backend_is_not_a_violation() {
    // The other direction, and the one that keeps the rule from reading as "no
    // third-party tools": every tool this repo uses arrives through a line like
    // this one.
    let root = tools_with(
        "prebuilt-backend",
        "\"aqua:koalaman/shellcheck\" = \"0.11.0\"",
    );
    assert!(findings(&root).is_empty());
}

// ---------------------------------------------------------------------------
// `no-cargo-install-in-ci`: the same pair, spelled by hand in a workflow step.
// ---------------------------------------------------------------------------

// carried: "cargo install in a workflow is a violation" crates/batten/tests/prebuilt_lint.rs
#[test]
fn cargo_install_in_a_workflow_is_a_violation() {
    let root = tools_with("workflow-cargo-install", "hk = \"1.54.0\"");
    workflow_with(&root, "cargo install cargo-hack");
    assert_eq!(
        findings(&root),
        vec![".github/workflows/t.yml:8 no-cargo-install-in-ci"]
    );
}

// carried: "a prebuilt install-action step is not a violation" crates/batten/tests/prebuilt_lint.rs
#[test]
fn a_prebuilt_install_action_step_is_not_a_violation() {
    let root = tools_with("workflow-prebuilt", "hk = \"1.54.0\"");
    workflow_with(&root, "echo pinned");
    assert!(findings(&root).is_empty());
}

// ---------------------------------------------------------------------------
// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). Its grammar is disjoint from
// CLOUD-908's case arms above by construction: a case arm's first field after the
// marker is a QUOTED case name, and a file arm's is a path.
//
// The successors are the engine's `forbid` implementation and this file. The
// predicate itself is not being ported — it is two declarative `[[rule]]` rows in
// `batten.toml`, which is neither a `.rego` module nor `crates/batten/src/*.rs`, so
// the policy surface named is the code that decides a `forbid` row. Converting the
// rows to a `policy` module would be a larger change than the shape asks for.
//
// carried: tests/prebuilt-lint.bats crates/batten/src/rules.rs crates/batten/tests/prebuilt_lint.rs
//
// The four waiver cases are NOT here: they were about the waiver SURFACE, generic
// over which `forbid` row it suppresses, and `crates/batten/tests/waivers.rs`
// already drives the compiled binary over exactly that. Their arms sit there.
// ---------------------------------------------------------------------------
