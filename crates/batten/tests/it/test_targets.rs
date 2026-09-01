//! `policy/test-targets.rego` over the COMPILED engine (CLOUD-1210).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads: `with input as` fabricates
//! the very shape the engine may be unable to produce, so a module reading a key
//! nothing fills passes its own suite green and enforces nothing.
//!
//! `.claude/rules/policy-modules.md` records that class twice over — a module
//! copied from `policy.rs`'s own doc iterated a tree key the engine never built,
//! and OpenTelemetry's `weaver` printed "No policy violation", exit 0, over a
//! knowingly-broken registry because its module read a key the v1 schema does not
//! build. Both live instances in this tree were found by adding this tier, not by
//! reading. So the cases below drive `run_static` over a real fixture repository
//! with a real base ref, and the fact under test — `input.tree["base-delta"]` — is
//! one the engine has to resolve from git rather than one a harness hands over.
//!
//! # What the rule is for
//!
//! Cargo autodiscovers one test target per top-level `crates/batten/tests/*.rs`
//! and rustc relinks the whole dependency closure into each. This repository had
//! 144 of them; CLOUD-1210 grouped them into one. The ratchet is what stops the
//! count regrowing, and it has to be survivable by CLOUD-843's campaign, which
//! adds a `crates/batten/tests/*.rs` tier per retired gate BY MANDATE — hence a
//! rule about TOP-LEVEL paths rather than about test files.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate id the module declares.
const TARGET_ADDED: &str = "test-target-added";

/// A fixture repository whose base is one commit back and whose working tree
/// ADDS `changed`, so the engine's own `base-delta` resolution is what produces
/// the fact under test.
///
/// `origin/main` is a local ref pointed at the base commit: `base_delta` resolves
/// a rev, and configuring a remote would make every case here depend on the
/// network for an entirely local question. Same shape as `filed_here.rs`.
fn repo(name: &str, added: &[&str]) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet"]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", &base]);

    for path in added {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, "// added\n").expect("write added file");
    }

    install_module(&root);
    root
}

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/test-targets.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/test-targets.rego")).expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "test-targets",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "module": "policy/test-targets.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
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
}

fn verdicts(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

fn pointers(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.path)
        .collect()
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by a module
// that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_branch_adding_no_test_file_passes_untouched() {
    let root = repo("test-targets-clean", &["src/lib.rs"]);
    assert!(
        verdicts(&root).is_empty(),
        "a diff that mints no cargo test target is not this rule's business"
    );
}

#[test]
fn a_new_top_level_test_file_is_refused_over_the_compiled_engine() {
    let root = repo("test-targets-added", &["crates/batten/tests/new_gate.rs"]);
    assert_eq!(
        verdicts(&root),
        vec![TARGET_ADDED.to_owned()],
        "a top-level crates/batten/tests/*.rs is a cargo test target, and the \
         engine's own base-delta is what has to surface it"
    );
    assert_eq!(
        pointers(&root),
        vec!["crates/batten/tests/new_gate.rs".to_owned()],
        "the finding points at the file that mints the target, and nothing else"
    );
}

/// THE CASE THAT MAKES THE RULE SURVIVABLE, and the one an implementer would
/// skip. `.claude/rules/toolchain.md` requires every retirement to land a
/// `crates/batten/tests/*.rs` tier, so a rule refusing every added test file
/// would fire on the next correctly-executed retirement and the campaign would
/// have to switch it off — the shape a gate does not survive. A tier landing as a
/// `mod` inside the group must be invisible to it.
#[test]
fn a_module_inside_the_group_is_not_a_target() {
    let root = repo(
        "test-targets-grouped",
        &["crates/batten/tests/it/new_gate.rs"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a file one segment deeper is a module in an existing target, not a new \
         one — this is what keeps CLOUD-843's campaign able to land its tiers"
    );
}

/// ANTI-VACUITY on the depth test. `crates/other/tests/x.rs` has the same shape
/// and the same segment count, so a rule anchored only on depth would refuse a
/// sibling crate's targets — and one anchored wrongly would refuse nothing at all
/// while still passing every case above.
#[test]
fn another_crates_test_file_is_not_this_rules_business() {
    let root = repo(
        "test-targets-other-crate",
        &["crates/other/tests/new_gate.rs"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the rule is about THIS crate's autodiscovered targets"
    );
}

/// Fixture data under `tests/` is not a target, however deep it sits.
#[test]
fn a_fixture_file_is_not_a_target() {
    let root = repo(
        "test-targets-fixture",
        &["crates/batten/tests/fixtures/hooks/new.json"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "only a .rs file directly under tests/ mints a target"
    );
}

/// Every added target is named, not just the first — a gate reporting one of
/// three reads as satisfied once that one is moved.
#[test]
fn every_added_target_is_named() {
    let root = repo(
        "test-targets-several",
        &[
            "crates/batten/tests/a_gate.rs",
            "crates/batten/tests/b_gate.rs",
            "crates/batten/tests/it/c_gate.rs",
        ],
    );
    let mut named = pointers(&root);
    named.sort();
    assert_eq!(
        named,
        vec![
            "crates/batten/tests/a_gate.rs".to_owned(),
            "crates/batten/tests/b_gate.rs".to_owned(),
        ],
        "both top-level additions are reported and the grouped one is not"
    );
}
