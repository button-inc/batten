//! [`batten::facts::Fact::Units`] through a real tree-scoped policy row
//! (CLOUD-1008 §7): a module decides over a Rust function's counts and a Rego
//! module's bindings, both ways, and a file its backend refuses is
//! could-not-look, never an empty node list.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::config_model::Rule;
use batten::rules;

fn vocabulary(root: &Path) -> batten::policy::Vocabulary<'static> {
    let table: &'static [batten::config_model::DeclaredVerdict] =
        Box::leak(common::verdicts_in(root).into_boxed_slice());
    batten::policy::Vocabulary {
        patterns: &[],
        verdicts: table,
        words: None,
        recorders: &[],
        registers: &[],
        traversals: &[],
        records: &[],
    }
}

fn units_row(globs: &[&str]) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "units-row",
        "kind": "policy",
        "scope": "tree",
        "bundle": "policy/",
        "unit_sources": globs,
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row declaring `unit_sources`")
}

fn scratch(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("source-facts-{name}"));
    common::init_repo(&dir);
    fs::create_dir_all(dir.join("policy")).expect("scratch");
    dir
}

fn scan(root: &Path, rows: &[Rule]) -> rules::Scan {
    rules::run_static(rows, &[], vocabulary(root), root)
        .expect("the read surface runs a policy row")
}

/// Refuses any function that can panic, by its unit's counts.
const NO_PANIC: &str = r#"
package batten

import rego.v1

rules contains "unit panic probe"

violation contains {"rule": "unit panic probe", "verdict": "unit panic probe"} if {
  some path, file in input.tree.units
  some node in file.nodes
  node.kind == "fn"
  node.counts.panics > 0
}
"#;

/// Fails by: the fact not reaching the module, a function's panic site
/// uncounted, or the module deciding the same way over a clean function.
#[test]
fn a_module_decides_over_a_functions_counts_both_ways() {
    let root = scratch("panics");
    fs::write(root.join("policy/gate.rego"), NO_PANIC).expect("module");
    fs::write(
        root.join("a.rs"),
        "pub fn f(x: Option<u8>) -> u8 { x.unwrap() }\n",
    )
    .expect("source");
    common::git_in(&root, &["add", "-A"]);
    let refused = scan(&root, &[units_row(&["*.rs"])]);
    assert_eq!(refused.findings.len(), 1, "{:?}", refused.findings);
    assert_eq!(refused.findings[0].rule, "unit panic probe");

    fs::write(
        root.join("a.rs"),
        "pub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n",
    )
    .expect("source");
    let clean = scan(&root, &[units_row(&["*.rs"])]);
    assert!(clean.findings.is_empty(), "{:?}", clean.findings);
    assert!(
        !clean.not_evaluated.contains_key("units-row"),
        "and it evaluated: a skip would make the refusal above pass for the wrong reason"
    );
}

/// Fails by: a file the parser refuses reaching the module as an empty node
/// list, which scores as a clean file (CLOUD-251's vacuous pass).
#[test]
fn a_file_its_backend_refuses_is_could_not_look() {
    let root = scratch("unparsed");
    // A module with NO could-not-look clause: under CLOUD-1049 the engine asks
    // the module first, and one that cannot speak about a missing path
    // abstains, so the row is skipped. Were the refused file present with an
    // empty node list instead, this module would evaluate, find no panic, and
    // the row would read as evaluated and clean.
    fs::write(root.join("policy/gate.rego"), NO_PANIC).expect("module");
    fs::write(root.join("broken.rs"), "fn f( {\n").expect("source");
    common::git_in(&root, &["add", "-A"]);
    let scan = scan(&root, &[units_row(&["*.rs"])]);
    // Exactly the `lines` fact's contract (`policy_tree.rs`).
    assert!(
        scan.not_evaluated.contains_key("units-row"),
        "the row reports COULD NOT LOOK for a file its backend refused"
    );
    assert!(
        scan.findings.is_empty(),
        "and could-not-look is neither a pass nor a violation: {:?}",
        scan.findings
    );
}

/// A row declaring `base` with `unit_sources`.
fn based_units_row(globs: &[&str], base: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "units-row",
        "kind": "policy",
        "scope": "tree",
        "bundle": "policy/",
        "unit_sources": globs,
        "base": base,
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row declaring `unit_sources` and `base`")
}

/// Refuses a function whose panic count rose against the same function at the
/// row's base: head against base, the comparison a ratchet makes in Rego.
const NO_NEW_PANIC: &str = r#"
package batten

import rego.v1

rules contains "unit panic grown"

violation contains {"rule": "unit panic grown", "verdict": "unit panic grown"} if {
  some path, file in input.tree.units
  some node in file.nodes
  node.kind == "fn"
  some was in input.tree.base.units[path].nodes
  was.kind == "fn"
  was.name == node.name
  node.counts.panics > was.counts.panics
}
"#;

/// Fails by: the base side absent (no comparison can be made), read from the
/// working tree instead of the base commit (the two would always agree), or the
/// module deciding the same way when the count did not grow.
#[test]
fn a_module_compares_a_functions_counts_against_its_base() {
    let root = scratch("base");
    fs::write(root.join("policy/gate.rego"), NO_NEW_PANIC).expect("module");
    fs::write(
        root.join("a.rs"),
        "pub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n",
    )
    .expect("source");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    let base = base.trim();

    fs::write(
        root.join("a.rs"),
        "pub fn f(x: Option<u8>) -> u8 { x.unwrap() }\n",
    )
    .expect("source");
    let grown = scan(&root, &[based_units_row(&["*.rs"], base)]);
    assert_eq!(grown.findings.len(), 1, "{:?}", grown.findings);
    assert_eq!(grown.findings[0].rule, "unit panic grown");

    fs::write(
        root.join("a.rs"),
        "pub fn f(x: Option<u8>) -> u8 { x.unwrap_or(1) }\n",
    )
    .expect("source");
    let same = scan(&root, &[based_units_row(&["*.rs"], base)]);
    assert!(same.findings.is_empty(), "{:?}", same.findings);
    assert!(
        !same.not_evaluated.contains_key("units-row"),
        "and it evaluated, over a real base side"
    );
}

/// Refuses a module edge the head has and the row's base did not: the shape
/// plan step 3's ratchet over `uses` takes, head against base, in Rego.
const NO_NEW_EDGE: &str = r#"
package batten

import rego.v1

rules contains "edge reach grown"

violation contains {"rule": "edge reach grown", "verdict": "edge reach grown"} if {
  some path, edges in input.tree.uses
  some edge in edges
  edge.origin == "internal"
  not base_reaches(path, edge.to)
}

base_reaches(path, to) if {
  some was in input.tree.base.uses[path]
  was.origin == "internal"
  was.to == to
}
"#;

fn based_uses_row(globs: &[&str], base: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "uses-row",
        "kind": "policy",
        "scope": "tree",
        "bundle": "policy/",
        "use_sources": globs,
        "base": base,
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row declaring `use_sources` and `base`")
}

/// Fails by: `input.tree.base.uses` absent (the module could not tell a new
/// edge from an old one, so it would refuse both or neither), the base read
/// from the working tree, or a qualified-path edge not counted on either side.
#[test]
fn a_module_compares_module_edges_against_its_base() {
    let root = scratch("base-uses");
    fs::write(root.join("policy/gate.rego"), NO_NEW_EDGE).expect("module");
    fs::write(root.join("lib.rs"), "mod a;\nmod b;\nmod c;\n").expect("root");
    fs::write(root.join("b.rs"), "pub fn g() {}\n").expect("b");
    fs::write(root.join("c.rs"), "pub fn h() {}\n").expect("c");
    fs::write(root.join("a.rs"), "pub fn f() { crate::c::h() }\n").expect("a");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    let base = base.trim();

    // A new edge, written as a qualified path: refused.
    fs::write(
        root.join("a.rs"),
        "pub fn f() { crate::c::h(); crate::b::g() }\n",
    )
    .expect("a");
    let grown = scan(&root, &[based_uses_row(&["*.rs"], base)]);
    assert_eq!(grown.findings.len(), 1, "{:?}", grown.findings);
    assert_eq!(grown.findings[0].rule, "edge reach grown");

    // The base's own edge, respelled as a `use`: the same edge, not refused.
    fs::write(root.join("a.rs"), "use crate::c::h;\npub fn f() { h() }\n").expect("a");
    let same = scan(&root, &[based_uses_row(&["*.rs"], base)]);
    assert!(same.findings.is_empty(), "{:?}", same.findings);
    assert!(
        !same.not_evaluated.contains_key("uses-row"),
        "and it evaluated, over a real base side"
    );
}

/// Refuses a change that lowers M-score against the row's base: the ratchet
/// plan step 3 retires `modules.lock` into.
const NO_DL_DROP: &str = r#"
package batten

import rego.v1

rules contains "module score dropped"

violation contains {"rule": "module score dropped", "verdict": "module score dropped"} if {
  input.tree.coupling.head.mscore < input.tree.coupling.base.mscore
}
"#;

/// Fails by: `input.tree.coupling` absent or measured on one side only, the
/// base read from the working tree (both sides would agree), or a cycle that
/// does not lower the level.
#[test]
fn a_module_refuses_a_lowered_mscore() {
    let root = scratch("coupling");
    fs::create_dir_all(root.join("src")).expect("src");
    fs::write(root.join("policy/gate.rego"), NO_DL_DROP).expect("module");
    fs::write(root.join("src/lib.rs"), "mod a;\nmod b;\nmod c;\n").expect("root");
    fs::write(root.join("src/a.rs"), "pub fn f() {}\n").expect("a");
    fs::write(root.join("src/b.rs"), "pub fn g() {}\n").expect("b");
    fs::write(root.join("src/c.rs"), "pub fn h() {}\n").expect("c");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    let base = base.trim();

    // `c` now depends on `a`: `a` gains a dependent from the three files below
    // it, so its cross-layer density is 1/3 and M-score falls from 1.0 to
    // 0.25·(2/3) + 0.75.
    fs::write(root.join("src/c.rs"), "pub fn h() { crate::a::f() }\n").expect("c");
    let coupled = scan(&root, &[based_uses_row(&["src/*.rs"], base)]);
    assert_eq!(coupled.findings.len(), 1, "{:?}", coupled.findings);
    assert_eq!(coupled.findings[0].rule, "module score dropped");

    // Decoupled again: the level is the base's, nothing refused.
    fs::write(root.join("src/c.rs"), "pub fn h() {}\n").expect("c");
    let same = scan(&root, &[based_uses_row(&["src/*.rs"], base)]);
    assert!(same.findings.is_empty(), "{:?}", same.findings);
    assert!(
        !same.not_evaluated.contains_key("uses-row"),
        "and it evaluated, over a real base side"
    );
}

/// The vendored `rust-quality` preset enabled over `src/*.rs`, judged against
/// `base`. The preset's own module, not a copy, so its `#MUTANT` rows reach it.
fn rust_quality_row(base: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "module graph worse",
        "kind": "policy",
        "scope": "tree",
        "preset": "rust-quality",
        "use_sources": ["src/*.rs"],
        "base": base,
        "severity": "deny",
    }))
    .expect("a tree-scoped preset row declaring `use_sources` and `base`")
}

/// Three independent modules committed as the base; returns the root and base.
fn three_module_base(name: &str) -> (PathBuf, String) {
    let root = scratch(name);
    fs::create_dir_all(root.join("src")).expect("src");
    fs::write(root.join("src/lib.rs"), "mod a;\nmod b;\nmod c;\n").expect("root");
    fs::write(root.join("src/a.rs"), "pub fn f() {}\n").expect("a");
    fs::write(root.join("src/b.rs"), "pub fn g() {}\n").expect("b");
    fs::write(root.join("src/c.rs"), "pub fn h() {}\n").expect("c");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    (root, base)
}

/// Fails by: the preset's M-score clause unread (`#MUTANT score-unread`). A
/// new edge with no cycle lowers M-score and leaves the largest cycle at 1, so
/// only that clause can refuse it.
#[test]
fn the_preset_refuses_a_lowered_mscore() {
    let (root, base) = three_module_base("rq-score");
    fs::write(root.join("src/c.rs"), "pub fn h() { crate::a::f() }\n").expect("c");
    let found = scan(&root, &[rust_quality_row(&base)]);
    let rules: Vec<&str> = found.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["module score dropped"], "{:?}", found.findings);
}

/// Fails by: the preset's largest-cycle clause unread (`#MUTANT cycle-unread`).
#[test]
fn the_preset_refuses_a_grown_cycle() {
    let (root, base) = three_module_base("rq-cycle");
    fs::write(root.join("src/a.rs"), "pub fn f() { crate::b::g() }\n").expect("a");
    fs::write(root.join("src/b.rs"), "pub fn g() { crate::a::f() }\n").expect("b");
    let found = scan(&root, &[rust_quality_row(&base)]);
    assert!(
        found
            .findings
            .iter()
            .any(|f| f.rule == "module cycle grown"),
        "{:?}",
        found.findings
    );
}

/// Fails by: the Rego arm missing a partial helper bound with `:=`, or
/// reading a defaulted helper as partial (CLOUD-2777's shape).
#[test]
fn the_rego_arm_names_a_partial_helper_bound_with_colon_equals() {
    let root = scratch("rego");
    fs::write(
        root.join("policy/gate.rego"),
        r#"
package batten

import rego.v1

rules contains "partial binding probe"

violation contains {"rule": "partial binding probe", "verdict": "partial binding probe"} if {
  some path, file in input.tree.units
  some binding in file.nodes
  binding.kind == "binding"
  some function in file.nodes
  function.kind == "function"
  function.name == binding.name
  not function.counts.total
}
"#,
    )
    .expect("module");
    fs::create_dir_all(root.join("subject")).expect("dir");
    fs::write(
        root.join("subject/h.rego"),
        "package h\n\nimport rego.v1\n\nsubject(args) := m if {\n\tsome m in args\n}\n\nv contains 1 if {\n\tm := subject(input.x)\n\tnot m\n}\n",
    )
    .expect("subject");
    common::git_in(&root, &["add", "-A"]);
    let refused = scan(&root, &[units_row(&["subject/*.rego"])]);
    assert_eq!(refused.findings.len(), 1, "{:?}", refused.findings);

    fs::write(
        root.join("subject/h.rego"),
        "package h\n\nimport rego.v1\n\ndefault subject(_) := \"\"\n\nsubject(args) := m if {\n\tsome m in args\n}\n\nv contains 1 if {\n\tm := subject(input.x)\n\tm == \"\"\n}\n",
    )
    .expect("subject");
    let clean = scan(&root, &[units_row(&["subject/*.rego"])]);
    assert!(clean.findings.is_empty(), "{:?}", clean.findings);
}
