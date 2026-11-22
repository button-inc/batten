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
