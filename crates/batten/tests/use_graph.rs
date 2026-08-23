//! CLOUD-762's measurement, pinned against this tree.
//!
//! §2 makes the syntactic-versus-resolved error count deliverable one and says
//! the count chooses the tier, so the count lives here as an assertion rather
//! than in a comment: a number in prose goes stale silently, and this one is the
//! whole argument for the fact being `Read x Check`.

use std::collections::BTreeMap;

use batten::facts::Look;
use batten::uses::{Origin, RootExports, UseEdge, resolve, root_exports, use_edges};

/// The crate root, read from the tree rather than from a fixture — the
/// measurement is a claim ABOUT this tree and a fixture could not make it.
fn root_table() -> RootExports {
    let source = std::fs::read_to_string("src/lib.rs").expect("the crate root is readable");
    match root_exports(&source) {
        Look::Is(table) => table,
        other => panic!("the crate root must parse, got {}", other.as_str()),
    }
}

/// Every module's resolved edges, keyed by file name.
fn resolved_tree() -> BTreeMap<String, Vec<UseEdge>> {
    let root = root_table();
    let mut out = BTreeMap::new();
    let entries = std::fs::read_dir("src").expect("the source directory is readable");
    for entry in entries {
        let path = entry.expect("a readable entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a utf-8 file name")
            .to_owned();
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        let Look::Is(mut edges) = use_edges(&source) else {
            panic!("{name} must parse");
        };
        resolve(&mut edges, &root);
        out.insert(name, edges);
    }
    out
}

/// THE MEASUREMENT. Every site where the module a `use` reaches differs from the
/// module its text names — the count CLOUD-762 parked on for two days.
///
/// Four, in two classes, and both are re-exports. This asserts the CLASSES and a
/// bound rather than an exact list, so adding a module does not fail the suite
/// while a new *kind* of divergence does.
///
/// **The discriminator is `via_root`, not the item's case, and that correction
/// came from the tree.** The first version of this case asked whether a resolved
/// edge's item name was CamelCase, which is true of every ordinary
/// `use crate::error::UsageError` as well: it reported **88** divergences where
/// there are four. Only the edges resolution CHANGED are the ones a line
/// predicate gets wrong.
///
/// Fails by: dropping the root table from `resolve`, which returns every one of
/// these edges to `RootItem` with an empty destination.
#[test]
fn the_syntactic_tier_diverges_at_four_sites_in_two_classes() {
    let tree = resolved_tree();

    let mut hidden_internal = Vec::new();
    let mut phantom_internal = Vec::new();
    let mut unresolved = Vec::new();
    for (file, edges) in &tree {
        for edge in edges {
            match edge.origin {
                // Resolved out of the root table: the text named no module.
                Origin::Internal if edge.via_root => {
                    hidden_internal.push(format!("{file}:{} -> {}", edge.line, edge.to));
                }
                Origin::External if edge.via_root => {
                    phantom_internal.push(format!("{file}:{}", edge.line));
                }
                Origin::RootItem => unresolved.push(format!("{file}:{}", edge.line)),
                _ => {}
            }
        }
    }

    assert_eq!(
        hidden_internal.len(),
        2,
        "hidden internal edges — a line predicate is silently GREEN on these: {hidden_internal:?}"
    );
    assert_eq!(
        phantom_internal.len(),
        2,
        "phantom internal edges — really external, a line predicate invents these: {phantom_internal:?}"
    );
    assert!(
        unresolved.is_empty(),
        "every crate-root name resolved; an unresolved one is a class the table cannot see: {unresolved:?}"
    );
}

/// Both hidden edges land on the same module, and naming it is the point: a
/// layering table keyed on `error` would have judged neither before this.
#[test]
fn the_hidden_edges_resolve_to_the_module_the_text_never_names() {
    let tree = resolved_tree();
    for file in ["trust.rs", "output.rs"] {
        let edges = tree.get(file).expect("the module is in the tree");
        assert!(
            edges
                .iter()
                .any(|edge| edge.origin == Origin::Internal && edge.via_root && edge.to == "error"),
            "{file} reaches `error` through the root's re-export, and the text does not say so"
        );
    }
}

/// Aliases and globs contribute ZERO divergence in this tree, which is half the
/// measurement and the half that was not obvious in advance.
///
/// Asserted rather than stated: the body of CLOUD-762 worried about all three
/// constructs equally, and only one of them turned out to matter.
#[test]
fn aliases_and_globs_move_no_top_level_edge() {
    let tree = resolved_tree();
    let crossing: Vec<String> = tree
        .iter()
        .flat_map(|(file, edges)| {
            edges
                .iter()
                .filter(|edge| edge.origin == Origin::Local && edge.item == "*")
                .map(move |edge| format!("{file}:{}", edge.line))
        })
        .collect();
    // Every glob in this tree is `use super::*` inside a `#[cfg(test)]` module.
    // `Local` is the answer, and `Local` crosses no top-level boundary.
    assert!(
        !crossing.is_empty(),
        "the tree does contain globs; a run finding none is measuring nothing"
    );
    for (file, edges) in &tree {
        for edge in edges {
            assert_ne!(
                (edge.origin, edge.item.as_str()),
                (Origin::Internal, "*"),
                "{file}:{} — a glob resolved to a top-level module edge",
                edge.line
            );
        }
    }
}

/// COULD-NOT-LOOK IS NOT AN EMPTY EDGE SET, asserted against each other.
///
/// Fails by: returning `Look::Is(vec![])` from the parse-failure arm, which is
/// CLOUD-251's vacuous pass — a layering gate over a corpus that failed to parse
/// reports clean.
#[test]
fn an_unparseable_file_could_not_look_rather_than_having_no_edges() {
    let refused = use_edges("mod m { fn f( {{{");
    assert!(refused.could_not_look(), "got {}", refused.as_str());

    let parsed_and_empty = use_edges("pub struct S;");
    assert_eq!(parsed_and_empty, Look::Is(Vec::new()));
    assert!(!parsed_and_empty.could_not_look());
    assert_ne!(refused.as_str(), parsed_and_empty.as_str());

    // The root table carries the same contract, and it is the one a consumer
    // reaches for first — an unparseable root that answered with an empty table
    // would silently un-resolve every edge in the crate.
    assert!(root_exports("fn f( {{{").could_not_look());
}

/// Module identity is stable across two runs over identical bytes, so a
/// consumer's set lookup is deterministic (§7c).
#[test]
fn the_edge_set_is_stable_across_runs() {
    assert_eq!(resolved_tree(), resolved_tree());
}

/// The layer table CLOUD-359 gates, asserted over the real tree.
///
/// `policy/module-layering.rego` is the gate; this is the same predicate in Rust
/// so a violation names itself in the failure output. The Rego module reports
/// pointer-only through the engine — a tree-scoped row's finding points at the
/// bundle and the module's own `msg` carries `path:line`, which is the shipped
/// convention and a deliberate decision in `rules.rs`. That is right for a gate
/// and useless for a bisect, so the enumeration lives here.
#[test]
fn the_documented_layerings_hold_over_this_tree() {
    let forbidden: &[(&str, &[&str])] = &[
        ("rules", &["hook"]),
        ("surface", &["cli", "lib"]),
        ("cli", &["lib", "journal"]),
        ("config", &["resolve", "trust", "lint", "epoch"]),
        ("resolve", &["trust", "lint", "epoch"]),
        ("trust", &["lint", "epoch"]),
        ("lint", &["epoch"]),
        ("store", &["findings", "journal"]),
    ];
    let tree = resolved_tree();
    let mut broken = Vec::new();
    for (file, edges) in &tree {
        let from = file.trim_end_matches(".rs");
        let Some((_, banned)) = forbidden.iter().find(|(module, _)| *module == from) else {
            continue;
        };
        for edge in edges {
            if edge.origin == Origin::Internal && banned.contains(&edge.to.as_str()) {
                broken.push(format!("{file}:{} {from} -> {}", edge.line, edge.to));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "documented layerings this tree violates: {broken:#?}"
    );
}
