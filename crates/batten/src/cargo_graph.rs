//! The ACTIVATED dependency graph, read from a `cargo metadata` document
//! (CLOUD-1717).
//!
//! # One walk, two gates, and that is the whole reason this module exists
//!
//! `evaluator-closure` asks whether an IO-bearing crate is reachable from one
//! package's node; `macos-link` asks whether anything in the built graph needs a
//! real platform SDK to link. The questions differ only in their ROOTS and in
//! what they look for once there — the reachability underneath is the same, down
//! to the weak-dependency rule.
//!
//! Both programs carried their own copy, and both said so in prose: *"the
//! activation reading is deliberately IDENTICAL … if one is corrected, correct
//! both."* That is a rule with no mechanism, which is half a change. This module
//! is the mechanism: there is one walk to correct, so the two cannot disagree.
//!
//! # Why the activation filter rather than the whole resolve
//!
//! `cargo metadata` lists every package the resolver CONSIDERED, including
//! optional dependencies nothing turned on. Scanning that asks "could some
//! configuration of this tree reach X" where both callers mean "does this one".
//!
//! Reverting to the whole resolve is the defect this exists to prevent, and it
//! was measured: an embedded-logging crate, an unactivated optional dependency
//! reaching no platform framework and never compiled, made the link gate refuse
//! a link that then completed on the same tree.
//!
//! # No crate name reaches this module
//!
//! Non-negotiable rule 1: the core stays repo-agnostic. Which package is the
//! evaluator, which crates bear IO, which need an SDK and which are vendored are
//! all CONSUMER facts, and they live in that consumer's `[[pattern]]` rows. What
//! is here is the graph reading, which is true of any Cargo workspace.

// THE THREE ROWS THAT USED TO BE STATED TWICE, now stated once over the code
// they actually mutate (CLOUD-1369's route, CLOUD-1717's use of it). Each names
// a unit case below, because a fabricated graph is what exercises the walk and
// no real resolve can be made to have these topologies on demand.
//
// Reverting the activation filter to the whole resolve is the defect the first
// row guards: an optional dependency nobody enabled reads as linked, and the
// gate refuses a link that succeeds.
//MUTANT-SUITE crates/batten/src/cargo_graph.rs
//MUTANT graph-scans-unactivated|s@^                if key.is_some_and(|key| enabled.contains(key)) {$@                if true {@|the_same_optional_dependency_once_activated_is_reached
//MUTANT graph-weak-dep-activates|s@^                && !head.ends_with(.?.)$@@|a_weak_reference_is_not_an_activation
//MUTANT graph-keeps-dev-edges|s@^            if dev_only(dep) && !is_member {$@            if false {@|a_dev_dependency_of_a_dependency_is_not_in_the_built_closure

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// A resolved `cargo metadata` document, walked along ACTIVATED edges only.
#[derive(Debug, Default)]
pub struct Graph {
    packages: BTreeMap<String, Value>,
    nodes: BTreeMap<String, Value>,
    members: BTreeSet<String>,
}

/// The dependency names this package's enabled features actually turn on.
///
/// THREE SPELLINGS REACH A DEPENDENCY and all three must be read, or an
/// activated dep looks dormant: the implicit feature (a bare `foo`), the
/// namespaced form (`dep:foo`), and enabling one of the dep's own features
/// (`foo/bar`).
///
/// THE WEAK FORM (`foo?/bar`) IS DELIBERATELY NOT ONE — it applies only if
/// something else already activated the dep, and reading it as an activation
/// drifts back toward the whole-resolve scan this replaces.
#[must_use]
pub fn activated_keys(package: &Value, enabled: &BTreeSet<String>) -> BTreeSet<String> {
    let mut keys = enabled.clone();
    let declared = package.get("features").and_then(Value::as_object);
    for feature in enabled {
        let Some(tokens) = declared
            .and_then(|features| features.get(feature))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for token in tokens.iter().filter_map(Value::as_str) {
            if let Some(name) = token.strip_prefix("dep:") {
                keys.insert(name.to_owned());
            } else if let Some((head, _)) = token.split_once('/')
                && !head.ends_with('?')
            {
                keys.insert(head.to_owned());
            }
        }
    }
    keys
}

impl Graph {
    /// Index a `cargo metadata` document by package id.
    ///
    /// A document with no `packages` array is not a resolve, and yields an empty
    /// graph rather than an error: the caller's own could-not-look arm decides
    /// what an unreadable document means, and a graph that answered "nothing is
    /// reachable" while claiming to have looked would be the vacuous pass.
    #[must_use]
    pub fn from_metadata(meta: &Value) -> Graph {
        let packages = meta
            .get("packages")
            .and_then(Value::as_array)
            .map(|found| {
                found
                    .iter()
                    .filter_map(|package| {
                        let id = package.get("id")?.as_str()?;
                        Some((id.to_owned(), package.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let nodes = meta
            .get("resolve")
            .and_then(|resolve| resolve.get("nodes"))
            .and_then(Value::as_array)
            .map(|found| {
                found
                    .iter()
                    .filter_map(|node| {
                        let id = node.get("id")?.as_str()?;
                        Some((id.to_owned(), node.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let members = meta
            .get("workspace_members")
            .and_then(Value::as_array)
            .map(|found| {
                found
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Graph {
            packages,
            nodes,
            members,
        }
    }

    /// How many packages the resolve holds nodes for.
    #[must_use]
    pub fn scanned(&self) -> usize {
        self.nodes.len()
    }

    /// The package name behind an id.
    #[must_use]
    pub fn name_of(&self, id: &str) -> Option<&str> {
        self.packages.get(id)?.get("name")?.as_str()
    }

    /// The native library a package declares it links against, if any.
    #[must_use]
    pub fn links_of(&self, id: &str) -> Option<&str> {
        self.packages.get(id)?.get("links")?.as_str()
    }

    /// The activated dependency ids of one node.
    #[must_use]
    pub fn edges(&self, node_id: &str) -> Vec<String> {
        let (Some(node), Some(package)) = (self.nodes.get(node_id), self.packages.get(node_id))
        else {
            return Vec::new();
        };
        let features: BTreeSet<String> = node
            .get("features")
            .and_then(Value::as_array)
            .map(|found| {
                found
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let enabled = activated_keys(package, &features);
        let is_member = self.members.contains(node_id);

        let mut reached = Vec::new();
        let Some(deps) = node.get("deps").and_then(Value::as_array) else {
            return reached;
        };
        for dep in deps {
            let Some(pkg) = dep.get("pkg").and_then(Value::as_str) else {
                continue;
            };
            let Some(target_name) = self.name_of(pkg) else {
                continue;
            };
            // A DEV-DEPENDENCY OF A *DEPENDENCY* IS NEVER BUILT. One of a
            // workspace member is: the test binaries link too.
            if dev_only(dep) && !is_member {
                continue;
            }
            let matching: Vec<&Value> = package
                .get("dependencies")
                .and_then(Value::as_array)
                .map(|declared| {
                    declared
                        .iter()
                        .filter(|entry| {
                            entry.get("name").and_then(Value::as_str) == Some(target_name)
                        })
                        .collect()
                })
                .unwrap_or_default();
            if matching.is_empty() {
                // AN EDGE THE MANIFEST DOES NOT EXPLAIN: keep it rather than
                // drop it. Unexplained means unmeasured, and unmeasured fails
                // closed.
                reached.push(pkg.to_owned());
                continue;
            }
            for entry in matching {
                if entry.get("optional").and_then(Value::as_bool) != Some(true) {
                    reached.push(pkg.to_owned());
                    break;
                }
                let key = entry
                    .get("rename")
                    .and_then(Value::as_str)
                    .or_else(|| entry.get("name").and_then(Value::as_str));
                if key.is_some_and(|key| enabled.contains(key)) {
                    reached.push(pkg.to_owned());
                    break;
                }
            }
        }
        reached
    }

    /// Every package id reachable from `roots` along activated edges.
    #[must_use]
    pub fn reachable<I, S>(&self, roots: I) -> BTreeSet<String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut seen = BTreeSet::new();
        let mut frontier: Vec<String> = roots.into_iter().map(Into::into).collect();
        while let Some(current) = frontier.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            frontier.extend(self.edges(&current));
        }
        seen
    }

    /// The workspace members the resolve holds nodes for.
    ///
    /// The starting set for a question about everything this tree builds.
    #[must_use]
    pub fn member_roots(&self) -> Vec<String> {
        self.members
            .iter()
            .filter(|id| self.nodes.contains_key(*id))
            .cloned()
            .collect()
    }

    /// Every node whose package name satisfies `wanted`.
    ///
    /// The starting set for a question about ONE package's sub-closure. A
    /// PREDICATE rather than a name, because WHICH package a consumer means is
    /// that consumer's fact and belongs in its `[[pattern]]` rows — non-
    /// negotiable rule 1 keeps the name out of this crate entirely.
    #[must_use]
    pub fn roots_matching(&self, wanted: impl Fn(&str) -> bool) -> Vec<String> {
        self.packages
            .iter()
            .filter(|(id, package)| {
                package
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(&wanted)
                    && self.nodes.contains_key(*id)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Every node for a package of this exact name.
    #[must_use]
    pub fn named_roots(&self, name: &str) -> Vec<String> {
        self.roots_matching(|found| found == name)
    }

    /// The reachable set, rendered as `(name, id)` pairs sorted by name.
    ///
    /// Sorted for byte-stability (house style §6): the same document yields the
    /// same order however the resolver happened to list its packages.
    #[must_use]
    pub fn named_in_order(&self, ids: &BTreeSet<String>) -> Vec<(&str, &str)> {
        // BOTH HALVES BORROW FROM `self`, never from `ids`: the caller's set is
        // a working value and the returned pairs outlive it.
        let mut named: Vec<(&str, &str)> = ids
            .iter()
            .filter_map(|id| {
                let (owned, package) = self.packages.get_key_value(id)?;
                Some((package.get("name")?.as_str()?, owned.as_str()))
            })
            .collect();
        named.sort_unstable();
        named
    }
}

/// Whether every kind on this edge is `dev`.
fn dev_only(dep: &Value) -> bool {
    let Some(kinds) = dep.get("dep_kinds").and_then(Value::as_array) else {
        // No `dep_kinds` at all is the normal-dependency shape, not a dev one.
        return false;
    };
    if kinds.is_empty() {
        return false;
    }
    kinds
        .iter()
        .all(|kind| kind.get("kind").and_then(Value::as_str) == Some("dev"))
}

#[cfg(test)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Graph, activated_keys};

    use serde_json::{Value, json};

    /// A three-package resolve: `root` -> `middle` -> `leaf`.
    ///
    /// `optional` and `features` are what the activation rules turn on, and
    /// `kind` is the edge's dependency kind. Fabricated rather than read from a
    /// real resolve, because no real tree can be made to have these topologies
    /// on demand — which is the whole reason the walk is a pure function.
    fn chain(kind: Option<&str>, optional: bool, features: &[&str]) -> Value {
        let dep_kinds = match kind {
            Some(kind) => json!([{ "kind": kind }]),
            None => json!([{}]),
        };
        json!({
            "packages": [
                {
                    "id": "root 1.0.0",
                    "name": "root",
                    "features": { "tls": ["leaf/std"], "std": [] },
                    "dependencies": [
                        { "name": "leaf", "optional": optional }
                    ],
                },
                { "id": "leaf 1.0.0", "name": "leaf", "dependencies": [] },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "root 1.0.0",
                        "features": features,
                        "deps": [ { "pkg": "leaf 1.0.0", "dep_kinds": dep_kinds } ],
                    },
                    { "id": "leaf 1.0.0", "features": [], "deps": [] },
                ]
            },
            "workspace_members": ["root 1.0.0"],
        })
    }

    fn reaches_leaf(meta: &Value) -> bool {
        let graph = Graph::from_metadata(meta);
        graph.reachable(graph.member_roots()).contains("leaf 1.0.0")
    }

    // --- the three rules that live here and nowhere else --------------------

    #[test]
    fn a_required_dependency_is_always_reached() {
        assert!(reaches_leaf(&chain(None, false, &[])));
    }

    /// THE MEASURED DEFECT: an optional dependency nobody enabled reads as
    /// linked under a whole-resolve scan, and the gate then refuses a link that
    /// succeeds.
    #[test]
    fn an_unactivated_optional_dependency_is_not_reached() {
        assert!(!reaches_leaf(&chain(None, true, &["std"])));
    }

    #[test]
    fn the_same_optional_dependency_once_activated_is_reached() {
        // The implicit feature: a bare `leaf` in the enabled set.
        assert!(reaches_leaf(&chain(None, true, &["leaf"])));
    }

    /// A WEAK REFERENCE IS NOT AN ACTIVATION. `leaf?/std` applies only if
    /// something else already activated `leaf`, and reading it as an activation
    /// drifts back toward the whole-resolve scan.
    #[test]
    fn a_weak_reference_is_not_an_activation() {
        let mut meta = chain(None, true, &["weak"]);
        meta["packages"][0]["features"] = json!({ "weak": ["leaf?/std"], "strong": ["leaf/std"] });
        assert!(!reaches_leaf(&meta), "a weak token activates nothing");

        let mut strong = chain(None, true, &["strong"]);
        strong["packages"][0]["features"] =
            json!({ "weak": ["leaf?/std"], "strong": ["leaf/std"] });
        assert!(reaches_leaf(&strong), "and the non-weak one does");
    }

    /// A dev-dependency of a *dependency* is never built. One of a workspace
    /// member is: the test binaries link too.
    #[test]
    fn a_dev_dependency_of_a_dependency_is_not_in_the_built_closure() {
        let mut meta = chain(Some("dev"), false, &[]);
        // Make `root` a non-member, so its dev edge is the not-built case.
        meta["workspace_members"] = json!([]);
        let graph = Graph::from_metadata(&meta);
        assert!(
            !graph
                .reachable(graph.named_roots("root"))
                .contains("leaf 1.0.0"),
            "a dev edge out of a dependency is not built"
        );
    }

    #[test]
    fn a_dev_dependency_of_a_workspace_member_is_built() {
        assert!(
            reaches_leaf(&chain(Some("dev"), false, &[])),
            "the member's test binaries link it"
        );
    }

    /// AN EDGE THE MANIFEST DOES NOT EXPLAIN IS KEPT. Unexplained means
    /// unmeasured, and unmeasured fails closed.
    #[test]
    fn an_edge_the_manifest_does_not_explain_is_kept() {
        let mut meta = chain(None, true, &[]);
        meta["packages"][0]["dependencies"] = json!([]);
        assert!(reaches_leaf(&meta), "fail closed, not open");
    }

    // --- the three spellings that reach a dependency -------------------------

    #[test]
    fn every_spelling_that_reaches_a_dependency_is_read() {
        let package = json!({
            "features": {
                "implicit": [],
                "namespaced": ["dep:alpha"],
                "through": ["beta/std"],
                "weakly": ["gamma?/std"],
            }
        });
        let enabled = ["namespaced", "through", "weakly"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        let keys = activated_keys(&package, &enabled);
        assert!(keys.contains("alpha"), "the namespaced form: {keys:?}");
        assert!(keys.contains("beta"), "the feature form: {keys:?}");
        assert!(
            !keys.contains("gamma"),
            "and the WEAK form is not one: {keys:?}"
        );
    }

    #[test]
    fn an_enabled_feature_name_is_itself_a_key() {
        let enabled = ["leaf".to_owned()].into_iter().collect();
        assert!(activated_keys(&json!({}), &enabled).contains("leaf"));
    }

    // --- the roots, and reading the document at all --------------------------

    #[test]
    fn member_roots_are_the_members_the_resolve_holds_nodes_for() {
        let graph = Graph::from_metadata(&chain(None, false, &[]));
        assert_eq!(graph.member_roots(), vec!["root 1.0.0".to_owned()]);
    }

    #[test]
    fn named_roots_select_one_packages_nodes() {
        let graph = Graph::from_metadata(&chain(None, false, &[]));
        assert_eq!(graph.named_roots("leaf"), vec!["leaf 1.0.0".to_owned()]);
        assert!(graph.named_roots("nobody").is_empty());
    }

    /// A document that is not a resolve yields an EMPTY graph rather than an
    /// error, and the caller's own could-not-look arm decides what that means. A
    /// graph that answered "nothing is reachable" while claiming to have looked
    /// would be the vacuous pass.
    #[test]
    fn a_document_that_is_not_a_resolve_is_an_empty_graph() {
        let graph = Graph::from_metadata(&json!({}));
        assert_eq!(graph.scanned(), 0);
        assert!(graph.member_roots().is_empty());
        assert!(graph.reachable(Vec::<String>::new()).is_empty());
    }

    #[test]
    fn a_cycle_terminates() {
        let meta = json!({
            "packages": [
                { "id": "a 1.0.0", "name": "a", "dependencies": [{ "name": "b" }] },
                { "id": "b 1.0.0", "name": "b", "dependencies": [{ "name": "a" }] },
            ],
            "resolve": { "nodes": [
                { "id": "a 1.0.0", "features": [], "deps": [{ "pkg": "b 1.0.0" }] },
                { "id": "b 1.0.0", "features": [], "deps": [{ "pkg": "a 1.0.0" }] },
            ]},
            "workspace_members": ["a 1.0.0"],
        });
        let graph = Graph::from_metadata(&meta);
        assert_eq!(graph.reachable(graph.member_roots()).len(), 2);
    }

    #[test]
    fn the_links_key_is_read_without_being_walked_for() {
        let meta = json!({
            "packages": [{ "id": "s 1.0.0", "name": "s", "links": "ssl" }],
            "resolve": { "nodes": [{ "id": "s 1.0.0", "features": [], "deps": [] }] },
            "workspace_members": [],
        });
        let graph = Graph::from_metadata(&meta);
        assert_eq!(graph.links_of("s 1.0.0"), Some("ssl"));
        assert_eq!(graph.links_of("nobody"), None);
        assert_eq!(graph.name_of("s 1.0.0"), Some("s"));
    }
}
