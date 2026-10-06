//! The `[[traversal]]` table: a declared walk a module reads the answer of
//! (CLOUD-1866).
//!
//! # Why the walk is DECLARED rather than written in a module
//!
//! A traversal is project-specific — which frontmatter field carries an edge,
//! and what a chain terminates at, is a consumer's vocabulary and not this
//! crate's. Non-negotiable rule 1 keeps those names out of `crates/batten`, so
//! they live in the consumer's `batten.toml` exactly as `[[pattern]]` rows do.
//!
//! Declaring it also bounds it. [`crate::graph`] cannot walk what no row asked
//! for, so a `check`'s cost is a property of the config rather than of how large
//! the tree happens to be — the argument `Rule::symbols` makes for the first
//! `Cost::Effect` fact, one surface over.
//!
//! # The answer is a REDUCTION, never the walk
//!
//! Non-negotiable rule 4: output is a pointer, never the payload. A module is
//! handed [`Reduce::Present`], [`Reduce::Count`] or [`Reduce::Path`] — a
//! boolean, an integer, or the node names along the chain, which are paths and
//! so are pointers already. It never receives a node's contents.
//!
//! # `null` is could-not-look, and it is not an empty answer
//!
//! The projected value is `null` where the walk could not be taken at all — an
//! unreadable seed, a source that would not parse. That is `git-worktrees`'s and
//! `records-blocked`'s rule: a predicate reading an absence as *the chain is
//! broken* would refuse a tree it never looked at.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::graph::{Bounds, Traversal, Until};

/// What a module is handed back, rather than the walk itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Reduce {
    /// Whether the walk reached a node satisfying its stop condition.
    ///
    /// The shape a chain-completeness predicate wants: *did this close*.
    Present,
    /// How many nodes the walk visited.
    ///
    /// For a predicate over the SIZE of a reachable set rather than over whether
    /// a particular node is in it.
    Count,
    /// The node names from seed to the satisfying node, inclusive.
    ///
    /// Admissible under rule 4 because a node name here IS a path — the
    /// `GraphSource` names nodes by tracked path — so this is a pointer list and
    /// never content. It is what lets a finding say which hop broke.
    Path,
}

/// One declared walk, keyed by an id a module reads the answer under.
///
/// Mirrors [`crate::pattern::NamedPattern`]'s shape deliberately: a
/// consumer-owned table in the one committed authority, keyed by an id the
/// config author picks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredTraversal {
    /// The name a module reads it by — the key under `input.tree.traversals`.
    ///
    /// Unique across the table, for [`crate::pattern::NamedPattern`]'s reason: a
    /// repeated id makes the lookup ambiguous, and *which declaration answered
    /// me* is not a question a reviewer should have to resolve.
    pub id: String,
    /// Where the walk starts.
    ///
    /// A node name as the source spells it. For a document source that is a
    /// tracked path; the source owns the vocabulary, not this table.
    ///
    /// Exactly one of `seed` and [`DeclaredTraversal::seeds`] (CLOUD-1868).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seed: String,
    /// A glob over tracked paths: one walk per matched file, answered per seed
    /// (CLOUD-1868). The shape a chain-completeness rule over a whole stage
    /// wants, where `seed` names one node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seeds: Option<String>,
    /// The document edges the walk may follow, by label (CLOUD-1868). Declared
    /// here because which frontmatter field is an edge, and what its value
    /// resolves to, is the consumer's vocabulary (rule 1). When declared, the
    /// walk follows these labels and `labels` may be left empty.
    #[serde(default, rename = "edge", skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<Edge>,
    /// Stop at a node that is a key of this `[[register]]` (CLOUD-1868):
    /// "terminating at a node registered in a declared register".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_register: Option<String>,
    /// The edge labels the walk follows, tried in the order given.
    ///
    /// Non-empty: a walk with no labels cannot leave its seed, so its answer
    /// would be about the seed alone while reading as a chain result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// The field a node must carry for the walk to stop, with `until_value`.
    ///
    /// Optional: a walk with no stop condition runs to exhaustion or to a bound,
    /// which is what a [`Reduce::Count`] over a reachable set wants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_key: Option<String>,
    /// The value `until_key` must carry. Declared together or not at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_value: Option<String>,
    /// The most nodes the walk may visit — CLOUD-1525's Class E counter.
    ///
    /// REQUIRED rather than defaulted, and that is the row's own cost statement.
    /// A default is a number nobody chose, and the first time it is hit the
    /// finding reads as a property of the tree rather than of a constant in this
    /// crate.
    pub max_visits: usize,
    /// The most hops the walk may take from its seed. Required, for the same
    /// reason.
    pub max_depth: usize,
    /// What the module is handed back.
    pub reduce: Reduce,
}

impl DeclaredTraversal {
    /// The engine-side walk this row declares, from `seed`.
    #[must_use]
    pub fn compiled(&self) -> Traversal {
        self.compiled_from(&self.seed)
    }

    /// The engine-side walk this row declares, from one `seed`.
    #[must_use]
    pub fn compiled_from(&self, seed: &str) -> Traversal {
        let labels = if self.edges.is_empty() {
            self.labels.clone()
        } else {
            self.edges.iter().map(|edge| edge.label.clone()).collect()
        };
        Traversal {
            seed: seed.to_owned(),
            labels,
            until: match (&self.until_key, &self.until_value, &self.until_register) {
                (_, _, Some(register)) => Some(Until::Registered {
                    register: register.clone(),
                }),
                (Some(key), Some(value), None) => Some(Until::Has {
                    key: key.clone(),
                    value: value.clone(),
                }),
                // Validated as declared-together at load, so the mixed arms are
                // unreachable for a config that loaded. Read as "no stop" rather
                // than panicking, because a boundary must never be the reason
                // work stops — `pattern::compiled`'s posture, stated there.
                _ => None,
            },
            bounds: Bounds {
                max_visits: self.max_visits,
                max_depth: self.max_depth,
            },
        }
    }
}

/// One declared document edge (CLOUD-1868): a frontmatter field whose values
/// lead somewhere, and how a value resolves to the node it names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    /// The label a walk follows.
    pub label: String,
    /// The dotted frontmatter node carrying the edge. A scalar or a list, and
    /// `name[].sub` reads `sub` from each list item — a field written as a
    /// string in one document and a list in the next is one field.
    pub field: String,
    /// How a value becomes a node.
    pub to: EdgeTarget,
}

/// How an edge value resolves (CLOUD-1868).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum EdgeTarget {
    /// The tracked files under this glob whose stem equals the value — the
    /// join key a corpus spells as the same filename across stages.
    SameStem(String),
    /// This path with `{value}` replaced. A path the tree does not carry is
    /// still a node; it is the dead end a finding points at.
    Template(String),
    /// The value is a key in this `[[register]]`; the node is
    /// [`register_node`]`(register, value)`.
    Register(String),
}

/// The node name a register-key edge resolves to. Never a tracked path, so a
/// register node and a document node cannot collide.
#[must_use]
pub fn register_node(register: &str, key: &str) -> String {
    format!("register:{register}:{key}")
}

/// What the walk may ask of a document: its parsed frontmatter.
///
/// `Is` a node, `IsNot` where the path carries no document (absent, or no
/// frontmatter), `CouldNotLook` where it could not be read or parsed — the
/// three answers `crate::facts::Look` already keeps apart.
pub type Frontmatter<'a> = dyn Fn(&str) -> crate::facts::Look<crate::facts::Node> + 'a;

/// A [`crate::graph::GraphSource`] over tracked markdown documents and declared
/// registers (CLOUD-1868).
///
/// **Pure over what it is handed**, `graph.rs`'s posture one layer up: the
/// caller supplies the frontmatter reader, so this opens no file and the
/// document cache stays the one acquirer. Frontmatter is read per VISITED node,
/// so a walk costs what it touches, never the tree (CLOUD-1866).
pub struct DocumentGraph<'a> {
    edges: BTreeMap<&'a str, &'a Edge>,
    stems: BTreeMap<&'a str, BTreeMap<String, Vec<String>>>,
    registers: &'a BTreeMap<String, crate::register::Built>,
    read: &'a Frontmatter<'a>,
}

impl std::fmt::Debug for DocumentGraph<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The reader is a closure and the registers are built sets; the edge
        // labels are what identifies this graph.
        f.debug_struct("DocumentGraph")
            .field("edges", &self.edges.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<'a> DocumentGraph<'a> {
    /// A graph over `row`'s edges, with `tracked` resolving same-stem joins.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a malformed same-stem glob.
    pub fn new(
        row: &'a DeclaredTraversal,
        tracked: &[String],
        registers: &'a BTreeMap<String, crate::register::Built>,
        read: &'a Frontmatter<'a>,
    ) -> anyhow::Result<Self> {
        let mut stems = BTreeMap::new();
        for edge in &row.edges {
            if let EdgeTarget::SameStem(glob) = &edge.to {
                let set = crate::rules::PathSet::selecting(&row.id, glob, &[])?;
                let mut by_stem: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for path in tracked.iter().filter(|path| set.contains(path)) {
                    by_stem
                        .entry(stem(path).to_owned())
                        .or_default()
                        .push(path.clone());
                }
                stems.insert(glob.as_str(), by_stem);
            }
        }
        Ok(Self {
            edges: row
                .edges
                .iter()
                .map(|edge| (edge.label.as_str(), edge))
                .collect(),
            stems,
            registers,
            read,
        })
    }
}

/// A path's file name without its last extension.
fn stem(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

impl crate::graph::GraphSource for DocumentGraph<'_> {
    fn out(&self, from: &str, label: &str) -> Option<Vec<crate::graph::NodeId>> {
        // A register node is a terminal by construction: it leads nowhere.
        if from.starts_with("register:") {
            return Some(Vec::new());
        }
        let Some(edge) = self.edges.get(label) else {
            return Some(Vec::new());
        };
        let node = match (self.read)(from) {
            crate::facts::Look::Is(node) => node,
            // Absent, or no frontmatter: looked, and it points nowhere — the
            // dead end a broken chain reports.
            crate::facts::Look::IsNot => return Some(Vec::new()),
            crate::facts::Look::CouldNotLook => return None,
        };
        let mut next = Vec::new();
        for value in crate::register::scalars(&node, &edge.field) {
            match &edge.to {
                EdgeTarget::SameStem(glob) => {
                    if let Some(paths) = self
                        .stems
                        .get(glob.as_str())
                        .and_then(|map| map.get(&value))
                    {
                        next.extend(paths.iter().filter(|path| path.as_str() != from).cloned());
                    }
                }
                EdgeTarget::Template(template) => next.push(template.replace("{value}", &value)),
                EdgeTarget::Register(register) => next.push(register_node(register, &value)),
            }
        }
        next.sort();
        next.dedup();
        Some(next)
    }

    fn has(&self, _node: &str, _key: &str, _value: &str) -> Option<bool> {
        // A document source answers `until_register`, not a field equality.
        None
    }

    fn registered(&self, node: &str, register: &str) -> Option<bool> {
        let Some(key) = node.strip_prefix(&format!("register:{register}:")) else {
            return Some(false);
        };
        self.registers.get(register)?.contains(key)
    }
}

/// One seed's answer, as a module reads it under
/// `input.tree.traversals["<id>"]["<seed>"]` (CLOUD-1868).
///
/// A reduction, never the walk: an outcome token, the path when it closed, and
/// the node where it broke when it did not. Every node is a path or a register
/// node name, so all of it is pointers (rule 4).
#[must_use]
pub fn answer(outcome: &crate::graph::Outcome) -> serde_json::Value {
    use crate::graph::Outcome;
    match outcome {
        Outcome::Reached { at, path } => serde_json::json!({
            "outcome": "reached", "at": at, "path": path,
        }),
        Outcome::Exhausted { visited, dead_end } => serde_json::json!({
            "outcome": "exhausted", "visited": visited, "broke_at": dead_end,
        }),
        Outcome::BoundExceeded { bound, visited } => serde_json::json!({
            "outcome": "bound-exceeded",
            "bound": match bound {
                crate::graph::Bound::Visits => "visits",
                crate::graph::Bound::Depth => "depth",
            },
            "visited": visited,
        }),
        Outcome::CouldNotLook { at } => serde_json::json!({
            "outcome": "could-not-look", "at": at,
        }),
    }
}

/// Refuse a malformed table at load, so a fault is a config error at exit `1`
/// rather than a surprise at the gate (house style §8).
///
/// # Errors
///
/// A [`UsageError`] for a blank or repeated id, a blank seed, an empty or blank
/// `labels`, a half-declared stop condition, or a zero bound.
pub fn validate(traversals: &[DeclaredTraversal]) -> anyhow::Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for row in traversals {
        if row.id.trim().is_empty() {
            return Err(UsageError::raise(String::from(
                "traversal: `id` cannot be blank — it is the name a module reads \
                 the answer under, and an empty one names nothing",
            )));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(UsageError::raise(format!(
                "traversal `{}` is declared twice; \
                 `input.tree.traversals[\"{}\"]` cannot resolve to two walks",
                row.id, row.id
            )));
        }
        if row.seed.trim().is_empty() == row.seeds.as_deref().is_none_or(|g| g.trim().is_empty()) {
            return Err(UsageError::raise(format!(
                "traversal `{}`: declare exactly one of `seed` (one node) or \
                 `seeds` (a glob) — a walk with no start has nowhere to go, and \
                 one with two cannot say which it answered for",
                row.id
            )));
        }
        if row.labels.is_empty() && row.edges.is_empty() {
            return Err(UsageError::raise(format!(
                "traversal `{}`: `labels` cannot be empty — a walk with no edge \
                 labels cannot leave its seed, so its answer would be about the \
                 seed alone while reading as a chain result",
                row.id
            )));
        }
        if row.labels.iter().any(|label| label.trim().is_empty()) {
            return Err(UsageError::raise(format!(
                "traversal `{}`: a blank edge label follows nothing",
                row.id
            )));
        }
        // THE HALF-DECLARED STOP IS THE ONE THAT MATTERS. `until_key` alone
        // reads as "stop when this field is present", which this table does not
        // offer, and it would silently walk to exhaustion instead — a predicate
        // answering a different question than its author wrote.
        match (&row.until_key, &row.until_value) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                return Err(UsageError::raise(format!(
                    "traversal `{}`: `until_key` without `until_value` — this \
                     table stops on a field EQUALLING a value, never on its mere \
                     presence, so a key alone would walk to exhaustion while \
                     reading as a stop condition",
                    row.id
                )));
            }
            (None, Some(_)) => {
                return Err(UsageError::raise(format!(
                    "traversal `{}`: `until_value` without `until_key` names no \
                     field to compare",
                    row.id
                )));
            }
        }
        // A ZERO BOUND IS REFUSED RATHER THAN READ AS "UNBOUNDED". Nothing in
        // this crate spells unbounded, and a row whose walk can never leave its
        // seed is a gate that decides nothing while loading clean.
        if row.max_visits == 0 {
            return Err(UsageError::raise(format!(
                "traversal `{}`: `max_visits` of 0 visits nothing; a bound is a \
                 budget, never a way to spell unbounded",
                row.id
            )));
        }
        if row.max_depth == 0 {
            return Err(UsageError::raise(format!(
                "traversal `{}`: `max_depth` of 0 never leaves the seed",
                row.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DeclaredTraversal, Reduce, validate};

    fn row(id: &str) -> DeclaredTraversal {
        DeclaredTraversal {
            id: id.to_owned(),
            seed: "entry.md".to_owned(),
            seeds: None,
            edges: Vec::new(),
            until_register: None,
            labels: vec!["warrant".to_owned()],
            until_key: Some("registered".to_owned()),
            until_value: Some("true".to_owned()),
            max_visits: 64,
            max_depth: 8,
            reduce: Reduce::Present,
        }
    }

    #[test]
    fn a_well_formed_row_loads() {
        assert!(validate(&[row("chain")]).is_ok());
    }

    #[test]
    fn a_repeated_id_is_refused_because_the_lookup_would_be_ambiguous() {
        assert!(validate(&[row("chain"), row("chain")]).is_err());
    }

    #[test]
    fn a_blank_id_is_refused() {
        let mut bad = row("chain");
        bad.id = "  ".to_owned();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_blank_seed_is_refused() {
        let mut bad = row("chain");
        bad.seed = "   ".to_owned();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn an_empty_label_list_is_refused_because_the_walk_cannot_leave_its_seed() {
        let mut bad = row("chain");
        bad.labels.clear();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_blank_edge_label_is_refused() {
        let mut bad = row("chain");
        bad.labels = vec![String::from("  ")];
        assert!(validate(&[bad]).is_err());
    }

    /// THE HALF-DECLARED STOP. A key without a value would walk to exhaustion
    /// while reading as a stop condition — a predicate answering a different
    /// question than its author wrote.
    #[test]
    fn an_until_key_without_a_value_is_refused() {
        let mut bad = row("chain");
        bad.until_value = None;
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn an_until_value_without_a_key_is_refused() {
        let mut bad = row("chain");
        bad.until_key = None;
        assert!(validate(&[bad]).is_err());
    }

    /// A walk with no stop condition is legitimate — it exhausts, or it hits a
    /// bound — so the both-absent arm must LOAD rather than be swept up with the
    /// half-declared ones.
    #[test]
    fn a_row_with_no_stop_condition_loads() {
        let mut open = row("reach");
        open.until_key = None;
        open.until_value = None;
        open.reduce = Reduce::Count;
        assert!(validate(&[open]).is_ok());
    }

    #[test]
    fn a_zero_visit_bound_is_refused_rather_than_read_as_unbounded() {
        let mut bad = row("chain");
        bad.max_visits = 0;
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_zero_depth_bound_is_refused() {
        let mut bad = row("chain");
        bad.max_depth = 0;
        assert!(validate(&[bad]).is_err());
    }

    /// The compiled walk carries the declared stop, so a row and the engine
    /// cannot disagree about what terminates it.
    #[test]
    fn a_declared_stop_reaches_the_compiled_walk() {
        let compiled = row("chain").compiled();
        assert_eq!(compiled.seed, "entry.md");
        assert_eq!(compiled.bounds.max_visits, 64);
        assert!(compiled.until.is_some());
    }

    #[test]
    fn a_row_without_a_stop_compiles_to_a_walk_that_exhausts() {
        let mut open = row("reach");
        open.until_key = None;
        open.until_value = None;
        assert!(open.compiled().until.is_none());
    }

    // ---- The document graph (CLOUD-1868): the 04 -> 02 -> 01 chain. ----

    use super::{DocumentGraph, Edge, EdgeTarget, answer};
    use crate::facts::{Look, Node};
    use std::collections::BTreeMap;

    fn chain_row() -> DeclaredTraversal {
        DeclaredTraversal {
            id: "warrant".to_owned(),
            seed: String::new(),
            seeds: Some("db/*.md".to_owned()),
            edges: vec![
                Edge {
                    label: "slug".to_owned(),
                    field: "slug".to_owned(),
                    to: EdgeTarget::SameStem("middle/*.md".to_owned()),
                },
                Edge {
                    label: "leaf".to_owned(),
                    field: "leaf".to_owned(),
                    to: EdgeTarget::Register("keyset".to_owned()),
                },
            ],
            until_register: Some("keyset".to_owned()),
            labels: Vec::new(),
            until_key: None,
            until_value: None,
            max_visits: 16,
            max_depth: 4,
            reduce: Reduce::Path,
        }
    }

    fn doc(pairs: &[(&str, Node)]) -> Node {
        Node::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    fn text(value: &str) -> Node {
        Node::Text(value.to_owned())
    }

    fn keyset(keys: &[&str]) -> BTreeMap<String, crate::register::Built> {
        let keys = keys.iter().map(|key| ((*key).to_owned(), vec![])).collect();
        BTreeMap::from([(
            "keyset".to_owned(),
            crate::register::Built::Keys {
                keys,
                defects: vec![],
            },
        )])
    }

    /// Walk `db/e.md` over `docs` with `registered` keys; return the answer.
    fn walk(docs: &[(&str, Node)], registered: &[&str]) -> serde_json::Value {
        let row = chain_row();
        let tracked: Vec<String> = docs.iter().map(|(path, _)| (*path).to_owned()).collect();
        let registers = keyset(registered);
        let store: BTreeMap<String, Node> = docs
            .iter()
            .map(|(path, node)| ((*path).to_owned(), node.clone()))
            .collect();
        let read = move |path: &str| match store.get(path) {
            Some(Node::Null) => Look::CouldNotLook,
            Some(node) => Look::Is(node.clone()),
            None => Look::IsNot,
        };
        let graph = DocumentGraph::new(&row, &tracked, &registers, &read).expect("graph");
        answer(&row.compiled_from("db/e.md").run(&graph))
    }

    #[test]
    fn a_closing_chain_reaches_a_registered_capture() {
        let out = walk(
            &[
                ("db/e.md", doc(&[("slug", text("e"))])),
                (
                    "middle/e.md",
                    doc(&[("leaf", Node::List(vec![text("key-a")]))]),
                ),
            ],
            &["key-a"],
        );
        assert_eq!(out["outcome"], "reached");
        assert_eq!(
            out["path"],
            serde_json::json!(["db/e.md", "middle/e.md", "register:keyset:key-a"])
        );
    }

    #[test]
    fn no_record_for_the_slug_breaks_at_the_entry() {
        let out = walk(&[("db/e.md", doc(&[("slug", text("e"))]))], &["key-a"]);
        assert_eq!(out["outcome"], "exhausted");
        assert_eq!(out["broke_at"], "db/e.md");
    }

    #[test]
    fn a_record_citing_no_capture_breaks_at_the_record() {
        let out = walk(
            &[
                ("db/e.md", doc(&[("slug", text("e"))])),
                ("middle/e.md", doc(&[("other", text("x"))])),
            ],
            &["key-a"],
        );
        assert_eq!(out["outcome"], "exhausted");
        assert_eq!(out["broke_at"], "middle/e.md");
    }

    #[test]
    fn a_capture_present_but_unregistered_breaks_at_the_register_node() {
        let out = walk(
            &[
                ("db/e.md", doc(&[("slug", text("e"))])),
                ("middle/e.md", doc(&[("leaf", text("key-z"))])),
            ],
            &["key-a"],
        );
        assert_eq!(out["outcome"], "exhausted");
        assert_eq!(out["broke_at"], "register:keyset:key-z");
    }

    #[test]
    fn an_unreadable_record_is_could_not_look_never_a_break() {
        let out = walk(
            &[
                ("db/e.md", doc(&[("slug", text("e"))])),
                ("middle/e.md", Node::Null),
            ],
            &["key-a"],
        );
        assert_eq!(out["outcome"], "could-not-look");
        assert_eq!(out["at"], "middle/e.md");
    }

    #[test]
    fn exactly_one_of_seed_and_seeds_is_required() {
        let mut both = chain_row();
        both.seed = "db/e.md".to_owned();
        assert!(validate(&[both]).is_err());
        let mut neither = chain_row();
        neither.seeds = None;
        assert!(validate(&[neither]).is_err());
        assert!(validate(&[chain_row()]).is_ok());
    }
}
