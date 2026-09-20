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

use std::collections::BTreeSet;

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
    pub seed: String,
    /// The edge labels the walk follows, tried in the order given.
    ///
    /// Non-empty: a walk with no labels cannot leave its seed, so its answer
    /// would be about the seed alone while reading as a chain result.
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
    /// The engine-side walk this row declares.
    #[must_use]
    pub fn compiled(&self) -> Traversal {
        Traversal {
            seed: self.seed.clone(),
            labels: self.labels.clone(),
            until: match (&self.until_key, &self.until_value) {
                (Some(key), Some(value)) => Some(Until::Has {
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
        if row.seed.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "traversal `{}`: `seed` cannot be blank — a walk with no start \
                 has nowhere to go",
                row.id
            )));
        }
        if row.labels.is_empty() {
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
}
