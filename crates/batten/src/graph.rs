//! A bounded, call-by-need traversal over a declared graph (CLOUD-1866).
//!
//! # Why this exists when `graph.reachable` already does
//!
//! CLOUD-1863 enabled regorus's `graph` feature, so a module can ask what a seed
//! REACHES. That closed the case `ci-cache-declared` was hand-unrolling, and it
//! does not close the case this module is for: reachability answers one question
//! and a warrant chain asks three.
//!
//! | need | `graph.reachable` |
//! | ---- | ----------------- |
//! | reach a set of nodes from a seed | yes |
//! | terminate on a node PROPERTY | no |
//! | name the hop that broke, for a pointer | `reachable_paths` only |
//! | bound the walk, and report the bound | no |
//!
//! The measured consumer is an ICM provenance chain: *walk a stage-04 entry's
//! warrant upward UNTIL a node is a REGISTERED capture, and tell me the path*.
//! Every clause there is an `until(has(...))` and a `path()`, and neither is
//! expressible over a materialised reachable set.
//!
//! # Call-by-need, and what it buys
//!
//! [`Traversal::run`] pulls one frontier at a time and stops at the first node
//! satisfying its stop condition. A walk that terminates three hops in never
//! asks the source for a fourth, which is what lets acquisition FOLLOW the walk
//! rather than precede it — the difference between reading the nodes a question
//! touches and reading the tree.
//!
//! # The bound is a counter, and it is CLOUD-1525's Class E
//!
//! That row names the class this module would otherwise create: *"a bounded file
//! read an unbounded number of times"*, whose stated mechanism is *"a counter in
//! the code path, not a lint over a call — the shape `documents_acquired`
//! already takes"*. [`Bounds::max_visits`] is that counter. Exceeding it is
//! [`Outcome::BoundExceeded`], which is NOT a negative answer: a walk that ran
//! out of budget has not shown the chain is broken, and reporting it as one
//! would be the under-deny direction that gets a gate switched off.
//!
//! # Layering
//!
//! This module reaches nothing else in the crate. It holds no sources and opens
//! no files: a [`GraphSource`] is supplied by the caller, so the engine cannot
//! become a second acquirer. `policy/module-layering.rego` carries the placement.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A node's identity, as the source names it.
///
/// A `String` rather than an interned index, because every consumer of a finding
/// needs the name back for its pointer and an index would have to be resolved
/// there anyway. The graphs this walks are a tracked tree's documents — hundreds,
/// not millions — so the interning it trades away buys nothing measurable.
pub type NodeId = String;

/// What a walk may ask of a node, supplied by the caller.
///
/// **The engine holds no sources**, which is what keeps it off the acquisition
/// path. An implementation over the tree surface reads a document; one over a
/// fixture reads a map; neither is this module's business.
pub trait GraphSource {
    /// The nodes `from` points at along `label`.
    ///
    /// `None` is could-not-look — the node could not be read at all — and is
    /// kept apart from `Some(vec![])`, a node read successfully that points at
    /// nothing. Collapsing them would let an unreadable document report as a
    /// chain that simply ends, which is the silence this crate is built against.
    fn out(&self, from: &str, label: &str) -> Option<Vec<NodeId>>;

    /// Whether `node` carries `key` with `value`.
    ///
    /// Three-valued for the same reason: `None` where the node could not be
    /// read, so a stop condition over an unreadable node abstains rather than
    /// deciding either way.
    fn has(&self, node: &str, key: &str, value: &str) -> Option<bool>;
}

/// How far a walk may go before it reports that it could not finish.
///
/// Both are REQUIRED rather than defaulted. A default bound is a number nobody
/// chose, and the first time it is hit the finding reads as a property of the
/// tree rather than of a constant in this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The most nodes a walk may visit. CLOUD-1525's Class E counter.
    pub max_visits: usize,
    /// The most hops a walk may take from its seed.
    pub max_depth: usize,
}

/// Which bound stopped a walk, so a finding names it rather than saying "a
/// bound".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// [`Bounds::max_visits`].
    Visits,
    /// [`Bounds::max_depth`].
    Depth,
}

/// What a walk found.
///
/// **`BoundExceeded` is not `Exhausted`**, and the separation is the point. A
/// walk that ran out of budget has shown nothing about the chain; one that
/// emptied its frontier has shown the chain does not close. A caller merging
/// them would report a clean tree over a graph it never finished reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The stop condition held, at this node, by this path from the seed.
    ///
    /// The path includes both ends, so a finding can point at the hop that broke
    /// without the caller reconstructing it.
    Reached {
        /// The node that satisfied the stop condition.
        at: NodeId,
        /// Seed to `at`, inclusive.
        path: Vec<NodeId>,
    },
    /// The frontier emptied and nothing satisfied the stop condition.
    Exhausted {
        /// How many nodes were visited before the frontier emptied.
        visited: usize,
    },
    /// A bound stopped the walk. Says nothing about the chain.
    BoundExceeded {
        /// Which bound.
        bound: Bound,
        /// How many nodes were visited before it was hit.
        visited: usize,
    },
    /// A node on the walk could not be read, so no answer is available.
    CouldNotLook {
        /// The node that could not be read.
        at: NodeId,
    },
}

/// The condition a walk stops on.
///
/// A closed enum rather than a closure, because a traversal is DECLARED config
/// and a closure cannot be written in a `batten.toml` row. Widening this is a
/// deliberate edit with a test behind it, which is what keeps a completion gate
/// from growing into a query engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Until {
    /// Stop at a node carrying `key` equal to `value`.
    Has {
        /// The field to read.
        key: String,
        /// The value it must carry.
        value: String,
    },
}

/// A declared walk: where it starts, which edges it follows, when it stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traversal {
    /// The node the walk starts from.
    pub seed: NodeId,
    /// The edge labels the walk follows, in the order they are tried.
    pub labels: Vec<String>,
    /// What stops the walk. `None` walks to exhaustion, bounded as ever.
    pub until: Option<Until>,
    /// How far it may go.
    pub bounds: Bounds,
}

impl Traversal {
    /// Walk, pulling one frontier at a time, stopping at the first satisfying
    /// node.
    ///
    /// **Breadth-first, and the reported `path` is what makes that visible.** A
    /// depth-first walk would report the first path it happened down rather than
    /// the shortest, so two trees differing only in edge order would produce
    /// different pointers for one defect — which §6's byte-stable output
    /// forbids.
    ///
    /// Cycle-safe by a visited set: a node is expanded once, so
    /// `a -> b -> a` terminates with [`Outcome::Exhausted`] rather than spinning.
    #[must_use]
    pub fn run(&self, source: &dyn GraphSource) -> Outcome {
        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        let mut parent: BTreeMap<NodeId, NodeId> = BTreeMap::new();
        let mut queue: VecDeque<(NodeId, usize)> = VecDeque::new();
        let mut visited = 0usize;

        queue.push_back((self.seed.clone(), 0));
        seen.insert(self.seed.clone());

        while let Some((node, depth)) = queue.pop_front() {
            visited += 1;
            if visited > self.bounds.max_visits {
                return Outcome::BoundExceeded {
                    bound: Bound::Visits,
                    visited,
                };
            }

            // THE STOP IS TESTED ON ARRIVAL, INCLUDING AT THE SEED. A chain of
            // length zero is a real answer — a node that is itself the thing
            // being looked for — and a walk that only tested successors would
            // report it as unreached.
            match self.satisfied(&node, source) {
                None => return Outcome::CouldNotLook { at: node },
                Some(true) => {
                    let path = trace(&parent, &self.seed, &node);
                    return Outcome::Reached { at: node, path };
                }
                Some(false) => {}
            }

            if depth == self.bounds.max_depth {
                // Not an answer about the chain: the walk stopped with a
                // frontier still to expand.
                if self.has_unexpanded(&node, source, &seen) {
                    return Outcome::BoundExceeded {
                        bound: Bound::Depth,
                        visited,
                    };
                }
                continue;
            }

            for label in &self.labels {
                let Some(next) = source.out(&node, label) else {
                    return Outcome::CouldNotLook { at: node };
                };
                for target in next {
                    if seen.insert(target.clone()) {
                        parent.insert(target.clone(), node.clone());
                        queue.push_back((target, depth + 1));
                    }
                }
            }
        }

        Outcome::Exhausted { visited }
    }

    /// Whether the stop condition holds at `node`. `None` is could-not-look.
    fn satisfied(&self, node: &str, source: &dyn GraphSource) -> Option<bool> {
        match &self.until {
            // A walk with no stop condition never stops early; it exhausts, or
            // it hits a bound. That is the "count everything reachable" shape
            // rather than a degenerate case.
            None => Some(false),
            Some(Until::Has { key, value }) => source.has(node, key, value),
        }
    }

    /// Whether `node` points anywhere the walk has not already seen.
    ///
    /// Read at the depth bound, and only there, to tell *the walk ended* from
    /// *the walk was cut off*. A node whose every successor is already seen is
    /// the end of its branch, so stopping there is exhaustion rather than a
    /// bound — reporting [`Bound::Depth`] for it would make a complete answer
    /// look like an incomplete one.
    fn has_unexpanded(
        &self,
        node: &str,
        source: &dyn GraphSource,
        seen: &BTreeSet<NodeId>,
    ) -> bool {
        self.labels.iter().any(|label| {
            source
                .out(node, label)
                .is_some_and(|next| next.iter().any(|target| !seen.contains(target)))
        })
    }
}

/// Rebuild the seed-to-node path from the parent links a walk recorded.
///
/// Bounded by construction: `parent` is acyclic because an entry is written once,
/// when a node is first seen, so the climb visits each node at most once and
/// cannot spin even over a cyclic INPUT graph.
fn trace(parent: &BTreeMap<NodeId, NodeId>, seed: &str, node: &str) -> Vec<NodeId> {
    let mut path = vec![node.to_owned()];
    let mut cursor = node;
    while cursor != seed {
        let Some(previous) = parent.get(cursor) else {
            break;
        };
        path.push(previous.clone());
        cursor = previous;
    }
    path.reverse();
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture graph: edges by label, a property table, and an unreadable set.
    struct Fixture {
        edges: BTreeMap<(String, String), Vec<NodeId>>,
        props: BTreeMap<String, BTreeMap<String, String>>,
        unreadable: BTreeSet<String>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                edges: BTreeMap::new(),
                props: BTreeMap::new(),
                unreadable: BTreeSet::new(),
            }
        }
        fn edge(mut self, from: &str, label: &str, to: &[&str]) -> Self {
            self.edges.insert(
                (from.to_owned(), label.to_owned()),
                to.iter().map(|s| (*s).to_owned()).collect(),
            );
            self
        }
        fn prop(mut self, node: &str, key: &str, value: &str) -> Self {
            self.props
                .entry(node.to_owned())
                .or_default()
                .insert(key.to_owned(), value.to_owned());
            self
        }
        fn unreadable(mut self, node: &str) -> Self {
            self.unreadable.insert(node.to_owned());
            self
        }
    }

    impl GraphSource for Fixture {
        fn out(&self, from: &str, label: &str) -> Option<Vec<NodeId>> {
            if self.unreadable.contains(from) {
                return None;
            }
            Some(
                self.edges
                    .get(&(from.to_owned(), label.to_owned()))
                    .cloned()
                    .unwrap_or_default(),
            )
        }
        fn has(&self, node: &str, key: &str, value: &str) -> Option<bool> {
            if self.unreadable.contains(node) {
                return None;
            }
            Some(
                self.props
                    .get(node)
                    .and_then(|fields| fields.get(key))
                    .map(String::as_str)
                    == Some(value),
            )
        }
    }

    fn walk(seed: &str, until: Option<Until>, bounds: Bounds) -> Traversal {
        Traversal {
            seed: seed.to_owned(),
            labels: vec!["warrant".to_owned()],
            until,
            bounds,
        }
    }

    fn registered() -> Option<Until> {
        Some(Until::Has {
            key: "registered".to_owned(),
            value: "true".to_owned(),
        })
    }

    const ROOMY: Bounds = Bounds {
        max_visits: 64,
        max_depth: 16,
    };

    /// THE CONSUMER'S SHAPE: an entry's warrant reaching a registered capture two
    /// hops up, with the path reported so a finding can point at it.
    #[test]
    fn a_chain_that_closes_reports_the_path_it_took() {
        let graph = Fixture::new()
            .edge("entry", "warrant", &["record"])
            .edge("record", "warrant", &["capture"])
            .prop("capture", "registered", "true");
        match walk("entry", registered(), ROOMY).run(&graph) {
            Outcome::Reached { at, path } => {
                assert_eq!(at, "capture");
                assert_eq!(path, vec!["entry", "record", "capture"]);
            }
            other => panic!("expected Reached, got {other:?}"),
        }
    }

    /// The deny arm: the chain runs out before anything satisfies the stop.
    #[test]
    fn a_chain_that_does_not_close_is_exhausted_rather_than_reached() {
        let graph = Fixture::new().edge("entry", "warrant", &["record"]).edge(
            "record",
            "warrant",
            &["orphan"],
        );
        assert!(matches!(
            walk("entry", registered(), ROOMY).run(&graph),
            Outcome::Exhausted { .. }
        ));
    }

    /// A cycle terminates, and does not invent a reach that is not there.
    #[test]
    fn a_cyclic_chain_terminates_and_invents_no_reach() {
        let graph = Fixture::new()
            .edge("a", "warrant", &["b"])
            .edge("b", "warrant", &["a"]);
        assert!(matches!(
            walk("a", registered(), ROOMY).run(&graph),
            Outcome::Exhausted { visited: 2 }
        ));
    }

    /// THE BOUND IS NOT A NEGATIVE ANSWER. A walk cut off by its visit budget
    /// reports the bound, never `Exhausted` — which a caller would otherwise read
    /// as "the chain does not close".
    #[test]
    fn a_visit_bound_is_reported_rather_than_read_as_no_chain() {
        let graph = Fixture::new()
            .edge("a", "warrant", &["b"])
            .edge("b", "warrant", &["c"])
            .edge("c", "warrant", &["d"])
            .prop("d", "registered", "true");
        let tight = Bounds {
            max_visits: 2,
            max_depth: 16,
        };
        assert!(matches!(
            walk("a", registered(), tight).run(&graph),
            Outcome::BoundExceeded {
                bound: Bound::Visits,
                ..
            }
        ));
    }

    /// The depth bound, and the half that distinguishes it from exhaustion: a
    /// frontier still to expand at the bound is a cut-off walk.
    #[test]
    fn a_depth_bound_with_more_to_expand_is_reported() {
        let graph = Fixture::new()
            .edge("a", "warrant", &["b"])
            .edge("b", "warrant", &["c"])
            .prop("c", "registered", "true");
        let shallow = Bounds {
            max_visits: 64,
            max_depth: 1,
        };
        assert!(matches!(
            walk("a", registered(), shallow).run(&graph),
            Outcome::BoundExceeded {
                bound: Bound::Depth,
                ..
            }
        ));
    }

    /// AND ITS MIRROR, the case a naive bound check gets wrong: a walk reaching
    /// the depth bound with nothing left to expand has FINISHED.
    #[test]
    fn a_depth_bound_with_nothing_left_to_expand_is_exhaustion() {
        let graph = Fixture::new().edge("a", "warrant", &["b"]);
        let shallow = Bounds {
            max_visits: 64,
            max_depth: 1,
        };
        assert!(matches!(
            walk("a", registered(), shallow).run(&graph),
            Outcome::Exhausted { .. }
        ));
    }

    /// A node that could not be read is could-not-look, never a broken chain.
    #[test]
    fn an_unreadable_node_is_could_not_look() {
        let graph = Fixture::new()
            .edge("entry", "warrant", &["record"])
            .unreadable("record");
        match walk("entry", registered(), ROOMY).run(&graph) {
            Outcome::CouldNotLook { at } => assert_eq!(at, "record"),
            other => panic!("expected CouldNotLook, got {other:?}"),
        }
    }

    /// A chain of length zero is an answer. The stop is tested on arrival, so a
    /// seed already satisfying it reports a one-node path.
    #[test]
    fn a_seed_that_already_satisfies_the_stop_reaches_at_depth_zero() {
        let graph = Fixture::new().prop("entry", "registered", "true");
        match walk("entry", registered(), ROOMY).run(&graph) {
            Outcome::Reached { at, path } => {
                assert_eq!(at, "entry");
                assert_eq!(path, vec!["entry"]);
            }
            other => panic!("expected Reached, got {other:?}"),
        }
    }

    /// CALL-BY-NEED, ASSERTED RATHER THAN CLAIMED. The walk stops at the first
    /// satisfying node, so the branch beyond it is never asked for — which is
    /// what lets acquisition follow the walk instead of preceding it.
    #[test]
    fn the_walk_does_not_ask_past_the_node_that_satisfies_it() {
        use std::cell::RefCell;

        struct Counting {
            inner: Fixture,
            asked: RefCell<Vec<String>>,
        }
        impl GraphSource for Counting {
            fn out(&self, from: &str, label: &str) -> Option<Vec<NodeId>> {
                self.asked.borrow_mut().push(from.to_owned());
                self.inner.out(from, label)
            }
            fn has(&self, node: &str, key: &str, value: &str) -> Option<bool> {
                self.inner.has(node, key, value)
            }
        }

        let graph = Counting {
            inner: Fixture::new()
                .edge("entry", "warrant", &["record"])
                .edge("record", "warrant", &["capture"])
                .edge("capture", "warrant", &["beyond"])
                .prop("capture", "registered", "true"),
            asked: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            walk("entry", registered(), ROOMY).run(&graph),
            Outcome::Reached { .. }
        ));
        let asked = graph.asked.borrow().clone();
        assert!(
            !asked.iter().any(|node| node == "capture"),
            "the walk expanded past its own stop: {asked:?}"
        );
    }

    /// Breadth-first, so the reported path is the shortest and two edge orders
    /// cannot produce two pointers for one defect (§6 byte-stability).
    #[test]
    fn the_reported_path_is_the_shortest_one() {
        let graph = Fixture::new()
            .edge("a", "warrant", &["long", "short"])
            .edge("long", "warrant", &["mid"])
            .edge("mid", "warrant", &["target"])
            .edge("short", "warrant", &["target"])
            .prop("target", "registered", "true");
        match walk("a", registered(), ROOMY).run(&graph) {
            Outcome::Reached { path, .. } => assert_eq!(path, vec!["a", "short", "target"]),
            other => panic!("expected Reached, got {other:?}"),
        }
    }
}
