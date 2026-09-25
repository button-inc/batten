//! The dependency-closure distribution, ratcheted (CLOUD-1765).
//!
//! # What this measures and why a number rather than an edge
//!
//! [`crate::module_layering`]'s rego table decides DIRECT edges: a named pair is
//! forbidden and the rest are permitted. That is the right shape for a claim the
//! tree already states in prose, and it is deliberately not an architecture
//! (`policy/module-layering.rego` says so: *"inventing a rank for all 65 modules
//! would be declaring an architecture nobody agreed to"*).
//!
//! This file asks the question that table cannot: **how entangled is the crate
//! as a whole, and is it getting worse.** The answer is one number per module —
//! the size of its transitive `use` closure — and the shape of the distribution
//! is what a split has to work with. Measured on `main` at the time of writing,
//! it is not a gradient:
//!
//! * a **rim** of modules whose closure is themselves, reaching nothing; and
//! * a **hairball** of modules that each reach nearly the whole crate.
//!
//! Nothing in between. A crate boundary can be drawn around the rim today and
//! around no part of the hairball at any granularity, because Rust forbids
//! mutually dependent crates. So the rim size and the hairball size are the two
//! numbers a workspace split moves, and this is the gate that keeps them moving
//! the right way.
//!
//! # It reads the RESOLVED graph, which is the whole reason it is a test
//!
//! CLOUD-762 measured a line predicate wrong in two classes in this tree — an
//! edge it cannot see (`use crate::UsageError`, really onto `error`) and one it
//! invents (`use crate::Result`, really external) — so counting `crate::`
//! occurrences with a scanner produces a confident wrong distribution. This uses
//! [`batten::uses`], the same fact `module-layering.rego` decides over, and
//! [`Origin::Internal`] AFTER [`resolve`] is what makes an edge real.
//!
//! # Direction, and why two numbers rather than one
//!
//! `forge` was on the rim and is not any more: it grew one edge between two
//! measurements sixteen days apart, and nothing reported it. That is the drift
//! this file exists to catch, and it is why the rim has a floor of its own — a
//! single "total edges" ceiling would have absorbed that move silently.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use batten::facts::Look;
use batten::uses::{Origin, resolve, root_exports, use_facts};
use common::at_root;

/// A module reaching nothing at all has a closure of exactly itself.
///
/// Stated as a named constant because `1` appears twice below and means the same
/// thing both times: the module itself, and no one else.
const REACHES_NOTHING: usize = 1;

/// The rim: modules whose closure is at most this many modules.
///
/// Two rather than one so `wiring` — which reaches exactly `environment` and
/// nothing further — counts as rim. It is extractable with its dependency, which
/// is the property the rim names.
const RIM_CEILING: usize = 2;

/// Modules whose closure is at most [`RIM_CEILING`] must not fall below this.
///
/// A floor rather than an equality: adding a genuinely independent module is
/// progress and must not redden. Losing one is the `forge` regression, and that
/// is what this refuses.
const RIM_FLOOR: usize = 14;

/// Modules reaching at least half the crate must not exceed this.
///
/// A ceiling for the same reason the rim gets a floor. The two together say
/// "decouple, do not merely add": a new leaf module raises the rim without
/// lowering this, and only actual untangling moves it down.
const HAIRBALL_CEILING: usize = 103;

/// Every top-level module of the library, mapped to the modules it reaches.
///
/// Keys are module names as `policy/module-layering.rego`'s `declared_modules`
/// spells them — a file's stem, a directory's own name, and `lib`/`main` for the
/// two entry points, which are files in the judged set like any other.
fn module_graph() -> BTreeMap<String, BTreeSet<String>> {
    let src = at_root("crates/batten/src");
    let root_source = fs::read_to_string(src.join("lib.rs")).unwrap();
    let Look::Is(exports) = root_exports(&root_source) else {
        panic!("the crate root did not parse, so no edge below can be resolved");
    };

    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (module, path) in module_files(&src) {
        let source = fs::read_to_string(&path).unwrap();
        let Look::Is(mut file) = use_facts(&source) else {
            panic!("{} did not parse", path.display());
        };
        resolve(&mut file.edges, &exports);

        let reached = graph.entry(module.clone()).or_default();
        for edge in &file.edges {
            // `Internal` AFTER resolution is the only class that crosses a
            // module boundary inside this crate. `RootItem` left unresolved is
            // could-not-look at the edge level, never an edge onto nothing, so
            // it is skipped rather than counted as a reach.
            if edge.origin == Origin::Internal && edge.to != module && !edge.to.is_empty() {
                reached.insert(edge.to.clone());
            }
        }
    }
    graph
}

/// Every library source file, paired with the module name it belongs to.
///
/// A directory module contributes every file beneath it under the directory's
/// own name: `policy/presets/foo.rs` is `policy`, because a crate boundary can
/// only ever be drawn around the directory as a unit.
fn module_files(src: &Path) -> Vec<(String, std::path::PathBuf)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(src).unwrap().flatten() {
        let path = entry.path();
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap()
            .to_owned();
        if path.is_dir() {
            collect_under(&path, &name, &mut found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push((name, path));
        }
    }
    found.sort();
    found
}

fn collect_under(dir: &Path, module: &str, found: &mut Vec<(String, std::path::PathBuf)>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_under(&path, module, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push((module.to_owned(), path));
        }
    }
}

/// Transitive closure of one module, including itself.
fn closure(graph: &BTreeMap<String, BTreeSet<String>>, start: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = vec![start.to_owned()];
    while let Some(module) = queue.pop() {
        if !seen.insert(module.clone()) {
            continue;
        }
        if let Some(reached) = graph.get(&module) {
            queue.extend(reached.iter().cloned());
        }
    }
    seen
}

/// Every module's closure size, smallest first.
fn distribution(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<(usize, String)> {
    let mut sizes: Vec<(usize, String)> = graph
        .keys()
        .map(|module| (closure(graph, module).len(), module.clone()))
        .collect();
    sizes.sort();
    sizes
}

#[test]
fn the_rim_does_not_shrink_and_the_hairball_does_not_grow() {
    let graph = module_graph();
    let sizes = distribution(&graph);
    let total = sizes.len();

    let rim: Vec<&str> = sizes
        .iter()
        .filter(|(size, _)| *size <= RIM_CEILING)
        .map(|(_, module)| module.as_str())
        .collect();
    let hairball = sizes
        .iter()
        .filter(|(size, _)| *size * 2 >= total)
        .count();

    assert!(
        rim.len() >= RIM_FLOOR,
        "the rim shrank to {} modules, below the floor of {RIM_FLOOR}. A module \
         that reached nothing now reaches something, which is how `forge` left \
         the rim unreported. Rim now: {rim:?}",
        rim.len(),
    );
    assert!(
        hairball <= HAIRBALL_CEILING,
        "{hairball} modules now reach at least half the crate, above the ceiling \
         of {HAIRBALL_CEILING}. A new edge pulled a module into the hairball; \
         decoupling is what lowers this, adding a leaf module is not.",
    );
}

#[test]
fn the_distribution_is_a_cliff_rather_than_a_gradient() {
    // The claim the split plan rests on, asserted rather than remembered: there
    // is no middle. If a module ever lands between the rim and the hairball,
    // that is a partial decoupling and the plan's "one extraction, then a
    // campaign" shape has a third option it did not have before. Redden so
    // somebody looks, rather than discovering it in a partition that fails.
    let graph = module_graph();
    let sizes = distribution(&graph);
    let total = sizes.len();

    let middle: Vec<&(usize, String)> = sizes
        .iter()
        .filter(|(size, _)| *size > RIM_CEILING && *size * 2 < total)
        .collect();

    assert!(
        middle.is_empty(),
        "modules now sit between the rim and the hairball: {middle:?}. This is \
         news rather than a defect — a crate boundary may now be drawable where \
         it was not. Re-read the split plan before raising this ceiling.",
    );
}

#[test]
fn every_rim_module_reaches_nothing_or_only_other_rim_modules() {
    // The rim's defining property, and the one that makes it extractable: it is
    // CLOSED. A rim module reaching into the hairball would still have a small
    // closure only by accident of the hairball module being small too, and the
    // crate drawn around it would not compile.
    let graph = module_graph();
    let rim: BTreeSet<String> = distribution(&graph)
        .into_iter()
        .filter(|(size, _)| *size <= RIM_CEILING)
        .map(|(_, module)| module)
        .collect();

    for module in &rim {
        let reached = &graph[module];
        let escaping: Vec<&String> = reached.difference(&rim).collect();
        assert!(
            escaping.is_empty(),
            "rim module `{module}` reaches outside the rim: {escaping:?}",
        );
        assert!(
            reached.len() < REACHES_NOTHING + RIM_CEILING,
            "rim module `{module}` reaches {} modules directly",
            reached.len(),
        );
    }
}
