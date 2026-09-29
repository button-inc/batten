//! The dependency-closure distribution, ratcheted (CLOUD-1765).
//!
//! # What this measures and why a number rather than an edge
//!
//! `policy/module-layering.rego` decides DIRECT edges: a named pair is
//! forbidden and the rest are permitted. That is the right shape for a claim the
//! tree already states in prose, and it is deliberately not an architecture —
//! that file says so: *"inventing a rank for all 65 modules would be declaring
//! an architecture nobody agreed to"*.
//!
//! This asks what that table cannot: **how entangled is the crate as a whole,
//! and is it getting worse.** One number per module — the size of its transitive
//! `use` closure — and the shape of the distribution is what a workspace split
//! has to work with.
//!
//! # It reads the RESOLVED graph, and that is not a detail
//!
//! CLOUD-762 measured a line predicate wrong in two classes in this tree: an
//! edge it cannot see (`use crate::UsageError`, really onto `error`) and one it
//! invents (`use crate::Result`, really external). The second class is the
//! expensive one here, because it grows with every module that imports
//! `crate::Result` and every such edge is a false weld.
//!
//! **Measured, by this file's own first version.** A `crate::` scanner put 103
//! of 119 modules in a single component each reaching ~98 others, and reported
//! no module between 3 and 97. Run against [`batten::uses`], the largest closure
//! in the crate is 27 and 64 modules sit at 8 or below. The scanner inflated
//! closures roughly fourfold and invented a hairball that does not exist. A
//! split plan was written on those numbers before this test contradicted them.
//!
//! # The real shape: two populations with a gap
//!
//! * **Plumbing**, 64 modules at closure ≤ 8 — `git` at 2, `capture` and
//!   `gitwrite` at 4, `exec` and `land` at 7, `pipeline` at 8. Every one of
//!   these is extractable into its own crate today or nearly so.
//! * **The decision core**, 55 modules at 24–27 — `rules`, `hook`, `config`,
//!   `facts`, `policy`, `preset`, `cli`. One cluster, which is what a split
//!   leaves in the top crate.
//! * **Nothing between 9 and 23**, which is a real cliff, unlike the one the
//!   scanner reported in a different place.
//!
//! So the gates below are three: the plumbing must not shrink, the core must not
//! grow, and the gap must stay empty. Each is falsifiable and none is vacuous —
//! which the first version's hairball assertion was, asking for closure ≥ half
//! the crate when nothing came within 30 of it, counting zero and passing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use batten::facts::Look;
use batten::uses::{Origin, resolve, root_exports, use_facts};
use common::at_root;

/// The largest closure that still counts as plumbing.
///
/// Eight, because `pipeline` sits there and the gap above it is fifteen wide.
/// Any boundary inside the gap would do; this one is the top of the lower
/// population rather than an arbitrary line through it.
const PLUMBING_CEILING: usize = 8;

/// The smallest closure that counts as the decision core.
///
/// Twenty-four, the bottom of the upper population. Together with
/// [`PLUMBING_CEILING`] this brackets the gap that
/// [`the_gap_between_the_two_populations_stays_empty`] holds open.
const CORE_FLOOR: usize = 24;

/// Modules at or below [`PLUMBING_CEILING`] must not fall below this.
///
/// A floor rather than an equality: decoupling a core module down into the
/// plumbing is the goal and must not redden.
const PLUMBING_FLOOR: usize = 64;

/// Modules at or above [`CORE_FLOOR`] must not exceed this.
///
/// The other half of the same claim, and the one that makes the pair
/// non-vacuous: a new leaf module raises the plumbing count without lowering
/// this, so only actual untangling moves both.
const CORE_CEILING: usize = 55;

/// No module's closure may exceed this.
///
/// The most entangled module reaches 27 of 119. Ratcheting this down is the
/// split's whole direction, and it is the one number that cannot be improved by
/// adding modules.
const DEEPEST_CLOSURE: usize = 27;

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
            // `Internal` AFTER resolution is the only class crossing a module
            // boundary inside this crate. A `RootItem` left unresolved is
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
fn module_files(src: &Path) -> Vec<(String, PathBuf)> {
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

fn collect_under(dir: &Path, module: &str, found: &mut Vec<(String, PathBuf)>) {
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
fn the_plumbing_does_not_shrink_and_the_core_does_not_grow() {
    let sizes = distribution(&module_graph());

    let plumbing: Vec<&str> = sizes
        .iter()
        .filter(|(size, _)| *size <= PLUMBING_CEILING)
        .map(|(_, module)| module.as_str())
        .collect();
    let core: Vec<&str> = sizes
        .iter()
        .filter(|(size, _)| *size >= CORE_FLOOR)
        .map(|(_, module)| module.as_str())
        .collect();

    assert!(
        plumbing.len() >= PLUMBING_FLOOR,
        "plumbing fell to {} modules, below the floor of {PLUMBING_FLOOR}: a \
         module that was extractable no longer is",
        plumbing.len(),
    );
    assert!(
        core.len() <= CORE_CEILING,
        "the decision core grew to {} modules, above the ceiling of \
         {CORE_CEILING}: a new edge pulled a module in. Decoupling lowers this; \
         adding a leaf module does not.",
        core.len(),
    );
}

#[test]
fn no_module_reaches_deeper_than_the_recorded_worst() {
    let sizes = distribution(&module_graph());
    let deepest = sizes.last().expect("the crate has modules");

    assert!(
        deepest.0 <= DEEPEST_CLOSURE,
        "`{}` now reaches {} modules, past the recorded worst of \
         {DEEPEST_CLOSURE}. This is the one number adding modules cannot \
         improve.",
        deepest.1,
        deepest.0,
    );
}

#[test]
fn the_gap_between_the_two_populations_stays_empty() {
    // The distribution is two populations, not a gradient — but the gap is
    // between 8 and 24, NOT between the rim and everything else, which is what
    // a line scan reported and what a split plan was written on. Asserted here
    // so the shape is a checked claim rather than a remembered one.
    //
    // A module landing in the gap is news rather than a defect: something
    // partially decoupled, and a crate boundary may be drawable where it was
    // not. Redden so somebody looks.
    let sizes = distribution(&module_graph());

    let straddling: Vec<&(usize, String)> = sizes
        .iter()
        .filter(|(size, _)| *size > PLUMBING_CEILING && *size < CORE_FLOOR)
        .collect();

    assert!(
        straddling.is_empty(),
        "modules now sit between plumbing and core: {straddling:?}. Re-read the \
         split plan before moving either boundary — this is the shape it rests \
         on.",
    );
}

#[test]
fn print_the_distribution() {
    // Not an assertion. The split plan needs the real numbers in front of it,
    // and a reader asking "what is extractable" gets the answer by running one
    // test rather than by trusting a figure in a doc comment that ages.
    let sizes = distribution(&module_graph());
    let mut by_size: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
    for (size, module) in &sizes {
        by_size.entry(*size).or_default().push(module.as_str());
    }
    println!("total modules: {}", sizes.len());
    for (size, modules) in &by_size {
        println!("  closure {size:3}: {:3} modules  {modules:?}", modules.len());
    }
}
