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
//! * **Plumbing**, 73 modules at closure ≤ 8 — `git` at 2, `capture` and
//!   `gitwrite` at 4, `land` at 7, `exec` and `pipeline` at 8. Every one of
//!   these is extractable into its own crate today or nearly so.
//! * **The decision core**, 55 modules at 24–27 — `rules`, `hook`, `config`,
//!   `facts`, `policy`, `preset`, `cli`. One cluster, which is what a split
//!   leaves in the top crate.
//!
//! **The core has not grown across three trunk measurements** — 119, 124 and now
//! 128 modules — while the plumbing went 64 → 69 → 73. Every module the trunk
//! added landed reaching nothing or nearly nothing, including all four of #962's
//! (`cargo_graph`, `durable`, `probe_verdict`, `signer_posture`, all at closure
//! 1). That is the split's direction holding without anyone steering for it.
//! * **Nothing between 10 and 23**, which is a real cliff, unlike the one the
//!   scanner reported in a different place. (It was 9 until CLOUD-843: a module
//!   that spawns through `exec`, the adapter the spawn rule requires, sits at
//!   `exec`'s 8 plus itself, and `attestation`, `dist` and `probe` are the
//!   first plumbing-shaped modules to do so.)
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

use common::at_root;

/// The largest closure that still counts as plumbing.
///
/// Nine: `exec` and `pipeline` sit at eight, and a module whose only non-leaf
/// edge is `exec` — the spawn adapter `policy/spawn-adapters.rego` requires —
/// sits at nine by construction (CLOUD-843). The boundary is still the top of
/// the lower population rather than an arbitrary line through the gap; raising
/// it was admitted by a recorded answer, not written here on its own authority.
const PLUMBING_CEILING: usize = 9;

/// The smallest closure that counts as the decision core.
///
/// Twenty-four, the bottom of the upper population. Together with
/// [`PLUMBING_CEILING`] this brackets the gap
/// [`the_gap_holds_only_the_recorded_middle`] reads ([`MIDDLE`]).
const CORE_FLOOR: usize = 24;

/// Every module that is plumbing today. None of them may stop being plumbing.
///
/// # Re-recorded on the corrected graph (2026-11-22)
///
/// Every list and number in this file was first recorded on a graph built from
/// the `uses` fact, which read `use` items alone. A module reached only by a
/// qualified path (`crate::trust::load(..)`) or inside a macro's arguments was
/// no edge, so `lib`, `mutate`, `land` and `startup` sat in this list at a
/// closure of nine or under while the real graph had each reaching eighty. The
/// graph is now `module_graph::read`'s, the one `modules.lock` already held, and
/// each value below is that graph's, from [`print_the_distribution`]. A
/// re-record forced by a corrected instrument is not a loosened gate: the old
/// values described a graph that did not exist.
///
/// # Why a set, and why a subset rather than an equality
///
/// This replaced a pair of population COUNTS — a plumbing floor and a core
/// ceiling — which had an escape: one module decoupling while another couples
/// nets to zero, so both counts hold and a real regression lands green. Counting
/// cannot see a swap; naming can.
///
/// The assertion is `⊆`, not `==`. A module ARRIVING in the plumbing is progress
/// (five did between two measurements: `arm`, `install`, `ripcord`, `suites`,
/// `tokens`) and must not redden, and an equality would also churn this list on
/// every new leaf module in the crate. A module LEAVING is the regression, and
/// that is what a subset check catches — including the leaving half of a swap.
///
/// Recorded by running [`print_the_distribution`], never by hand.
///
/// `durable`, `identity`, `scratch` and `source` left this list by leaving the
/// crate (CLOUD-2789): they are `batten-facts` now, with nothing above them, so
/// a closure can no longer be drawn over them here — which is the split working.
const PLUMBING: &[&str] = &[
    "asked",
    "budget",
    "census",
    "config_model",
    "design",
    "emission",
    "error",
    "findings",
    "history",
    "init",
    "item_index",
    "journal",
    "mutation_markers",
    "o200k",
    "output",
    "preset_catalog",
    "prune",
    "redirect",
    "rego_units",
    "render",
    "session",
    "spec",
    "store",
    "surface",
    "surface_table",
    "waiver",
];

/// No module's closure may exceed this.
///
/// The most entangled module reaches 27 of 119. Ratcheting this down is the
/// split's whole direction, and it is the one number that cannot be improved by
/// adding modules.
///
/// Twenty-eight since CLOUD-843: `board_check` evaluates the tracker-hygiene
/// preset through `policy`, so it sits one layer above the whole core. Raised by
/// a recorded answer, and the direction of travel is unchanged — down.
///
/// Twenty-nine since CLOUD-2005: `rules` gained `register`, the pure key-set
/// module the `reference` kind joins through, and `board_check` reaches the
/// rule engine. One genuinely new module, not an edge between old ones —
/// `register` itself is plumbing, and `traversal` was kept plumbing by
/// injecting its reads rather than letting it reach the fact model.
///
/// Eighty-nine on the corrected graph (see [`PLUMBING`]'s re-record note), and
/// `lib` is not judged by it: the crate root dispatches every verb, so its
/// closure is the whole crate by construction and no cut can lower it. The
/// deepest library module, `disk_watch`, is the number that can move.
const DEEPEST_CLOSURE: usize = 89;

/// The crate root's own recorded worst (CLOUD-2789): `lib` dispatches every
/// verb, so its closure is every module it can reach and [`DEEPEST_CLOSURE`]
/// does not judge it. It is ratcheted apart, on the same terms: the split moves
/// modules out and this number down; a module added to the crate fails it until
/// the number is re-recorded here, deliberately.
///
/// 118 since CLOUD-2840: `session_setup`, the session's setup as one detached
/// task, is a new module added on purpose, reached only from `lib`.
const ROOT_CLOSURE: usize = 118;

/// Every top-level module of the library, mapped to the modules it reaches.
///
/// Keys are module names as `policy/module-layering.rego`'s `declared_modules`
/// spells them — a file's stem, a directory's own name, and `lib`/`main` for the
/// two entry points, which are files in the judged set like any other.
fn module_graph() -> BTreeMap<String, BTreeSet<String>> {
    // ONE GRAPH for this test and `modules.lock`: `module_graph::read` reads
    // `use` items, qualified paths in code (`crate::m::f()`) and paths inside
    // macro token trees, and skips `#[cfg(test)]` items. This test used to build
    // its own graph from the `uses` fact, which read `use` items ALONE, so every
    // module reached by a qualified path was invisible to it: [`MIDDLE`] and
    // [`PLUMBING`] were recorded on that blind graph while the ratchet's own
    // read held one 61-module cycle (`modules.lock`). Two readers of one graph
    // disagreeing is the defect; this is the reader the lock already trusts.
    batten::module_graph::read(&at_root("crates/batten/src"))
        .expect("the library parses")
        .edges
}

/// Whether a workspace crate other than `batten` carries `module`, as a file
/// or a directory module under its `src`.
fn in_another_crate(module: &str) -> bool {
    fs::read_dir(at_root("crates"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|krate| krate.file_name().is_some_and(|name| name != "batten"))
        .any(|krate| {
            let src = krate.join("src");
            src.join(format!("{module}.rs")).is_file() || src.join(module).is_dir()
        })
}

/// The shortest path from `start` back to `start`, breadth first, or `None`
/// when `start` is on no cycle.
fn cycle_witness(graph: &BTreeMap<String, BTreeSet<String>>, start: &str) -> Option<Vec<String>> {
    let mut parent: BTreeMap<String, String> = BTreeMap::new();
    let mut queue = std::collections::VecDeque::new();
    for next in graph.get(start).into_iter().flatten() {
        if next == start {
            return Some(vec![start.to_owned(), start.to_owned()]);
        }
        if !parent.contains_key(next) {
            parent.insert(next.clone(), start.to_owned());
            queue.push_back(next.clone());
        }
    }
    while let Some(module) = queue.pop_front() {
        for next in graph.get(&module).into_iter().flatten() {
            if next == start {
                // Walk the parents back from `module` to `start`, then turn it
                // around: start -> ... -> module -> start.
                let mut back = vec![module.clone()];
                let mut at = module.clone();
                while let Some(up) = parent.get(&at) {
                    if up == start {
                        break;
                    }
                    back.push(up.clone());
                    at = up.clone();
                }
                back.reverse();
                let mut path = vec![start.to_owned()];
                path.extend(back);
                path.push(start.to_owned());
                return Some(path);
            }
            if !parent.contains_key(next) && next != start {
                parent.insert(next.clone(), module.clone());
                queue.push_back(next.clone());
            }
        }
    }
    None
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
fn no_module_leaves_the_plumbing() {
    let graph = module_graph();
    let plumbing: BTreeSet<String> = distribution(&graph)
        .into_iter()
        .filter(|(size, _)| *size <= PLUMBING_CEILING)
        .map(|(_, module)| module)
        .collect();

    let recorded: BTreeSet<String> = PLUMBING.iter().map(|name| (*name).to_owned()).collect();

    // A recorded module this crate no longer HAS left by leaving the crate:
    // the split (CLOUD-2789) moved it into a package below, where Cargo's
    // acyclic package graph holds it more strongly than a closure ceiling can.
    // That is only true of a module some other workspace crate really carries;
    // one found nowhere was deleted, and is reported like any other departure.
    let (moved, vanished): (Vec<&String>, Vec<&String>) = recorded
        .iter()
        .filter(|module| !graph.contains_key(module.as_str()))
        .partition(|module| in_another_crate(module));
    assert!(
        vanished.is_empty(),
        "these plumbing modules are in no workspace crate: {vanished:?}. A deleted \
         module leaves PLUMBING by an edit, never silently.",
    );
    if !moved.is_empty() {
        report(&format!(
            "plumbing that left for a lower package: {moved:?}"
        ));
    }

    let left: Vec<&String> = recorded
        .iter()
        .filter(|module| graph.contains_key(module.as_str()) && !plumbing.contains(*module))
        .collect();

    assert!(
        left.is_empty(),
        "these modules were plumbing and are not any more: {left:?}. Each grew an \
         edge that pulled its closure past {PLUMBING_CEILING}, so a crate \
         boundary that could be drawn around it no longer can. This is the half \
         a population count could not see — a swap holds the count and moves \
         these names.",
    );

    // Arrivals are progress, not a finding, so they are reported and never
    // asserted on. Recording them is a separate, deliberate edit to `PLUMBING`
    // — which is what keeps the list a measurement rather than a mirror of
    // whatever the tree happens to say today.
    let arrived: Vec<&String> = plumbing.difference(&recorded).collect();
    if !arrived.is_empty() {
        report(&format!(
            "arrived in the plumbing since PLUMBING was recorded: {arrived:?}"
        ));
    }
}

#[test]
fn no_module_reaches_deeper_than_the_recorded_worst() {
    let sizes = distribution(&module_graph());
    let deepest = sizes
        .iter()
        .rfind(|(_, module)| module.as_str() != batten::module_graph::LIB)
        .expect("the crate has modules");

    assert!(
        deepest.0 <= DEEPEST_CLOSURE,
        "`{}` now reaches {} modules, past the recorded worst of \
         {DEEPEST_CLOSURE}. This is the one number adding modules cannot \
         improve.",
        deepest.1,
        deepest.0,
    );
}

/// Fails by: the crate root left out of every ratchet, so a root that grew its
/// reach (a new module, a new edge from `lib`) passed unseen — the deepest
/// module's bound excludes `lib` by design.
#[test]
fn the_crate_root_reaches_no_further_than_its_recorded_worst() {
    let sizes = distribution(&module_graph());
    let (reach, _) = sizes
        .iter()
        .find(|(_, module)| module.as_str() == batten::module_graph::LIB)
        .expect("the crate has a root");
    assert!(
        *reach <= ROOT_CLOSURE,
        "the crate root now reaches {reach} modules, past its recorded worst of \
         {ROOT_CLOSURE}. Re-record `ROOT_CLOSURE` only for a module added on \
         purpose."
    );
}

/// Every module the cycle break moved out of the core into the gap (CLOUD-2789).
///
/// The gap was empty while the crate's largest cycle held 148 modules: every
/// module reaching the core reached all of it. Breaking that cycle to 128 left
/// these with closures of 12 to 23 — a tier a crate boundary can now be drawn
/// under, which is what the split is for. Same discipline as [`PLUMBING`]: a
/// subset, recorded by [`print_the_distribution`], and a module LEAVING it for
/// the core is the regression, while a module arriving fails until recorded.
///
/// EMPTY on the corrected graph: the 34 modules recorded here sat in the gap
/// only on the `use`-only graph, and every one is in the core once qualified
/// paths count. The gap is real (nothing lives between 9 and 80), so a module
/// arriving in it fails until it is recorded here, exactly as on `main`.
const MIDDLE: &[&str] = &[];

#[test]
fn the_gap_holds_only_the_recorded_middle() {
    // The distribution was two populations, not a gradient, with the gap between
    // 9 and 24 — NOT between the rim and everything else, which is what a line
    // scan reported and what a split plan was written on. The cycle break
    // (CLOUD-2789) put [`MIDDLE`] in it, which is the plan working.
    //
    // Two failures are news. A module of [`MIDDLE`] climbing back to the core
    // undoes a break. A module arriving in the gap that [`MIDDLE`] does not
    // record fails too: it may be progress, but recording it is a deliberate
    // edit, never a report line.
    let graph = module_graph();
    let sizes = distribution(&graph);
    let middle: BTreeSet<&str> = MIDDLE.iter().copied().collect();

    // Each climbed module with the direct edges that put it there: the ones
    // landing on a module that is itself core-sized. A failure that names the
    // edge to cut is a failure a reader can act on without a second tool.
    let core: BTreeSet<&str> = sizes
        .iter()
        .filter(|(size, _)| *size >= CORE_FLOOR)
        .map(|(_, module)| module.as_str())
        .collect();
    let climbed: Vec<(usize, &str, Vec<&str>)> = sizes
        .iter()
        .filter(|(size, module)| *size >= CORE_FLOOR && middle.contains(module.as_str()))
        .map(|(size, module)| {
            let into_core = graph
                .get(module)
                .into_iter()
                .flatten()
                .map(String::as_str)
                .filter(|to| core.contains(to))
                .collect();
            (*size, module.as_str(), into_core)
        })
        .collect();
    // A CYCLE WITNESS per climbed module: the shortest path from it back to
    // itself through the resolved graph. The edges into the core say where a
    // module enters the cycle; the witness says which edge closes it, which is
    // the one a fix has to cut.
    let witnesses: Vec<String> = climbed
        .iter()
        .filter_map(|(_, module, _)| cycle_witness(&graph, module))
        .map(|path| path.join(" -> "))
        .collect();
    assert!(
        climbed.is_empty(),
        "these modules were below the core and reach it again, each with its edges \
         into the core: {climbed:?}. Shortest cycle through each: {witnesses:#?}. Each \
         grew an edge back into the largest cycle; re-read the split plan.",
    );

    // A module in the gap that MIDDLE does not record FAILS, as
    // `the_gap_between_the_two_populations_stays_empty` failed on `main`: the
    // split plan rests on the two populations, so a straddler is news somebody
    // has to look at and record, never a line in a report nobody reads. With
    // MIDDLE empty this is that assertion verbatim.
    let arrived: Vec<&(usize, String)> = sizes
        .iter()
        .filter(|(size, module)| {
            *size > PLUMBING_CEILING && *size < CORE_FLOOR && !middle.contains(module.as_str())
        })
        .collect();
    assert!(
        arrived.is_empty(),
        "modules now sit between plumbing and core and MIDDLE does not record them: \
         {arrived:?}. Re-read the split plan before moving either boundary — this \
         is the shape it rests on — and record each in MIDDLE deliberately.",
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
    report(&format!("total modules: {}", sizes.len()));
    for (size, modules) in &by_size {
        report(&format!(
            "  closure {size:3}: {:3} modules  {modules:?}",
            modules.len()
        ));
    }
}

/// Stderr, as `bundle.rs`'s `skipped` does: the workspace denies `print_stdout`.
fn report(line: &str) {
    use std::io::Write as _;
    drop(writeln!(std::io::stderr(), "{line}"));
}
