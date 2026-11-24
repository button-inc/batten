//! Architecture measures over a file-level dependency graph: Decoupling Level
//! (Mo, Cai, Kazman, Xiao, Feng, ICSE 2016) and propagation cost.
//!
//! # Why these, and why DL is the one a ratchet gates
//!
//! The same paper reports propagation cost "is sensitive to the size of the
//! DSM: the greater the number of files, the smaller the PC", so a ratchet on
//! PC is satisfied by adding unconnected files; measured on this repository
//! when the `units` module landed. DL was proposed there as the measure that is
//! not. PC is reported beside it for a reader, never gated.
//!
//! # The formula, from the paper's §3.1 (equations 1 to 5)
//!
//! `DL = Σ DL_Li` over the hierarchy's layers. For an upper layer,
//! `DL_Li = Σ_j (#Files(Mj)/#AllFiles) · (1 − #Deps(Mj)/#LowerLayerFiles)`, where
//! `#Deps(Mj)` counts lower-layer files that directly or indirectly depend on
//! `Mj`. For the last layer (modules nothing depends on),
//! `DL_Ln = Σ_j SizeFactor(Mj)`, `SizeFactor = #Files(Mj)/#AllFiles`, times
//! `(log5 #Files(Mj))^-1` when a module holds more than five files.
//!
//! # The one approximation, stated
//!
//! The paper's modules are Design Rule Hierarchy modules. Here a module is a
//! strongly connected component of the file graph, and an upper component's
//! lower layers are every file outside the upper components no deeper than it
//! (depth = how many files it reaches outside itself). Both choices keep the
//! paper's invariants: a dependent is always in a lower layer, so
//! `#Deps ≤ #LowerLayerFiles`, and the last layer is exactly the components with
//! no dependents. `figure_two_reproduces` checks the result against the paper's
//! own Figure 2 values before anything gates on it.

use std::collections::{BTreeMap, BTreeSet};

/// A file-level dependency graph: each file and the files it depends on.
pub type FileGraph = BTreeMap<String, BTreeSet<String>>;

/// The measures over one graph.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
#[non_exhaustive]
pub struct Coupling {
    /// M-score, 0 to 1 (Pisch, Cai, Kazman, Lefever, Fang, ESEM 2024). The
    /// measure a ratchet gates: DL's size penalty applies only in the lowest
    /// layer, so one isolated file can lift a large module's penalty, and a
    /// 1,252-project study found no significant correlation between DL and any
    /// maintenance activity (ICSE 2025), where M-score "correlated well with
    /// maintenance effort" over 1,220 releases.
    pub mscore: f64,
    /// Decoupling Level, 0 to 1 (Mo et al. 2016). Reported, never gated.
    pub decoupling_level: f64,
    /// Propagation cost: the mean share of files each file reaches, itself
    /// included (`MacCormack` et al.). Reported, never gated (see module docs).
    pub propagation_cost: f64,
    /// Files in the largest strongly connected component.
    pub largest_component: usize,
    /// Files in the graph.
    pub files: usize,
}

/// A Rust file's crate source root and top-level module: `a/src/x.rs` is
/// (`a/src/`, `x`), `a/src/x/y.rs` is (`a/src/`, `x`), `a/src/lib.rs` is
/// (`a/src/`, `lib`). Rust's own layout convention, so no consumer path is
/// named (rule 1). `None` for a path under no `src/`.
fn module_key(path: &str) -> Option<(&str, &str)> {
    let at = if path.starts_with("src/") {
        0
    } else {
        path.find("/src/")? + 1
    };
    let root = &path[..at + 4];
    let rest = &path[at + 4..];
    let first = rest.split('/').next()?;
    Some((root, first.strip_suffix(".rs").unwrap_or(first)))
}

/// The file graph a projected `uses` map describes.
///
/// `uses` is `input.tree.uses`: path -> resolved edges, each with `to` (a
/// module, after resolution) and `origin`. An `internal` edge from `f` to
/// module `m` becomes an edge from `f` to every declared file of `m` in the
/// same crate, so the graph is over files, as Decoupling Level counts them.
/// Every declared path is a node, even with no edge.
#[must_use]
pub fn file_graph(uses: &serde_json::Map<String, serde_json::Value>) -> FileGraph {
    let mut by_module: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for path in uses.keys() {
        if let Some(key) = module_key(path) {
            by_module.entry(key).or_default().push(path);
        }
    }
    let mut graph = FileGraph::new();
    for (path, edges) in uses {
        let node = graph.entry(path.clone()).or_default();
        let Some((root, own)) = module_key(path) else {
            continue;
        };
        for edge in edges.as_array().into_iter().flatten() {
            if edge.get("origin").and_then(serde_json::Value::as_str) != Some("internal") {
                continue;
            }
            let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if to == own {
                continue;
            }
            for target in by_module.get(&(root, to)).into_iter().flatten() {
                node.insert((*target).to_owned());
            }
        }
    }
    graph
}

/// Every file `from` reaches, itself included.
fn reach(graph: &FileGraph, from: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([from.to_owned()]);
    let mut queue = vec![from.to_owned()];
    while let Some(at) = queue.pop() {
        for next in graph.get(&at).into_iter().flatten() {
            if seen.insert(next.clone()) {
                queue.push(next.clone());
            }
        }
    }
    seen
}

/// Each file's reach, keyed by owned path so a member lookup cannot miss.
type Reaches = BTreeMap<String, BTreeSet<String>>;

/// A component's (size, dependents, depth): its file count, the files outside
/// it that reach it, and the files it reaches outside itself.
type Shape = (usize, usize, usize);

/// The measures over `graph`. An edge to a file the graph does not hold as a
/// key is still a file: the node set is the keys and every edge target.
#[must_use]
pub fn measure(graph: &FileGraph) -> Coupling {
    let files: BTreeSet<String> = graph
        .iter()
        .flat_map(|(from, to)| std::iter::once(from.clone()).chain(to.iter().cloned()))
        .collect();
    let all = files.len();
    if all == 0 {
        return Coupling {
            mscore: 1.0,
            decoupling_level: 1.0,
            propagation_cost: 0.0,
            largest_component: 0,
            files: 0,
        };
    }
    let reaches: Reaches = files
        .iter()
        .map(|file| (file.clone(), reach(graph, file)))
        .collect();
    let components = components_of(&files, &reaches);
    let shapes: Vec<Shape> = components
        .iter()
        .map(|component| shape_of(component, &files, &reaches))
        .collect();
    let propagation_cost =
        exact(reaches.values().map(BTreeSet::len).sum::<usize>()) / (exact(all) * exact(all));
    Coupling {
        mscore: mscore_of(graph, &components, &shapes, all),
        decoupling_level: decoupling_level_of(&shapes, all),
        propagation_cost,
        largest_component: components.iter().map(BTreeSet::len).max().unwrap_or(0),
        files: all,
    }
}

/// The strongly connected components: the files mutually reachable with each file.
fn components_of(files: &BTreeSet<String>, reaches: &Reaches) -> Vec<BTreeSet<String>> {
    let mut components: Vec<BTreeSet<String>> = Vec::new();
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    for file in files {
        if placed.contains(file.as_str()) {
            continue;
        }
        let component: BTreeSet<String> = reaches[file]
            .iter()
            .filter(|other| reaches.get(*other).is_some_and(|back| back.contains(file)))
            .cloned()
            .collect();
        for member in &component {
            if let Some(key) = files.get(member) {
                placed.insert(key);
            }
        }
        components.push(component);
    }
    components
}

/// A component's [`Shape`].
fn shape_of(component: &BTreeSet<String>, files: &BTreeSet<String>, reaches: &Reaches) -> Shape {
    let dependents = files
        .iter()
        .filter(|file| !component.contains(*file))
        .filter(|file| {
            component
                .iter()
                .any(|member| reaches[*file].contains(member))
        })
        .count();
    let depth = component
        .iter()
        .next()
        .and_then(|any| reaches.get(any))
        .map_or(0, |reached| {
            reached
                .iter()
                .filter(|other| !component.contains(*other))
                .count()
        });
    (component.len(), dependents, depth)
}

/// A count as a float, LOSSLESS BY CONSTRUCTION rather than by annotation, as
/// `pr_watch::interval_for` is (CLOUD-1338): narrowing to `u32` first makes the
/// conversion exact for every value that survives it, and saturating states the
/// bound in code. A graph of `u32::MAX` files was never going to be measured.
#[must_use]
pub fn exact(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

/// A component's share of all files.
fn weight(size: usize, all: usize) -> f64 {
    exact(size) / exact(all)
}

/// Decoupling Level (Mo et al. 2016, equations 2 to 5) over the components' shapes.
fn decoupling_level_of(shapes: &[Shape], all: usize) -> f64 {
    let mut level = 0.0;
    for &(size, deps, own_depth) in shapes {
        if deps == 0 {
            // Last layer: SizeFactor (equations 3 to 5).
            let penalty = if size > 5 {
                exact(size).log(5.0).recip()
            } else {
                1.0
            };
            level += weight(size, all) * penalty;
        } else {
            // Upper layer (equation 2). Lower layers: every file outside the
            // upper components no deeper than this one.
            let upper_not_lower: usize = shapes
                .iter()
                .filter(|(_, d, depth)| *d > 0 && *depth <= own_depth)
                .map(|(size, ..)| size)
                .sum();
            let lower = all - upper_not_lower;
            let ratio = if lower == 0 {
                1.0
            } else {
                exact(deps) / exact(lower)
            };
            level += weight(size, all) * (1.0 - ratio);
        }
    }
    level
}

/// M-score (ESEM 2024, formulas 1 to 7), on the same hierarchy: every module
/// of every layer contributes SF·CLDDF·IMCF. SF carries the size penalty in
/// EVERY layer (DL's lowest-layer-only penalty is the flaw it fixes); CLDDP is
/// the density of lower-layer files' edges into the module; IMCP the density
/// of the module's own internal edges (five files and up).
fn mscore_of(
    graph: &FileGraph,
    components: &[BTreeSet<String>],
    shapes: &[Shape],
    all: usize,
) -> f64 {
    let edges: Vec<(&String, &String)> = graph
        .iter()
        .flat_map(|(from, to)| to.iter().map(move |target| (from, target)))
        .filter(|(from, target)| from != target)
        .collect();
    let mut mscore = 0.0;
    for (component, &(size, deps, own_depth)) in components.iter().zip(shapes) {
        let penalty = if size >= 5 {
            exact(size).log(5.0).recip()
        } else {
            1.0
        };
        let cross = if deps == 0 {
            0.0
        } else {
            let upper: BTreeSet<&String> = components
                .iter()
                .zip(shapes)
                .filter(|(_, (_, d, depth))| *d > 0 && *depth <= own_depth)
                .flat_map(|(members, _)| members.iter())
                .collect();
            let lower = all - upper.len();
            let into = edges
                .iter()
                .filter(|(from, target)| component.contains(*target) && !upper.contains(from))
                .count();
            if lower == 0 {
                0.0
            } else {
                exact(into) / exact(lower * size)
            }
        };
        let inner = if size >= 5 {
            let internal = edges
                .iter()
                .filter(|(from, target)| component.contains(*from) && component.contains(*target))
                .count();
            exact(internal) / exact((size - 1) * size)
        } else {
            0.0
        };
        mscore += weight(size, all) * penalty * (1.0 - cross) * (1.0 - inner);
    }
    mscore
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Fails by: a component's depth counted over the members it reaches
    /// rather than the files outside it.
    #[test]
    fn a_components_depth_is_what_it_reaches_outside_itself() {
        let set = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        let component = set(&["a", "b"]);
        let files = set(&["a", "b", "c", "d"]);
        let reaches: Reaches = [
            (String::from("a"), set(&["b", "c", "d"])),
            (String::from("b"), set(&["a", "c", "d"])),
            (String::from("c"), set(&["d"])),
            (String::from("d"), set(&[])),
        ]
        .into();
        assert_eq!(shape_of(&component, &files, &reaches), (2, 0, 2));
    }

    /// `groups` clusters of `size` files, each cluster one cycle, no edges
    /// between clusters: the systems of the paper's Figure 2.
    fn clusters(groups: usize, size: usize) -> FileGraph {
        let mut graph = FileGraph::new();
        for group in 0..groups {
            for file in 0..size {
                let next = (file + 1) % size;
                graph
                    .entry(format!("g{group}f{file}"))
                    .or_default()
                    .insert(format!("g{group}f{next}"));
            }
        }
        graph
    }

    /// The paper's Figure 2, one layer of 100 files: 25 modules of 4 is 100%,
    /// 4 of 25 is 50%, 2 of 50 is 41%, 1 of 100 is 35%.
    #[test]
    fn figure_two_reproduces() {
        for (groups, size, expected) in
            [(25, 4, 1.00), (4, 25, 0.50), (2, 50, 0.41), (1, 100, 0.35)]
        {
            let measured = measure(&clusters(groups, size)).decoupling_level;
            assert!(
                (measured - expected).abs() < 0.01,
                "{groups} modules of {size} files: DL {measured:.3}, the paper says {expected}"
            );
        }
    }

    /// M-score's formula on graphs worked by hand. One 5-file cycle (5 internal
    /// edges of 20 possible): SF = 1·(1/log5 5) = 1, IMCF = 1 − 5/20 = 0.75.
    /// Eight singletons where `l0 -> u0` and `l1 -> u1`: `u0` and `u1` are upper
    /// modules whose lower layer is the other six files, one edge each of six
    /// possible, so each scores 1/8·(1 − 1/6); the six others score 1/8.
    #[test]
    fn mscore_matches_its_formula() {
        let five = measure(&clusters(1, 5)).mscore;
        assert!((five - 0.75).abs() < 1e-9, "5-file cycle: {five}");

        let mut graph = FileGraph::new();
        for module in ["u", "l"] {
            for file in 0..4 {
                graph.entry(format!("{module}{file}")).or_default();
            }
        }
        graph.get_mut("l0").expect("l0").insert("u0".to_owned());
        graph.get_mut("l1").expect("l1").insert("u1".to_owned());
        let expected = 2.0 * 0.125 * (1.0 - 1.0 / 6.0) + 6.0 * 0.125;
        let measured = measure(&graph).mscore;
        assert!(
            (measured - expected).abs() < 1e-9,
            "{measured} vs {expected}"
        );
    }

    /// The property M-score exists for: padding a tangle with isolated files
    /// cannot lift its size penalty. A 25-file cycle padded with 25 isolated
    /// files scores below 50 files in independent 5-file modules, and the
    /// padding moves the score by less than DL's lowest-layer-only penalty would
    /// let a real decoupling move it.
    #[test]
    fn padding_a_tangle_does_not_lift_its_size_penalty() {
        let tangle = clusters(1, 25);
        let mut padded = tangle.clone();
        for pad in 0..25 {
            padded.entry(format!("pad{pad}")).or_default();
        }
        let split = clusters(10, 5);
        assert!(measure(&padded).mscore < measure(&split).mscore);
        assert!(measure(&tangle).mscore < measure(&split).mscore);
    }

    /// A design rule many files depend on lowers DL; the same files independent
    /// raise it. Fails if dependents are not counted.
    #[test]
    fn a_depended_upon_module_lowers_the_level() {
        let mut star = FileGraph::new();
        for client in 0..4 {
            star.entry(format!("c{client}"))
                .or_default()
                .insert("rule".to_owned());
        }
        let mut apart = FileGraph::new();
        for file in ["c0", "c1", "c2", "c3", "rule"] {
            apart.entry(file.to_owned()).or_default();
        }
        let star = measure(&star);
        let apart = measure(&apart);
        assert!(
            star.decoupling_level < apart.decoupling_level,
            "{star:?} vs {apart:?}"
        );
        assert_eq!(star.largest_component, 1);
    }

    /// A `uses` edge onto a module reaches every file of that module in the same
    /// crate and none in another; a non-internal edge reaches nothing.
    #[test]
    fn an_edge_onto_a_module_reaches_its_files_in_its_crate() {
        let uses = serde_json::json!({
            "a/src/x.rs": [{"to": "y", "origin": "internal"}, {"to": "serde", "origin": "external"}],
            "a/src/y/mod.rs": [],
            "a/src/y/z.rs": [],
            "b/src/y.rs": [],
        });
        let graph = file_graph(uses.as_object().expect("an object"));
        let reached: Vec<&str> = graph["a/src/x.rs"].iter().map(String::as_str).collect();
        assert_eq!(reached, ["a/src/y/mod.rs", "a/src/y/z.rs"]);
        assert_eq!(graph.len(), 4, "every declared path is a node");
    }

    /// Adding an unconnected file lowers propagation cost (the sensitivity the
    /// paper names) but cannot raise a tangled system's DL above an untangled one.
    #[test]
    fn padding_lowers_propagation_cost_not_the_tangle() {
        let tangled = clusters(1, 10);
        let mut padded = tangled.clone();
        for pad in 0..10 {
            padded.entry(format!("pad{pad}")).or_default();
        }
        assert!(measure(&padded).propagation_cost < measure(&tangled).propagation_cost);
        assert!(measure(&padded).decoupling_level < measure(&clusters(5, 4)).decoupling_level);
    }

    /// Equation 2 worked by hand on an uneven hierarchy: a lowest layer of 3
    /// files (1 · 3/4) under one upper file depended on once, whose lower layer
    /// is the 3 files outside it (1/4 · (1 − 1/3)). Fails by: the upper set
    /// read as the lowest layer's components, the lower layer added to rather
    /// than subtracted from, or the ratio multiplied.
    #[test]
    fn decoupling_level_matches_equation_two_on_an_uneven_hierarchy() {
        let level = decoupling_level_of(&[(3, 0, 0), (1, 1, 1)], 4);
        let expected = 0.75 + 0.25 * (1.0 - 1.0 / 3.0);
        assert!((level - expected).abs() < 1e-9, "{level} vs {expected}");
    }

    /// A 5-file cycle with one edge out to `x`: the cycle's own 5 internal
    /// edges of 20 possible give IMCF 0.75, so it scores 5/6 · 0.75, and `x`
    /// scores 1/6 · (1 − 1/5). Fails by: the edge leaving the cycle counted
    /// as one of its internal edges.
    #[test]
    fn an_edge_leaving_a_module_is_not_internal_to_it() {
        let mut graph = clusters(1, 5);
        graph.get_mut("g0f0").expect("g0f0").insert("x".to_owned());
        let expected = 5.0 / 6.0 * 0.75 + 1.0 / 6.0 * (1.0 - 1.0 / 5.0);
        let measured = measure(&graph).mscore;
        assert!(
            (measured - expected).abs() < 1e-9,
            "{measured} vs {expected}"
        );
    }
}
