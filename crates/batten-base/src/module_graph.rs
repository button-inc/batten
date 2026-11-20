//! The module graph of a crate's source, and its largest strongly connected
//! component (CLOUD-2789).
//!
//! WHY A COMPONENT, NOT A FAN-OUT. A workspace crate must be a
//! dependency-closed set of modules: nothing in it may name the crate it was
//! cut from. While one strongly connected component spans most of the crate,
//! every such set is the whole crate, so no cut exists and per-package clippy,
//! cross-check and darwin-link buy nothing. The component's size is the one
//! number that says how far that is from true, and a gate holds it from growing.
//!
//! WHAT AN EDGE IS, read off the lossless syntax tree `codemod` uses, never a
//! text scan (a scan counted doc comments and test code, and could not see
//! `use crate::{a, b}`):
//!
//! - a node is a top-level module of the root (`<m>.rs` or `<m>/`, its
//!   submodules rolled up into it), plus [`LIB`] for the items `lib.rs` itself
//!   defines;
//! - `a → b` when `a`'s non-test code names `crate::b…`, a `use crate::{…}`
//!   group member `b`, or a `super::…` chain that climbs to the root and then
//!   names `b`; in `lib.rs` a path whose first segment is a module also counts;
//! - `a → lib` when such a path names an item `lib.rs` defines;
//! - a name that is neither (a re-exported external crate, `pub use
//!   batten_fsio as fsio`) is no node and no edge;
//! - `#[cfg(test)]` items are not read: the graph is the library's.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ra_ap_syntax::ast::{HasAttrs as _, HasModuleItem as _, HasName as _};
use ra_ap_syntax::{AstNode as _, SourceFile, SyntaxKind, SyntaxNode, ast};

use crate::codemod::CouldNotLook;

/// The node standing for the items `lib.rs` defines.
pub const LIB: &str = "lib";

/// A module graph: every node, and each node's distinct successors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Graph {
    /// Each node and the nodes it names.
    pub edges: BTreeMap<String, BTreeSet<String>>,
}

impl Graph {
    /// The node count of the largest strongly connected component (Tarjan),
    /// 0 for an empty graph. A node in no cycle is a component of one.
    #[must_use]
    pub fn largest_component(&self) -> usize {
        let nodes: Vec<&str> = self.edges.keys().map(String::as_str).collect();
        let at: BTreeMap<&str, usize> = nodes.iter().enumerate().map(|(i, n)| (*n, i)).collect();
        let succ: Vec<Vec<usize>> = nodes
            .iter()
            .map(|node| {
                self.edges[*node]
                    .iter()
                    .filter_map(|next| at.get(next.as_str()).copied())
                    .collect()
            })
            .collect();
        let mut tarjan = Tarjan::new(nodes.len());
        for start in 0..nodes.len() {
            if tarjan.index[start].is_none() {
                tarjan.visit(start, &succ);
            }
        }
        tarjan.largest
    }
}

/// Tarjan's algorithm, iterative so a deep chain cannot overflow the stack.
struct Tarjan {
    index: Vec<Option<usize>>,
    low: Vec<usize>,
    on_stack: Vec<bool>,
    stack: Vec<usize>,
    next: usize,
    largest: usize,
}

impl Tarjan {
    fn new(n: usize) -> Self {
        Self {
            index: vec![None; n],
            low: vec![0; n],
            on_stack: vec![false; n],
            stack: Vec::new(),
            next: 0,
            largest: 0,
        }
    }

    fn open(&mut self, node: usize) {
        self.index[node] = Some(self.next);
        self.low[node] = self.next;
        self.next += 1;
        self.stack.push(node);
        self.on_stack[node] = true;
    }

    fn visit(&mut self, start: usize, succ: &[Vec<usize>]) {
        // Each frame: the node and how many of its successors it has walked.
        let mut frames: Vec<(usize, usize)> = vec![(start, 0)];
        self.open(start);
        while let Some(&mut (node, ref mut walked)) = frames.last_mut() {
            if let Some(&next) = succ[node].get(*walked) {
                *walked += 1;
                match self.index[next] {
                    None => {
                        self.open(next);
                        frames.push((next, 0));
                    }
                    Some(seen) if self.on_stack[next] => {
                        self.low[node] = self.low[node].min(seen);
                    }
                    Some(_) => {}
                }
                continue;
            }
            frames.pop();
            if let Some(&(parent, _)) = frames.last() {
                self.low[parent] = self.low[parent].min(self.low[node]);
            }
            if Some(self.low[node]) == self.index[node] {
                let mut size = 0;
                while let Some(member) = self.stack.pop() {
                    self.on_stack[member] = false;
                    size += 1;
                    if member == node {
                        break;
                    }
                }
                self.largest = self.largest.max(size);
            }
        }
    }
}

/// Read the graph of the crate whose source root is `root` (the directory
/// holding `lib.rs`).
///
/// # Errors
///
/// A directory or file cannot be read, or a file does not parse
/// ([`CouldNotLook`], which names nothing: the caller names the file).
pub fn read(root: &Path) -> anyhow::Result<Graph> {
    let mut modules: BTreeSet<String> = BTreeSet::new();
    let mut files: Vec<(String, Vec<String>, std::path::PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
            continue;
        };
        if path.is_dir() {
            modules.insert(stem.clone());
            for file in rust_files(&path)? {
                let below = file.strip_prefix(&path).unwrap_or(&file);
                let mut module = vec![stem.clone()];
                module.extend(module_path(below));
                files.push((stem.clone(), module, file));
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            if stem == "lib" {
                files.push((LIB.to_owned(), Vec::new(), path));
            } else if stem != "main" {
                modules.insert(stem.clone());
                files.push((stem.clone(), vec![stem], path));
            }
        }
    }
    let lib_source = crate::fsio::read_to_string(root.join("lib.rs")).unwrap_or_default();
    let lib_items = lib_items(&lib_source)?;
    let mut graph = Graph::default();
    graph.edges.insert(LIB.to_owned(), BTreeSet::new());
    for module in &modules {
        graph.edges.insert(module.clone(), BTreeSet::new());
    }
    for (node, module, file) in files {
        let source = crate::fsio::read_to_string(&file)?;
        for name in
            root_names(&source, &module).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?
        {
            let target = if modules.contains(&name) {
                name
            } else if lib_items.contains(&name) {
                LIB.to_owned()
            } else {
                continue;
            };
            if target != node {
                graph.edges.entry(node.clone()).or_default().insert(target);
            }
        }
    }
    Ok(graph)
}

/// `modules cycle`: print the largest component's size, and refuse (exit 2,
/// the verdict) when it holds more than `max` modules.
///
/// One line on `out`, `modules cycle: <n> module(s) in the largest component`,
/// a count and never the members (rule 4). `max` that is not a non-negative
/// integer is a usage error (1); a root that cannot be read or a file that
/// does not parse is could-not-look (3), with its reason on `err`.
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_cycle(
    root: &Path,
    max: Option<&str>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::exit::ExitCode> {
    use crate::exit::ExitCode;
    let max = match max.map(str::parse::<usize>) {
        None => None,
        Some(Ok(max)) => Some(max),
        Some(Err(_)) => {
            writeln!(err, "modules cycle: --max takes a non-negative integer")?;
            return Ok(ExitCode::Usage);
        }
    };
    let graph = match read(root) {
        Ok(graph) => graph,
        Err(reason) => {
            writeln!(
                err,
                "modules cycle: could not read the module graph: {reason}"
            )?;
            return Ok(ExitCode::Internal);
        }
    };
    let largest = graph.largest_component();
    writeln!(
        out,
        "modules cycle: {largest} module(s) in the largest component"
    )?;
    if let Some(max) = max.filter(|max| largest > *max) {
        writeln!(
            err,
            "modules cycle: {largest} is more than the committed {max}; break a cycle rather than grow one"
        )?;
        return Ok(ExitCode::Violation);
    }
    Ok(ExitCode::Success)
}

/// Every `.rs` file under `dir`, sorted.
fn rust_files(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The module path a file below its top-level directory stands for:
/// `schema.rs` is `["schema"]`, `mod.rs` and `a/mod.rs` drop the `mod`.
fn module_path(below: &Path) -> Vec<String> {
    let mut parts: Vec<String> = below
        .with_extension("")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.last().is_some_and(|last| last == "mod") {
        parts.pop();
    }
    parts
}

/// The names of the items `lib.rs` defines at its top level: functions,
/// types, traits, constants, statics and macros, never a `mod` or a `use`.
///
/// # Errors
///
/// [`CouldNotLook`] when the source does not parse.
pub fn lib_items(source: &str) -> Result<BTreeSet<String>, CouldNotLook> {
    let file = parse(source)?;
    Ok(file
        .items()
        .filter(|item| !matches!(item, ast::Item::Module(_) | ast::Item::Use(_)))
        .filter(|item| !cfg_test(item.syntax()))
        .filter_map(|item| match item {
            ast::Item::Fn(it) => it.name(),
            ast::Item::Struct(it) => it.name(),
            ast::Item::Enum(it) => it.name(),
            ast::Item::Union(it) => it.name(),
            ast::Item::Trait(it) => it.name(),
            ast::Item::TypeAlias(it) => it.name(),
            ast::Item::Const(it) => it.name(),
            ast::Item::Static(it) => it.name(),
            ast::Item::MacroRules(it) => it.name(),
            _ => None,
        })
        .map(|name| name.text().to_string())
        .collect())
}

/// Every name a file at module path `module` reaches at the crate root, from
/// its non-test code: `crate::name…`, `use crate::{name, …}`, a `super::` chain
/// that climbs to the root and then names `name`, and — in the root file
/// itself (`module` empty) — any path's first segment.
///
/// # Errors
///
/// [`CouldNotLook`] when the source does not parse.
pub fn root_names(source: &str, module: &[String]) -> Result<BTreeSet<String>, CouldNotLook> {
    let file = parse(source)?;
    let mut names = BTreeSet::new();
    for node in file.syntax().descendants() {
        if let Some(path) = ast::Path::cast(node.clone()) {
            // Only a path's outermost form is read: its qualifier paths are
            // descendants of it too, and would read again.
            if path
                .syntax()
                .parent()
                .is_some_and(|p| p.kind() == SyntaxKind::PATH)
            {
                continue;
            }
            if cfg_test(path.syntax()) {
                continue;
            }
            if let Some(name) = from_root(&segments(&path), module) {
                names.insert(name);
            }
        } else if let Some(tree) = ast::UseTree::cast(node) {
            // `use crate::{a, b}`: the group's members name the root.
            let (Some(path), Some(list)) = (tree.path(), tree.use_tree_list()) else {
                continue;
            };
            if cfg_test(tree.syntax()) {
                continue;
            }
            let prefix = segments(&path);
            if !reaches_root(&prefix, module) || prefix.len() != root_depth(&prefix) {
                continue;
            }
            for member in list.use_trees() {
                if let Some(first) = member
                    .path()
                    .as_ref()
                    .map(segments)
                    .and_then(|s| s.into_iter().next())
                    && first != "self"
                {
                    names.insert(first);
                }
            }
        }
    }
    Ok(names)
}

/// The written segments of `path`, outermost qualifier first.
fn segments(path: &ast::Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut at = Some(path.clone());
    while let Some(path) = at {
        if let Some(segment) = path.segment() {
            out.push(
                segment
                    .syntax()
                    .text()
                    .to_string()
                    .split('<')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned(),
            );
        }
        at = path.qualifier();
    }
    out.reverse();
    out
}

/// How many leading segments of `segments` climb to the root: `crate` is one;
/// a `super` chain is its length.
fn root_depth(segments: &[String]) -> usize {
    match segments.first().map(String::as_str) {
        Some("crate") => 1,
        _ => segments.iter().take_while(|s| *s == "super").count(),
    }
}

/// Whether the leading `crate` or `super` chain of `segments`, read from a
/// file at `module`, ends at the crate root.
fn reaches_root(segments: &[String], module: &[String]) -> bool {
    match segments.first().map(String::as_str) {
        Some("crate") => true,
        Some("super") => root_depth(segments) == module.len(),
        _ => module.is_empty(),
    }
}

/// The root-level name `segments` reaches from a file at `module`, if any.
fn from_root(segments: &[String], module: &[String]) -> Option<String> {
    match segments.first().map(String::as_str)? {
        "crate" | "super" => {
            if !reaches_root(segments, module) {
                return None;
            }
            segments.get(root_depth(segments)).cloned()
        }
        // In the root file a bare path's first segment is a root name; a
        // single-segment path is a local, a type or a function call, which
        // the caller's filter keeps only when it names a module or lib item.
        _ if module.is_empty() && segments.len() > 1 => segments.first().cloned(),
        _ => None,
    }
}

/// Whether `node` sits inside an item carrying `#[cfg(test)]`.
fn cfg_test(node: &SyntaxNode) -> bool {
    node.ancestors().any(|ancestor| {
        ast::AnyHasAttrs::cast(ancestor).is_some_and(|item| {
            item.attrs().any(|attr| {
                let text: String = attr
                    .syntax()
                    .text()
                    .to_string()
                    .split_whitespace()
                    .collect();
                text == "#[cfg(test)]"
            })
        })
    })
}

fn parse(source: &str) -> Result<SourceFile, CouldNotLook> {
    let parse = SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024);
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    Ok(parse.tree())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &[&str])]) -> Graph {
        Graph {
            edges: edges
                .iter()
                .map(|(from, to)| {
                    (
                        (*from).to_owned(),
                        to.iter().map(|t| (*t).to_owned()).collect(),
                    )
                })
                .collect(),
        }
    }

    fn names(source: &str, module: &[&str]) -> Vec<String> {
        let module: Vec<String> = module.iter().map(|m| (*m).to_owned()).collect();
        root_names(source, &module).unwrap().into_iter().collect()
    }

    /// Fails by: a back edge not closing the component, or each node counted
    /// as its own component.
    #[test]
    fn a_two_module_cycle_is_one_component_of_two() {
        let g = graph(&[("a", &["b"]), ("b", &["a"]), ("c", &["a"])]);
        assert_eq!(g.largest_component(), 2);
    }

    /// Fails by: a chain read as a cycle, or a largest of 0 for a graph with nodes.
    #[test]
    fn a_chain_has_no_component_above_one() {
        let g = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &[])]);
        assert_eq!(g.largest_component(), 1);
        assert_eq!(Graph::default().largest_component(), 0);
    }

    /// Two cycles joined one way stay two components; the larger is counted.
    #[test]
    fn the_largest_of_two_components_is_counted() {
        let g = graph(&[
            ("a", &["b"]),
            ("b", &["c"]),
            ("c", &["a", "d"]),
            ("d", &["e"]),
            ("e", &["d"]),
        ]);
        assert_eq!(g.largest_component(), 3);
    }

    /// Fails by: a name with no node kept as an edge target.
    #[test]
    fn a_reference_to_a_missing_module_is_not_an_edge() {
        let g = graph(&[("a", &["ghost"]), ("ghost2", &[])]);
        assert_eq!(g.largest_component(), 1);
    }

    /// Fails by: a `use` group read as one name, or `self` kept.
    #[test]
    fn a_use_group_names_each_member() {
        let got = names(
            "use crate::{git, hook::Thing, self};\nfn f() {}\n",
            &["step"],
        );
        assert_eq!(got, ["git", "hook"]);
    }

    /// Fails by: test code or a doc comment read as an edge.
    #[test]
    fn a_cfg_test_path_is_not_an_edge() {
        let source = "/// See [`crate::doc_only`].\nfn f() { crate::git::x(); }\n\
                      #[cfg(test)]\nmod tests { fn t() { crate::fixture::y(); } }\n";
        assert_eq!(names(source, &["step"]), ["git"]);
    }

    /// Fails by: a `super` chain that stops short of the root read as a root
    /// name, or one that reaches it missed.
    #[test]
    fn a_super_chain_counts_only_when_it_reaches_the_root() {
        let source = "fn f() { super::sibling::x(); super::super::git::y(); }\n";
        assert_eq!(names(source, &["mutate", "schema"]), ["git"]);
        assert_eq!(names("fn f() { super::git::y(); }\n", &["step"]), ["git"]);
    }

    /// Fails by: a lib item not collected, or a `mod`/`use` taken as one.
    #[test]
    fn a_lib_item_is_an_edge_to_lib() {
        let lib = "mod git;\npub use batten_fsio as fsio;\npub fn helper() {}\n\
                   pub struct Thing;\n#[cfg(test)]\nfn only_in_tests() {}\n";
        let items: Vec<String> = lib_items(lib).unwrap().into_iter().collect();
        assert_eq!(items, ["Thing", "helper"]);
        let dir = crate::scratch::scratch("module-graph-lib");
        std::fs::write(
            dir.join("lib.rs"),
            format!("{lib}fn root() {{ git::x(); }}\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("git.rs"),
            "fn x() { crate::helper(); crate::fsio::read(); }\n",
        )
        .unwrap();
        let g = read(&dir).unwrap();
        assert_eq!(g.edges["git"], BTreeSet::from([LIB.to_owned()]));
        assert_eq!(g.edges[LIB], BTreeSet::from([String::from("git")]));
        assert_eq!(g.largest_component(), 2);
    }

    /// A directory module's files roll up into it.
    #[test]
    fn a_directory_module_rolls_up_its_files() {
        let dir = crate::scratch::scratch("module-graph-dir");
        std::fs::write(dir.join("lib.rs"), "mod m;\nmod git;\n").unwrap();
        std::fs::write(dir.join("git.rs"), "fn x() { crate::m::y(); }\n").unwrap();
        std::fs::create_dir_all(dir.join("m")).unwrap();
        std::fs::write(dir.join("m/mod.rs"), "mod inner;\n").unwrap();
        std::fs::write(
            dir.join("m/inner.rs"),
            "fn y() { super::super::git::x(); }\n",
        )
        .unwrap();
        let g = read(&dir).unwrap();
        assert_eq!(g.edges["m"], BTreeSet::from([String::from("git")]));
        assert_eq!(g.largest_component(), 2);
    }
}
