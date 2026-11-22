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

use ra_ap_syntax::ast::{HasAttrs as _, HasModuleItem as _, HasName as _, HasVisibility as _};
use std::fmt::Write as _;

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

    /// Every node each node reaches by one or more edges.
    fn reach(&self) -> BTreeMap<&str, BTreeSet<&str>> {
        self.edges
            .keys()
            .map(|start| {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                let mut queue: Vec<&str> = self.successors(start).collect();
                while let Some(node) = queue.pop() {
                    if seen.insert(node) {
                        queue.extend(self.successors(node));
                    }
                }
                (start.as_str(), seen)
            })
            .collect()
    }

    fn successors<'a>(&'a self, node: &str) -> impl Iterator<Item = &'a str> {
        self.edges
            .get(node)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .filter(|next| self.edges.contains_key(*next))
    }

    /// `MacCormack`, Rusnak & Baldwin's propagation cost (Management Science,
    /// 2006): the share of (node, node) pairs where the first reaches the
    /// second, each node counted as reaching itself, in percent. The cycle's
    /// size says how many modules are tangled; this says how far a change in
    /// any one of them can travel.
    #[must_use]
    pub fn propagation_cost(&self) -> f64 {
        let nodes = self.edges.len();
        if nodes == 0 {
            return 0.0;
        }
        let reached: usize = self
            .reach()
            .iter()
            .map(|(node, seen)| seen.len() + usize::from(!seen.contains(node)))
            .sum();
        #[expect(
            clippy::cast_precision_loss,
            reason = "a module count is far below 2^52, so the ratio is exact enough for a percentage"
        )]
        let share = reached as f64 / (nodes * nodes) as f64;
        share * 100.0
    }

    /// Lakos's levelization (*Large-Scale C++ Software Design*, 1996): a
    /// node reaching nothing outside its own cycle is level 1, and any other
    /// is one above the highest level it reaches. Every member of a cycle
    /// shares one level, which is why a cycle is the thing to break.
    #[must_use]
    pub fn levels(&self) -> BTreeMap<String, usize> {
        let reach = self.reach();
        let tangled = |a: &str, b: &str| reach[a].contains(b) && reach[b].contains(a);
        // A node reached from another outside its cycle reaches strictly
        // less, so ascending reach size orders every node after what it needs.
        let mut order: Vec<&str> = reach.keys().copied().collect();
        order.sort_by_key(|node| reach[node].len());
        let mut level: BTreeMap<&str, usize> = BTreeMap::new();
        for node in order {
            let below = reach[node]
                .iter()
                .filter(|next| **next != node && !tangled(node, next))
                .filter_map(|next| level.get(next))
                .max()
                .copied()
                .unwrap_or(0);
            level.insert(node, below + 1);
        }
        level
            .into_iter()
            .map(|(node, at)| (node.to_owned(), at))
            .collect()
    }

    /// Every edge inside the largest component, each with that component's
    /// size once the edge alone is gone, smallest first: Shah et al.'s
    /// ranking of dependency-breaking moves (CSMR 2012, ICSM 2013) at module
    /// granularity. An edge whose removal shrinks the cycle is the one move
    /// that pays; one that leaves it unchanged has a parallel path.
    #[must_use]
    pub fn cut_ranking(&self) -> Vec<(String, String, usize)> {
        let reach = self.reach();
        let largest = self.largest_component();
        let members: BTreeSet<&str> = reach
            .keys()
            .copied()
            .filter(|node| {
                reach[node]
                    .iter()
                    .filter(|other| reach[*other].contains(node))
                    .count()
                    == largest
            })
            .collect();
        let mut ranked: Vec<(String, String, usize)> = members
            .iter()
            .flat_map(|from| {
                self.successors(from)
                    .filter(|to| members.contains(to))
                    .map(move |to| (*from, to))
            })
            .map(|(from, to)| {
                let mut cut = self.clone();
                if let Some(next) = cut.edges.get_mut(from) {
                    next.remove(to);
                }
                (from.to_owned(), to.to_owned(), cut.largest_component())
            })
            .collect();
        ranked.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| (&a.0, &a.1).cmp(&(&b.0, &b.1))));
        ranked
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
    let (modules, files) = sources(root)?;
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

/// The top-level modules under `root`, and every library source file with its
/// graph node and module path. ONE WALK for the graph and both censuses, so
/// they can never disagree about which files are the crate.
type Sources = (
    BTreeSet<String>,
    Vec<(String, Vec<String>, std::path::PathBuf)>,
);

fn sources(root: &Path) -> anyhow::Result<Sources> {
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
    Ok((modules, files))
}

/// How many inherent impls sit away from their type (CLOUD-2792).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImplCensus {
    /// Impls whose self type resolves to a declaration in another top-level
    /// module.
    pub outside: usize,
    /// Impls of a type declared in this tree whose declaring module the
    /// census could not resolve (a glob import, a path it does not read):
    /// counted, so an unread impl cannot hide.
    pub ambiguous: usize,
}

/// Count every `impl T { … }` with no trait, outside test code, whose `T`
/// does not resolve to a declaration in the impl's own top-level module.
///
/// `T` is the self type, references stripped and generic arguments dropped,
/// RESOLVED the way the file reads it, not matched by name: a name its own
/// file declares is home; otherwise the file's `use` leaf for it, or the
/// path as written, names the module (`crate::`, `self::`, `super::`, or in
/// the crate root a child module), and a landing on a crate-root re-export
/// follows it once. Matching by name alone counted every impl of a name two
/// modules both declare (a private `Entry` in each) as having no home: 153
/// of the first 193.
///
/// A type declared nowhere in the tree is foreign, which Rust gives no
/// inherent impl, so it is not counted.
///
/// # Errors
///
/// The root cannot be read, or a file does not parse.
pub fn impl_census(root: &Path) -> anyhow::Result<ImplCensus> {
    let parsed = parsed_sources(root)?;
    let mut census = ImplCensus::default();
    for site in impl_sites(&parsed).sites {
        match site.home {
            Some(home) if home == parsed[site.file].0 => {}
            Some(_) => census.outside += 1,
            None => census.ambiguous += 1,
        }
    }
    Ok(census)
}

/// One inherent impl outside test code, of a type this tree declares.
struct ImplSite {
    /// Index of its file in the parsed sources.
    file: usize,
    found: ast::Impl,
    /// Its self type's name.
    name: String,
    /// The top-level module declaring that type, or `None` unresolved.
    home: Option<String>,
}

/// Every [`ImplSite`], and each file's declared type names.
struct Sites {
    sites: Vec<ImplSite>,
    declared: Vec<BTreeSet<String>>,
}

/// THE ONE WALK the census and the move recipe share, so the gate and the
/// rewrite cannot disagree about which impl is outside.
fn impl_sites(parsed: &[(String, Vec<String>, SourceFile)]) -> Sites {
    let modules: BTreeSet<String> = parsed
        .iter()
        .map(|(node, _, _)| node.clone())
        .filter(|node| node != LIB)
        .collect();
    let mut homes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let declared: Vec<BTreeSet<String>> = parsed
        .iter()
        .map(|(node, _, tree)| {
            let names: BTreeSet<String> = tree
                .syntax()
                .descendants()
                .filter(|syntax| !cfg_test(syntax))
                .filter_map(|syntax| match_ast_name(&syntax))
                .collect();
            for name in &names {
                homes.entry(name.clone()).or_default().insert(node.clone());
            }
            names
        })
        .collect();
    let lib_aliases = parsed
        .iter()
        .find(|(node, _, _)| node == LIB)
        .map(|(_, _, tree)| top_level_aliases(tree))
        .unwrap_or_default();
    let resolver = Resolver {
        modules: &modules,
        homes: &homes,
        lib_aliases: &lib_aliases,
    };
    let mut sites = Vec::new();
    for (file, ((node, module, tree), names)) in parsed.iter().zip(&declared).enumerate() {
        let aliases = top_level_aliases(tree);
        for found in tree.syntax().descendants().filter_map(ast::Impl::cast) {
            if found.trait_().is_some() || cfg_test(found.syntax()) {
                continue;
            }
            let Some(path) = self_type_path(&found) else {
                continue;
            };
            let Some(name) = path.last().filter(|name| homes.contains_key(*name)) else {
                continue;
            };
            // Read where the impl sits: inside inline modules, their own `use`
            // items come first and `self::`/`super::` are theirs.
            let (at, local) = enclosing_scope(&found, module, name);
            let home = if path.len() == 1 && names.contains(name) {
                Some(node.clone())
            } else if path.len() == 1 {
                local
                    .or_else(|| aliases.get(name).cloned())
                    .and_then(|target| resolver.node_of(&target, &at, 2))
            } else {
                resolver.node_of(&path, &at, 2)
            };
            sites.push(ImplSite {
                file,
                found,
                name: name.clone(),
                home,
            });
        }
    }
    Sites { sites, declared }
}

/// Every file of `files` that changes, or is created, when a module file
/// made only of inline modules is split: each `mod name { … }` becomes its
/// own file beside it (`x.rs` gives `x/name.rs`; a `mod.rs`, `lib.rs` or
/// `main.rs` gives `name.rs` in its directory), its body dedented one level,
/// and its declaration stays as `mod name;` with its docs and attributes.
/// Module paths are unchanged, so every `super::` and every caller still
/// resolves.
///
/// ONLY A FILE THAT IS NOTHING BUT INLINE MODULES (and `use` items), with
/// two or more of them: a file that groups modules in one text. A test
/// module, a `#[path]` module, or a target that already exists leaves the
/// file whole. Measured: `config_check.rs`, 23 inline modules over 5,600
/// lines, whose impls the extension-trait recipe could not reach
/// (CLOUD-2793).
#[must_use]
pub fn split_inline_modules(files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (path, text) in files {
        if let Some(split) = split_one(path, text, files) {
            out.extend(split);
        }
    }
    out
}

/// [`split_inline_modules`] for one file, or `None` when it does not qualify.
fn split_one(
    path: &str,
    text: &str,
    files: &BTreeMap<String, String>,
) -> Option<BTreeMap<String, String>> {
    let dir = match path.rsplit_once('/') {
        Some((parent, "mod.rs" | "lib.rs" | "main.rs")) => format!("{parent}/"),
        _ => format!("{}/", path.strip_suffix(".rs")?),
    };
    let tree = parse(text).ok()?;
    let items: Vec<ast::Item> = tree.items().collect();
    if !items
        .iter()
        .all(|item| matches!(item, ast::Item::Module(_) | ast::Item::Use(_)))
    {
        return None;
    }
    let inline: Vec<ast::Module> = items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Module(module) if module.item_list().is_some() => Some(module.clone()),
            _ => None,
        })
        .collect();
    let guarded = inline.iter().any(|module| {
        cfg_test(module.syntax())
            || module
                .attrs()
                .any(|attribute| attribute.syntax().text().to_string().contains("path"))
    });
    if inline.len() < 2 || guarded {
        return None;
    }
    let mut out = BTreeMap::new();
    let mut parent = text.to_owned();
    for module in inline.iter().rev() {
        let name = module.name()?.text().to_string();
        let list = module.item_list()?.syntax().text_range();
        let (open, close) = (usize::from(list.start()), usize::from(list.end()));
        let child = format!("{dir}{name}.rs");
        if files.contains_key(&child) {
            return None;
        }
        out.insert(child, dedent(&text[open + 1..close - 1]));
        // From the end of the name to the closing brace becomes `;`.
        let after_name = usize::from(module.name()?.syntax().text_range().end());
        parent.replace_range(after_name..close, ";");
    }
    out.insert(path.to_owned(), parent);
    Some(out)
}

/// A module body moved to its own file: one level of indentation removed,
/// leading blank lines dropped, ending in one newline.
fn dedent(body: &str) -> String {
    let lines: Vec<&str> = body
        .lines()
        .map(|line| {
            line.strip_prefix("    ")
                .unwrap_or(if line.trim().is_empty() { "" } else { line })
        })
        .skip_while(|line| line.is_empty())
        .collect();
    let mut out = lines.join("\n").trim_end().to_owned();
    out.push('\n');
    out
}

/// The files of `files` under `src` that parse, as their keys and their
/// `(node, module, tree)`, index for index.
/// Each parsed file as `(node, module path, tree)`, index for index with its key.
type Parsed = Vec<(String, Vec<String>, SourceFile)>;

/// The `use` lines owed per `(file, insertion point)`: each path, and whether it
/// is gated `#[cfg(test)]`.
type Imports = BTreeMap<(String, Option<usize>), BTreeSet<(String, bool)>>;

fn parse_src(src: &str, files: &BTreeMap<String, String>) -> (Vec<String>, Parsed) {
    let prefix = format!("{}/", src.trim_end_matches('/'));
    let mut keys = Vec::new();
    let mut parsed = Vec::new();
    for (key, text) in files {
        let Some(below) = key.strip_prefix(&prefix) else {
            continue;
        };
        let (Some((node, module)), Ok(tree)) = (locate(below), parse(text)) else {
            continue;
        };
        keys.push(key.clone());
        parsed.push((node, module, tree));
    }
    (keys, parsed)
}

/// Every file of `files` that changes when each type's inherent impls that
/// sit outside its type's top-level module, in one file, become that file's
/// extension trait (CLOUD-2793's `impl-to-extension-trait`). `src` is a
/// crate's source directory and `krate` its name, used to import the trait
/// from outside `src`.
///
/// BEHAVIOUR STAYS IN ITS LAYER. These impls are a higher layer's logic over
/// a lower layer's type: moving them home inverts the layering (measured: 155
/// errors). `impl T { … }` becomes `trait TExt { signatures }` plus
/// `impl TExt for T { … }`, legal under the orphan rule because the trait is
/// local, so every call keeps its method syntax and gains one import.
///
/// Per item: a method's signature, doc comments and `#[must_use]` go to the
/// trait, its other attributes and body stay in the impl, and visibility is
/// dropped (a trait item has its trait's). An associated const splits the
/// same way. The trait is `pub` when any item was `pub`, else `pub(crate)`.
/// An empty impl is deleted. A group holding anything else (a macro call) is
/// left as written, so the gate still counts it.
///
/// Every other file that calls one of the trait's items by name gets
/// `use …::TExt as _;`, gated `#[cfg(test)]` where only test code calls it;
/// `cargo fix` drops the ones a same-named method elsewhere made spurious.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one pass over one parse: group, declare, import, rewrite; split it when a second caller needs a stage"
)]
pub fn impls_to_extension_traits(
    src: &str,
    krate: &str,
    files: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let (keys, parsed) = parse_src(src, files);
    let sites = impl_sites(&parsed).sites;
    let mut groups: BTreeMap<(usize, String), Vec<ast::Impl>> = BTreeMap::new();
    for site in sites {
        // An impl inside an inline module (`config_check.rs`'s seven) is left:
        // its trait would need that module's path, and the file's inline
        // modules are their own smell to split into files first.
        let inline = site
            .found
            .syntax()
            .ancestors()
            .any(|node| ast::Module::can_cast(node.kind()));
        if !inline
            && site
                .home
                .as_ref()
                .is_some_and(|home| *home != parsed[site.file].0)
        {
            groups
                .entry((site.file, site.name))
                .or_default()
                .push(site.found);
        }
    }
    let mut edits: BTreeMap<String, Vec<(std::ops::Range<usize>, String)>> = BTreeMap::new();
    let mut imports: Imports = BTreeMap::new();
    for ((file, name), blocks) in groups {
        let Some(trait_) = extension_trait(&name, &blocks) else {
            continue;
        };
        let key = &keys[file];
        for (at, block) in blocks.iter().enumerate() {
            let range = block.syntax().text_range();
            let replacement = if at == 0 {
                trait_.text.clone()
            } else {
                String::new()
            };
            edits.entry(key.clone()).or_default().push((
                usize::from(range.start())..usize::from(range.end()),
                replacement,
            ));
        }
        if trait_.items.is_empty() {
            continue;
        }
        let module = &parsed[file].1;
        // Only this package's own targets can name it: another package may
        // not depend on this crate, and a build script cannot depend on the
        // crate it builds (measured: `build.rs` given the import, and the
        // tree stopped compiling).
        let package = src.trim_end_matches('/').trim_end_matches("src");
        let targets =
            ["src/", "tests/", "examples/", "benches/"].map(|dir| format!("{package}{dir}"));
        for (other, text) in files {
            let rust = std::path::Path::new(other)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
            if !rust || !targets.iter().any(|dir| other.starts_with(dir.as_str())) {
                continue;
            }
            // A binary target (`main.rs`, `src/bin/`) is its own crate root,
            // where `crate::` is the binary: it names the library by name.
            let src_dir = format!("{}/", src.trim_end_matches('/'));
            let binary = other == &format!("{src_dir}main.rs")
                || other.starts_with(&format!("{src_dir}bin/"));
            let inside = other.starts_with(&src_dir) && !binary;
            // Outside the library only a `pub` trait can be imported, and a
            // test could never have called a `pub(crate)` method there: a
            // name match there is another method of that name (measured: 50
            // spurious test imports).
            if !inside && !trait_.public {
                continue;
            }
            let head = if inside { "crate" } else { krate };
            let path: Vec<&str> = std::iter::once(head)
                .chain(module.iter().map(String::as_str))
                .collect();
            let line = format!("use {}::{}Ext as _;", path.join("::"), name);
            for (scope, test_only) in calls(text, &trait_.items) {
                // The trait's own scope needs no import.
                if other == key && scope.is_none() {
                    continue;
                }
                imports
                    .entry((other.clone(), scope))
                    .or_default()
                    .insert((line.clone(), test_only));
            }
        }
    }
    for ((file, scope), lines) in imports {
        let Ok(tree) = parse(&files[&file]) else {
            continue;
        };
        let at = match scope {
            Some(at) => at,
            None => match tree.items().next() {
                Some(first) => usize::from(first.syntax().text_range().start()),
                None => continue,
            },
        };
        let block: String = lines
            .into_iter()
            .map(|(line, test_only)| {
                if test_only {
                    format!("#[cfg(test)]\n{line}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect();
        edits.entry(file).or_default().push((at..at, block));
    }
    edits
        .into_iter()
        .filter_map(|(file, mut list)| {
            let original = &files[&file];
            let mut text = original.clone();
            list.sort_by_key(|(range, _)| (range.start, range.end));
            for (range, replacement) in list.into_iter().rev() {
                text.replace_range(range, &replacement);
            }
            (text != *original).then_some((file, text))
        })
        .collect()
}

/// A type's extension trait: its text (trait and impl, or empty for impls
/// with no items) and the names of its items.
struct ExtensionTrait {
    text: String,
    items: BTreeSet<String>,
    /// Whether the trait is `pub`: only then can another crate (a test, a
    /// binary) import it.
    public: bool,
}

/// The extension trait `blocks` (one type's impls in one file) become, or
/// `None` when an item is neither a method nor a const.
fn extension_trait(name: &str, blocks: &[ast::Impl]) -> Option<ExtensionTrait> {
    let self_ty = blocks.first()?.self_ty()?.syntax().text().to_string();
    let (mut signatures, mut bodies) = (Vec::new(), Vec::new());
    let mut items = BTreeSet::new();
    let mut public = false;
    for block in blocks {
        for item in block.assoc_item_list()?.assoc_items() {
            let syntax = item.syntax();
            let visibility = syntax.children().find_map(ast::Visibility::cast);
            public |= visibility
                .as_ref()
                .is_some_and(|v| v.syntax().text() == "pub");
            // Doc comments and `#[must_use]` describe the declaration; every
            // other attribute is about the body.
            let (mut declared, mut kept) = (String::new(), String::new());
            for child in syntax.children_with_tokens() {
                match child.kind() {
                    // The parser wraps a doc comment in its own node.
                    SyntaxKind::DOC_COMMENT => {
                        let _ = writeln!(declared, "    {child}");
                    }
                    SyntaxKind::ATTR if child.to_string().contains("must_use") => {
                        let _ = writeln!(declared, "    {child}");
                    }
                    SyntaxKind::ATTR => {
                        let _ = writeln!(kept, "    {child}");
                    }
                    _ => {}
                }
            }
            let start = item_start(syntax)?;
            let past_visibility =
                visibility.map_or(start, |v| usize::from(v.syntax().text_range().end()));
            let whole = syntax.text_range();
            let base = usize::from(whole.start());
            let text = syntax.text().to_string();
            let mut body_text = text[past_visibility - base..].trim_start().to_owned();
            // Only a function loses `const`; an associated const keeps it.
            if matches!(item, ast::AssocItem::Fn(_)) {
                body_text = body_text.trim_start_matches("const ").to_owned();
            }
            let (signature, item_name) = match &item {
                ast::AssocItem::Fn(function) => {
                    let body = function.body()?.syntax().text_range();
                    let head = &text[past_visibility - base..usize::from(body.start()) - base];
                    // A trait cannot declare a `const fn`, so `const` is dropped.
                    // A caller that is really in a const context is then a
                    // compile error naming a function that belongs with its
                    // type in the vocabulary layer, which is where it moves.
                    let head = head.trim().trim_start_matches("const ");
                    (format!("{head};"), function.name()?.text().to_string())
                }
                ast::AssocItem::Const(constant) => {
                    let ty = constant.ty()?.syntax().text().to_string();
                    let const_name = constant.name()?.text().to_string();
                    (format!("const {const_name}: {ty};"), const_name)
                }
                _ => return None,
            };
            items.insert(item_name);
            signatures.push(format!("{declared}    {signature}"));
            bodies.push(format!("{kept}    {body_text}"));
        }
    }
    if items.is_empty() {
        return Some(ExtensionTrait {
            text: String::new(),
            items,
            public,
        });
    }
    let visibility = if public { "pub" } else { "pub(crate)" };
    Some(ExtensionTrait {
        text: format!(
            "/// `{name}` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).\n{visibility} trait {name}Ext: Sized {{\n{}\n}}\n\nimpl {name}Ext for {self_ty} {{\n{}\n}}",
            signatures.join("\n\n"),
            bodies.join("\n\n")
        ),
        items,
        public,
    })
}

/// Each scope of `text` that calls any of `items` by name (a method call or
/// a path segment), as where its import goes, with whether every call there
/// is under test code. The scope is the nearest enclosing inline module,
/// whose body does not see its file's imports (its first item, as `Some`), or
/// the file's top level (`None`): measured, a file-level import left the
/// calls inside `config_check.rs`'s inline modules unresolved.
fn calls(text: &str, items: &BTreeSet<String>) -> BTreeMap<Option<usize>, bool> {
    let tree = batten_facts::source::rust_parse(text, ra_ap_syntax::Edition::Edition2024).tree();
    let mut found: BTreeMap<Option<usize>, bool> = BTreeMap::new();
    for token in tree
        .syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| token.kind() == SyntaxKind::IDENT && items.contains(token.text()))
    {
        // Inside a macro's arguments there is no call node, only a token tree
        // (measured: `row.severity()` in a `vec![…]`): there a call is the
        // name between `.`/`::` and `(`.
        let in_macro = || {
            let next =
                std::iter::successors(token.next_token(), ra_ap_syntax::SyntaxToken::next_token)
                    .find(|at| at.kind() != SyntaxKind::WHITESPACE);
            let previous =
                std::iter::successors(token.prev_token(), ra_ap_syntax::SyntaxToken::prev_token)
                    .find(|at| at.kind() != SyntaxKind::WHITESPACE);
            next.is_some_and(|at| at.kind() == SyntaxKind::L_PAREN)
                && previous
                    .is_some_and(|at| matches!(at.kind(), SyntaxKind::DOT | SyntaxKind::COLON2))
        };
        let called = token.parent_ancestors().take(3).any(|node| {
            matches!(
                node.kind(),
                SyntaxKind::METHOD_CALL_EXPR | SyntaxKind::PATH_SEGMENT
            )
        }) || (token
            .parent()
            .is_some_and(|parent| parent.kind() == SyntaxKind::TOKEN_TREE)
            && in_macro());
        if !called {
            continue;
        }
        let in_test = token.parent_ancestors().any(|node| cfg_test(&node));
        let scope = token
            .parent_ancestors()
            .find_map(ast::ItemList::cast)
            .map(|list| {
                list.items().next().map_or_else(
                    || {
                        list.l_curly_token()
                            .map_or(0, |open| usize::from(open.text_range().end()))
                    },
                    |first| usize::from(first.syntax().text_range().start()),
                )
            });
        let all_test = found.entry(scope).or_insert(true);
        *all_test = *all_test && in_test;
    }
    found
}

/// The node and module path of a file at `below` (relative to a crate's
/// `src/`), or `None` for a binary's `main.rs`: the same rule [`sources`]
/// walks by.
fn locate(below: &str) -> Option<(String, Vec<String>)> {
    let path = Path::new(below);
    let mut parts = path.components();
    let first = parts.next()?.as_os_str().to_string_lossy().into_owned();
    if parts.next().is_none() {
        let stem = Path::new(&first)
            .file_stem()?
            .to_string_lossy()
            .into_owned();
        return match stem.as_str() {
            "lib" => Some((LIB.to_owned(), Vec::new())),
            "main" => None,
            _ => Some((stem.clone(), vec![stem])),
        };
    }
    let below_dir = path.strip_prefix(&first).ok()?;
    let mut module = vec![first.clone()];
    module.extend(module_path(below_dir));
    Some((first, module))
}

/// Every file of `files` (path to text) that changes when each inherent impl
/// under `src` (a crate's source directory, relative like the keys) that
/// sits outside its type's top-level module moves into the one file of that
/// module declaring the type (CLOUD-2793's `move-impl-home`).
///
/// The move carries what the impl needs: each `use` leaf of its old file it
/// names (an `as _` trait import always), rebased to a crate-absolute path,
/// and a `use` of each item of the old module it names, raised to
/// `pub(crate)` there when private. A method of the moved impl that its old
/// module still calls is raised to `pub(crate)` too. The impl lands before
/// the new file's `#[cfg(test)]` module, or at its end.
///
/// An impl whose home has no single declaring file, or that the census left
/// unresolved, is left where it is, so the gate still counts it. What this
/// cannot see is a compile error naming the site, never a silent change.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one pass over one parse: locate, lift, re-import, splice; split it when a second caller needs a stage"
)]
pub fn move_impls_home(src: &str, files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let (keys, parsed) = parse_src(src, files);
    let Sites { sites, declared } = impl_sites(&parsed);
    let nodes: BTreeSet<String> = parsed
        .iter()
        .map(|(node, _, _)| node.clone())
        .filter(|node| node != LIB)
        .collect();
    // An item two moving impls both name is raised once.
    let mut raised: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut edits: BTreeMap<usize, Vec<(std::ops::Range<usize>, String)>> = BTreeMap::new();
    let mut uses: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let mut landed: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for site in &sites {
        let (node, module, tree) = &parsed[site.file];
        let Some(home) = site.home.as_ref().filter(|home| *home != node) else {
            continue;
        };
        let targets: Vec<usize> = (0..parsed.len())
            .filter(|&at| parsed[at].0 == *home && declared[at].contains(&site.name))
            .collect();
        let [target] = targets[..] else {
            continue;
        };
        let source = &files[&keys[site.file]];
        let range = site.found.syntax().text_range();
        let (start, end) = (usize::from(range.start()), usize::from(range.end()));
        let named: BTreeSet<String> = site
            .found
            .syntax()
            .descendants_with_tokens()
            .filter_map(ra_ap_syntax::NodeOrToken::into_token)
            .filter(|token| token.kind() == SyntaxKind::IDENT)
            .map(|token| token.text().to_owned())
            .collect();
        let used_outside = |name: &str| {
            tree.syntax()
                .descendants_with_tokens()
                .filter_map(ra_ap_syntax::NodeOrToken::into_token)
                .any(|token| {
                    let at = usize::from(token.text_range().start());
                    token.kind() == SyntaxKind::IDENT
                        && token.text() == name
                        && !(start..end).contains(&at)
                })
        };
        // The moved impl's private methods its old module still calls.
        let mut text = source[start..end].to_owned();
        let mut private_calls: Vec<usize> = site
            .found
            .assoc_item_list()
            .into_iter()
            .flat_map(|list| list.assoc_items())
            .filter_map(|item| match item {
                ast::AssocItem::Fn(function) => Some(function),
                _ => None,
            })
            .filter(|function| function.visibility().is_none())
            .filter(|function| {
                function
                    .name()
                    .is_some_and(|name| used_outside(name.text()))
            })
            .filter_map(|function| item_start(function.syntax()))
            .map(|at| at - start)
            .collect();
        private_calls.sort_unstable();
        for at in private_calls.into_iter().rev() {
            text.insert_str(at, "pub(crate) ");
        }
        landed.entry(target).or_default().push(text);
        edits
            .entry(site.file)
            .or_default()
            .push((start..end, String::new()));
        // What the impl names from its old file.
        let wanted = uses.entry(target).or_default();
        for (name, path) in top_level_aliases(tree) {
            if name == "_" || named.contains(&name) {
                wanted.insert(use_line(&rebase(&path, module, &nodes), &name));
            }
        }
        for item in tree.items() {
            let Some(name) = item_name(&item) else {
                continue;
            };
            if name == site.name || !named.contains(&name) {
                continue;
            }
            let path: Vec<String> = std::iter::once(String::from("crate"))
                .chain(module.iter().cloned())
                .chain(std::iter::once(name.clone()))
                .collect();
            wanted.insert(use_line(&path, &name));
            if item_visibility(&item).is_none()
                && let Some(at) = item_start(item.syntax())
                && raised.insert((site.file, at))
            {
                edits
                    .entry(site.file)
                    .or_default()
                    .push((at..at, String::from("pub(crate) ")));
            }
        }
    }
    for (target, texts) in landed {
        let tree = &parsed[target].2;
        let text = &files[&keys[target]];
        let local: BTreeSet<String> = top_level_aliases(tree)
            .into_keys()
            .chain(tree.items().filter_map(|item| item_name(&item)))
            .collect();
        let at = tree
            .items()
            .find(|item| matches!(item, ast::Item::Module(_)) && cfg_test(item.syntax()))
            .map_or(text.len(), |item| {
                usize::from(item.syntax().text_range().start())
            });
        let body = texts.iter().fold(String::new(), |mut body, moved| {
            let _ = write!(body, "\n{moved}\n\n");
            body
        });
        let list = edits.entry(target).or_default();
        list.push((at..at, body));
        let lines: Vec<String> = uses
            .remove(&target)
            .unwrap_or_default()
            .into_iter()
            .filter(|line| use_name(line).is_none_or(|name| name == "_" || !local.contains(name)))
            .collect();
        if !lines.is_empty()
            && let Some(first) = tree.items().next()
        {
            let at = usize::from(first.syntax().text_range().start());
            list.push((at..at, format!("{}\n", lines.join("\n"))));
        }
    }
    edits
        .into_iter()
        .filter_map(|(file, mut list)| {
            let mut text = files[&keys[file]].clone();
            list.sort_by_key(|(range, _)| (range.start, range.end));
            for (range, replacement) in list.into_iter().rev() {
                text.replace_range(range, &replacement);
            }
            (text != files[&keys[file]]).then(|| (keys[file].clone(), text))
        })
        .collect()
}

/// Each inherent impl under `src` the census counts outside its type's
/// module, as a pointer: its file, its first line, its type, the module
/// declaring that type, and how many lines it spans. Unresolved impls are
/// listed with the home `?`. This is the evidence for choosing, per impl,
/// between moving it home and keeping its behaviour in the layer above.
#[must_use]
pub fn impl_plan(src: &str, files: &BTreeMap<String, String>) -> Vec<String> {
    let (keys, parsed) = parse_src(src, files);
    impl_sites(&parsed)
        .sites
        .into_iter()
        .filter(|site| site.home.as_ref() != Some(&parsed[site.file].0))
        .map(|site| {
            let text = &files[&keys[site.file]];
            let range = site.found.syntax().text_range();
            let line = text[..usize::from(range.start())].lines().count() + 1;
            let span = text[usize::from(range.start())..usize::from(range.end())]
                .lines()
                .count();
            format!(
                "{}:{line} {} -> {} ({span} lines)",
                keys[site.file],
                site.name,
                site.home.as_deref().unwrap_or("?")
            )
        })
        .collect()
}

/// A `use` leaf's path rebased to `crate::…` from a file at `module`;
/// `nodes` are the crate's top-level modules, the only heads a crate root
/// reads root-relative (`serde::…` there is still the crate `serde`).
fn rebase(path: &[String], module: &[String], nodes: &BTreeSet<String>) -> Vec<String> {
    match path.first().map(String::as_str) {
        Some("self") => std::iter::once(String::from("crate"))
            .chain(module.iter().cloned())
            .chain(path[1..].iter().cloned())
            .collect(),
        Some("super") => {
            let supers = path
                .iter()
                .take_while(|segment| *segment == "super")
                .count();
            let kept = module.len().saturating_sub(supers);
            std::iter::once(String::from("crate"))
                .chain(module[..kept].iter().cloned())
                .chain(path[supers..].iter().cloned())
                .collect()
        }
        Some(head) if module.is_empty() && nodes.contains(head) => {
            // A crate root's own child module, read root-relative.
            std::iter::once(String::from("crate"))
                .chain(path.iter().cloned())
                .collect()
        }
        _ => path.to_vec(),
    }
}

fn use_line(path: &[String], name: &str) -> String {
    let joined = path.join("::");
    if path.last().is_some_and(|last| last == name) {
        format!("use {joined};")
    } else {
        format!("use {joined} as {name};")
    }
}

/// The name a `use` line binds.
fn use_name(line: &str) -> Option<&str> {
    let body = line.strip_prefix("use ")?.strip_suffix(';')?;
    Some(body.rsplit_once(" as ").map_or_else(
        || body.rsplit("::").next().unwrap_or(body),
        |(_, name)| name,
    ))
}

/// The name an item declares, when a path can name it.
fn item_name(item: &ast::Item) -> Option<String> {
    let name = match item {
        ast::Item::Fn(item) => item.name(),
        ast::Item::Struct(item) => item.name(),
        ast::Item::Enum(item) => item.name(),
        ast::Item::Const(item) => item.name(),
        ast::Item::Static(item) => item.name(),
        ast::Item::TypeAlias(item) => item.name(),
        ast::Item::Trait(item) => item.name(),
        ast::Item::Union(item) => item.name(),
        _ => None,
    }?;
    Some(name.text().to_string())
}

fn item_visibility(item: &ast::Item) -> Option<ast::Visibility> {
    item.syntax().children().find_map(ast::Visibility::cast)
}

/// Where an item's own tokens start, past its attributes and doc comments:
/// where a visibility goes. The parser wraps a doc comment in a
/// `DOC_COMMENT` node; not skipping it put `pub(crate) ` ahead of the doc
/// comment instead of the item (15 errors in the first `move-impl-home` run).
fn item_start(syntax: &SyntaxNode) -> Option<usize> {
    syntax
        .children_with_tokens()
        .find(|child| {
            !matches!(
                child.kind(),
                SyntaxKind::ATTR
                    | SyntaxKind::COMMENT
                    | SyntaxKind::DOC_COMMENT
                    | SyntaxKind::WHITESPACE
            )
        })
        .map(|child| usize::from(child.text_range().start()))
}

/// The module path where `found` sits (`module` plus each enclosing inline
/// module, outermost first), and the `use` leaf for `name` in the nearest
/// enclosing inline module that has one: the scope the compiler reads
/// before the file's top level. `config_check.rs` holds its impls in inline
/// modules (`pub mod action { use crate::config_model::Action; impl Action
/// … }`), and reading only the top level left all seven unresolved.
fn enclosing_scope(
    found: &ast::Impl,
    module: &[String],
    name: &str,
) -> (Vec<String>, Option<Vec<String>>) {
    let mut chain: Vec<String> = found
        .syntax()
        .ancestors()
        .filter_map(ast::Module::cast)
        .filter_map(|inline| inline.name().map(|name| name.text().to_string()))
        .collect();
    chain.reverse();
    let at: Vec<String> = module.iter().cloned().chain(chain).collect();
    let local = found
        .syntax()
        .ancestors()
        .filter_map(ast::ItemList::cast)
        .find_map(|list| {
            list.items()
                .filter_map(|item| match item {
                    ast::Item::Use(declaration) => declaration.use_tree(),
                    _ => None,
                })
                .flat_map(|tree| use_leaves(&tree))
                .find(|leaf| leaf.name == name)
                .map(|leaf| leaf.path)
        });
    (at, local)
}

/// A file's top-level `use` leaves: the name each makes visible, to its path.
fn top_level_aliases(tree: &SourceFile) -> BTreeMap<String, Vec<String>> {
    tree.items()
        .filter_map(|item| match item {
            ast::Item::Use(declaration) => declaration.use_tree(),
            _ => None,
        })
        .flat_map(|tree| use_leaves(&tree))
        .map(|leaf| (leaf.name, leaf.path))
        .collect()
}

/// Resolves a type path to the top-level module declaring it.
struct Resolver<'a> {
    modules: &'a BTreeSet<String>,
    homes: &'a BTreeMap<String, BTreeSet<String>>,
    lib_aliases: &'a BTreeMap<String, Vec<String>>,
}

impl Resolver<'_> {
    /// The top-level module declaring `path`'s last segment, read from a file
    /// at `module`, or `None` when the path does not resolve to a module
    /// that declares it. A landing on the crate root follows the root's own
    /// re-export of the name, at most `hops` times.
    fn node_of(&self, path: &[String], module: &[String], hops: u8) -> Option<String> {
        let (head, rest) = path.split_first()?;
        let name = path.last()?;
        let node = match head.as_str() {
            "crate" if rest.len() >= 2 => rest[0].clone(),
            "self" => module.first().cloned().unwrap_or_else(|| LIB.to_owned()),
            "super" if module.len() >= 2 => module[0].clone(),
            "crate" | "super" => LIB.to_owned(),
            child if module.is_empty() && self.modules.contains(child) => child.to_owned(),
            _ => return None,
        };
        let declares = |node: &str| {
            self.homes
                .get(name)
                .is_some_and(|declaring| declaring.contains(node))
        };
        if node == LIB && !declares(LIB) {
            let target = self.lib_aliases.get(name)?;
            return self.node_of(target, &[], hops.checked_sub(1)?);
        }
        declares(&node).then_some(node)
    }
}

/// The type name a node declares, when it is a struct, enum, union or a type
/// alias that is not an associated type.
fn match_ast_name(syntax: &SyntaxNode) -> Option<String> {
    let name = if let Some(item) = ast::Struct::cast(syntax.clone()) {
        item.name()
    } else if let Some(item) = ast::Enum::cast(syntax.clone()) {
        item.name()
    } else if let Some(item) = ast::Union::cast(syntax.clone()) {
        item.name()
    } else {
        let item = ast::TypeAlias::cast(syntax.clone())?;
        if syntax
            .parent()
            .is_some_and(|parent| parent.kind() == SyntaxKind::ASSOC_ITEM_LIST)
        {
            return None;
        }
        item.name()
    }?;
    Some(name.text().to_string())
}

/// An impl's self type, references stripped, as its path's segments with
/// generic arguments dropped.
fn self_type_path(found: &ast::Impl) -> Option<Vec<String>> {
    let mut ty = found.self_ty()?;
    loop {
        match ty {
            ast::Type::RefType(reference) => ty = reference.ty()?,
            ast::Type::PathType(path) => {
                let mut depth = 0_usize;
                let bare: String = path
                    .path()?
                    .syntax()
                    .text()
                    .to_string()
                    .chars()
                    .filter(|c| {
                        match c {
                            '<' => depth += 1,
                            '>' => depth = depth.saturating_sub(1),
                            _ => return depth == 0 && !c.is_whitespace(),
                        }
                        false
                    })
                    .collect();
                return Some(bare.split("::").map(str::to_owned).collect());
            }
            _ => return None,
        }
    }
}

/// How many re-exports a crate makes of its own items outside its root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShimCensus {
    /// `pub` or `pub(crate)` `use crate::…` leaves outside `lib.rs`.
    pub reexports: usize,
    /// Of those, the leaves renamed with `as`.
    pub aliased: usize,
}

/// Count every leaf of a `pub` or `pub(crate)` `use crate::…` item, outside
/// test code and outside the crate root (CLOUD-2792). The unit is the LEAF:
/// `pub use crate::a::{X, Y as Z};` is two, one aliased. `pub(super)`,
/// `pub(in …)` and `self::`/`super::` paths re-export within a module tree, not
/// a crate's own item to the crate, and are out of scope.
///
/// # Errors
///
/// The root cannot be read, or a file does not parse.
pub fn shim_census(root: &Path) -> anyhow::Result<ShimCensus> {
    let mut census = ShimCensus::default();
    for (node, _, tree) in parsed_sources(root)? {
        if node == LIB {
            continue;
        }
        for found in tree.syntax().descendants().filter_map(ast::Use::cast) {
            let visibility: String = found
                .visibility()
                .map(|v| v.syntax().text().to_string())
                .unwrap_or_default()
                .split_whitespace()
                .collect();
            if !matches!(visibility.as_str(), "pub" | "pub(crate)") || cfg_test(found.syntax()) {
                continue;
            }
            let Some(tree) = found.use_tree() else {
                continue;
            };
            for leaf in use_leaves(&tree) {
                if leaf.path.first().is_some_and(|first| first == "crate") {
                    census.reexports += 1;
                    census.aliased += usize::from(leaf.renamed);
                }
            }
        }
    }
    Ok(census)
}

/// Every module-graph quality metric of one source root (CLOUD-2821), each an
/// integer so a comparison is exact and the record byte-stable. Lower is
/// better for every field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metrics {
    /// The node count of the largest strongly connected component.
    pub cycle: usize,
    /// Propagation cost in basis points (a hundredth of a percent), rounded.
    pub propagation: usize,
    /// Inherent impls away from their type's module, ambiguous ones included.
    pub impls: usize,
    /// Re-export leaves of the crate's own items outside its root.
    pub shims: usize,
}

impl Metrics {
    /// Each metric's name and value, in record order.
    #[must_use]
    pub fn fields(&self) -> [(&'static str, usize); 4] {
        [
            ("cycle", self.cycle),
            ("propagation", self.propagation),
            ("impls", self.impls),
            ("shims", self.shims),
        ]
    }

    /// The record's form: `cycle=<n> propagation=<bp> impls=<n> shims=<n>`.
    #[must_use]
    pub fn line(&self) -> String {
        self.fields()
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Parse [`Metrics::line`]'s form; `None` on any missing, extra or
    /// non-integer field, so a hand-mangled record is could-not-look.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut read: BTreeMap<&str, usize> = BTreeMap::new();
        for word in text.split_whitespace() {
            let (name, value) = word.split_once('=')?;
            if read.insert(name, value.parse().ok()?).is_some() {
                return None;
            }
        }
        let metrics = Self {
            cycle: read.remove("cycle")?,
            propagation: read.remove("propagation")?,
            impls: read.remove("impls")?,
            shims: read.remove("shims")?,
        };
        read.is_empty().then_some(metrics)
    }
}

/// Propagation cost, a percentage, as whole basis points.
#[must_use]
pub fn basis_points(percent: f64) -> usize {
    // A share of pairs is in [0, 100], so the product is in [0, 10000].
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a percentage in [0, 100] times 100 fits usize and is non-negative"
    )]
    let points = (percent * 100.0).round().max(0.0) as usize;
    points
}

/// Measure every metric of `root`.
///
/// # Errors
///
/// The root cannot be read, or a file does not parse.
pub fn metrics(root: &Path) -> anyhow::Result<Metrics> {
    let graph = read(root)?;
    let impls = impl_census(root)?;
    Ok(Metrics {
        cycle: graph.largest_component(),
        propagation: basis_points(graph.propagation_cost()),
        impls: impls.outside + impls.ambiguous,
        shims: shim_census(root)?.reexports,
    })
}

/// `modules metrics`: one line, `<root> <metrics line>`.
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_metrics(
    root: &Path,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::exit::ExitCode> {
    match metrics(root) {
        Ok(measured) => {
            writeln!(out, "{} {}", root.display(), measured.line())?;
            Ok(crate::exit::ExitCode::Success)
        }
        Err(reason) => {
            writeln!(
                err,
                "modules metrics: could not read the module graph: {reason}"
            )?;
            Ok(crate::exit::ExitCode::Internal)
        }
    }
}

/// One root's judgement against its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judged {
    /// Every metric equals the record.
    Held,
    /// No metric is worse and at least one is better: the record tightens.
    Better,
    /// These metrics are worse: `(name, recorded, measured)`.
    Worse(Vec<(&'static str, usize, usize)>),
}

/// Compare a measurement with its record, metric by metric.
#[must_use]
pub fn judge(recorded: &Metrics, measured: &Metrics) -> Judged {
    let worse: Vec<_> = recorded
        .fields()
        .iter()
        .zip(measured.fields())
        .filter(|((_, was), (_, now))| now > was)
        .map(|((name, was), (_, now))| (*name, *was, now))
        .collect();
    if !worse.is_empty() {
        Judged::Worse(worse)
    } else if recorded == measured {
        Judged::Held
    } else {
        Judged::Better
    }
}

/// `modules ratchet` (CLOUD-2821): measure every root `record` names and
/// compare each with its recorded line.
///
/// - any metric worse: refused (exit 2, the verdict), naming the metric, the
///   recorded and the measured value;
/// - all held: exit 0, nothing written;
/// - some better, none worse: the record is rewritten to the measurement, so
///   it only ever tightens (exit 0), unless `check` is set, in which case a
///   record looser than the tree is refused too: a commit that improves a
///   metric must carry the tightened record, so a later one cannot spend it.
///
/// The record is one line per root, `<root> <metrics line>`, roots relative
/// to the record's directory. A record that cannot be read or parsed, or a
/// root that cannot be measured, is could-not-look (3).
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_ratchet(
    record: &Path,
    check: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::exit::ExitCode> {
    use crate::exit::ExitCode;
    let text = match crate::fsio::read_to_string(record) {
        Ok(text) => text,
        Err(reason) => {
            writeln!(
                err,
                "modules ratchet: could not read {}: {reason}",
                record.display()
            )?;
            return Ok(ExitCode::Internal);
        }
    };
    let base = record.parent().unwrap_or_else(|| Path::new(""));
    let mut rows: Vec<(String, Metrics)> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = line
            .split_once(' ')
            .and_then(|(root, rest)| Some((root.to_owned(), Metrics::parse(rest)?)));
        let Some(row) = parsed else {
            writeln!(
                err,
                "modules ratchet: {}:{} is not `<root> {}`",
                record.display(),
                number + 1,
                Metrics::default().line()
            )?;
            return Ok(ExitCode::Internal);
        };
        rows.push(row);
    }
    if rows.is_empty() {
        writeln!(err, "modules ratchet: {} names no root", record.display())?;
        return Ok(ExitCode::Internal);
    }
    let mut refused = false;
    let mut tightened = false;
    let mut measured_rows: BTreeMap<&str, Metrics> = BTreeMap::new();
    for (root, recorded) in &rows {
        let measured = match metrics(&base.join(root)) {
            Ok(measured) => measured,
            Err(reason) => {
                writeln!(
                    err,
                    "modules ratchet: could not read the module graph of {root}: {reason}"
                )?;
                return Ok(ExitCode::Internal);
            }
        };
        writeln!(out, "{root} {}", measured.line())?;
        match judge(recorded, &measured) {
            Judged::Held => {}
            Judged::Better => {
                tightened = true;
                if check {
                    refused = true;
                    writeln!(
                        err,
                        "modules ratchet: {root} scores better than {}; run `batten modules ratchet --record {}` and commit the tightened record",
                        record.display(),
                        record.display()
                    )?;
                }
            }
            Judged::Worse(worse) => {
                refused = true;
                for (name, was, now) in worse {
                    writeln!(
                        err,
                        "modules ratchet: {root} {name} {now} is worse than the recorded {was}; improve it rather than spend the record"
                    )?;
                }
            }
        }
        measured_rows.insert(root, measured);
    }
    if refused {
        return Ok(ExitCode::Violation);
    }
    if tightened {
        // Comments and blank lines are kept where they stood; only row lines
        // take the measurement.
        let mut next = String::new();
        for line in text.lines() {
            let row = line
                .split_once(' ')
                .and_then(|(root, _)| measured_rows.get(root).map(|m| (root, m)));
            match row {
                Some((root, measured)) if !line.starts_with('#') => {
                    let _ = writeln!(next, "{root} {}", measured.line());
                }
                _ => {
                    let _ = writeln!(next, "{line}");
                }
            }
        }
        let staged = record.with_extension("lock.tmp");
        std::fs::write(&staged, next)?;
        std::fs::rename(&staged, record)?;
        writeln!(out, "modules ratchet: tightened {}", record.display())?;
    }
    Ok(ExitCode::Success)
}

/// Every library source under `root`, parsed, with its graph node.
fn parsed_sources(root: &Path) -> anyhow::Result<Vec<(String, Vec<String>, SourceFile)>> {
    let (_, files) = sources(root)?;
    files
        .into_iter()
        .map(|(node, module, file)| {
            let source = crate::fsio::read_to_string(&file)?;
            let tree = parse(&source).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
            Ok((node, module, tree))
        })
        .collect()
}

/// One leaf of a `use` tree: the name it makes visible, the path it stands
/// for, and whether `as` renamed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseLeaf {
    /// The name visible where the `use` sits.
    pub name: String,
    /// The `::`-separated path it stands for, as written.
    pub path: Vec<String>,
    /// Whether the leaf carried `as`.
    pub renamed: bool,
}

/// The leaves of a `use` tree, groups expanded. A glob names nothing and is
/// skipped; `self` in a group names the group's own prefix. THE ONE FLATTENER,
/// read by `shims` and by `item_index`'s resolution.
#[must_use]
pub fn use_leaves(tree: &ast::UseTree) -> Vec<UseLeaf> {
    fn walk(tree: &ast::UseTree, prefix: &[String], out: &mut Vec<UseLeaf>) {
        let mut path = prefix.to_vec();
        if let Some(written) = tree.path() {
            let text: String = written
                .syntax()
                .text()
                .to_string()
                .split_whitespace()
                .collect();
            path.extend(text.split("::").map(str::to_owned));
        }
        if tree.star_token().is_some() {
            return;
        }
        if let Some(list) = tree.use_tree_list() {
            for nested in list.use_trees() {
                walk(&nested, &path, out);
            }
            return;
        }
        if path.last().is_some_and(|last| last == "self") {
            path.pop();
        }
        // `Trait as _` binds no name: its leaf is named `_`, which no path
        // resolves through, so a consumer regenerating it keeps the `as _`.
        let rename = tree.rename().and_then(|rename| {
            rename
                .name()
                .map(|name| name.text().to_string())
                .or_else(|| rename.underscore_token().map(|_| String::from("_")))
        });
        let renamed = rename.is_some();
        if let Some(name) = rename.or_else(|| path.last().cloned()) {
            out.push(UseLeaf {
                name,
                path,
                renamed,
            });
        }
    }
    let mut out = Vec::new();
    walk(tree, &[], &mut out);
    out
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
        } else if node.kind() == SyntaxKind::TOKEN_TREE {
            // A MACRO'S ARGUMENTS ARE TOKENS, NOT PATHS (CLOUD-2789): the
            // `crate::review::for_body` inside `matches!(…)` was no edge, so a
            // module reached its caller unseen and read as below the cycle.
            // Read once, at the outermost tree: an inner one is a descendant.
            if node
                .parent()
                .is_some_and(|p| p.kind() == SyntaxKind::TOKEN_TREE)
                || cfg_test(&node)
            {
                continue;
            }
            names.extend(token_paths(&node, module));
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

/// Every root name a macro token tree spells as a path: `crate::a…` or a
/// `super::…` chain, assembled from its identifier and `::` tokens.
fn token_paths(tree: &SyntaxNode, module: &[String]) -> Vec<String> {
    let tokens: Vec<(SyntaxKind, String)> = tree
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| !token.kind().is_trivia())
        .map(|token| (token.kind(), token.text().to_owned()))
        .collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        let (kind, text) = &tokens[at];
        if !matches!(kind, SyntaxKind::CRATE_KW | SyntaxKind::SUPER_KW) {
            at += 1;
            continue;
        }
        let mut segments = vec![text.clone()];
        let mut next = at + 1;
        loop {
            // `::` is one token or, inside a token tree, two `:`.
            let step = match tokens.get(next).map(|t| t.0) {
                Some(SyntaxKind::COLON2) => 1,
                Some(SyntaxKind::COLON)
                    if tokens.get(next + 1).map(|t| t.0) == Some(SyntaxKind::COLON) =>
                {
                    2
                }
                _ => break,
            };
            match tokens.get(next + step) {
                Some((SyntaxKind::IDENT | SyntaxKind::SUPER_KW, word)) => {
                    segments.push(word.clone());
                    next += step + 1;
                }
                _ => break,
            }
        }
        if let Some(name) = from_root(&segments, module) {
            found.push(name);
        }
        at = next.max(at + 1);
    }
    found
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
#[must_use]
pub fn cfg_test(node: &SyntaxNode) -> bool {
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
    let parse = batten_facts::source::rust_parse(source, ra_ap_syntax::Edition::Edition2024);
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

    /// Fails by: a cycle's members given different levels, or a node placed
    /// at or below something it reaches.
    #[test]
    fn a_cycle_shares_one_level_above_what_it_reaches() {
        let g = graph(&[
            ("leaf", &[]),
            ("a", &["b", "leaf"]),
            ("b", &["a"]),
            ("top", &["a"]),
        ]);
        let levels = g.levels();
        assert_eq!(levels["leaf"], 1);
        assert_eq!((levels["a"], levels["b"]), (2, 2));
        assert_eq!(levels["top"], 3);
    }

    /// Fails by: a node not counted as reaching itself, or reach not followed
    /// past one edge. A chain of three reaches 3 + 2 + 1 of 9 pairs.
    #[test]
    fn propagation_cost_counts_every_transitive_pair() {
        let chain = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &[])]);
        assert!((chain.propagation_cost() - 600.0 / 9.0).abs() < 1e-9);
        let cycle = graph(&[("a", &["b"]), ("b", &["a"])]);
        assert!((cycle.propagation_cost() - 100.0).abs() < 1e-9);
        assert!(Graph::default().propagation_cost().abs() < 1e-9);
    }

    /// Fails by: an edge with a parallel path ranked as breaking the cycle, or
    /// the one bridge edge not ranked first.
    #[test]
    fn the_edge_whose_cut_shrinks_the_cycle_ranks_first() {
        // a→b→c→a and a→c: cutting c→a breaks every cycle; cutting a→b leaves
        // a→c→a.
        let g = graph(&[("a", &["b", "c"]), ("b", &["c"]), ("c", &["a"])]);
        let ranked = g.cut_ranking();
        assert_eq!(ranked[0], ("c".to_owned(), "a".to_owned(), 1));
        assert!(ranked.contains(&("a".to_owned(), "b".to_owned(), 2)));
        assert_eq!(ranked.len(), 4);
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
    /// Fails by: a path inside a macro's arguments read as no edge, the hole
    /// that put `ready` below the cycle while `matches!` hid its call into
    /// `review`; or a test-only macro read as one.
    #[test]
    fn a_path_inside_a_macro_is_an_edge() {
        let source = "fn f() { if matches!(crate::review::for_body(x), Some(_)) {} \
                      assert!(super::git::y()); }\n\
                      #[cfg(test)]\nmod tests { fn t() { assert!(crate::fixture::y()); } }\n";
        assert_eq!(names(source, &["ready"]), ["git", "review"]);
    }

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

    /// A scratch crate root holding `files` (name, text).
    fn crate_root(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = crate::scratch::scratch(name);
        for (file, text) in files {
            std::fs::write(dir.join(file), text).unwrap();
        }
        dir
    }

    fn impls(files: &[(&str, &str)], name: &str) -> ImplCensus {
        impl_census(&crate_root(name, files)).unwrap()
    }

    fn shims(files: &[(&str, &str)], name: &str) -> ShimCensus {
        shim_census(&crate_root(name, files)).unwrap()
    }

    /// Fails by: an impl beside its own type counted as split.
    #[test]
    fn an_impl_beside_its_type_is_not_counted() {
        let census = impls(
            &[
                ("lib.rs", "mod a;\n"),
                ("a.rs", "pub struct T;\nimpl T { fn f() {} }\n"),
            ],
            "impls-beside",
        );
        assert_eq!(census, ImplCensus::default());
    }

    /// Fails by: an impl in another module than its type's missed — the split
    /// a crate boundary cannot carry.
    #[test]
    fn an_impl_in_another_module_is_counted() {
        let census = impls(
            &[
                ("lib.rs", "mod a;\nmod b;\n"),
                ("a.rs", "pub struct T;\n"),
                (
                    "b.rs",
                    "impl crate::a::T { fn f() {} }\nimpl &crate::a::T { fn g() {} }\n",
                ),
            ],
            "impls-outside",
        );
        assert_eq!(
            census,
            ImplCensus {
                outside: 2,
                ambiguous: 0
            }
        );
    }

    /// Fails by: a trait impl counted. Rust's orphan rule, not this gate,
    /// decides where a trait impl may sit.
    #[test]
    fn a_trait_impl_is_not_counted() {
        let census = impls(
            &[
                ("lib.rs", "mod a;\nmod b;\n"),
                ("a.rs", "pub struct T;\n"),
                (
                    "b.rs",
                    "impl Clone for crate::a::T { fn clone(&self) -> Self { todo!() } }\n",
                ),
            ],
            "impls-trait",
        );
        assert_eq!(census, ImplCensus::default());
    }

    /// Fails by: an impl of a name this crate never declares counted.
    #[test]
    fn an_impl_of_a_foreign_type_is_not_counted() {
        let census = impls(
            &[
                ("lib.rs", "mod b;\n"),
                ("b.rs", "impl Elsewhere { fn f() {} }\n"),
            ],
            "impls-foreign",
        );
        assert_eq!(census, ImplCensus::default());
    }

    /// The measured 153: matched by name, an impl of a name two modules both
    /// declare had no home. Fails by: an impl beside its own declaration
    /// counted because another module declares the same name; or one that
    /// names its type through a `use` charged to the wrong module.
    #[test]
    fn an_impl_is_resolved_the_way_its_file_reads_the_name() {
        let census = impls(
            &[
                ("lib.rs", "mod a;\nmod b;\nmod c;\n"),
                ("a.rs", "pub struct Pin;\nimpl Pin { fn f() {} }\n"),
                ("b.rs", "pub type Pin = u8;\n"),
                ("c.rs", "use crate::a::Pin;\nimpl Pin { fn g() {} }\n"),
            ],
            "impls-resolved",
        );
        assert_eq!(
            census,
            ImplCensus {
                outside: 1,
                ambiguous: 0
            }
        );
    }

    /// The measured seven: `config_check.rs` holds impls in inline modules
    /// that import their type there. Fails by: an inline module's own `use`
    /// unread, leaving the impl unresolved.
    #[test]
    fn an_impl_in_an_inline_module_reads_that_modules_imports() {
        let census = impls(
            &[
                ("lib.rs", "mod model;\nmod check;\n"),
                ("model.rs", "pub struct Action;\n"),
                (
                    "check.rs",
                    "pub mod action {\n    use crate::model::Action;\n    impl Action { fn f() {} }\n}\n",
                ),
            ],
            "impls-inline",
        );
        assert_eq!(
            census,
            ImplCensus {
                outside: 1,
                ambiguous: 0
            }
        );
    }

    /// Fails by: an impl whose type the census cannot resolve (named through
    /// a glob) hidden, rather than counted ambiguous.
    #[test]
    fn an_impl_the_census_cannot_resolve_is_ambiguous() {
        let root = crate_root(
            "impls-ambiguous",
            &[
                ("lib.rs", "mod a;\nmod b;\n"),
                ("a.rs", "pub struct Pin;\n"),
                ("b.rs", "use crate::a::*;\nimpl Pin { fn f() {} }\n"),
            ],
        );
        assert_eq!(
            impl_census(&root).unwrap(),
            ImplCensus {
                outside: 0,
                ambiguous: 1
            }
        );
    }

    /// Fails by: `lib.rs` treated as no module, so an impl elsewhere of a type
    /// it declares goes uncounted.
    #[test]
    fn an_impl_of_a_lib_type_elsewhere_is_counted() {
        let census = impls(
            &[
                ("lib.rs", "mod b;\npub struct Root;\n"),
                ("b.rs", "impl crate::Root { fn f() {} }\n"),
            ],
            "impls-lib",
        );
        assert_eq!(
            census,
            ImplCensus {
                outside: 1,
                ambiguous: 0
            }
        );
    }

    /// Fails by: test code counted, which no crate cut carries.
    #[test]
    fn a_cfg_test_impl_is_not_counted() {
        let census = impls(
            &[
                ("lib.rs", "mod a;\nmod b;\n"),
                ("a.rs", "pub struct T;\n"),
                (
                    "b.rs",
                    "#[cfg(test)]\nmod tests { impl crate::a::T { fn f() {} } }\n",
                ),
            ],
            "impls-test",
        );
        assert_eq!(census, ImplCensus::default());
    }

    /// Fails by: a grouped re-export counted once. The unit is the leaf.
    #[test]
    fn a_crate_reexport_outside_the_root_is_a_shim_per_leaf() {
        let census = shims(
            &[
                ("lib.rs", "mod a;\nmod b;\n"),
                (
                    "b.rs",
                    "pub use crate::a::{X, Y};\npub(crate) use crate::a::Z;\n",
                ),
            ],
            "shims-leaf",
        );
        assert_eq!(census.reexports, 3);
    }

    /// Fails by: the crate root's own re-exports counted. `lib.rs` is where a
    /// crate's public surface is stated.
    #[test]
    fn a_reexport_in_the_root_is_not_a_shim() {
        let census = shims(
            &[("lib.rs", "mod a;\npub use crate::a::X;\n")],
            "shims-root",
        );
        assert_eq!(census, ShimCensus::default());
    }

    /// Fails by: an `as` rename not reported as aliased.
    #[test]
    fn an_aliased_leaf_is_counted_as_aliased() {
        let census = shims(
            &[
                ("lib.rs", "mod b;\n"),
                ("b.rs", "pub use crate::a::{X as Z, Y};\n"),
            ],
            "shims-alias",
        );
        assert_eq!(
            census,
            ShimCensus {
                reexports: 2,
                aliased: 1
            }
        );
    }

    /// Fails by: a re-export within a module tree, a private `use`, or a test
    /// module's `use` counted as a shim of the crate's own item.
    #[test]
    fn a_super_or_self_reexport_is_out_of_scope() {
        let census = shims(
            &[
                ("lib.rs", "mod b;\n"),
                (
                    "b.rs",
                    "pub use super::X;\npub use self::inner::Y;\npub(super) use crate::a::Z;\nuse crate::a::W;\n#[cfg(test)]\nmod t { pub use crate::a::V; }\n",
                ),
            ],
            "shims-scope",
        );
        assert_eq!(census, ShimCensus::default());
    }

    /// Fails by: the impl left in place or landing after its new file's test
    /// module; a `use` of its old file it names (or an `as _` trait import)
    /// not carried; the old module's private helper it calls not raised; or
    /// its private method the old module still calls left private.
    #[test]
    fn an_impl_moves_home_with_what_it_names() {
        let files: BTreeMap<String, String> = [
            ("src/lib.rs", "mod a;\nmod b;\n"),
            ("src/a.rs", "pub struct T { x: u8 }\n#[cfg(test)]\nmod tests {}\n"),
            (
                "src/b.rs",
                "use crate::a::T;\nuse std::fmt::Write as _;\nfn helper() -> u8 { 1 }\nimpl T {\n    fn get(&self) -> u8 { helper() + self.x }\n}\nfn caller(t: &T) -> u8 { t.get() }\n",
            ),
        ]
        .into_iter()
        .map(|(path, text)| (path.to_owned(), text.to_owned()))
        .collect();
        let moved = move_impls_home("src", &files);
        assert_eq!(
            moved["src/a.rs"],
            "use crate::b::helper;\nuse std::fmt::Write as _;\npub struct T { x: u8 }\n\nimpl T {\n    pub(crate) fn get(&self) -> u8 { helper() + self.x }\n}\n\n#[cfg(test)]\nmod tests {}\n"
        );
        assert_eq!(
            moved["src/b.rs"],
            "use crate::a::T;\nuse std::fmt::Write as _;\npub(crate) fn helper() -> u8 { 1 }\n\nfn caller(t: &T) -> u8 { t.get() }\n"
        );
    }

    /// Fails by: a signature, doc comment or `#[must_use]` left off the
    /// trait; a body attribute moved onto it; a visibility kept on a trait
    /// item; the trait narrower than a `pub` method it now carries; an
    /// associated const not split; or a caller, in the crate or its tests,
    /// left without the import its method call now needs.
    #[test]
    fn an_impl_over_a_lower_layers_type_becomes_an_extension_trait() {
        let files: BTreeMap<String, String> = [
            ("src/lib.rs", "mod model;\nmod rules;\nmod user;\n"),
            ("src/model.rs", "pub struct Rule { pub x: u8 }\n"),
            (
                "src/rules.rs",
                "use crate::model::Rule;\nimpl Rule {\n    /// Doubles.\n    #[must_use]\n    #[allow(dead_code)]\n    pub fn twice(&self) -> u8 { self.x * 2 }\n    const ONE: u8 = 1;\n}\n",
            ),
            ("src/user.rs", "use crate::model::Rule;\nfn f(r: &Rule) -> u8 { r.twice() }\n"),
            ("tests/it.rs", "fn t(r: &app::model::Rule) -> u8 { r.twice() }\n"),
        ]
        .into_iter()
        .map(|(path, text)| (path.to_owned(), text.to_owned()))
        .collect();
        let changed = impls_to_extension_traits("src", "app", &files);
        assert_eq!(
            changed["src/rules.rs"],
            "use crate::model::Rule;\n/// `Rule` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).\npub trait RuleExt: Sized {\n    /// Doubles.\n    #[must_use]\n    fn twice(&self) -> u8;\n\n    const ONE: u8;\n}\n\nimpl RuleExt for Rule {\n    #[allow(dead_code)]\n    fn twice(&self) -> u8 { self.x * 2 }\n\n    const ONE: u8 = 1;\n}\n"
        );
        assert_eq!(
            changed["src/user.rs"],
            "use crate::rules::RuleExt as _;\nuse crate::model::Rule;\nfn f(r: &Rule) -> u8 { r.twice() }\n"
        );
        assert_eq!(
            changed["tests/it.rs"],
            "use app::rules::RuleExt as _;\nfn t(r: &app::model::Rule) -> u8 { r.twice() }\n"
        );
    }

    /// The measured `preset.rs` miss: `row.severity()` inside `vec![…]`.
    /// Fails by: a call inside a macro's arguments, a token tree with no
    /// call node, not counted, so its file is left without the import; or
    /// a bare mention counted as a call.
    #[test]
    fn a_call_inside_a_macros_arguments_is_a_call() {
        let items: BTreeSet<String> = [String::from("twice")].into();
        let found = calls("fn f(r: &R) { let _ = vec![r.twice()]; }\n", &items);
        assert_eq!(found, BTreeMap::from([(None, false)]));
        assert!(calls("fn f() { let _ = vec![twice]; }\n", &items).is_empty());
    }

    /// The measured shape: `config_check.rs`, nothing but inline modules.
    /// Fails by: a body not moved to its own file, or moved without its
    /// indentation removed; the declaration losing its doc comment or not
    /// left as `mod name;`; or a file holding anything but modules split.
    #[test]
    fn a_file_of_only_inline_modules_splits_into_one_file_each() {
        let files: BTreeMap<String, String> = [
            (
                "src/check.rs",
                "/// Actions.\npub mod action {\n    use crate::model::Action;\n\n    pub fn f() {}\n}\n\npub mod budget {\n    pub fn g() {}\n}\n",
            ),
            ("src/mixed.rs", "pub mod a {\n    pub fn f() {}\n}\npub mod b {}\nfn h() {}\n"),
        ]
        .into_iter()
        .map(|(path, text)| (path.to_owned(), text.to_owned()))
        .collect();
        let split = split_inline_modules(&files);
        assert_eq!(
            split["src/check.rs"],
            "/// Actions.\npub mod action;\n\npub mod budget;\n"
        );
        assert_eq!(
            split["src/check/action.rs"],
            "use crate::model::Action;\n\npub fn f() {}\n"
        );
        assert_eq!(split["src/check/budget.rs"], "pub fn g() {}\n");
        assert!(!split.contains_key("src/mixed.rs"), "{split:?}");
    }
}
