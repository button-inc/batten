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

/// One `modules` gate: parse `--max`, measure, print the measure's one line,
/// and refuse (exit 2, the verdict) a count above `max`.
///
/// THE ONE EXIT DISCIPLINE for every `modules` verb: `max` that is not a
/// non-negative integer is a usage error (1); a root that cannot be read or a
/// file that does not parse is could-not-look (3), with its reason on `err`.
/// `measure` returns the gated count and the line that reports it, a count and
/// never the members (rule 4); `remedy` ends the refusal.
fn gate(
    verb: &str,
    max: Option<&str>,
    remedy: &str,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
    measure: impl FnOnce() -> anyhow::Result<(usize, String)>,
) -> anyhow::Result<crate::exit::ExitCode> {
    use crate::exit::ExitCode;
    let max = match max.map(str::parse::<usize>) {
        None => None,
        Some(Ok(max)) => Some(max),
        Some(Err(_)) => {
            writeln!(err, "modules {verb}: --max takes a non-negative integer")?;
            return Ok(ExitCode::Usage);
        }
    };
    let (count, line) = match measure() {
        Ok(measured) => measured,
        Err(reason) => {
            writeln!(
                err,
                "modules {verb}: could not read the module graph: {reason}"
            )?;
            return Ok(ExitCode::Internal);
        }
    };
    writeln!(out, "modules {verb}: {line}")?;
    if let Some(max) = max.filter(|max| count > *max) {
        writeln!(
            err,
            "modules {verb}: {count} is more than the committed {max}; {remedy}"
        )?;
        return Ok(ExitCode::Violation);
    }
    Ok(ExitCode::Success)
}

/// `modules cycle`: print the largest component's size, and refuse when it
/// holds more than `max` modules. One line on `out`, `modules cycle: <n>
/// module(s) in the largest component`.
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
    gate(
        "cycle",
        max,
        "break a cycle rather than grow one",
        out,
        err,
        || {
            let largest = read(root)?.largest_component();
            Ok((
                largest,
                format!("{largest} module(s) in the largest component"),
            ))
        },
    )
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
            let home = if path.len() == 1 && names.contains(name) {
                Some(node.clone())
            } else if path.len() == 1 {
                aliases
                    .get(name)
                    .and_then(|target| resolver.node_of(target, module, 2))
            } else {
                resolver.node_of(&path, module, 2)
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
pub fn move_impls_home(src: &str, files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
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
        let mut raises: Vec<usize> = site
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
                    .is_some_and(|name| used_outside(&name.text()))
            })
            .filter_map(|function| item_start(function.syntax()))
            .map(|at| at - start)
            .collect();
        raises.sort_unstable();
        for at in raises.into_iter().rev() {
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
        let body: String = texts.iter().map(|moved| format!("\n{moved}\n\n")).collect();
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
/// where a visibility goes.
fn item_start(syntax: &SyntaxNode) -> Option<usize> {
    syntax
        .children_with_tokens()
        .find(|child| {
            !matches!(
                child.kind(),
                SyntaxKind::ATTR | SyntaxKind::COMMENT | SyntaxKind::WHITESPACE
            )
        })
        .map(|child| usize::from(child.text_range().start()))
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
            "crate" => LIB.to_owned(),
            "self" => module.first().cloned().unwrap_or_else(|| LIB.to_owned()),
            "super" if module.len() >= 2 => module[0].clone(),
            "super" => LIB.to_owned(),
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
    } else if let Some(item) = ast::TypeAlias::cast(syntax.clone()) {
        if syntax
            .parent()
            .is_some_and(|parent| parent.kind() == SyntaxKind::ASSOC_ITEM_LIST)
        {
            return None;
        }
        item.name()
    } else {
        return None;
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

/// `modules impls`: print how many inherent impls sit away from their type,
/// and refuse when outside plus ambiguous is more than `max` (CLOUD-2792).
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_impls(
    root: &Path,
    max: Option<&str>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::exit::ExitCode> {
    let remedy = "put the impl beside its type, or make it a free function where it is used";
    gate("impls", max, remedy, out, err, || {
        let census = impl_census(root)?;
        Ok((
            census.outside + census.ambiguous,
            format!(
                "{} outside their type's module, {} ambiguous",
                census.outside, census.ambiguous
            ),
        ))
    })
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

/// `modules shims`: print how many re-exports of the crate's own items sit
/// outside its root, and refuse more than `max` (CLOUD-2792).
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_shims(
    root: &Path,
    max: Option<&str>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::exit::ExitCode> {
    let remedy = "name the item at its home and delete the re-export";
    gate("shims", max, remedy, out, err, || {
        let census = shim_census(root)?;
        Ok((
            census.reexports,
            format!(
                "{} re-export(s), {} aliased",
                census.reexports, census.aliased
            ),
        ))
    })
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

    /// Fails by: an impl whose type the census cannot resolve (named through
    /// a glob) hidden, rather than counted ambiguous and gated.
    #[test]
    fn an_impl_the_census_cannot_resolve_is_ambiguous_and_gated() {
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
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_impls(&root, Some("0"), &mut out, &mut err).unwrap();
        assert_eq!(code, crate::exit::ExitCode::Violation);
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
}
