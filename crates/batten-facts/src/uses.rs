//! The `use` graph as a fact: which module reaches which (CLOUD-762).
//!
//! # What a line predicate gets wrong, measured rather than assumed
//!
//! CLOUD-762's §2 makes the measurement deliverable one, because the tier this
//! fact belongs in is decided by a count and not by an argument. Over
//! `crates/batten/src/**`, the syntactic tier is wrong in **two classes**, and
//! both are re-exports — aliases and glob imports contribute nothing at all:
//!
//! * **A hidden internal edge.** `trust.rs` and `output.rs` write
//!   `use crate::UsageError`. The text names no module; the edge is really onto
//!   `crate::error`, because the root re-exports that name. A layering gate
//!   reading lines is silently GREEN on an edge it was built to judge.
//! * **A phantom internal edge.** `use crate::Result` reads as an internal edge,
//!   and the root's own private `use anyhow::Result` means it is really an
//!   EXTERNAL dependency. The same gate is silently confused in the opposite
//!   direction.
//!
//! **The CLASSES are the measurement; the site count is not** (CLOUD-1121). It
//! was four when this was written and the phantom half grows with every module
//! that imports `crate::Result` — three did in one change, describing nothing
//! that had changed about the tier. `crates/batten/tests/it/use_graph.rs` asserts
//! the classes and the root NAME behind each, and a count in this paragraph would
//! be the prose-goes-stale failure the suite exists to replace.
//!
//! Aliases are all `as _` trait imports or paths into other crates, and the one
//! crate-internal alias leaves its module path plainly visible. Every glob is
//! `use super::*` inside a `#[cfg(test)]` module, which crosses no module
//! boundary. Neither can move a top-level module edge in this tree.
//!
//! # Why this is `Read x Check` and needs no delegated analyser
//!
//! Two classes, each bounded and nameable, is the arm CLOUD-762's reversal
//! condition sends to `Read x Check`. But the stronger reason is one that
//! condition did not anticipate: **the re-export table is itself syntax.**
//! Resolving every one of those sites needs no name resolution, no rust-analyzer and no `Cost::Effect` — it needs
//! the crate root's own `use` and `pub use` items, which a parser reads exactly
//! as it reads any other statement. So the fact is cheap AND correct about the
//! cases a line predicate gets wrong, rather than trading one for the other.
//!
//! # Resolution is a post-pass over the DECLARED set, never a hardcoded path
//!
//! [`resolve`] applies one file's export table to another's edges, and the
//! caller decides which file is the root by Rust's own convention — a library
//! crate's root is `lib.rs`. That is a language fact, not a consumer identifier,
//! so non-negotiable rule 1 is untouched: nothing here names a repository, an
//! account or an entity path, and a consumer whose root is elsewhere simply
//! declares it.
//!
//! # Pointer-only
//!
//! An edge is two module names and a line (rule 4). The imported ITEM name is
//! carried because resolution needs it, and it is a path segment rather than
//! content — never the source line, and never the file's text.

use std::collections::BTreeMap;

use ra_ap_syntax::ast::{HasModuleItem as _, HasName as _};
use ra_ap_syntax::{AstNode, Edition, ast};

use crate::facts::Look;

/// Where a `use` statement's first segment points, before resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// `use crate::<module>::…` — the module is named in the text, and a line
    /// predicate reads it correctly.
    Internal,
    /// `use <other_crate>::…` — outside this crate entirely.
    External,
    /// `use crate::<Item>` — a name reaching through the crate root's own
    /// re-export table. **The module is NOT in the text**, which is the whole
    /// class this fact exists to resolve.
    RootItem,
    /// `use self::…` / `use super::…` — inside the file's own module tree, so it
    /// crosses no top-level boundary. Kept as its own answer rather than dropped:
    /// "there is no edge here" and "I did not look" must stay distinct.
    Local,
}

/// One `use` edge: what it reaches, and where it was written.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
// Kebab-case so the emitted key matches `Fact::Uses`' schema fragment. The two
// disagreeing is the drift CLOUD-845 measured, where a documented key was never
// emitted and nothing could tell.
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct UseEdge {
    /// The module or crate reached, once resolved. Empty exactly while
    /// [`Origin::RootItem`] is unresolved — which [`resolve`] fills in, and which
    /// a consumer must never read as "reaches nothing".
    pub to: String,
    /// The imported item's leaf name. What resolution looks up.
    pub item: String,
    /// Which class the first segment put this edge in.
    pub origin: Origin,
    /// Whether [`resolve`] is what supplied `to`, rather than the text.
    ///
    /// **This is the flag the measurement counts, and it exists because the
    /// obvious discriminator is wrong.** An edge written `use crate::error::X`
    /// and one written `use crate::UsageError` both end as [`Origin::Internal`]
    /// onto `error`, and telling them apart by the item's case counts all 88
    /// ordinary edges in this crate as divergences — measured, on the first run
    /// of the case below. Only the edges resolution CHANGED are the ones a line
    /// predicate gets wrong, and only this field knows which those are.
    pub via_root: bool,
    /// Whether the edge was written as a qualified path in code (`crate::m::f()`,
    /// a `crate::m::T` type) rather than a `use` item.
    ///
    /// Both are edges a crate boundary has to cut, and before this field existed
    /// only the `use` half was collected: `config.rs` reached about thirty modules
    /// through inline paths while its `use` edges named seven, so every closure and
    /// layering verdict over this fact judged a graph missing most of its edges.
    /// Kept as a field rather than folded in silently, so a consumer can tell the
    /// two spellings apart. One edge per distinct `(to, item)` per file: a path
    /// written forty times is one dependency, not forty.
    pub qualified: bool,
    /// 1-indexed line of the `use` statement, or of the path's first occurrence.
    pub line: usize,
}

/// A file's crate-root export table: item name -> the module it really lives in,
/// or `None` where the root imported it from another crate.
///
/// Built from the root's own statements. `pub use` and a private `use` are both
/// read, and the difference is the whole point: a `pub use error::UsageError`
/// makes `crate::UsageError` an INTERNAL edge onto `error`, while a private
/// `use anyhow::Result` makes `crate::Result` an EXTERNAL one. A table that
/// recorded only the public half would resolve the first class and leave the
/// second reading as an edge to nothing.
pub type RootExports = BTreeMap<String, Option<String>>;

/// The crate root's export table, or the reason there is none.
///
/// [`Look::CouldNotLook`] when the text is not parseable Rust — never an empty
/// table, which would resolve nothing while looking exactly like a root that
/// re-exports nothing.
#[must_use]
pub fn root_exports(source: &str) -> Look<RootExports> {
    // THE ONE PARSE (CLOUD-1008), lossless; a text with any parse error is
    // could-not-look, never a partial table.
    let Look::Is(file) = crate::source::rust_tree(source, Edition::Edition2024) else {
        return Look::CouldNotLook;
    };
    Look::Is(exports_of(&file))
}

/// [`root_exports`] over an already-parsed file.
fn exports_of(file: &ast::SourceFile) -> RootExports {
    // THE ROOT'S OWN `mod` DECLARATIONS, COLLECTED FIRST, and they are what makes
    // the rest correct. At a crate root `use error::UsageError` and
    // `use anyhow::Result` are the SAME SHAPE — a bare first segment is either a
    // top-level module or another crate, and nothing in the statement says which.
    // The root declares its modules, so the answer is in the same file, and this
    // stays pure syntax rather than becoming name resolution.
    let modules: std::collections::BTreeSet<String> = file
        .items()
        .filter_map(|item| match item {
            ast::Item::Module(module) => module.name().map(|name| name.text().to_string()),
            _ => None,
        })
        .collect();
    // EVERY DECLARED MODULE IS ITS OWN ENTRY, and leaving them out is what the
    // tree corrected: `use crate::{config, rules}` imports MODULES directly, and
    // a table holding only re-exported items leaves 39 such edges in this crate
    // unresolved — measured, on the second run of `use_graph`. A module maps to
    // itself, which is what makes `resolve` able to say the text already named
    // the destination.
    let mut table: RootExports = modules
        .iter()
        .map(|name| (name.clone(), Some(name.clone())))
        .collect();
    for item in file.items() {
        let ast::Item::Use(item_use) = item else {
            continue;
        };
        if let Some(tree) = item_use.use_tree() {
            collect_root_tree(&tree, None, &modules, &mut table);
        }
    }
    table
}

/// One `use` tree read as `syn`'s nested shape: the path's segments, then
/// what ends it.
struct Shape {
    /// Every segment the tree's own path names, in order.
    segments: Vec<String>,
    /// What follows the segments.
    end: End,
}

/// How a `use` tree ends after its path.
enum End {
    /// The last segment is the imported name.
    Name,
    /// `… as alias`: the last segment is the original, the alias the local name.
    Rename(String),
    /// `…::*`.
    Glob,
    /// `…::{a, b}`.
    Group(Vec<ast::UseTree>),
}

/// The text of each segment of `path`, outermost first.
fn segments(path: &ast::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = Some(path.clone());
    while let Some(path) = at {
        if let Some(segment) = path.segment() {
            out.push(segment.syntax().text().to_string().trim().to_owned());
        }
        at = path.qualifier();
    }
    out.reverse();
    out
}

/// A `use` tree's [`Shape`], or `None` for one that names nothing.
fn shape(tree: &ast::UseTree) -> Option<Shape> {
    let segments = tree.path().map(|path| segments(&path)).unwrap_or_default();
    let end = if let Some(list) = tree.use_tree_list() {
        End::Group(list.use_trees().collect())
    } else if tree.star_token().is_some() {
        End::Glob
    } else if let Some(rename) = tree.rename() {
        End::Rename(
            rename
                .name()
                .map_or_else(|| "_".to_owned(), |name| name.text().to_string()),
        )
    } else {
        if segments.is_empty() {
            return None;
        }
        End::Name
    };
    Some(Shape { segments, end })
}

/// Walk one `use` tree in the crate root, recording what each leaf name resolves
/// to.
///
/// `first` carries the path's first segment once it is known, which is what
/// decides internal-versus-external for every leaf underneath it.
fn collect_root_tree(
    tree: &ast::UseTree,
    first: Option<&str>,
    modules: &std::collections::BTreeSet<String>,
    table: &mut RootExports,
) {
    let Some(Shape { segments, end }) = shape(tree) else {
        return;
    };
    let steps = match end {
        End::Name | End::Rename(_) => segments.len().saturating_sub(1),
        End::Glob | End::Group(_) => segments.len(),
    };
    let first = first
        .map(str::to_owned)
        .or_else(|| segments.first().filter(|_| steps > 0).cloned());
    let first = first.as_deref();
    match end {
        End::Name => {
            if let Some(name) = segments.last() {
                insert_root_name(name, first, modules, table);
            }
        }
        // The ALIAS is the name other modules can reach, so it is the key. The
        // original is unreachable through the root and recording it would invent
        // an edge nobody can write.
        End::Rename(alias) => insert_root_name(&alias, first, modules, table),
        // A glob at the root re-exports names this pass cannot enumerate without
        // resolving the target module. Deliberately not recorded: a guess here
        // would be a wrong edge, and an absent entry leaves the consumer's edge
        // unresolved and visibly so, which is the honest failure direction.
        End::Glob => {}
        End::Group(items) => {
            for item in &items {
                collect_root_tree(item, first, modules, table);
            }
        }
    }
}

/// Record one root-level leaf, keyed by the name a sibling module would write.
fn insert_root_name(
    name: &str,
    first: Option<&str>,
    modules: &std::collections::BTreeSet<String>,
    table: &mut RootExports,
) {
    let Some(first) = first else {
        return;
    };
    // `Some(module)` is an internal edge, `None` an external one — and the
    // declared-module set is the only thing that can tell them apart here.
    // A root that re-exports from its own submodule records the SUBMODULE, which
    // is the answer a layering table is keyed on.
    let module = if modules.contains(first) {
        Some(first.to_owned())
    } else {
        None
    };
    table.insert(name.to_owned(), module);
}

/// The 1-based line `offset` falls on in `source`.
fn line_of(source: &str, offset: usize) -> usize {
    source.get(..offset).map_or(1, |head| {
        head.bytes().filter(|byte| *byte == b'\n').count() + 1
    })
}

/// Every `use` edge in a Rust source text, or the reason there are none.
///
/// [`Look::CouldNotLook`] when the text does not parse — **never an empty list**.
/// A file nobody could parse and a file that imports nothing are different
/// answers, and Rego reads an undefined path as "does not hold", so collapsing
/// them is a layering gate that is silently off (CLOUD-251).
///
/// Edges whose [`Origin`] is [`Origin::RootItem`] arrive with an empty `to` and
/// are completed by [`resolve`]. Handing them back unresolved rather than
/// guessing is deliberate: a consumer that never resolves sees an obviously
/// blank destination instead of a plausible wrong one.
#[must_use]
pub fn use_edges(source: &str) -> Look<Vec<UseEdge>> {
    let Look::Is(file) = crate::source::rust_tree(source, Edition::Edition2024) else {
        return Look::CouldNotLook;
    };
    Look::Is(edges_of(source, &file))
}

/// [`use_edges`] over an already-parsed file.
fn edges_of(source: &str, file: &ast::SourceFile) -> Vec<UseEdge> {
    let mut found = Vec::new();
    for item_use in file.syntax().descendants().filter_map(ast::Use::cast) {
        let line = line_of(source, usize::from(item_use.syntax().text_range().start()));
        if let Some(tree) = item_use.use_tree() {
            collect_edges(&tree, None, line, &mut found);
        }
    }
    // A qualified path anywhere outside a `use` item: an expression callee, a
    // type, a trait bound, a pattern. Only the OUTERMOST path node is read (a
    // qualifier is a nested path), and paths under a `use` are its tree's, so
    // no edge is counted twice. Paths inside a macro's token tree are NOT seen:
    // the parser keeps them as tokens, the blind spot every syntactic reader here
    // states.
    for path in file.syntax().descendants().filter_map(ast::Path::cast) {
        if path.syntax().parent().and_then(ast::Path::cast).is_some()
            || path
                .syntax()
                .ancestors()
                .any(|node| ast::Use::can_cast(node.kind()))
        {
            continue;
        }
        let names = segments(&path);
        if names.len() < 2 || names[0] != "crate" {
            continue;
        }
        let line = line_of(source, usize::from(path.syntax().text_range().start()));
        let second = names[1].clone();
        let edge = if names.len() == 2 {
            // `crate::Item`: through the root's table, exactly as a `use`.
            UseEdge {
                to: String::new(),
                item: second,
                origin: Origin::RootItem,
                via_root: false,
                qualified: true,
                line,
            }
        } else {
            UseEdge {
                item: names.last().cloned().unwrap_or_else(|| second.clone()),
                to: second,
                origin: Origin::Internal,
                via_root: false,
                qualified: true,
                line,
            }
        };
        if !found
            .iter()
            .any(|seen: &UseEdge| seen.qualified && seen.to == edge.to && seen.item == edge.item)
        {
            found.push(edge);
        }
    }
    found
}

/// Walk one `use` tree, emitting an edge per leaf.
///
/// Per LEAF rather than per statement, because `use crate::{a::A, b::B}` is two
/// edges and reporting it as one would undercount exactly the grouped imports
/// this tree favours.
fn collect_edges(tree: &ast::UseTree, first: Option<&str>, line: usize, out: &mut Vec<UseEdge>) {
    let Some(Shape { segments, end }) = shape(tree) else {
        return;
    };
    let steps = match end {
        End::Name | End::Rename(_) => segments.len().saturating_sub(1),
        End::Glob | End::Group(_) => segments.len(),
    };
    let mut first = first.map(str::to_owned);
    for (at, segment) in segments.iter().take(steps).enumerate() {
        match first.as_deref() {
            // Already inside a path whose first segment is `crate`: THIS one is
            // the module — the ordinary internal edge, and the only place `to`
            // is filled in directly.
            Some("crate") => {
                let leaf = match &end {
                    End::Name | End::Rename(_) => segments.last().cloned(),
                    End::Glob | End::Group(_) => None,
                };
                // A leaf that IS this segment (`crate::a` ends at `a`) is not a
                // step; only a deeper leaf names the item.
                let item = leaf
                    .filter(|_| at + 1 < segments.len())
                    .unwrap_or_else(|| segment.clone());
                out.push(UseEdge {
                    to: segment.clone(),
                    item,
                    origin: Origin::Internal,
                    via_root: false,
                    qualified: false,
                    line,
                });
                return;
            }
            Some(_) => {}
            None => first = Some(segment.clone()),
        }
    }
    let first = first.as_deref();
    match end {
        // A rename is keyed by the ORIGINAL, because that is the name the root's
        // table is keyed on; the local alias is this file's business alone.
        End::Name | End::Rename(_) => {
            if let Some(name) = segments.last() {
                push_leaf(name, first, line, out);
            }
        }
        End::Glob => {
            if let Some(first) = first {
                push_leaf("*", Some(first), line, out);
            }
        }
        End::Group(items) => {
            for item in &items {
                collect_edges(item, first, line, out);
            }
        }
    }
}

/// Emit one leaf as an edge, classified by the path's first segment.
fn push_leaf(name: &str, first: Option<&str>, line: usize, out: &mut Vec<UseEdge>) {
    let Some(first) = first else {
        return;
    };
    let (origin, to) = match first {
        // THE CLASS THIS FACT EXISTS FOR: `use crate::<Item>` names no module.
        // `to` stays empty until `resolve` fills it, so an unresolved edge is
        // visibly blank rather than plausibly wrong.
        "crate" => (Origin::RootItem, String::new()),
        "self" | "super" => (Origin::Local, first.to_owned()),
        other => (Origin::External, other.to_owned()),
    };
    out.push(UseEdge {
        to,
        item: name.to_owned(),
        origin,
        via_root: false,
        qualified: false,
        line,
    });
}

/// Complete every [`Origin::RootItem`] edge against the crate root's table.
///
/// The two outcomes are the two measured classes, and they are deliberately
/// different values rather than one "unknown":
///
/// * the table names a module — the edge becomes [`Origin::Internal`] onto it,
///   which is the hidden internal edge a line predicate misses entirely;
/// * the table says the root imported the name from elsewhere — the edge becomes
///   [`Origin::External`], which is the phantom internal edge a line predicate
///   invents.
///
/// A name the table does not carry is **left unresolved**, `to` still empty. That
/// is could-not-look at the edge level: the root may re-export it through a glob
/// this pass declines to guess at, and a fabricated destination would be worse
/// than a blank one.
pub fn resolve(edges: &mut [UseEdge], root: &RootExports) {
    for edge in edges {
        if edge.origin != Origin::RootItem {
            continue;
        }
        match root.get(&edge.item) {
            Some(Some(module)) => {
                // `via_root` is FALSE when the name IS the module: the text named
                // its destination and a line predicate reads it correctly. Only a
                // name that had to be looked up is a divergence.
                edge.via_root = module != &edge.item;
                edge.to = module.clone();
                edge.origin = Origin::Internal;
            }
            Some(None) => {
                edge.origin = Origin::External;
                edge.via_root = true;
            }
            None => {}
        }
    }
}

/// One file's `use` edges and its own export table, from a single parse.
///
/// Both halves together because resolution needs both and parsing twice to get
/// them would double the cost of the fact for no property gained — the crate
/// root is a file like any other, and whichever file the caller nominates as the
/// root has already been parsed here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct UseFile {
    /// The edges this file writes, unresolved.
    pub edges: Vec<UseEdge>,
    /// What this file re-exports, for the case where it IS the crate root.
    #[serde(skip)]
    pub exports: RootExports,
}

/// A file's `use` facts, or the reason there are none (CLOUD-762).
///
/// [`Look::CouldNotLook`] when the text does not parse, never an empty
/// [`UseFile`] — the same contract [`use_edges`] holds and for the same reason.
#[must_use]
pub fn use_facts(source: &str) -> Look<UseFile> {
    // ONE PARSE for both halves, as the struct's doc says.
    let Look::Is(file) = crate::source::rust_tree(source, Edition::Edition2024) else {
        return Look::CouldNotLook;
    };
    Look::Is(UseFile {
        edges: edges_of(source, &file),
        exports: exports_of(&file),
    })
}
