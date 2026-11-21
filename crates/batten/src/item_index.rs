//! Which item a path names, across a tree's crates (CLOUD-2790).
//!
//! `test replay` asks whether a base test still holds at HEAD. A move that
//! respells a path — `crate::rules::Rule` becoming `crate::config_model::Rule`
//! once `Rule` lives in the model — changes no assertion, yet compares as a
//! modified body. This index resolves each path that starts at `crate::` or at
//! one of the tree's own crates to the file and name that DEFINE it, following
//! `use` and `pub use` aliases and modules re-exported from a sibling crate, so
//! a body is compared by the items it names rather than by how it spells them.
//!
//! THE CRATES COME FROM THE TREE, never from this repository's layout: a crate
//! is the directory of a `Cargo.toml` that declares `[package] name`, its
//! identifier that name with `-` read as `_`, and its modules the files under
//! that directory's `src/`. A consumer with one crate at its root and a
//! workspace with forty under `crates/` are read by the same rule (rule 1).
//!
//! What it reads, per indexed file: the items declared at the top level of the
//! file and of its inline modules (never a `#[cfg(test)]` one), and its `use`
//! declarations. What it does not resolve is left exactly as written:
//! `super::`, `self::`, a bare name a `use` brought in, a path through a type,
//! or a macro-built path. A path it cannot resolve therefore compares as
//! before, which is the direction that can only report more, never less.

use std::collections::BTreeMap;

use ra_ap_syntax::ast::{self, HasModuleItem as _, HasName as _, HasVisibility as _};
use ra_ap_syntax::{AstNode as _, Edition, SourceFile};

/// A defining site: the file an item is declared in, and its name there.
pub type Key = (String, String);

/// What one module holds.
#[derive(Debug, Default)]
struct Module {
    /// Items declared here: name to its declaration's text.
    declared: BTreeMap<String, String>,
    /// `use` aliases: the name visible here to the path it stands for.
    aliases: BTreeMap<String, Vec<String>>,
}

/// Every module of every crate in one tree.
#[derive(Debug, Default)]
pub struct Index {
    /// `(crate identifier, module path)` to its contents.
    modules: BTreeMap<(String, Vec<String>), Module>,
    /// Each indexed file's crate and module path.
    files: BTreeMap<String, (String, Vec<String>)>,
    /// Each crate root directory (`""` for the tree's root, else ending `/`)
    /// to its identifier, longest first so a nested crate wins.
    roots: Vec<(String, String)>,
}

/// The crate roots a tree declares: each `Cargo.toml` with a `[package] name`,
/// as its directory and identifier. A virtual manifest declares no crate.
fn crate_roots(manifests: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut roots: Vec<(String, String)> = manifests
        .iter()
        .filter_map(|(path, text)| {
            let dir = path.strip_suffix("Cargo.toml")?;
            if !(dir.is_empty() || dir.ends_with('/')) {
                return None;
            }
            let table: toml::Table = toml::from_str(text).ok()?;
            let name = table.get("package")?.get("name")?.as_str()?;
            Some((dir.to_owned(), name.replace('-', "_")))
        })
        .collect();
    roots.sort_by_key(|(dir, _)| std::cmp::Reverse(dir.len()));
    roots
}

/// The crate and module path `path` is, or `None` when it is no crate's
/// library source (a test, an example, a build script, a binary's `main`).
fn module_of(roots: &[(String, String)], path: &str) -> Option<(String, Vec<String>)> {
    let (dir, krate) = roots
        .iter()
        .find(|(dir, _)| path.starts_with(&format!("{dir}src/")))?;
    let inside = path.strip_prefix(&format!("{dir}src/"))?;
    let stem = inside.strip_suffix(".rs")?;
    let mut segments: Vec<String> = stem.split('/').map(str::to_owned).collect();
    match segments.last().map(String::as_str) {
        Some("lib") if segments.len() == 1 => segments.clear(),
        Some("main" | "build") if segments.len() == 1 => return None,
        Some("mod") => {
            segments.pop();
        }
        _ => {}
    }
    Some((krate.clone(), segments))
}

/// The name an item declares, when it declares one a path can name.
fn declared_name(item: &ast::Item) -> Option<String> {
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

/// Whitespace removed, so a reformat is not a difference.
fn shape(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// A path's resolution: the defining site, the crate and module declaring it,
/// how many of the path's segments it consumed, and whether it passed through
/// a SHIM — a `use crate::…` alias in a module other than its crate's root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    key: Key,
    krate: String,
    module: Vec<String>,
    used: usize,
    through_shim: bool,
}

impl Index {
    /// Index the library sources in `files` (path to text) of the crates
    /// `manifests` (path to `Cargo.toml` text) declare. A file that does not
    /// parse contributes nothing.
    #[must_use]
    pub fn new(files: &BTreeMap<String, String>, manifests: &BTreeMap<String, String>) -> Self {
        let mut index = Self {
            roots: crate_roots(manifests),
            ..Self::default()
        };
        for (path, text) in files {
            let Some((krate, module)) = module_of(&index.roots, path) else {
                continue;
            };
            // A file with a parse error contributes nothing: an index built on
            // a misread tree could resolve a path to the wrong item.
            let parse = SourceFile::parse(text, Edition::Edition2024);
            if !parse.errors().is_empty() {
                continue;
            }
            index
                .files
                .insert(path.clone(), (krate.clone(), module.clone()));
            let items: Vec<ast::Item> = parse.tree().items().collect();
            index.add(&krate, &module, &items);
        }
        index
    }

    fn add(&mut self, krate: &str, module: &[String], items: &[ast::Item]) {
        let mut inline = Vec::new();
        {
            let entry = self
                .modules
                .entry((krate.to_owned(), module.to_vec()))
                .or_default();
            for item in items {
                if crate::module_graph::cfg_test(item.syntax()) {
                    continue;
                }
                if let Some(name) = declared_name(item) {
                    entry
                        .declared
                        .insert(name, item.syntax().text().to_string());
                }
                match item {
                    ast::Item::Use(declaration) => {
                        if let Some(tree) = declaration.use_tree() {
                            entry.aliases.extend(
                                crate::module_graph::use_leaves(&tree)
                                    .into_iter()
                                    .map(|leaf| (leaf.name, leaf.path)),
                            );
                        }
                    }
                    ast::Item::Module(nested) => {
                        if let (Some(name), Some(list)) = (nested.name(), nested.item_list()) {
                            inline
                                .push((name.text().to_string(), list.items().collect::<Vec<_>>()));
                        }
                    }
                    _ => {}
                }
            }
        }
        for (name, nested_items) in inline {
            let mut path = module.to_vec();
            path.push(name);
            self.add(krate, &path, &nested_items);
        }
    }

    /// The crate whose `crate::` paths a file's code means, when it is a
    /// library source this index read.
    #[must_use]
    pub fn crate_of(&self, path: &str) -> Option<String> {
        self.files.get(path).map(|(krate, _)| krate.clone())
    }

    /// The file a module's items live in: the indexed file whose module path
    /// is the longest prefix of `module` in `krate` (an inline module lives in
    /// its parent's file).
    fn file_of(&self, krate: &str, module: &[String]) -> Option<String> {
        self.files
            .iter()
            .filter(|(_, (file_krate, file_module))| {
                file_krate == krate && module.starts_with(file_module)
            })
            .max_by_key(|(_, (_, file_module))| file_module.len())
            .map(|(path, _)| path.clone())
    }

    /// The resolution of an absolute path (`[crate, module.., Name, ..]`), or
    /// `None` when it does not resolve within `depth` alias hops.
    fn resolve_from(&self, segments: &[String], depth: u8) -> Option<Found> {
        if depth == 0 {
            return None;
        }
        let (krate, rest) = segments.split_first()?;
        let mut module: Vec<String> = Vec::new();
        for (at, segment) in rest.iter().enumerate() {
            let here = self.modules.get(&(krate.clone(), module.clone()))?;
            let mut deeper = module.clone();
            deeper.push(segment.clone());
            if self.modules.contains_key(&(krate.clone(), deeper.clone())) {
                module = deeper;
                continue;
            }
            if here.declared.contains_key(segment) {
                let file = self.file_of(krate, &module)?;
                return Some(Found {
                    key: (file, segment.clone()),
                    krate: krate.clone(),
                    module,
                    used: at + 2,
                    through_shim: false,
                });
            }
            let target = here.aliases.get(segment)?;
            // A `crate::`/`self::` alias outside the crate root is a shim; one
            // at the root is the crate's stated surface.
            let shim = matches!(target.first().map(String::as_str), Some("crate" | "self"))
                && !module.is_empty();
            let mut absolute: Vec<String> = match target.first().map(String::as_str) {
                Some("crate") => std::iter::once(krate.clone())
                    .chain(target[1..].iter().cloned())
                    .collect(),
                Some("self") => std::iter::once(krate.clone())
                    .chain(module.iter().cloned())
                    .chain(target[1..].iter().cloned())
                    .collect(),
                Some("super") => return None,
                _ => target.clone(),
            };
            let alias_len = absolute.len();
            absolute.extend(rest[at + 1..].iter().cloned());
            let mut found = self.resolve_from(&absolute, depth - 1)?;
            // The original path consumed everything through this segment,
            // plus whatever of its remainder the alias's resolution used.
            found.used = at + 2 + found.used.saturating_sub(alias_len);
            found.through_shim |= shim;
            return Some(found);
        }
        None
    }

    /// The resolution of `path` read from inside `krate`. Only a path starting
    /// at `crate` or at one of the tree's crates is resolved.
    fn resolve_found(&self, krate: &str, path: &[String]) -> Option<Found> {
        let first = path.first()?;
        let absolute: Vec<String> = if first == "crate" {
            std::iter::once(krate.to_owned())
                .chain(path[1..].iter().cloned())
                .collect()
        } else if self.modules.contains_key(&(first.clone(), Vec::new())) {
            path.to_vec()
        } else {
            return None;
        };
        self.resolve_from(&absolute, 8)
    }

    /// The defining site of `path` read from inside `krate`, and how many of
    /// its segments that consumed.
    #[must_use]
    pub fn resolve(&self, krate: &str, path: &[String]) -> Option<(Key, usize)> {
        self.resolve_found(krate, path)
            .map(|found| (found.key, found.used))
    }

    /// How a reader in crate `from` spells a resolved item at its home:
    /// `crate::m::Name` inside its own crate, `<crate>::m::Name` elsewhere
    /// (`from` is empty for a file no crate's library holds).
    fn home(found: &Found, from: &str) -> String {
        let head = if found.krate == from {
            "crate"
        } else {
            found.krate.as_str()
        };
        std::iter::once(head)
            .chain(found.module.iter().map(String::as_str))
            .chain(std::iter::once(found.key.1.as_str()))
            .collect::<Vec<_>>()
            .join("::")
    }

    /// Every defining site of `name`: the file and declaration text of each.
    fn sites(&self, name: &str) -> Vec<(String, String)> {
        let mut found: Vec<(String, String)> = self
            .modules
            .iter()
            .filter_map(|((krate, module), held)| {
                let text = held.declared.get(name)?;
                Some((self.file_of(krate, module)?, text.clone()))
            })
            .collect();
        found.sort();
        found.dedup();
        found
    }
}

/// Items that moved between files from `before` to `after`.
///
/// TWO CONDITIONS, AND THE SECOND IS WHAT MAKES IT SAFE. The name is declared
/// in exactly one file on each side and they differ — `git::pair_moves`' rule
/// for files — AND the declaration is the same item: its text, with every path
/// it names resolved, is equal on both sides. Name alone pairs a deleted item
/// with an unrelated new one that happens to share its name, and a test
/// switched from one to the other would then compare as unchanged. An item
/// whose declaration was edited is not a move either, so a test naming it is
/// judged as modified: the direction that reports.
#[must_use]
pub fn moved_items(before: &Index, after: &Index) -> BTreeMap<Key, Key> {
    let mut moves = BTreeMap::new();
    let names: std::collections::BTreeSet<&String> = before
        .modules
        .values()
        .flat_map(|module| module.declared.keys())
        .collect();
    for name in names {
        let (base, head) = (before.sites(name), after.sites(name));
        let ([(base_file, base_text)], [(head_file, head_text)]) =
            (base.as_slice(), head.as_slice())
        else {
            continue;
        };
        if base_file == head_file {
            continue;
        }
        let same = |index: &Index, file: &str, text: &str| {
            let krate = index.crate_of(file).unwrap_or_default();
            shape(&canonical(text, &krate, index, &BTreeMap::new()))
        };
        if same(before, base_file, base_text) == same(after, head_file, head_text) {
            moves.insert(
                (base_file.clone(), name.clone()),
                (head_file.clone(), name.clone()),
            );
        }
    }
    moves
}

/// `body` with every resolvable path replaced by the site that defines it,
/// mapped through `moves`, so two bodies naming the same items compare equal
/// however they spell them. String, raw-string and char literals are left
/// untouched: a path inside a string is data the test asserts on.
#[must_use]
pub fn canonical(body: &str, krate: &str, index: &Index, moves: &BTreeMap<Key, Key>) -> String {
    let mut out = String::with_capacity(body.len());
    let bytes = body.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &body[at..];
        if let Some(len) = literal_len(rest) {
            out.push_str(&rest[..len]);
            at += len;
            continue;
        }
        let starts_path = at == 0 || !(is_ident_byte(bytes[at - 1]) || bytes[at - 1] == b':');
        if starts_path
            && let Some((segments, len)) = path_at(rest)
            && let Some(((file, name), used)) = index.resolve(krate, &segments)
        {
            let (file, name) = moves
                .get(&(file.clone(), name.clone()))
                .cloned()
                .unwrap_or((file, name));
            out.push('⟨');
            out.push_str(&file);
            out.push('#');
            out.push_str(&name);
            out.push('⟩');
            for segment in &segments[used.min(segments.len())..] {
                out.push_str("::");
                out.push_str(segment);
            }
            at += len;
            continue;
        }
        let next = rest.chars().next().map_or(1, char::len_utf8);
        out.push_str(&rest[..next]);
        at += next;
    }
    out
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The length of a string, raw string or char literal at the start of `text`.
fn literal_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if text.starts_with('"') {
        let mut at = 1;
        while at < bytes.len() {
            match bytes[at] {
                b'\\' => at += 2,
                b'"' => return Some(at + 1),
                _ => at += 1,
            }
        }
        return Some(bytes.len());
    }
    if let Some(after) = text.strip_prefix('r') {
        let hashes = after.bytes().take_while(|&b| b == b'#').count();
        if after[hashes..].starts_with('"') {
            let close = format!("\"{}", "#".repeat(hashes));
            let body = &after[hashes + 1..];
            return Some(
                body.find(&close)
                    .map_or(text.len(), |end| 1 + hashes + 1 + end + close.len()),
            );
        }
    }
    if text.starts_with('\'') {
        // A char literal closes within a few characters; a lifetime does not.
        let (close, _) = text[1..]
            .char_indices()
            .take(10)
            .find(|&(_, c)| c == '\'')?;
        let inner = &text[1..=close];
        if inner.chars().count() == 1 || inner.starts_with('\\') {
            return Some(close + 2);
        }
    }
    None
}

/// A `::`-separated path of two or more identifiers at the start of `text`,
/// and its length in bytes.
fn path_at(text: &str) -> Option<(Vec<String>, usize)> {
    let mut segments = Vec::new();
    let mut at = 0;
    loop {
        let ident: String = text[at..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if ident.is_empty() || ident.as_bytes()[0].is_ascii_digit() {
            break;
        }
        at += ident.len();
        segments.push(ident);
        if text[at..].starts_with("::")
            && text[at + 2..].starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        {
            at += 2;
        } else {
            break;
        }
    }
    (segments.len() >= 2).then_some((segments, at))
}

/// Every file of `files` whose text changes when each path through a shim is
/// respelled at its item's home and each shim becomes a private `use`
/// (CLOUD-2793's `respell-through-shims`). `manifests` declares the crates.
///
/// THREE PASSES PER FILE, in this order:
/// 1. A grouped `use` (`use crate::rules::{Rule, Kind};`) with a leaf reaching
///    through a shim is regenerated from the syntax tree, one `use` per home
///    module, keeping its attributes and visibility: pass 2's scan cannot see
///    inside a group.
/// 2. Every other path resolving through a shim — in code, a `use`, a doc link
///    or a macro — is respelled at its item's home, keeping the segments after
///    the item. String and char literals are never touched.
/// 3. In a library file below its crate's root, a `pub` or `pub(crate)`
///    `use crate::…` loses its visibility: it may still serve its own module's
///    bare names, and `cargo fix` removes the ones nothing uses.
///
/// A path the index cannot resolve is left as written, so what this misses is
/// a compile error naming the site, never a silent change.
#[must_use]
pub fn respell_through_shims(
    files: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let index = Index::new(files, manifests);
    files
        .iter()
        .filter_map(|(path, text)| {
            let from = index.crate_of(path).unwrap_or_default();
            let grouped = regroup_uses(text, &from, &index);
            let respelled = respell_paths(&grouped, &from, &index);
            let below_root = index
                .files
                .get(path)
                .is_some_and(|(_, module)| !module.is_empty());
            let out = if below_root {
                downgrade_shims(&respelled)
            } else {
                respelled
            };
            (out != *text).then(|| (path.clone(), out))
        })
        .collect()
}

/// Pass 1: a grouped `use` with a leaf through a shim, regenerated by home.
fn regroup_uses(text: &str, from: &str, index: &Index) -> String {
    let parse = SourceFile::parse(text, Edition::Edition2024);
    if !parse.errors().is_empty() {
        return text.to_owned();
    }
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    for declaration in parse
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::Use::cast)
    {
        let Some(tree) = declaration.use_tree() else {
            continue;
        };
        if !tree
            .syntax()
            .descendants()
            .any(|node| ast::UseTreeList::can_cast(node.kind()))
        {
            continue;
        }
        let resolved: Vec<(crate::module_graph::UseLeaf, Option<Found>)> =
            crate::module_graph::use_leaves(&tree)
                .into_iter()
                .map(|leaf| {
                    let hit = index
                        .resolve_found(from, &leaf.path)
                        .filter(|found| found.through_shim);
                    (leaf, hit)
                })
                .collect();
        if resolved.iter().all(|(_, hit)| hit.is_none()) {
            continue;
        }
        // Attributes and visibility: every token before `use`.
        let head: String = declaration
            .syntax()
            .children_with_tokens()
            .take_while(|child| child.kind() != ra_ap_syntax::SyntaxKind::USE_KW)
            .map(|child| child.to_string())
            .collect();
        let mut by_prefix: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (leaf, hit) in resolved {
            let full = hit.map_or_else(|| leaf.path.join("::"), |found| Index::home(&found, from));
            let (prefix, last) = full.rsplit_once("::").unwrap_or(("", full.as_str()));
            let item = if leaf.renamed && leaf.name != last {
                format!("{last} as {}", leaf.name)
            } else {
                last.to_owned()
            };
            by_prefix.entry(prefix.to_owned()).or_default().push(item);
        }
        let lines: Vec<String> = by_prefix
            .into_iter()
            .map(|(prefix, items)| {
                let tail = match items.as_slice() {
                    [one] => one.clone(),
                    _ => format!("{{{}}}", items.join(", ")),
                };
                if prefix.is_empty() {
                    format!("{head}use {tail};")
                } else {
                    format!("{head}use {prefix}::{tail};")
                }
            })
            .collect();
        let range = declaration.syntax().text_range();
        edits.push((
            usize::from(range.start())..usize::from(range.end()),
            lines.join("\n"),
        ));
    }
    let mut out = text.to_owned();
    for (range, replacement) in edits.into_iter().rev() {
        out.replace_range(range, &replacement);
    }
    out
}

/// Pass 2: every resolvable path through a shim, respelled at its home.
fn respell_paths(body: &str, from: &str, index: &Index) -> String {
    let mut out = String::with_capacity(body.len());
    let bytes = body.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &body[at..];
        if let Some(len) = literal_len(rest) {
            out.push_str(&rest[..len]);
            at += len;
            continue;
        }
        let starts_path = at == 0 || !(is_ident_byte(bytes[at - 1]) || bytes[at - 1] == b':');
        if starts_path
            && let Some((segments, len)) = path_at(rest)
            && let Some(found) = index.resolve_found(from, &segments)
            && found.through_shim
        {
            out.push_str(&Index::home(&found, from));
            for segment in &segments[found.used.min(segments.len())..] {
                out.push_str("::");
                out.push_str(segment);
            }
            at += len;
            continue;
        }
        let next = rest.chars().next().map_or(1, char::len_utf8);
        out.push_str(&rest[..next]);
        at += next;
    }
    out
}

/// Pass 3: `pub use crate::…` and `pub(crate) use crate::…` become `use crate::…`.
fn downgrade_shims(text: &str) -> String {
    let parse = SourceFile::parse(text, Edition::Edition2024);
    if !parse.errors().is_empty() {
        return text.to_owned();
    }
    let mut cuts: Vec<std::ops::Range<usize>> = Vec::new();
    for declaration in parse
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::Use::cast)
    {
        let Some(visibility) = declaration.visibility() else {
            continue;
        };
        let spelled: String = visibility
            .syntax()
            .text()
            .to_string()
            .split_whitespace()
            .collect();
        let crate_rooted = declaration
            .use_tree()
            .and_then(|tree| tree.path())
            .is_some_and(|path| path.syntax().text().to_string().starts_with("crate"));
        if matches!(spelled.as_str(), "pub" | "pub(crate)") && crate_rooted {
            let range = visibility.syntax().text_range();
            // The visibility and the one space after it.
            let end = usize::from(range.end());
            let end = if text[end..].starts_with(' ') {
                end + 1
            } else {
                end
            };
            cuts.push(usize::from(range.start())..end);
        }
    }
    let mut out = text.to_owned();
    for range in cuts.into_iter().rev() {
        out.replace_range(range, "");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const ROOT: (&str, &str) = ("Cargo.toml", "[package]\nname = \"app\"\n");

    fn tree(files: &[(&str, &str)]) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let (manifests, sources): (Vec<_>, Vec<_>) = files
            .iter()
            .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
            .partition(|(path, _)| path.ends_with("Cargo.toml"));
        (
            sources.into_iter().collect(),
            manifests.into_iter().collect(),
        )
    }

    fn index(files: &[(&str, &str)]) -> Index {
        let (sources, manifests) = tree(files);
        Index::new(&sources, &manifests)
    }

    /// Two bodies, each read through its own tree, the base side mapped
    /// through the moves between them.
    fn same(
        before: &[(&str, &str)],
        after: &[(&str, &str)],
        base_body: &str,
        head_body: &str,
    ) -> bool {
        let (base, head) = (index(before), index(after));
        let moves = moved_items(&base, &head);
        canonical(base_body, "app", &base, &moves)
            == canonical(head_body, "app", &head, &BTreeMap::new())
    }

    const BEFORE_MOVE: &[(&str, &str)] = &[
        ROOT,
        ("src/lib.rs", "pub mod rules;\npub mod model;\n"),
        ("src/rules.rs", "pub struct Rule;\n"),
        ("src/model.rs", ""),
    ];
    const AFTER_MOVE: &[(&str, &str)] = &[
        ROOT,
        ("src/lib.rs", "pub mod rules;\npub mod model;\n"),
        ("src/rules.rs", ""),
        ("src/model.rs", "pub struct Rule;\n"),
    ];

    /// Fails by: a respelling at a moved item's new home compared as a
    /// modified assertion, which is what made every move cost an admission.
    #[test]
    fn a_path_respelled_at_a_moved_items_home_names_the_same_item() {
        assert!(same(
            BEFORE_MOVE,
            AFTER_MOVE,
            "{ let r = crate::rules::Rule; }",
            "{ let r = crate::model::Rule; }",
        ));
    }

    /// Fails by: a re-export not followed, so a body spelled through a shim at
    /// base and at the defining module at head looked modified.
    #[test]
    fn a_re_export_names_the_item_it_re_exports() {
        let files = &[
            ROOT,
            ("src/lib.rs", "pub mod rules;\npub mod model;\n"),
            ("src/rules.rs", "pub use crate::model::Rule;\n"),
            ("src/model.rs", "pub struct Rule;\n"),
        ];
        assert!(same(
            files,
            files,
            "{ crate::rules::Rule::check(); }",
            "{ crate::model::Rule::check(); }"
        ));
    }

    /// Fails by: a sibling crate's module re-export not followed, so a helper
    /// moved into another crate looked like a different item. The crates come
    /// from the manifests, under any directory.
    #[test]
    fn a_module_re_exported_from_a_sibling_crate_resolves_there() {
        let core = ("libs/core/Cargo.toml", "[package]\nname = \"app-core\"\n");
        let before = &[
            ROOT,
            core,
            (
                "src/lib.rs",
                "pub use app_core::selector;\npub mod rules;\n",
            ),
            ("src/rules.rs", "pub fn glob_match() {}\n"),
            ("libs/core/src/lib.rs", "pub mod selector;\n"),
            ("libs/core/src/selector.rs", ""),
        ];
        let after = &[
            ROOT,
            core,
            (
                "src/lib.rs",
                "pub use app_core::selector;\npub mod rules;\n",
            ),
            ("src/rules.rs", ""),
            ("libs/core/src/lib.rs", "pub mod selector;\n"),
            ("libs/core/src/selector.rs", "pub fn glob_match() {}\n"),
        ];
        assert!(same(
            before,
            after,
            "{ assert!(crate::rules::glob_match()); }",
            "{ assert!(crate::selector::glob_match()); }",
        ));
    }

    /// Fails by: a use tree's rename, group or `self` arm dropped, so a path
    /// through one resolved nowhere and compared as written.
    #[test]
    fn a_use_rename_group_and_self_each_resolve() {
        let files = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "pub struct X;\npub struct Y;\n"),
            (
                "src/b.rs",
                "pub use crate::a::{X as Z, Y, self as inner};\n",
            ),
        ];
        assert!(same(files, files, "{ crate::b::Z }", "{ crate::a::X }"));
        assert!(same(files, files, "{ crate::b::Y }", "{ crate::a::Y }"));
        assert!(same(
            files,
            files,
            "{ crate::b::inner::X }",
            "{ crate::a::X }"
        ));
    }

    /// Fails by: an inline module skipped (its items would never resolve), or
    /// a `#[cfg(test)]` module indexed (a test helper would pass for a library
    /// item).
    #[test]
    fn an_inline_module_is_indexed_and_a_cfg_test_module_is_not() {
        let built = index(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod outer { pub struct In; }\n#[cfg(test)]\nmod t { pub struct Hidden; }\n",
            ),
        ]);
        let empty = BTreeMap::new();
        assert_eq!(
            canonical("crate::outer::In", "app", &built, &empty),
            "⟨src/lib.rs#In⟩"
        );
        assert_eq!(
            canonical("crate::t::Hidden", "app", &built, &empty),
            "crate::t::Hidden"
        );
    }

    /// Fails by: the segments after the item dropped, so two bodies calling
    /// different methods of one type compared equal.
    #[test]
    fn a_path_through_an_item_keeps_its_tail() {
        let built = index(AFTER_MOVE);
        let empty = BTreeMap::new();
        assert_eq!(
            canonical("crate::model::Rule::check()", "app", &built, &empty),
            "⟨src/model.rs#Rule⟩::check()"
        );
        assert!(!same(
            AFTER_MOVE,
            AFTER_MOVE,
            "{ crate::model::Rule::a() }",
            "{ crate::model::Rule::b() }"
        ));
    }

    /// Fails by: resolution by name alone. Two items of one name are two items.
    #[test]
    fn a_different_item_of_the_same_name_is_a_different_item() {
        let files = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "pub fn parse() {}\n"),
            ("src/b.rs", "pub fn parse() {}\n"),
        ];
        assert!(!same(
            files,
            files,
            "{ crate::a::parse(); }",
            "{ crate::b::parse(); }"
        ));
    }

    /// Fails by: pairing a deleted item with an unrelated new one of its name,
    /// which let a test switched from one to the other read as unchanged.
    #[test]
    fn an_item_deleted_and_another_of_its_name_added_is_not_a_move() {
        let before = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "pub fn value() -> u8 { 1 }\n"),
            ("src/b.rs", ""),
        ];
        let after = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", ""),
            ("src/b.rs", "pub fn value() -> u8 { 2 }\n"),
        ];
        assert!(!same(
            before,
            after,
            "{ crate::a::value() }",
            "{ crate::b::value() }"
        ));
    }

    /// Fails by: a moved item whose declaration also changed paired as a move,
    /// so a test naming it would skip the replay its changed code needs.
    #[test]
    fn an_item_whose_declaration_changed_is_not_a_move() {
        let after = &[
            ROOT,
            ("src/lib.rs", "pub mod rules;\npub mod model;\n"),
            ("src/rules.rs", ""),
            ("src/model.rs", "pub struct Rule(u8);\n"),
        ];
        assert!(!same(
            BEFORE_MOVE,
            after,
            "{ crate::rules::Rule }",
            "{ crate::model::Rule }"
        ));
        assert!(moved_items(&index(BEFORE_MOVE), &index(after)).is_empty());
    }

    /// Fails by: a name declared twice at base paired with its one head site.
    #[test]
    fn a_name_declared_twice_at_base_is_not_paired() {
        let before = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\npub mod c;\n"),
            ("src/a.rs", "pub fn parse() {}\n"),
            ("src/b.rs", ""),
            ("src/c.rs", "pub fn parse() {}\n"),
        ];
        let after = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\npub mod c;\n"),
            ("src/a.rs", ""),
            ("src/b.rs", "pub fn parse() {}\n"),
            ("src/c.rs", ""),
        ];
        assert!(moved_items(&index(before), &index(after)).is_empty());
        assert!(!same(
            before,
            after,
            "{ crate::a::parse(); }",
            "{ crate::b::parse(); }"
        ));
    }

    /// Fails by: a changed assertion hidden behind a path. Only the path is
    /// canonical; every other token still has to match.
    #[test]
    fn an_assertion_that_changed_still_differs() {
        assert!(!same(
            BEFORE_MOVE,
            AFTER_MOVE,
            "{ assert_eq!(crate::rules::Rule::count(), 2); }",
            "{ assert_eq!(crate::model::Rule::count(), 3); }",
        ));
    }

    /// Fails by: a path inside a string literal rewritten. A string is data.
    #[test]
    fn a_path_inside_a_string_is_data() {
        let files = &[
            ROOT,
            ("src/lib.rs", "pub mod rules;\npub mod model;\n"),
            ("src/rules.rs", "pub use crate::model::Rule;\n"),
            ("src/model.rs", "pub struct Rule;\n"),
        ];
        assert!(!same(
            files,
            files,
            r#"{ assert_eq!(name(), "crate::rules::Rule"); }"#,
            r#"{ assert_eq!(name(), "crate::model::Rule"); }"#,
        ));
    }

    /// Fails by: a raw string rewritten, or a `'"'` char literal read as the
    /// start of a string that then swallows the code after it.
    #[test]
    fn a_raw_string_and_a_char_literal_are_data() {
        let built = index(BEFORE_MOVE);
        let body = r##"{ let s = r#"crate::rules::Rule"#; let q = '"'; crate::rules::Rule }"##;
        assert_eq!(
            canonical(body, "app", &built, &BTreeMap::new()),
            r##"{ let s = r#"crate::rules::Rule"#; let q = '"'; ⟨src/rules.rs#Rule⟩ }"##
        );
    }

    /// Fails by: a glob treated as naming something, so a path through it
    /// resolved to a guess.
    #[test]
    fn a_glob_names_nothing() {
        let built = index(&[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "pub struct X;\n"),
            ("src/b.rs", "pub use crate::a::*;\n"),
        ]);
        assert_eq!(
            canonical("crate::b::X", "app", &built, &BTreeMap::new()),
            "crate::b::X"
        );
    }

    /// Fails by: an alias cycle followed forever. It stops, unresolved.
    #[test]
    fn an_alias_cycle_stops_at_the_depth_bound() {
        let built = index(&[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "pub use crate::b::X;\n"),
            ("src/b.rs", "pub use crate::a::X;\n"),
        ]);
        assert_eq!(
            canonical("crate::a::X", "app", &built, &BTreeMap::new()),
            "crate::a::X"
        );
    }

    /// Fails by: an unresolvable path changed or dropped.
    #[test]
    fn an_unresolvable_path_is_left_as_written() {
        let built = index(&[ROOT, ("src/lib.rs", "")]);
        let body = "{ std::fs::read(p); super::helper(); 'a: loop {} }";
        assert_eq!(canonical(body, "app", &built, &BTreeMap::new()), body);
    }

    /// Fails by: a file's crate or module misread, which every answer rests on.
    /// The crate is the nearest manifest's package, wherever it sits.
    #[test]
    fn a_files_crate_and_module_come_from_its_path() {
        let roots = crate_roots(
            &tree(&[
                ROOT,
                ("tools/x/Cargo.toml", "[package]\nname = \"x-tool\"\n"),
                ("ws/Cargo.toml", "[workspace]\nmembers = []\n"),
            ])
            .1,
        );
        assert_eq!(
            module_of(&roots, "src/lib.rs"),
            Some((String::from("app"), vec![]))
        );
        assert_eq!(
            module_of(&roots, "src/mutate/mod.rs"),
            Some((String::from("app"), vec![String::from("mutate")]))
        );
        assert_eq!(
            module_of(&roots, "tools/x/src/a/b.rs"),
            Some((
                String::from("x_tool"),
                vec![String::from("a"), String::from("b")]
            ))
        );
        assert_eq!(module_of(&roots, "tests/it/main.rs"), None);
        assert_eq!(module_of(&roots, "src/main.rs"), None);
        assert_eq!(
            module_of(&roots, "ws/src/lib.rs"),
            None,
            "a virtual manifest is no crate"
        );
    }

    const SHIMMED: &[(&str, &str)] = &[
        ROOT,
        (
            "src/lib.rs",
            "pub mod rules;\npub mod model;\npub mod user;\npub use model::Root;\n",
        ),
        (
            "src/model.rs",
            "pub struct Rule;\npub struct Kind;\npub struct Root;\n",
        ),
        (
            "src/rules.rs",
            "pub use crate::model::{Kind, Rule};\npub fn check(_: &Rule) {}\n",
        ),
        (
            "src/user.rs",
            "use crate::rules::{check, Kind, Rule};\npub fn f() -> crate::rules::Rule { let _ = \"crate::rules::Rule\"; crate::Root; Rule }\n",
        ),
        ("tests/it.rs", "fn t() { let _ = app::rules::Rule; }\n"),
    ];

    fn respelled(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        let (sources, manifests) = tree(files);
        respell_through_shims(&sources, &manifests)
    }

    /// Fails by: a path through a shim left at the shim, so deleting the shim
    /// breaks it; a crate-root re-export (the crate's stated surface)
    /// respelled; or a string touched.
    #[test]
    fn a_path_through_a_shim_is_respelled_at_its_home_and_nothing_else_moves() {
        let changed = respelled(SHIMMED);
        let user = &changed["src/user.rs"];
        assert!(user.contains("-> crate::model::Rule"), "{user}");
        assert!(
            user.contains("\"crate::rules::Rule\""),
            "a string is data: {user}"
        );
        assert!(
            user.contains("crate::Root;"),
            "a root re-export stays: {user}"
        );
    }

    /// Fails by: a grouped import through a shim left whole, or split without
    /// keeping its non-shim leaf at its own path.
    #[test]
    fn a_grouped_import_through_a_shim_is_regrouped_by_home() {
        let user = respelled(SHIMMED)["src/user.rs"].clone();
        assert!(user.contains("use crate::model::{Kind, Rule};"), "{user}");
        assert!(user.contains("use crate::rules::check;"), "{user}");
    }

    /// Fails by: a shim kept public (it would still count), deleted where its
    /// own module still names the item bare, or the crate root's own
    /// re-export downgraded.
    #[test]
    fn a_shim_becomes_a_private_use_and_the_roots_surface_stays() {
        let changed = respelled(SHIMMED);
        let rules = &changed["src/rules.rs"];
        assert!(
            rules.starts_with("use crate::model::{Kind, Rule};"),
            "{rules}"
        );
        assert!(
            !changed.contains_key("src/lib.rs"),
            "{:?}",
            changed.get("src/lib.rs")
        );
    }

    /// Fails by: a file outside the crate's library (an integration test)
    /// left naming the shim through the crate's name.
    #[test]
    fn a_test_outside_the_crate_is_respelled_through_the_crate_name() {
        let test = respelled(SHIMMED)["tests/it.rs"].clone();
        assert!(test.contains("app::model::Rule"), "{test}");
    }

    /// Fails by: a second run changing anything — the migrated tree is a
    /// fixed point, which is the recipe's own regression test.
    #[test]
    fn respelling_twice_changes_nothing() {
        let (mut sources, manifests) = tree(SHIMMED);
        for (path, text) in respell_through_shims(&sources, &manifests) {
            sources.insert(path, text);
        }
        assert!(respell_through_shims(&sources, &manifests).is_empty());
    }
}
