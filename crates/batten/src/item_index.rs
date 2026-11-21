//! Which item a path names, across a tree's crates (CLOUD-2790).
//!
//! `test replay` asks whether a base test still holds at HEAD. A move that
//! respells a path — `crate::config_model::Rule` becoming `crate::config_model::Rule`
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

use ra_ap_syntax::ast::{
    self, HasAttrs as _, HasModuleItem as _, HasName as _, HasVisibility as _,
};
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
    /// Every module declared `pub`, as `(crate, module path)`: a path into a
    /// module outside this set does not compile from another crate.
    public: std::collections::BTreeSet<(String, Vec<String>)>,
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

/// A SHIM: a `use crate::…` or `use self::…` alias in a module other than
/// its crate's root (a root alias is the crate's stated surface). It is named
/// by the crate and module holding it and the name it makes visible there.
type Shim = (String, Vec<String>, String);

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
                        if let Some(name) = nested.name()
                            && nested.visibility().is_some_and(|visibility| {
                                visibility.syntax().text().to_string() == "pub"
                            })
                        {
                            let mut path = module.to_vec();
                            path.push(name.text().to_string());
                            self.public.insert((krate.to_owned(), path));
                        }
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

    /// The defining site of an absolute path (`[crate, module.., Name, ..]`),
    /// and how many of its segments that consumed; or `None` when it does not
    /// resolve within `depth` alias hops.
    fn resolve_from(&self, segments: &[String], depth: u8) -> Option<(Key, usize)> {
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
                return Some(((file, segment.clone()), at + 2));
            }
            let target = here.aliases.get(segment)?;
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
            let (key, used) = self.resolve_from(&absolute, depth - 1)?;
            // The original path consumed everything through this segment,
            // plus whatever of its remainder the alias's resolution used.
            return Some((key, at + 2 + used.saturating_sub(alias_len)));
        }
        None
    }

    /// `path` as an absolute path (`[crate, ..]`) read from inside `krate`:
    /// one starting at `crate` or at one of the tree's crates, or — in a
    /// crate root file (`at_root`) — at one of the root's child modules.
    fn absolute(&self, krate: &str, at_root: bool, path: &[String]) -> Option<Vec<String>> {
        let first = path.first()?;
        if first == "crate" {
            return Some(
                std::iter::once(krate.to_owned())
                    .chain(path[1..].iter().cloned())
                    .collect(),
            );
        }
        if at_root
            && self
                .modules
                .contains_key(&(krate.to_owned(), vec![first.clone()]))
        {
            return Some(
                std::iter::once(krate.to_owned())
                    .chain(path.iter().cloned())
                    .collect(),
            );
        }
        self.modules
            .contains_key(&(first.clone(), Vec::new()))
            .then(|| path.to_vec())
    }

    /// The defining site of `path` read from inside `krate`, and how many of
    /// its segments that consumed.
    #[must_use]
    pub fn resolve(&self, krate: &str, path: &[String]) -> Option<(Key, usize)> {
        self.resolve_from(&self.absolute(krate, false, path)?, 8)
    }

    /// The shim an absolute path's FIRST alias hop is, and the absolute path
    /// it stands for there (the shim's target, then the path's remaining
    /// segments); `None` when the path reaches an item or a root alias first,
    /// or does not resolve that far.
    fn first_shim(&self, segments: &[String]) -> Option<(Shim, Vec<String>)> {
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
            if module.is_empty() {
                return None;
            }
            let target = here.aliases.get(segment)?;
            let mut absolute: Vec<String> = match target.first().map(String::as_str) {
                Some("crate") => std::iter::once(krate.clone())
                    .chain(target[1..].iter().cloned())
                    .collect(),
                Some("self") => std::iter::once(krate.clone())
                    .chain(module.iter().cloned())
                    .chain(target[1..].iter().cloned())
                    .collect(),
                _ => return None,
            };
            absolute.extend(rest[at + 1..].iter().cloned());
            return Some(((krate.clone(), module, segment.clone()), absolute));
        }
        None
    }

    /// What an absolute path respells to when its first alias hop is a shim:
    /// that shim's target, followed through further shims while each next
    /// hop is one. The target is code that compiled, so the respelling is
    /// valid whether or not the index can follow it to the item (a glob
    /// re-export, an external crate).
    /// [`Index::unshim`] as a reader in crate `from` may spell it: from
    /// another crate, every module on the target path must be `pub`, or the
    /// path is left as written, which keeps its shim reached and public.
    fn respelled_for(&self, from: &str, segments: &[String]) -> Option<Vec<String>> {
        let path = self.unshim(segments)?;
        let (krate, rest) = path.split_first()?;
        if krate != from {
            let mut module: Vec<String> = Vec::new();
            for segment in rest {
                module.push(segment.clone());
                if !self.modules.contains_key(&(krate.clone(), module.clone())) {
                    break;
                }
                if !self.public.contains(&(krate.clone(), module.clone())) {
                    return None;
                }
            }
        }
        Some(path)
    }

    fn unshim(&self, segments: &[String]) -> Option<Vec<String>> {
        let (_, mut path) = self.first_shim(segments)?;
        for _ in 0..8 {
            match self.first_shim(&path) {
                Some((_, next)) => path = next,
                None => break,
            }
        }
        Some(path)
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

/// Where a file's paths are read from: its crate and module, and whether it
/// is a crate root (whose root-relative paths name the root's modules). A file
/// no crate's library holds (a test, an example) has neither. Its `aliases`
/// are the file's own top-level `use` leaves, read from its text whether or
/// not a crate's library holds it: a test's `use batten::verdict;` is what
/// makes its `verdict::Native` a path through a shim.
#[derive(Debug, Default)]
struct Reader {
    krate: String,
    module: Vec<String>,
    at_root: bool,
    aliases: BTreeMap<String, Vec<String>>,
    /// Every inline module in the file, as its byte span and name, outermost
    /// first, so the module at a point is the file's plus each enclosing one.
    inline: Vec<(usize, usize, String)>,
}

impl Index {
    /// [`Index::absolute`] for a path read by `reader`, which also reads a
    /// head the reading file imported by name (`use crate::config;`, then
    /// `config::X`).
    fn absolute_in(&self, reader: &Reader, path: &[String]) -> Option<Vec<String>> {
        if let Some(absolute) = self.absolute(&reader.krate, reader.at_root, path) {
            return Some(absolute);
        }
        let (first, rest) = path.split_first()?;
        let target = reader.aliases.get(first)?;
        let head: Vec<String> = match target.first().map(String::as_str) {
            Some("crate") if !reader.krate.is_empty() => std::iter::once(reader.krate.clone())
                .chain(target[1..].iter().cloned())
                .collect(),
            Some("self") if !reader.krate.is_empty() => std::iter::once(reader.krate.clone())
                .chain(reader.module.iter().cloned())
                .chain(target[1..].iter().cloned())
                .collect(),
            Some(krate) if self.modules.contains_key(&(krate.to_owned(), Vec::new())) => {
                target.clone()
            }
            _ => return None,
        };
        // Only a MODULE imported by name: a path through an imported item
        // (`Rule::new` after `use crate::config_model::Rule;`) is respelled at its
        // `use`, and expanding it here would spell out every call.
        let (krate, module) = head.split_first()?;
        if !self.modules.contains_key(&(krate.clone(), module.to_vec())) {
            return None;
        }
        Some(head.into_iter().chain(rest.iter().cloned()).collect())
    }

    fn reader(&self, path: &str, text: &str) -> Reader {
        let mut reader = self
            .files
            .get(path)
            .map_or_else(Reader::default, |(krate, module)| Reader {
                krate: krate.clone(),
                module: module.clone(),
                at_root: module.is_empty(),
                aliases: BTreeMap::new(),
                inline: Vec::new(),
            });
        let tree = SourceFile::parse(text, Edition::Edition2024).tree();
        for item in tree.items() {
            if let ast::Item::Use(declaration) = item
                && let Some(tree) = declaration.use_tree()
            {
                reader.aliases.extend(
                    crate::module_graph::use_leaves(&tree)
                        .into_iter()
                        .map(|leaf| (leaf.name, leaf.path)),
                );
            }
        }
        // `descendants` is pre-order, so an outer module precedes its inner.
        reader.inline = tree
            .syntax()
            .descendants()
            .filter_map(ast::Module::cast)
            .filter_map(|module| {
                let list = module.item_list()?;
                let span = list.syntax().text_range();
                Some((
                    usize::from(span.start()),
                    usize::from(span.end()),
                    module.name()?.text().to_string(),
                ))
            })
            .collect();
        reader
    }

    /// `path`, written at byte `at` of the reader's file, as an absolute
    /// path. `self::` and `super::` are read from the module AT THAT POINT —
    /// the file's module plus every inline module enclosing it — so
    /// `crate::surface_table::Half` inside `lib.rs`'s `mod tests` is the crate root's
    /// `rules`, exactly. Anything else is [`Index::absolute_in`].
    fn rooted_at(&self, reader: &Reader, at: usize, path: &[String]) -> Option<Vec<String>> {
        if !matches!(path.first().map(String::as_str), Some("self" | "super")) {
            return self.absolute_in(reader, path);
        }
        if reader.krate.is_empty() {
            return None;
        }
        let mut module = reader.module.clone();
        module.extend(
            reader
                .inline
                .iter()
                .filter(|(start, end, _)| (*start..*end).contains(&at))
                .map(|(_, _, name)| name.clone()),
        );
        let mut rest = path;
        if rest.first().is_some_and(|head| head == "self") {
            rest = &rest[1..];
        }
        while rest.first().is_some_and(|head| head == "super") {
            module.pop()?;
            rest = &rest[1..];
        }
        Some(
            std::iter::once(reader.krate.clone())
                .chain(module)
                .chain(rest.iter().cloned())
                .collect(),
        )
    }

    /// The shim `path`, written at byte `at` of the reader's file, reaches
    /// first.
    fn reached_shim(&self, reader: &Reader, at: usize, path: &[String]) -> Option<Shim> {
        let absolute = self.rooted_at(reader, at, path)?;
        self.first_shim(&absolute).map(|(shim, _)| shim)
    }

    /// Every shim a module holds.
    fn shims_of(&self, krate: &str, module: &[String]) -> Vec<Shim> {
        if module.is_empty() {
            return Vec::new();
        }
        self.modules
            .get(&(krate.to_owned(), module.to_vec()))
            .map(|held| {
                held.aliases
                    .iter()
                    .filter(|(_, target)| {
                        matches!(target.first().map(String::as_str), Some("crate" | "self"))
                    })
                    .map(|(name, _)| (krate.to_owned(), module.to_vec(), name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// `path` (`[crate, ..]`) as `from` spells it: `crate::…` inside that crate.
fn spell(path: &[String], from: &str) -> String {
    let mut segments: Vec<&str> = path.iter().map(String::as_str).collect();
    if segments.first() == Some(&from) {
        segments[0] = "crate";
    }
    segments.join("::")
}

/// Every file of `files` whose text changes when each path through a shim is
/// respelled at the shim's target, and each shim nothing reaches any more
/// becomes a private `use` (CLOUD-2793's `respell-through-shims`).
/// `manifests` declares the crates.
///
/// A SHIM is a `use crate::…`/`use self::…` alias below its crate's root; a
/// root alias is the crate's stated surface and is never respelled through.
/// A path is respelled at its first shim's TARGET, followed through further
/// shims, not resolved to the item: the target is code that compiled, so the
/// respelling is valid even where the index cannot follow it (a glob
/// re-export, another crate's item).
///
/// THREE PASSES:
/// 1. A `use` with a leaf through a shim is regenerated from the syntax tree,
///    one `use` per prefix, keeping its attributes, its visibility and every
///    name it binds: a shim may rename (`pub use crate::digest::sha256_hex as
///    digest;`), and a text respelling of the path would drop the `as`. A
///    `use` holding a glob is left whole: its leaves cannot all be named.
/// 2. Every other path through a shim — in code, a `use`, a doc link or a
///    macro (`$crate::…`) — is respelled. String and char literals are data.
/// 3. Over the respelled tree, every shim some path still reaches (a
///    `super::` path, a glob, a group left whole) is kept; each other `pub` or
///    `pub(crate)` shim at a file's top level goes private, still serving its
///    module's bare names, and `cargo fix` drops the ones nothing uses.
///
/// What this cannot read is left as written, so a miss is a compile error
/// naming the site, never a silent change.
#[must_use]
pub fn respell_through_shims(
    files: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let index = Index::new(files, manifests);
    let mut respelled: BTreeMap<String, String> = files
        .iter()
        .map(|(path, text)| {
            let reader = index.reader(path, text);
            let grouped = regroup_uses(text, &reader, &index);
            (path.clone(), respell_paths(&grouped, &reader, &index))
        })
        .collect();
    let reached: std::collections::BTreeSet<Shim> = respelled
        .iter()
        .flat_map(|(path, text)| reached_shims(text, &index.reader(path, text), &index))
        .collect();
    for (path, text) in &mut respelled {
        let reader = index.reader(path, text);
        if !reader.krate.is_empty() {
            let shims = !reader.module.is_empty();
            *text = downgrade_shims(text, &reader, &reached, shims);
        }
    }
    respelled
        .into_iter()
        .filter(|(path, text)| files.get(path) != Some(text))
        .collect()
}

/// Whether a use tree holds a glob anywhere: a glob binds names no leaf can
/// carry, so the tree is left whole. (`Trait as _` is a leaf named `_`, which
/// regenerates with its `as _` and is never judged by a name it does not
/// bind.)
fn binds_unnamed(tree: &ast::UseTree) -> bool {
    tree.syntax()
        .descendants()
        .filter_map(ast::UseTree::cast)
        .any(|nested| nested.star_token().is_some())
}

/// Pass 1: a `use` with a leaf through a shim, regenerated by prefix.
fn regroup_uses(text: &str, reader: &Reader, index: &Index) -> String {
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
        if binds_unnamed(&tree) {
            continue;
        }
        let at = usize::from(declaration.syntax().text_range().start());
        let resolved: Vec<(crate::module_graph::UseLeaf, Option<Vec<String>>)> =
            crate::module_graph::use_leaves(&tree)
                .into_iter()
                .map(|leaf| {
                    let hit = index
                        .rooted_at(reader, at, &leaf.path)
                        .and_then(|absolute| index.respelled_for(&reader.krate, &absolute));
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
            let full = hit.map_or_else(|| leaf.path.join("::"), |path| spell(&path, &reader.krate));
            let (prefix, last) = full.rsplit_once("::").unwrap_or(("", full.as_str()));
            // A shim may rename, so the name this file sees is kept either way.
            let item = if leaf.name == last {
                last.to_owned()
            } else {
                format!("{last} as {}", leaf.name)
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

/// Every path in `body` outside a literal, with its byte offset and length.
///
/// A COMMENT IS SCANNED FOR PATHS BUT NEVER FOR LITERALS: prose quotes
/// (`"the base declared a key` over two lines, a `"""` triple) would otherwise
/// open a string that swallows the code after it, and its paths would be
/// silently left at their shims.
fn paths_in(body: &str) -> Vec<(usize, Vec<String>, usize)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let rest = &body[at..];
        let comment = if rest.starts_with("//") {
            Some(rest.find('\n').unwrap_or(rest.len()))
        } else if rest.starts_with("/*") {
            Some(rest.find("*/").map_or(rest.len(), |end| end + 2))
        } else {
            None
        };
        if let Some(len) = comment {
            scan_paths(body, at, at + len, false, &mut found);
            at += len;
            continue;
        }
        let next = scan_paths(body, at, body.len(), true, &mut found);
        at = next;
    }
    found
}

/// Paths in `body[from..to]`, appended to `found`. With `code`, a literal is
/// skipped and the scan stops at a comment's start, returning where it
/// stopped; without, everything up to `to` is read as path or prose.
fn scan_paths(
    body: &str,
    from: usize,
    to: usize,
    code: bool,
    found: &mut Vec<(usize, Vec<String>, usize)>,
) -> usize {
    let bytes = body.as_bytes();
    let mut at = from;
    while at < to {
        let rest = &body[at..to];
        if code {
            if rest.starts_with("//") || rest.starts_with("/*") {
                return at;
            }
            if let Some(len) = literal_len(rest) {
                at += len;
                continue;
            }
        }
        let starts_path = at == 0 || !(is_ident_byte(bytes[at - 1]) || bytes[at - 1] == b':');
        if starts_path && let Some((segments, len)) = path_at(rest) {
            found.push((at, segments, len));
            at += len;
            continue;
        }
        at += rest.chars().next().map_or(1, char::len_utf8);
    }
    to
}

/// Pass 2: every path through a shim, respelled at the shim's target.
fn respell_paths(body: &str, reader: &Reader, index: &Index) -> String {
    let mut out = body.to_owned();
    for (at, segments, len) in paths_in(body).into_iter().rev() {
        if let Some(path) = index
            .rooted_at(reader, at, &segments)
            .and_then(|absolute| index.respelled_for(&reader.krate, &absolute))
        {
            out.replace_range(at..at + len, &spell(&path, &reader.krate));
        }
    }
    out
}

/// The shims `text` still reaches: by a path, by a `use` leaf (a group's
/// leaves are not text paths), or by a glob over a shim's module.
fn reached_shims(text: &str, reader: &Reader, index: &Index) -> Vec<Shim> {
    let mut reached: Vec<Shim> = paths_in(text)
        .into_iter()
        .filter_map(|(at, segments, _)| index.reached_shim(reader, at, &segments))
        .collect();
    let parse = SourceFile::parse(text, Edition::Edition2024);
    for tree in parse
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::UseTree::cast)
    {
        if tree.star_token().is_some() {
            // A `super::*` glob comes from a child of the module it names,
            // which sees that module's private imports: it needs no `pub`.
            let Some(prefix) = tree.path() else { continue };
            let segments: Vec<String> = prefix
                .syntax()
                .text()
                .to_string()
                .split("::")
                .map(|segment| segment.trim().to_owned())
                .collect();
            if segments.first().is_some_and(|first| first == "super") {
                continue;
            }
            if let Some(absolute) = index.absolute_in(reader, &segments)
                && let Some((krate, module)) = absolute.split_first()
            {
                reached.extend(index.shims_of(krate, module));
            }
        }
    }
    for declaration in parse
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::Use::cast)
    {
        if let Some(tree) = declaration.use_tree() {
            let at = usize::from(declaration.syntax().text_range().start());
            for leaf in crate::module_graph::use_leaves(&tree) {
                reached.extend(index.reached_shim(reader, at, &leaf.path));
            }
        }
    }
    reached
}

/// Pass 3, over one library file's top-level `use` items: a `pub` or
/// `pub(crate)` shim nothing reaches goes private (`shims`, false in a crate
/// root, whose aliases are its surface), and each leaf of a private `use`
/// that only test code names is gated `#[cfg(test)]`.
///
/// THE GATE IS WHAT KEEPS `cargo fix` SAFE. A leaf the respelling left used
/// only by test code — a shim kept for a test module's `use super::*`, or a
/// module import (`use crate::config;`) whose library uses moved away — reads
/// as unused to the library build, `cargo fix` deletes it there first, and
/// the test build then fails: the cfg split, measured at 167 errors over the
/// first full run. Gating in place, rather than moving the leaf into a test
/// module, is right for every shape measured: two test modules, a test
/// function inside a non-test module, and a glob import alike.
fn downgrade_shims(
    text: &str,
    reader: &Reader,
    reached: &std::collections::BTreeSet<Shim>,
    shims: bool,
) -> String {
    let parse = SourceFile::parse(text, Edition::Edition2024);
    if !parse.errors().is_empty() {
        return text.to_owned();
    }
    let root = parse.tree();
    let idents: Vec<ra_ap_syntax::SyntaxToken> = root
        .syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| token.kind() == ra_ap_syntax::SyntaxKind::IDENT)
        .collect();
    // Whether `name` is named, outside `skip`, and only under test code.
    let test_only = |name: &str, skip: ra_ap_syntax::TextRange| -> bool {
        let mut seen = false;
        for token in idents.iter().filter(|token| token.text() == name) {
            if skip.contains_range(token.text_range()) {
                continue;
            }
            if !token
                .parent_ancestors()
                .any(|node| crate::module_graph::cfg_test(&node))
            {
                return false;
            }
            seen = true;
        }
        seen
    };
    // A leaf as a `use` line.
    let line = |leaf: &crate::module_graph::UseLeaf| -> String {
        let joined = leaf.path.join("::");
        if leaf.path.last() == Some(&leaf.name) {
            format!("use {joined};")
        } else {
            format!("use {joined} as {};", leaf.name)
        }
    };
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    for item in root.items() {
        let ast::Item::Use(declaration) = item else {
            continue;
        };
        let Some(tree) = declaration.use_tree() else {
            continue;
        };
        if binds_unnamed(&tree) || crate::module_graph::cfg_test(declaration.syntax()) {
            continue;
        }
        let shim = match declaration.visibility() {
            None => false,
            Some(visibility) => {
                let spelled: String = visibility
                    .syntax()
                    .text()
                    .to_string()
                    .split_whitespace()
                    .collect();
                let rooted = tree.path().is_some_and(|path| {
                    let text = path.syntax().text().to_string();
                    text.starts_with("crate") || text.starts_with("self")
                });
                let kept = crate::module_graph::use_leaves(&tree).iter().any(|leaf| {
                    reached.contains(&(
                        reader.krate.clone(),
                        reader.module.clone(),
                        leaf.name.clone(),
                    ))
                });
                if !(shims && matches!(spelled.as_str(), "pub" | "pub(crate)") && rooted && !kept) {
                    continue;
                }
                true
            }
        };
        let whole = declaration.syntax().text_range();
        let (gated, staying): (Vec<_>, Vec<_>) = crate::module_graph::use_leaves(&tree)
            .into_iter()
            .partition(|leaf| test_only(&leaf.name, whole));
        if gated.is_empty() {
            if shim && let Some(visibility) = declaration.visibility() {
                let range = visibility.syntax().text_range();
                // The visibility and the one space after it.
                let end = usize::from(range.end());
                let end = if text[end..].starts_with(' ') {
                    end + 1
                } else {
                    end
                };
                edits.push((usize::from(range.start())..end, String::new()));
            }
            continue;
        }
        let attributes: String = declaration
            .attrs()
            .map(|attribute| format!("{attribute}\n"))
            .collect();
        let lines: Vec<String> = staying
            .iter()
            .map(|leaf| format!("{attributes}{}", line(leaf)))
            .chain(
                gated
                    .iter()
                    .map(|leaf| format!("{attributes}#[cfg(test)]\n{}", line(leaf))),
            )
            .collect();
        edits.push((
            usize::from(whole.start())..usize::from(whole.end()),
            lines.join("\n"),
        ));
    }
    let mut out = text.to_owned();
    for (range, replacement) in edits.into_iter().rev() {
        out.replace_range(range, &replacement);
    }
    out
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
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

    /// The measured failure: `crate::error::Native` reached a shim whose
    /// target sat behind a glob re-export of another crate, so the item never
    /// resolved and the path was left at a shim pass 3 then made private.
    /// Fails by: a path whose shim target the index cannot follow left as
    /// written, or a root-relative path in the crate root not read.
    #[test]
    fn a_path_is_respelled_at_its_shims_target_even_past_a_glob() {
        let changed = respelled(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod error;\npub mod verdict;\npub use verdict::Native;\nfn f(_: verdict::Native) {}\n",
            ),
            ("src/error.rs", "pub use other::error::*;\n"),
            ("src/verdict.rs", "pub use crate::error::Native;\n"),
        ]);
        let lib = &changed["src/lib.rs"];
        assert!(lib.contains("pub use crate::error::Native;"), "{lib}");
        assert!(lib.contains("fn f(_: crate::error::Native)"), "{lib}");
        assert_eq!(changed["src/verdict.rs"], "use crate::error::Native;\n");
    }

    const REACHED: &[(&str, &str)] = &[
        ROOT,
        (
            "src/lib.rs",
            "pub mod model;\npub mod rules;\npub mod user;\n",
        ),
        ("src/model.rs", "pub struct Rule;\npub struct Kind;\n"),
        (
            "src/rules.rs",
            "pub use crate::model::Rule;\npub use crate::model::Kind;\npub mod inner;\n",
        ),
        ("src/rules/inner.rs", "fn f(_: super::Rule) {}\n"),
        ("src/user.rs", "fn g(_: crate::rules::Kind) {}\n"),
    ];

    /// `super::` is read at the point it is written: the file's module plus
    /// each enclosing inline module. Fails by: `super::Rule` in a child file
    /// left at its shim; `super::rules::Half` in `lib.rs`'s inline test module
    /// (the measured remainder) read as anything but the crate root's
    /// `rules`; or a shim either reaches kept public once both are respelled.
    #[test]
    fn a_super_path_is_read_at_its_module_and_respelled() {
        let mut files = REACHED.to_vec();
        files[1] = (
            "src/lib.rs",
            "pub mod model;\npub mod rules;\npub mod user;\n#[cfg(test)]\nmod tests {\n    fn t(_: super::rules::Kind) {}\n}\n",
        );
        let changed = respelled(&files);
        assert_eq!(
            changed["src/rules/inner.rs"],
            "fn f(_: crate::model::Rule) {}\n"
        );
        assert!(
            changed["src/lib.rs"].contains("fn t(_: crate::model::Kind)"),
            "{}",
            changed["src/lib.rs"]
        );
        assert_eq!(
            changed["src/rules.rs"],
            "use crate::model::Rule;\nuse crate::model::Kind;\npub mod inner;\n"
        );
    }

    /// Fails by: a shim made private while a glob over its module imports
    /// it elsewhere.
    #[test]
    fn a_glob_over_a_shims_module_keeps_every_shim_public() {
        let mut files = REACHED.to_vec();
        files.push(("src/glob.rs", "use crate::rules::*;\n"));
        files[1] = (
            "src/lib.rs",
            "pub mod model;\npub mod rules;\npub mod user;\npub mod glob;\n",
        );
        let changed = respelled(&files);
        assert!(
            !changed.contains_key("src/rules.rs"),
            "{:?}",
            changed.get("src/rules.rs")
        );
    }

    /// The second measured miss: `use crate::config;` then
    /// `config::CONFIG_FILE`, through a shim in `config`. Fails by: a path
    /// headed by a module imported by name left at the shim; or a path
    /// through an imported ITEM (`Rule::new`) spelled out in full, which
    /// would rewrite every call instead of the one `use`.
    #[test]
    fn a_path_headed_by_an_imported_module_is_respelled_and_an_imported_item_is_not() {
        let changed = respelled(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod model;\npub mod config;\npub mod user;\n",
            ),
            (
                "src/model.rs",
                "pub const FILE: &str = \"x\";\npub struct Rule;\n",
            ),
            ("src/config.rs", "pub use crate::model::{FILE, Rule};\n"),
            (
                "src/user.rs",
                "use crate::config;\nuse crate::config::Rule;\nfn f() -> &'static str { let _ = Rule::new; config::FILE }\n",
            ),
        ]);
        let user = &changed["src/user.rs"];
        assert!(user.contains("crate::model::FILE }"), "{user}");
        assert!(user.contains("use crate::model::Rule;"), "{user}");
        assert!(user.contains("let _ = Rule::new;"), "{user}");
    }

    /// The third measured miss: a prose comment's quote (`// "the base`)
    /// opened a string that swallowed the code below it. Fails by: a path
    /// after such a comment left at its shim; or a path inside a comment (a
    /// doc link) not respelled.
    #[test]
    fn a_quote_in_a_comment_does_not_hide_the_code_after_it() {
        let changed = respelled(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod model;\npub mod config;\npub mod user;\n",
            ),
            ("src/model.rs", "pub struct Rule;\n"),
            ("src/config.rs", "pub use crate::model::Rule;\n"),
            (
                "src/user.rs",
                "// and \"the base declared\n/// See [crate::config::Rule].\nfn f() -> crate::config::Rule { crate::config::Rule }\n",
            ),
        ]);
        let user = &changed["src/user.rs"];
        assert!(
            user.contains("-> crate::model::Rule { crate::model::Rule }"),
            "{user}"
        );
        assert!(user.contains("[crate::model::Rule]"), "{user}");
    }

    /// The fourth measured pair. Fails by: a plain `use` through a renaming
    /// shim respelled as text, dropping the name the file uses (`digest`);
    /// or an integration test's module imported by name (`use app::verdict;`
    /// then `verdict::Native`) left unread, its shim then made private.
    #[test]
    fn a_renaming_shim_keeps_its_name_and_a_tests_module_import_is_read() {
        let changed = respelled(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod digest;\npub mod provision;\npub mod verdict;\npub mod error;\n",
            ),
            ("src/digest.rs", "pub fn sha256_hex() {}\n"),
            ("src/error.rs", "pub enum Native {}\n"),
            (
                "src/provision.rs",
                "pub use crate::digest::sha256_hex as digest;\n",
            ),
            ("src/verdict.rs", "pub use crate::error::Native;\n"),
            (
                "tests/it.rs",
                "use app::provision::digest;\nuse app::verdict;\nfn t(_: verdict::Native) { digest() }\n",
            ),
        ]);
        let test = &changed["tests/it.rs"];
        assert!(
            test.contains("use app::digest::sha256_hex as digest;"),
            "{test}"
        );
        assert!(test.contains("fn t(_: app::error::Native)"), "{test}");
    }

    /// The cfg split, measured at 167 errors. Fails by: a leaf only test
    /// code names — a shim's, or a private import's whose library use the
    /// respelling moved away (`config` below) — left ungated, where
    /// `cargo fix` deletes it as unused and the test build breaks; or a leaf
    /// the module's own code names gated away from it.
    #[test]
    fn a_leaf_only_test_code_names_is_gated_to_test_builds() {
        let changed = respelled(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod check;\npub mod config;\npub mod action;\n",
            ),
            ("src/check.rs", "pub fn validate() {}\npub fn plan() {}\n"),
            (
                "src/config.rs",
                "pub use crate::check::plan as load;\npub fn other() {}\n",
            ),
            (
                "src/action.rs",
                "#[allow(unused_imports)]\npub use crate::check::{plan, validate};\nuse crate::config;\nfn run() { plan(); config::load() }\n#[cfg(test)]\nmod tests {\n    use super::*;\n    fn t() { validate(); config::other() }\n}\n#[cfg(test)]\nmod half_tests {\n    use super::*;\n    fn u() { validate() }\n}\n",
            ),
        ]);
        assert_eq!(
            changed["src/action.rs"],
            "#[allow(unused_imports)]\nuse crate::check::plan;\n#[allow(unused_imports)]\n#[cfg(test)]\nuse crate::check::validate;\n#[cfg(test)]\nuse crate::config;\nfn run() { plan(); crate::check::plan() }\n#[cfg(test)]\nmod tests {\n    use super::*;\n    fn t() { validate(); config::other() }\n}\n#[cfg(test)]\nmod half_tests {\n    use super::*;\n    fn u() { validate() }\n}\n"
        );
    }

    /// The measured `journal.rs` break: `use anyhow::{Context as _, Result};`
    /// lost its `as _` and was gated, because the test module names an
    /// unrelated `findings::Context`. Fails by: an underscore import judged
    /// by a name it never binds, or regenerated without its `as _`.
    #[test]
    fn an_underscore_import_is_left_whole() {
        let action = "use anyhow::{Context as _, Result};\nfn run() -> Result<()> { Ok(()) }\n#[cfg(test)]\nmod tests {\n    use crate::findings::Context;\n}\n";
        let changed = respelled(&[
            ROOT,
            ("src/lib.rs", "pub mod findings;\npub mod action;\n"),
            ("src/findings.rs", "pub struct Context;\n"),
            ("src/action.rs", action),
        ]);
        assert!(
            !changed.contains_key("src/action.rs"),
            "{:?}",
            changed.get("src/action.rs")
        );
    }

    /// Fails by: a test outside the crate respelled into a module that is
    /// not `pub`, which does not compile from there (the path must stay, and
    /// so must its shim's `pub`); or a group holding `Streamed as _` (the
    /// measured `exec_streamed.rs` remainder) left whole, or regenerated
    /// without its `as _`.
    #[test]
    fn an_outside_reader_is_never_respelled_into_a_private_module_and_as_underscore_survives() {
        let changed = respelled(&[
            ROOT,
            ("src/lib.rs", "mod hidden;\npub mod open;\npub mod exec;\n"),
            ("src/hidden.rs", "pub struct Keep;\n"),
            ("src/open.rs", "pub trait Streamed {}\npub struct Plain;\n"),
            (
                "src/exec.rs",
                "pub use crate::hidden::Keep;\npub use crate::open::{Plain, Streamed};\n",
            ),
            (
                "tests/it.rs",
                "use app::exec::{Keep, Plain, Streamed as _};\n",
            ),
        ]);
        let test = &changed["tests/it.rs"];
        assert!(test.contains("use app::exec::Keep;"), "{test}");
        assert!(
            test.contains("use app::open::{Plain, Streamed as _};"),
            "{test}"
        );
        assert!(
            changed["src/exec.rs"].starts_with("pub use crate::hidden::Keep;"),
            "{}",
            changed["src/exec.rs"]
        );
    }
}
