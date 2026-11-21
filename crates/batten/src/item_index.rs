//! Which item a path names, across the workspace's crates (CLOUD-2789).
//!
//! `test replay` asks whether a base test still holds at HEAD. A move that
//! respells a path — `crate::rules::Rule` becoming `crate::config_model::Rule`
//! once `Rule` lives in the model — changes no assertion, yet compares as a
//! modified body. This index resolves each `crate::`, `batten::` or
//! `batten_<name>::` path to the file and name that DEFINE it, following
//! `pub use` re-exports and modules re-exported from a sibling crate, so a body
//! is compared by the items it names rather than by how it spells them.
//!
//! What it reads, per `crates/<dir>/src/**.rs` file: the items declared at the
//! top level of the file and its inline modules, and its `use` declarations
//! (any visibility: a `use` in the file is how its own paths resolve, and a
//! `pub use` is how other paths reach through it). What it does not resolve
//! is left exactly as written: `super::`, `self::`, a path through a type, or a
//! macro-built path. A path it cannot resolve therefore compares as before.

use std::collections::BTreeMap;

/// A defining site: the file an item is declared in, and its name there.
pub type Key = (String, String);

/// One crate's module tree, flattened: module path to what it holds.
#[derive(Debug, Default)]
struct Module {
    /// The file this module's items are declared in.
    file: String,
    /// Items declared here: name to the defining file (`file` itself).
    declared: BTreeMap<String, String>,
    /// `use` aliases: the name visible here to the absolute path it stands for.
    aliases: BTreeMap<String, Vec<String>>,
}

/// Every module of every crate in one tree.
#[derive(Debug, Default)]
pub struct Index {
    /// `(crate name, module path)` to its contents.
    modules: BTreeMap<(String, Vec<String>), Module>,
}

/// The crate name and module path a file under `crates/<dir>/src/` is, or
/// `None` for any other file (tests, examples, build scripts).
fn module_of(path: &str) -> Option<(String, Vec<String>)> {
    let rest = path.strip_prefix("crates/")?;
    let (dir, inside) = rest.split_once("/src/")?;
    let krate = dir.replace('-', "_");
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
    Some((krate, segments))
}

/// Flatten one `use` tree into `(visible name, absolute path)` pairs, with
/// `prefix` the path so far. A glob names nothing and is skipped.
fn flatten(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<(String, Vec<String>)>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let ident = name.ident.to_string();
            if ident == "self" {
                if let Some(last) = prefix.last() {
                    out.push((last.clone(), prefix.clone()));
                }
            } else {
                let mut full = prefix.clone();
                full.push(ident.clone());
                out.push((ident, full));
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            full.push(rename.ident.to_string());
            out.push((rename.rename.to_string(), full));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                flatten(item, prefix, out);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

/// The name an item declares, when it declares one a path can name.
fn declared_name(item: &syn::Item) -> Option<String> {
    let ident = match item {
        syn::Item::Fn(item) => &item.sig.ident,
        syn::Item::Struct(item) => &item.ident,
        syn::Item::Enum(item) => &item.ident,
        syn::Item::Const(item) => &item.ident,
        syn::Item::Static(item) => &item.ident,
        syn::Item::Type(item) => &item.ident,
        syn::Item::Trait(item) => &item.ident,
        syn::Item::Union(item) => &item.ident,
        _ => return None,
    };
    Some(ident.to_string())
}

impl Index {
    /// Index every Rust file under a crate's `src/` in `files` (path to text).
    /// A file that does not parse contributes nothing.
    #[must_use]
    pub fn new(files: &BTreeMap<String, String>) -> Self {
        let mut index = Self::default();
        for (path, text) in files {
            let Some((krate, module)) = module_of(path) else {
                continue;
            };
            let Ok(file) = crate::source::rust(text) else {
                continue;
            };
            index.add(&krate, &module, path, &file.items);
        }
        index
    }

    fn add(&mut self, krate: &str, module: &[String], file: &str, items: &[syn::Item]) {
        let mut inline = Vec::new();
        {
            let entry = self
                .modules
                .entry((krate.to_owned(), module.to_vec()))
                .or_default();
            entry.file = file.to_owned();
            for item in items {
                if let Some(name) = declared_name(item) {
                    entry.declared.insert(name, file.to_owned());
                }
                match item {
                    syn::Item::Use(declaration) => {
                        let mut pairs = Vec::new();
                        flatten(&declaration.tree, &mut Vec::new(), &mut pairs);
                        for (name, target) in pairs {
                            entry.aliases.insert(name, target);
                        }
                    }
                    syn::Item::Mod(nested) => {
                        if let Some((_, nested_items)) = &nested.content {
                            let is_test = nested.attrs.iter().any(|attr| {
                                attr.path().is_ident("cfg")
                                    && attr
                                        .parse_args::<syn::Ident>()
                                        .is_ok_and(|arg| arg == "test")
                            });
                            if !is_test {
                                inline.push((nested.ident.to_string(), nested_items.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        for (name, nested_items) in inline {
            let mut path = module.to_vec();
            path.push(name);
            self.add(krate, &path, file, &nested_items);
        }
    }

    /// The defining site of an absolute path (`[crate, module.., Name]`), and
    /// how many of its segments that consumed; or `None` when it does not
    /// resolve. Follows aliases, at most `depth` hops.
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
            if let Some(file) = here.declared.get(segment) {
                return Some(((file.clone(), segment.clone()), at + 2));
            }
            let target = here.aliases.get(segment)?;
            // An alias stands for an absolute path: `crate::x` in this crate,
            // or a sibling crate by name.
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
            absolute.extend(rest[at + 1..].iter().cloned());
            let (key, used) = self.resolve_from(&absolute, depth - 1)?;
            // Segments consumed in the original path: everything up to and
            // including this one, plus whatever the alias's remainder used.
            let alias_len = absolute.len() - (rest.len() - at - 1);
            return Some((key, at + 2 + used.saturating_sub(alias_len)));
        }
        None
    }

    /// The defining site of `path` (`crate::a::B`, `batten_core::x::Y`) read
    /// from inside `krate`, and how many segments it consumed.
    #[must_use]
    pub fn resolve(&self, krate: &str, path: &[String]) -> Option<(Key, usize)> {
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

    /// Every defining site of `name`, across all crates.
    fn sites(&self, name: &str) -> Vec<String> {
        let mut files: Vec<String> = self
            .modules
            .values()
            .filter_map(|module| module.declared.get(name).cloned())
            .collect();
        files.sort();
        files.dedup();
        files
    }
}

/// Items that moved between files from `before` to `after`: a name declared in
/// exactly one file on each side, and a different file on each. The same rule
/// `git::pair_moves` applies to files: unique on both sides, or not a move.
#[must_use]
pub fn moved_items(before: &Index, after: &Index) -> BTreeMap<Key, Key> {
    let mut moves = BTreeMap::new();
    for module in before.modules.values() {
        for name in module.declared.keys() {
            let (base, head) = (before.sites(name), after.sites(name));
            if let ([base], [head]) = (base.as_slice(), head.as_slice())
                && base != head
            {
                moves.insert((base.clone(), name.clone()), (head.clone(), name.clone()));
            }
        }
    }
    moves
}

/// The crate a file belongs to, for resolving its `crate::` paths: the
/// directory under `crates/` (`batten-core` is `batten_core`).
#[must_use]
pub fn crate_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix("crates/")?;
    Some(rest.split('/').next()?.replace('-', "_"))
}

/// `body` with every resolvable path replaced by the site that defines it,
/// mapped through `moves`, so two bodies naming the same items compare equal
/// however they spell them. String and char literals are left untouched: a
/// path inside a string is data the test asserts on, not a reference.
#[must_use]
pub fn canonical(body: &str, krate: &str, index: &Index, moves: &BTreeMap<Key, Key>) -> String {
    let mut out = String::with_capacity(body.len());
    let bytes = body.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &body[at..];
        // Skip a string or char literal whole.
        if let Some(len) = literal_len(rest) {
            out.push_str(&rest[..len]);
            at += len;
            continue;
        }
        let starts_word = at == 0 || !is_ident_byte(bytes[at - 1]) && bytes[at - 1] != b':';
        if starts_word && let Some((segments, len)) = path_at(rest) {
            if let Some(((file, name), used)) = index.resolve(krate, &segments) {
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
        // A char literal closes within a few bytes; a lifetime does not close.
        let close = text[1..]
            .char_indices()
            .take(10)
            .find(|&(_, c)| c == '\'')?;
        let inner = &text[1..1 + close.0];
        if inner.chars().count() == 1 || inner.starts_with('\\') {
            return Some(1 + close.0 + 1);
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

#[cfg(test)]
mod tests;
