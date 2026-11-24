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
use std::fmt::Write as _;

use ra_ap_syntax::ast::{
    self, HasAttrs as _, HasModuleItem as _, HasName as _, HasVisibility as _,
};
use ra_ap_syntax::{AstNode as _, Edition};

/// A defining site: the file an item is declared in, and its name there.
pub type Key = (String, String);

/// What one module holds.
#[derive(Debug, Default)]
struct Module {
    /// Items declared here: name to its declaration's text.
    declared: BTreeMap<String, String>,
    /// `use` aliases: the name visible here to the path it stands for.
    aliases: BTreeMap<String, Vec<String>>,
    /// Each `use p::*;` here, as `p` written: a name no declaration or alias
    /// binds may be one of its target's.
    globs: Vec<Vec<String>>,
    /// `#[cfg(test)] use` aliases: bound only in the test build, which is
    /// where a replayed test body compiles.
    test_aliases: BTreeMap<String, Vec<String>>,
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

/// The names an item-position macro call declares, read as each item keyword
/// followed by an identifier at the call's own token level (CLOUD-2789):
/// `token_enum! { pub enum Native by id { … } }` declares `Native`. A nested
/// tree (a body, a field list) is not read, so a `fn` inside an `impl` the
/// macro writes is not taken for a module item. Without it an item a macro
/// declares was unknown to the index, and a test naming one could follow no
/// move: measured on #1276, `crate::verdict::Native` spliced as written.
fn macro_declared_names(call: &ast::MacroCall) -> Vec<String> {
    use ra_ap_syntax::SyntaxKind;
    let Some(tree) = call.token_tree() else {
        return Vec::new();
    };
    let tokens: Vec<ra_ap_syntax::SyntaxToken> = tree
        .syntax()
        .children_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| !token.kind().is_trivia())
        .collect();
    tokens
        .windows(2)
        .filter(|pair| {
            matches!(
                pair[0].kind(),
                SyntaxKind::ENUM_KW
                    | SyntaxKind::STRUCT_KW
                    | SyntaxKind::FN_KW
                    | SyntaxKind::CONST_KW
                    | SyntaxKind::STATIC_KW
                    | SyntaxKind::TYPE_KW
                    | SyntaxKind::TRAIT_KW
                    | SyntaxKind::UNION_KW
            ) && pair[1].kind() == SyntaxKind::IDENT
        })
        .map(|pair| pair[1].text().to_owned())
        .collect()
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
            let parse = batten_facts::source::rust_parse(text, Edition::Edition2024);
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
                    if let ast::Item::Use(declaration) = item
                        && let Some(tree) = declaration.use_tree()
                    {
                        entry.test_aliases.extend(
                            crate::module_graph::use_leaves(&tree)
                                .into_iter()
                                .map(|leaf| (leaf.name, leaf.path)),
                        );
                    }
                    continue;
                }
                if let Some(name) = declared_name(item) {
                    entry
                        .declared
                        .insert(name, item.syntax().text().to_string());
                }
                if let ast::Item::MacroCall(call) = item {
                    for name in macro_declared_names(call) {
                        entry
                            .declared
                            .entry(name)
                            .or_insert_with(|| item.syntax().text().to_string());
                    }
                }
                match item {
                    ast::Item::Use(declaration) => {
                        if let Some(tree) = declaration.use_tree() {
                            entry.aliases.extend(
                                crate::module_graph::use_leaves(&tree)
                                    .into_iter()
                                    .map(|leaf| (leaf.name, leaf.path)),
                            );
                            if tree.star_token().is_some()
                                && let Some(path) = tree.path()
                            {
                                entry.globs.push(
                                    path.syntax()
                                        .text()
                                        .to_string()
                                        .split("::")
                                        .map(|segment| segment.trim().to_owned())
                                        .collect(),
                                );
                            }
                        }
                    }
                    ast::Item::Module(nested) => {
                        if let Some(name) = nested.name()
                            && nested
                                .visibility()
                                .is_some_and(|visibility| visibility.syntax().text() == "pub")
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

    /// The module path a library source this index read is, below its crate.
    #[must_use]
    pub fn module_path_of(&self, path: &str) -> Option<&[String]> {
        self.files.get(path).map(|(_, module)| module.as_slice())
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
        self.resolve_through(segments, depth, false)
    }

    /// [`Index::resolve_from`], reading as the TEST BUILD binds when
    /// `test_build` is set: through a glob re-export, and through a
    /// `#[cfg(test)] use`. Only where HEAD's own `use` chain is followed for a
    /// replayed test body ([`moved_through_uses`]); a canonical reading never
    /// does — a glob names nothing a reader can see (`a_glob_names_nothing`).
    fn resolve_through(
        &self,
        segments: &[String],
        depth: u8,
        test_build: bool,
    ) -> Option<(Key, usize)> {
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
            let alias = here
                .aliases
                .get(segment)
                .or_else(|| test_build.then(|| here.test_aliases.get(segment)).flatten());
            let Some(target) = alias else {
                // A GLOB RE-EXPORT (`pub use batten_facts::error::*;`) binds
                // every public name of its target (CLOUD-2789).
                // EXACTLY ONE glob may bind it: two that both do are the
                // ambiguity rustc refuses, so neither is taken.
                if !test_build {
                    return None;
                }
                let bound: Vec<(Key, usize)> = here
                    .globs
                    .iter()
                    .filter_map(|glob| {
                        let mut absolute = Self::anchored(krate, &module, glob)?;
                        let glob_len = absolute.len();
                        absolute.extend(rest[at..].iter().cloned());
                        let (key, used) = self.resolve_through(&absolute, depth - 1, test_build)?;
                        (used > glob_len).then(|| (key, at + 1 + used - glob_len))
                    })
                    .collect();
                return match bound.as_slice() {
                    [one] => Some(one.clone()),
                    _ => None,
                };
            };
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
            let (key, used) = self.resolve_through(&absolute, depth - 1, test_build)?;
            // The original path consumed everything through this segment,
            // plus whatever of its remainder the alias's resolution used.
            return Some((key, at + 2 + used.saturating_sub(alias_len)));
        }
        None
    }

    /// A `use` target written in `module` of `krate`, as an absolute path:
    /// `crate::` and `self::` anchored there, a crate's name as written.
    fn anchored(krate: &str, module: &[String], target: &[String]) -> Option<Vec<String>> {
        Some(match target.first().map(String::as_str) {
            Some("crate") => std::iter::once(krate.to_owned())
                .chain(target[1..].iter().cloned())
                .collect(),
            Some("self") => std::iter::once(krate.to_owned())
                .chain(module.iter().cloned())
                .chain(target[1..].iter().cloned())
                .collect(),
            Some("super") | None => return None,
            _ => target.to_vec(),
        })
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

/// One item's declaration site: its module and its name there.
type Site = (String, String);

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
///
/// TO A FIXPOINT (CLOUD-2804): a declaration naming another moved item reads
/// equal only once that move is known, so each pass compares the base side
/// through every move found so far, until a pass finds none. A pass only adds
/// moves and a paired candidate leaves the list, so it ends.
#[must_use]
pub fn moved_items(before: &Index, after: &Index) -> BTreeMap<Key, Key> {
    let names: std::collections::BTreeSet<&String> = before
        .modules
        .values()
        .flat_map(|module| module.declared.keys())
        .collect();
    let mut candidates: Vec<(String, Site, Site)> = names
        .into_iter()
        .filter_map(|name| {
            let (base, head) = (before.sites(name), after.sites(name));
            let ([base_site], [head_site]) = (base.as_slice(), head.as_slice()) else {
                return None;
            };
            (base_site.0 != head_site.0)
                .then(|| (name.clone(), base_site.clone(), head_site.clone()))
        })
        .collect();
    let read = |index: &Index, file: &str, text: &str, moves: &BTreeMap<Key, Key>| {
        let krate = index.crate_of(file).unwrap_or_default();
        shape(&canonical(text, &krate, index, moves))
    };
    let no_moves = BTreeMap::new();
    let mut moves = BTreeMap::new();
    loop {
        let found: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter(|(_, (_, (base_file, base_text), (head_file, head_text)))| {
                read(before, base_file, base_text, &moves)
                    == read(after, head_file, head_text, &no_moves)
            })
            .map(|(at, _)| at)
            .collect();
        if found.is_empty() {
            return moves;
        }
        for at in found.into_iter().rev() {
            let (name, (base_file, _), (head_file, _)) = candidates.swap_remove(at);
            moves.insert((base_file, name.clone()), (head_file, name));
        }
    }
}

/// The items each MOVED FILE declares, paired with the same name in the same
/// module of the file it moved to (`files`, base path to HEAD path).
///
/// [`moved_items`] pairs by a name declared once in the whole tree, so a file
/// moved whole between crates (a cut) loses every item whose name it shares
/// with another file — `run`, `new`, a test helper — and a test naming one
/// read as modified although only the file's home changed. Measured on #1276:
/// 750 `test-expectation-changed` refusals. Here the file pairing, which is
/// `git::pair_moves`' own decision, pairs the file's items too.
///
/// A declaration edited in the move is still the same item, as one edited in
/// place keeps its name: a test is judged by its OWN text, never by what the
/// items it names now do.
#[must_use]
pub fn moved_with_files(
    before: &Index,
    after: &Index,
    files: &BTreeMap<String, String>,
) -> BTreeMap<Key, Key> {
    let mut moves = BTreeMap::new();
    for (old, new) in files {
        let at_head = after.declared_in(new);
        for (inside, names) in before.declared_in(old) {
            let Some(head_names) = at_head.get(&inside) else {
                continue;
            };
            for name in names.intersection(head_names) {
                moves.insert((old.clone(), name.clone()), (new.clone(), name.clone()));
            }
        }
    }
    moves
}

/// Items that LEFT their base file, by NAME ALONE: declared exactly once on
/// each side, in different files (CLOUD-2789). FOR SPLICING, NEVER FOR
/// COMPARISON.
///
/// [`moved_items`] refuses an edited declaration, rightly: a test naming an
/// edited item must be judged modified and replayed. But the replay then
/// splices the base body in, and `crate::preset::MANIFESTS` no longer compiles
/// once `MANIFESTS` lives in `preset_catalog.rs` — so the base assertion was
/// never run against HEAD's data at all, and the compile error read as an
/// expectation change. Spelled at its one HEAD home, the base body runs; an
/// item that is truly different fails the base assertion there, and stays
/// refused. Measured on #1276: `preset::{MANIFESTS, find, verdict_rows}` and
/// `policy::preset_names`, 13 rows.
#[must_use]
pub fn relocated_items(before: &Index, after: &Index) -> BTreeMap<Key, Key> {
    let names: std::collections::BTreeSet<&String> = before
        .modules
        .values()
        .flat_map(|module| module.declared.keys())
        .collect();
    names
        .into_iter()
        .filter_map(|name| {
            let (base, head) = (before.sites(name), after.sites(name));
            let ([(base_file, _)], [(head_file, _)]) = (base.as_slice(), head.as_slice()) else {
                return None;
            };
            (base_file != head_file).then(|| {
                (
                    (base_file.clone(), name.clone()),
                    (head_file.clone(), name.clone()),
                )
            })
        })
        .collect()
}

/// Items that LEFT their base file, each paired with the item HEAD's own code
/// binds the old path to (CLOUD-2789).
///
/// [`moved_items`] needs the declaration's text equal on both sides, so an item
/// edited as it moved pairs with nothing: `token_enum!`'s `Native` gained
/// variants on its way from `verdict.rs` to `batten-facts`. But the old home
/// kept a `use` of it, so the old path still resolves at HEAD — aliases
/// followed, privacy aside — to exactly one item: the one rustc binds there.
/// That binding, not a name match, is the pairing, so an unrelated item of the
/// same name elsewhere is never taken for it. Measured on #1276: 82 of 179
/// residual replay refusals.
#[must_use]
pub fn moved_through_uses(before: &Index, after: &Index) -> BTreeMap<Key, Key> {
    let mut moves = BTreeMap::new();
    for (file, (krate, module)) in &before.files {
        let at_head = after.declared_in(file);
        for (inside, names) in before.declared_in(file) {
            for name in names {
                if at_head
                    .get(&inside)
                    .is_some_and(|held| held.contains(&name))
                {
                    continue;
                }
                let path: Vec<String> = std::iter::once(krate.clone())
                    .chain(module.iter().cloned())
                    .chain(inside.iter().cloned())
                    .chain(std::iter::once(name.clone()))
                    .collect();
                if let Some((site, used)) = after.resolve_through(&path, 8, true)
                    && used == path.len()
                    && site.0 != *file
                {
                    moves.insert((file.clone(), name.clone()), site);
                }
            }
        }
    }
    moves
}

impl Index {
    /// Every name `file` declares, by the module path below the file's own
    /// (empty for the file's module, one segment per inline module in it).
    fn declared_in(&self, file: &str) -> BTreeMap<Vec<String>, std::collections::BTreeSet<String>> {
        let Some((krate, module)) = self.files.get(file) else {
            return BTreeMap::new();
        };
        self.modules
            .iter()
            .filter(|((held_krate, held_module), _)| {
                held_krate == krate
                    && held_module.starts_with(module)
                    && self.file_of(held_krate, held_module).as_deref() == Some(file)
            })
            .map(|((_, held_module), held)| {
                (
                    held_module[module.len()..].to_vec(),
                    held.declared.keys().cloned().collect(),
                )
            })
            .collect()
    }
}

/// `body` with every resolvable path replaced by the site that defines it,
/// mapped through `moves`, so two bodies naming the same items compare equal
/// however they spell them. String, raw-string and char literals are left
/// untouched: a path inside a string is data the test asserts on.
#[must_use]
pub fn canonical(body: &str, krate: &str, index: &Index, moves: &BTreeMap<Key, Key>) -> String {
    let mut out = String::with_capacity(body.len());
    let mut last = 0;
    for (at, segments, len) in token_paths(body) {
        let Some(((file, name), used)) = index.resolve(krate, &segments) else {
            continue;
        };
        let (file, name) = moves
            .get(&(file.clone(), name.clone()))
            .cloned()
            .unwrap_or((file, name));
        out.push_str(&body[last..at]);
        out.push('⟨');
        out.push_str(&file);
        out.push('#');
        out.push_str(&name);
        out.push('⟩');
        for segment in &segments[used.min(segments.len())..] {
            out.push_str("::");
            out.push_str(segment);
        }
        last = at + len;
    }
    out.push_str(&body[last..]);
    out
}

/// Every `::`-joined path of two or more identifiers in `body`, as its byte
/// offset, segments and length, read off the REAL Rust tokenizer (plan item 4c:
/// this replaced a hand lexer that guessed where literals and comments end).
///
/// The body is lexed inside a macro token tree (`m!{…}`), so a fragment that is
/// no item (a bare path, a block) still tokenizes, and every token of the file
/// is read whatever the tree around it, so an unbalanced brace drops nothing. A
/// string, char or comment is ONE token whose text no identifier test accepts,
/// so a path inside a literal is never rewritten: the test asserts on that data.
/// The path grammar is `path_at`'s: identifiers (no leading digit) joined by an
/// adjacent `::`, starting where the previous token is not glued on as an
/// identifier or a colon.
fn token_paths(body: &str) -> Vec<(usize, Vec<String>, usize)> {
    use ra_ap_syntax::{AstNode as _, SyntaxKind};
    const OPEN: &str = "m!{";
    let wrapped = format!("{OPEN}{body}\n}}");
    let parse = batten_facts::source::rust_parse(&wrapped, Edition::Edition2024);
    let tokens: Vec<(SyntaxKind, String, usize, usize)> = parse
        .tree()
        .syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .map(|token| {
            let range = token.text_range();
            (
                token.kind(),
                token.text().to_owned(),
                usize::from(range.start()),
                usize::from(range.end()),
            )
        })
        .filter(|(_, _, start, end)| *start >= OPEN.len() && *end <= OPEN.len() + body.len())
        .collect();
    let ident = |kind: SyntaxKind, text: &str| {
        !matches!(
            kind,
            SyntaxKind::COMMENT | SyntaxKind::OUTER_DOC_COMMENT | SyntaxKind::INNER_DOC_COMMENT
        ) && text.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    // `::` as one token, or as two adjacent `:` tokens, ending where it ends.
    let colons = |at: usize| -> Option<(usize, usize)> {
        let (kind, _, start, end) = tokens.get(at)?;
        if *kind == SyntaxKind::COLON2 {
            return Some((at + 1, *end));
        }
        let (next, _, next_start, next_end) = tokens.get(at + 1)?;
        (*kind == SyntaxKind::COLON && *next == SyntaxKind::COLON && *next_start == *end)
            .then_some((at + 2, *next_end))
            .filter(|_| *start < *next_end)
    };
    let mut found = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        let (kind, text, start, end) = &tokens[at];
        let glued = at > 0 && {
            let (prev_kind, prev_text, _, prev_end) = &tokens[at - 1];
            *prev_end == *start
                && (ident(*prev_kind, prev_text)
                    || matches!(prev_kind, SyntaxKind::COLON | SyntaxKind::COLON2))
        };
        if glued || !ident(*kind, text) {
            at += 1;
            continue;
        }
        let mut segments = vec![text.clone()];
        let mut stop = *end;
        let mut next = at + 1;
        while let Some((after, colon_end)) = colons(next).filter(|_| tokens[next].2 == stop) {
            match tokens.get(after) {
                Some((kind, text, seg_start, seg_end))
                    if *seg_start == colon_end && ident(*kind, text) =>
                {
                    segments.push(text.clone());
                    stop = *seg_end;
                    next = after + 1;
                }
                _ => break,
            }
        }
        if segments.len() >= 2 {
            found.push((start - OPEN.len(), segments, stop - start));
            at = next;
        } else {
            at += 1;
        }
    }
    found
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
        let tree = batten_facts::source::rust_parse(text, Edition::Edition2024).tree();
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
    let parse = batten_facts::source::rust_parse(text, Edition::Edition2024);
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
    let mut found = token_paths(body);
    for (start, end) in comment_spans(body) {
        let mut at = start;
        while at < end {
            let rest = &body[at..end];
            let bytes = body.as_bytes();
            let starts_path = at == 0 || !(is_ident_byte(bytes[at - 1]) || bytes[at - 1] == b':');
            if starts_path && let Some((segments, len)) = path_at(rest) {
                found.push((at, segments, len));
                at += len;
                continue;
            }
            at += rest.chars().next().map_or(1, char::len_utf8);
        }
    }
    found.sort_by_key(|(at, ..)| *at);
    found
}

/// Every comment's byte span in `body`, from the real tokenizer (the same
/// macro-wrapped lex as [`token_paths`]).
fn comment_spans(body: &str) -> Vec<(usize, usize)> {
    use ra_ap_syntax::{AstNode as _, SyntaxKind};
    const OPEN: &str = "m!{";
    let wrapped = format!("{OPEN}{body}\n}}");
    let parse = batten_facts::source::rust_parse(&wrapped, Edition::Edition2024);
    parse
        .tree()
        .syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        // A doc comment is its own kind (`///`, `//!`), and its paths are the
        // links a respelling must follow too.
        .filter(|token| {
            matches!(
                token.kind(),
                SyntaxKind::COMMENT | SyntaxKind::OUTER_DOC_COMMENT | SyntaxKind::INNER_DOC_COMMENT
            )
        })
        .map(|token| {
            let range = token.text_range();
            (usize::from(range.start()), usize::from(range.end()))
        })
        .filter(|(start, end)| *start >= OPEN.len() && *end <= OPEN.len() + body.len())
        .map(|(start, end)| (start - OPEN.len(), end - OPEN.len()))
        .collect()
}

/// Pass 2: every path through a shim, respelled at the shim's target.
fn respell_paths(body: &str, reader: &Reader, index: &Index) -> String {
    respell_paths_at(body, 0, reader, index)
}

/// `text[span]` — one body of the BASE file `path` — with each path naming an
/// item `moves` moved respelled at the item's HEAD home, as `head_krate`
/// spells it: `crate::…` inside that crate, its name outside (CLOUD-2789);
/// a path through a shim base had, to an item that did not move, at the shim's
/// target, as [`respell_through_shims`]' second pass respells it.
///
/// A branch that moved `Native` from `verdict.rs` to `error.rs` and left a
/// private `use` behind made the base spelling `crate::verdict::Native` a
/// privacy error at HEAD, so a modified test's base body failed to compile on
/// a path rather than on an assertion: measured on #1276, 300 of the
/// remaining compile errors. A `use` naming one is regenerated one `use` per
/// prefix, as the shim respelling regenerates it. A spelling HEAD does not
/// resolve to the same item is left as written, so a miss is a compile error
/// charged to the body, never a different item.
#[must_use]
pub fn respell_span_at_moves(
    base: &Index,
    head: &Index,
    moves: &BTreeMap<Key, Key>,
    path: &str,
    text: &str,
    span: (usize, usize),
    head_krate: &str,
) -> String {
    let reader = base.reader(path, text);
    let at_home = |at: usize, segments: &[String]| -> Option<String> {
        let absolute = base.rooted_at(&reader, at, segments)?;
        let (site, used) = base.resolve_from(&absolute, 8)?;
        let (head_file, name) = moves.get(&site)?;
        let (krate, module) = head.files.get(head_file)?;
        let spelled: Vec<String> = std::iter::once(krate.clone())
            .chain(module.iter().cloned())
            .chain(std::iter::once(name.clone()))
            .chain(absolute.get(used..).unwrap_or_default().iter().cloned())
            .collect();
        let written = spell(&spelled, head_krate);
        let reread: Vec<String> = written.split("::").map(str::to_owned).collect();
        let (again, _) = head.resolve(head_krate, &reread)?;
        (again == (head_file.clone(), name.clone())).then_some(written)
    };
    // Through a shim base had, at its target: `respell_through_shims`' second
    // pass for a path whose item did not move.
    let shimmed = |at: usize, segments: &[String]| -> Option<String> {
        base.rooted_at(&reader, at, segments)
            .and_then(|absolute| base.respelled_for(&reader.krate, &absolute))
            .map(|path| spell(&path, &reader.krate))
    };
    respell_body_with(&text[span.0..span.1], span.0, &|at, segments| {
        at_home(at, segments).or_else(|| shimmed(at, segments))
    })
}

/// `body`, which starts at byte `offset` of its file, with each path and each
/// `use` leaf `respell` answers rewritten: `respell` is given the file offset
/// and the path as written, and answers the whole new spelling. A `use` with a
/// rewritten leaf is regenerated one `use` per prefix, keeping its renames; one
/// holding a glob is left whole.
fn respell_body_with(
    body: &str,
    offset: usize,
    respell: &dyn Fn(usize, &[String]) -> Option<String>,
) -> String {
    const OPEN: &str = "fn f() ";
    let wrapped = format!("{OPEN}{body}");
    let parse = batten_facts::source::rust_parse(&wrapped, Edition::Edition2024);
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    let mut uses: Vec<std::ops::Range<usize>> = Vec::new();
    for declaration in parse
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::Use::cast)
    {
        let range = declaration.syntax().text_range();
        let range = usize::from(range.start()) - OPEN.len()..usize::from(range.end()) - OPEN.len();
        uses.push(range.clone());
        let Some(tree) = declaration.use_tree() else {
            continue;
        };
        if binds_unnamed(&tree) {
            continue;
        }
        let leaves: Vec<(crate::module_graph::UseLeaf, Option<String>)> =
            crate::module_graph::use_leaves(&tree)
                .into_iter()
                .map(|leaf| {
                    let hit = respell(offset + range.start, &leaf.path);
                    (leaf, hit)
                })
                .collect();
        if leaves.iter().all(|(_, hit)| hit.is_none()) {
            continue;
        }
        let mut by_prefix: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (leaf, hit) in leaves {
            let full = hit.unwrap_or_else(|| leaf.path.join("::"));
            let (prefix, last) = full.rsplit_once("::").unwrap_or(("", full.as_str()));
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
                    format!("use {tail};")
                } else {
                    format!("use {prefix}::{tail};")
                }
            })
            .collect();
        edits.push((range, lines.join(" ")));
    }
    for (at, segments, len) in paths_in(body) {
        if uses.iter().any(|range| range.contains(&at)) {
            continue;
        }
        if let Some(written) = respell(offset + at, &segments) {
            edits.push((at..at + len, written));
        }
    }
    edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut out = body.to_owned();
    for (range, replacement) in edits {
        out.replace_range(range, &replacement);
    }
    out
}

/// [`respell_paths`] over `body`, which starts at byte `offset` of the file
/// `reader` reads, so an inline module around it is still seen.
fn respell_paths_at(body: &str, offset: usize, reader: &Reader, index: &Index) -> String {
    let mut out = body.to_owned();
    for (at, segments, len) in paths_in(body).into_iter().rev() {
        if let Some(path) = index
            .rooted_at(reader, offset + at, &segments)
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
    let parse = batten_facts::source::rust_parse(text, Edition::Edition2024);
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

/// A leaf as a `use` line.
fn use_line(leaf: &crate::module_graph::UseLeaf) -> String {
    let joined = leaf.path.join("::");
    if leaf.path.last() == Some(&leaf.name) {
        format!("use {joined};")
    } else {
        format!("use {joined} as {};", leaf.name)
    }
}

/// Whether a `use` is a shim [`downgrade_shims`] privatises: `Some(false)` for
/// a private `use`, `Some(true)` for a `pub`/`pub(crate)` re-export rooted at
/// `crate`/`self` that nothing reaches through, and `None` for any other
/// visible `use`, which is left alone.
fn shim_decision(
    declaration: &ast::Use,
    tree: &ast::UseTree,
    reader: &Reader,
    reached: &std::collections::BTreeSet<Shim>,
    shims: bool,
) -> Option<bool> {
    let Some(visibility) = declaration.visibility() else {
        return Some(false);
    };
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
    let kept = crate::module_graph::use_leaves(tree).iter().any(|leaf| {
        reached.contains(&(
            reader.krate.clone(),
            reader.module.clone(),
            leaf.name.clone(),
        ))
    });
    (shims && matches!(spelled.as_str(), "pub" | "pub(crate)") && rooted && !kept).then_some(true)
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
    let parse = batten_facts::source::rust_parse(text, Edition::Edition2024);
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
            // `cfg_test` already walks every ancestor: asked of the parent once.
            if !token
                .parent()
                .is_some_and(|parent| crate::module_graph::cfg_test(&parent))
            {
                return false;
            }
            seen = true;
        }
        seen
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
        let Some(shim) = shim_decision(&declaration, &tree, reader, reached, shims) else {
            continue;
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
            .fold(String::new(), |mut text, attribute| {
                let _ = writeln!(text, "{attribute}");
                text
            });
        let lines: Vec<String> = staying
            .iter()
            .map(|leaf| format!("{attributes}{}", use_line(leaf)))
            .chain(
                gated
                    .iter()
                    .map(|leaf| format!("{attributes}#[cfg(test)]\n{}", use_line(leaf))),
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

    /// Fails by: a root child module's name read as one outside the crate
    /// root, where it names nothing, or a name the root has no module of read
    /// as one inside it.
    #[test]
    fn only_a_crate_root_reads_its_child_module_by_name() {
        let index = index(&[
            ROOT,
            ("src/lib.rs", "pub mod model;\n"),
            ("src/model.rs", "pub struct Rule;\n"),
        ]);
        let path = |segments: &[&str]| -> Vec<String> {
            segments
                .iter()
                .map(|segment| (*segment).to_owned())
                .collect()
        };
        assert_eq!(
            index.absolute("app", true, &path(&["model", "Rule"])),
            Some(path(&["app", "model", "Rule"]))
        );
        assert_eq!(
            index.absolute("app", false, &path(&["model", "Rule"])),
            None
        );
        assert_eq!(index.absolute("app", true, &path(&["other", "Rule"])), None);
    }

    /// Fails by: whitespace or punctuation read as a path's first segment, so
    /// the path after it reads as glued to it and is lost; or a path after a
    /// leading `::` read as one this crate names.
    #[test]
    fn a_token_path_starts_at_an_identifier_no_token_glues_to() {
        let at = |body: &str| -> Vec<(usize, Vec<String>)> {
            token_paths(body)
                .into_iter()
                .map(|(start, segments, _)| (start, segments))
                .collect()
        };
        let a_b = vec![String::from("a"), String::from("b")];
        assert_eq!(at(" a::b"), [(1, a_b.clone())]);
        assert_eq!(at("(a::b)"), [(1, a_b)]);
        assert!(at("::a::b").is_empty(), "{:?}", at("::a::b"));
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

    /// Fails by: a base body spliced in a spelling through a shim HEAD
    /// retired, which then fails to compile on the path, not the assertion
    /// (#1276's `crate::verdict::Native`). Only the body's span is respelled.
    #[test]
    fn a_span_is_respelled_through_its_trees_shims() -> anyhow::Result<()> {
        let text = "fn a() { crate::verdict::Native::A; }\nfn b() { crate::verdict::Native::A; }\n";
        let base = index(&[
            ROOT,
            (
                "src/lib.rs",
                "pub mod error;\npub mod verdict;\npub mod other;\n",
            ),
            ("src/error.rs", "pub enum Native { A }\n"),
            ("src/verdict.rs", "pub use crate::error::Native;\n"),
            ("src/other.rs", text),
        ]);
        let (Some(open), Some(close)) = (text.find('{'), text.find('}')) else {
            anyhow::bail!("the fixture holds a braced body");
        };
        let span = (open, close + 1);
        assert_eq!(
            respell_span_at_moves(
                &base,
                &base,
                &BTreeMap::new(),
                "src/other.rs",
                text,
                span,
                "app"
            ),
            "{ crate::error::Native::A; }"
        );
        Ok(())
    }

    /// Fails by: an item a macro declares is unknown to the index, so a path
    /// naming it follows no move (#1276: `token_enum! { pub enum Native … }`).
    /// A `fn` inside a nested tree the macro writes is not a module item.
    #[test]
    fn an_item_a_macro_declares_is_indexed_and_follows_its_move() -> anyhow::Result<()> {
        let call = "token_enum! {\n    pub enum Native by id { A => \"a\" }\n}\nimpl_it! { impl X { fn inner() {} } }\n";
        let text = "fn t() { crate::verdict::Native::A; }\n";
        let base = index(&[
            ("Cargo.toml", "[workspace]\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\n"),
            ("one/src/lib.rs", "pub mod verdict;\npub mod other;\n"),
            ("one/src/verdict.rs", call),
            ("one/src/other.rs", text),
        ]);
        assert!(
            base.resolve("one", &["crate".into(), "verdict".into(), "Native".into()])
                .is_some()
        );
        assert!(
            base.resolve("one", &["crate".into(), "verdict".into(), "inner".into()])
                .is_none()
        );
        let head = index(&[
            ("Cargo.toml", "[workspace]\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\n"),
            ("two/Cargo.toml", "[package]\nname = \"two\"\n"),
            ("one/src/lib.rs", "pub mod verdict;\npub mod other;\n"),
            ("one/src/verdict.rs", "use two::error::Native;\n"),
            ("one/src/other.rs", text),
            ("two/src/lib.rs", "pub mod error;\n"),
            ("two/src/error.rs", call),
        ]);
        let moves = moved_items(&base, &head);
        let (Some(open), Some(close)) = (text.find('{'), text.rfind('}')) else {
            anyhow::bail!("the fixture holds a braced body");
        };
        let span = (open, close + 1);
        assert_eq!(
            respell_span_at_moves(&base, &head, &moves, "one/src/other.rs", text, span, "one"),
            "{ two::error::Native::A; }"
        );
        // The declaration edited in the move pairs by text with nothing, but
        // the old home's `use` still binds the old path to it at HEAD.
        let edited = call.replace("A => \"a\"", "A => \"a\", B => \"b\"");
        let head = index(&[
            ("Cargo.toml", "[workspace]\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\n"),
            ("two/Cargo.toml", "[package]\nname = \"two\"\n"),
            ("one/src/lib.rs", "pub mod verdict;\npub mod other;\n"),
            ("one/src/verdict.rs", "use two::error::Native;\n"),
            ("one/src/other.rs", text),
            ("two/src/lib.rs", "pub mod error;\n"),
            ("two/src/error.rs", &edited),
        ]);
        assert!(moved_items(&base, &head).is_empty());
        let moves = moved_through_uses(&base, &head);
        assert_eq!(
            respell_span_at_moves(&base, &head, &moves, "one/src/other.rs", text, span, "one"),
            "{ two::error::Native::A; }"
        );
        // #1276's own chain: the old home's `use` reaches the item through a
        // glob re-export (`pub use two::error::*;`).
        let head = index(&[
            ("Cargo.toml", "[workspace]\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\n"),
            ("two/Cargo.toml", "[package]\nname = \"two\"\n"),
            (
                "one/src/lib.rs",
                "pub mod error;\npub mod verdict;\npub mod other;\n",
            ),
            ("one/src/error.rs", "pub use two::error::*;\n"),
            ("one/src/verdict.rs", "use crate::error::Native;\n"),
            ("one/src/other.rs", text),
            ("two/src/lib.rs", "pub mod error;\n"),
            ("two/src/error.rs", &edited),
        ]);
        let moves = moved_through_uses(&base, &head);
        assert_eq!(
            respell_span_at_moves(&base, &head, &moves, "one/src/other.rs", text, span, "one"),
            "{ two::error::Native::A; }"
        );
        Ok(())
    }

    /// Fails by: an item edited as it moved, with nothing left at its old home,
    /// spliced as written and failing to compile, so its base assertion never
    /// ran against HEAD's item (#1276: `crate::preset::MANIFESTS`). Paired by a
    /// name declared once on each side, for the splice; still not a move for
    /// the comparison, and a name declared twice pairs with nothing.
    #[test]
    fn an_edited_item_that_left_its_file_is_relocated_for_the_splice() {
        let lib = (
            "src/lib.rs",
            "pub mod preset;\npub mod catalog;\npub mod other;\n",
        );
        let base = index(&[
            ROOT,
            lib,
            ("src/preset.rs", "pub const MANIFESTS: &[u8] = &[1];\n"),
            ("src/catalog.rs", ""),
            ("src/other.rs", ""),
        ]);
        let head = index(&[
            ROOT,
            lib,
            ("src/preset.rs", ""),
            ("src/catalog.rs", "pub const MANIFESTS: &[u8] = &[1, 2];\n"),
            ("src/other.rs", ""),
        ]);
        assert!(moved_items(&base, &head).is_empty());
        let relocated = relocated_items(&base, &head);
        assert_eq!(
            relocated.get(&("src/preset.rs".to_owned(), "MANIFESTS".to_owned())),
            Some(&("src/catalog.rs".to_owned(), "MANIFESTS".to_owned()))
        );
        let twice = index(&[
            ROOT,
            lib,
            ("src/preset.rs", ""),
            ("src/catalog.rs", "pub const MANIFESTS: &[u8] = &[1, 2];\n"),
            ("src/other.rs", "pub const MANIFESTS: &[u8] = &[3];\n"),
        ]);
        assert!(relocated_items(&base, &twice).is_empty());
    }

    /// Fails by: an old home that keeps the moved item only through a
    /// `#[cfg(test)] use` pairs with nothing, since the index skips test-only
    /// items — yet the test build, where a replayed body compiles, binds it
    /// (#1276: `rules.rs`' `#[cfg(test)] use crate::config_check::rules::validate`).
    /// A canonical reading still does not see the test-only import.
    #[test]
    fn a_test_only_import_at_the_old_home_pairs_the_moved_item() {
        let lib = (
            "src/lib.rs",
            "pub mod rules;\npub mod check;\npub mod other;\n",
        );
        let base = index(&[
            ROOT,
            lib,
            ("src/rules.rs", "pub fn validate(x: u8) -> u8 { x }\n"),
            ("src/check.rs", ""),
        ]);
        let head = index(&[
            ROOT,
            lib,
            (
                "src/rules.rs",
                "#[cfg(test)]\nuse crate::check::validate;\n",
            ),
            (
                "src/check.rs",
                "pub fn validate(x: u8, y: u8) -> u8 { x + y }\n",
            ),
        ]);
        let moves = moved_through_uses(&base, &head);
        assert_eq!(
            moves.get(&("src/rules.rs".to_owned(), "validate".to_owned())),
            Some(&("src/check.rs".to_owned(), "validate".to_owned()))
        );
        let path: Vec<String> = ["crate", "rules", "validate"].map(String::from).to_vec();
        assert!(head.resolve("app", &path).is_none());
    }

    /// Fails by: a base body naming an item the branch moved, leaving a private
    /// `use` at its old home, is spliced as written and fails to compile on the
    /// path (#1276: `crate::verdict::Native`, `crate::refusal::{…, Severity}`).
    #[test]
    fn a_span_naming_a_moved_item_is_respelled_at_its_home() -> anyhow::Result<()> {
        let lib = (
            "src/lib.rs",
            "pub mod error;\npub mod verdict;\npub mod other;\n",
        );
        let text = "fn a() { use crate::verdict::{Native, Other}; crate::verdict::Native::A; }\n";
        let base = index(&[
            ROOT,
            lib,
            ("src/error.rs", ""),
            (
                "src/verdict.rs",
                "pub enum Native { A }\npub struct Other;\n",
            ),
            ("src/other.rs", text),
        ]);
        let head = index(&[
            ROOT,
            lib,
            ("src/error.rs", "pub enum Native { A }\n"),
            (
                "src/verdict.rs",
                "use crate::error::Native;\npub struct Other;\n",
            ),
            ("src/other.rs", text),
        ]);
        let moves = moved_items(&base, &head);
        let (Some(open), Some(close)) = (text.find('{'), text.rfind('}')) else {
            anyhow::bail!("the fixture holds a braced body");
        };
        let span = (open, close + 1);
        assert_eq!(
            respell_span_at_moves(&base, &head, &moves, "src/other.rs", text, span, "app"),
            "{ use crate::error::Native; use crate::verdict::Other; crate::error::Native::A; }"
        );
        // Anti-vacuity: with no move known, nothing is respelled.
        assert_eq!(
            respell_span_at_moves(
                &base,
                &head,
                &BTreeMap::new(),
                "src/other.rs",
                text,
                span,
                "app"
            ),
            &text[span.0..span.1]
        );
        Ok(())
    }

    /// Fails by: a file moved whole between crates, declaring a name another
    /// file shares, reads as naming a different item at base and HEAD, since
    /// [`moved_items`] pairs only a name unique in the tree (#1276's 750).
    #[test]
    fn a_file_moved_between_crates_moves_every_item_it_declares() {
        let base_files: &[(&str, &str)] = &[
            ("Cargo.toml", "[workspace]\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\n"),
            ("one/src/lib.rs", "pub mod git;\npub mod other;\n"),
            ("one/src/git.rs", "pub fn run() {}\n"),
            ("one/src/other.rs", "pub fn run() {}\n"),
        ];
        let head_files: &[(&str, &str)] = &[
            ("Cargo.toml", "[workspace]\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\n"),
            ("two/Cargo.toml", "[package]\nname = \"two\"\n"),
            ("one/src/lib.rs", "pub mod other;\n"),
            ("one/src/other.rs", "pub fn run() {}\n"),
            ("two/src/lib.rs", "pub mod git;\n"),
            ("two/src/git.rs", "pub fn run() {}\n"),
        ];
        let (base, head) = (index(base_files), index(head_files));
        let files: BTreeMap<String, String> =
            [("one/src/git.rs".to_owned(), "two/src/git.rs".to_owned())].into();
        let moves = moved_with_files(&base, &head, &files);
        let body = "{ crate::git::run(); }";
        assert_eq!(
            canonical(body, "one", &base, &moves),
            canonical(body, "two", &head, &BTreeMap::new())
        );
        // Anti-vacuity: without the file's pairing the two read differently,
        // and an item the file did not keep is not invented at its new home.
        assert_ne!(
            canonical(body, "one", &base, &moved_items(&base, &head)),
            canonical(body, "two", &head, &BTreeMap::new())
        );
        assert_eq!(moves.len(), 1, "{moves:?}");
    }

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

    /// Fails by: an item whose declaration names another moved item read as
    /// edited, because its declaration was compared before that move was
    /// known (CLOUD-2804: `testing.rs`' tests calling `init_on_main`, which
    /// calls the moved git layer, were each `test-removed`).
    #[test]
    fn an_item_naming_another_moved_item_moves_with_it() {
        let before = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            (
                "src/a.rs",
                "pub fn inner() {}\npub fn outer() { crate::a::inner() }\n",
            ),
            ("src/b.rs", ""),
        ];
        let after = &[
            ROOT,
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", ""),
            (
                "src/b.rs",
                "pub fn inner() {}\npub fn outer() { crate::b::inner() }\n",
            ),
        ];
        assert_eq!(moved_items(&index(before), &index(after)).len(), 2);
        assert!(same(
            before,
            after,
            "{ crate::a::outer(); }",
            "{ crate::b::outer(); }"
        ));
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

    /// Fails by: a nested `main.rs` read as a binary root, a `type` alias
    /// declaring no name, a `crate::` target left unanchored, or a comment's
    /// end placed past where it ends.
    #[test]
    fn the_small_readers_answer_their_own_shapes() {
        let roots = [(String::new(), "app".to_owned())];
        assert_eq!(
            module_of(&roots, "src/bin/main.rs"),
            Some(("app".to_owned(), vec!["bin".to_owned(), "main".to_owned()]))
        );
        assert_eq!(module_of(&roots, "src/main.rs"), None);
        let parsed = batten_facts::source::rust_parse("type A = u8;\n", Edition::Edition2024);
        let named = parsed
            .tree()
            .items()
            .next()
            .and_then(|item| declared_name(&item));
        assert_eq!(named.as_deref(), Some("A"));
        assert_eq!(
            Index::anchored("app", &[], &["crate".to_owned(), "a".to_owned()]),
            Some(vec!["app".to_owned(), "a".to_owned()])
        );
        assert_eq!(comment_spans("// a\nx"), [(0, 4)]);
    }

    /// Fails by: a file's module path answered as anything but its own, a root
    /// child module anchored from a file that is not the root, or a `self::`
    /// import's head dropped when the reader has a crate.
    #[test]
    fn a_path_is_anchored_only_where_its_reader_can_name_it() {
        let index = index(&[
            ROOT,
            ("src/lib.rs", "pub mod config;\npub mod m;\n"),
            ("src/config.rs", "pub struct X;\n"),
            ("src/m.rs", "pub mod inner;\n"),
            ("src/m/inner.rs", "pub struct Y;\n"),
        ]);
        assert_eq!(
            index.module_path_of("src/config.rs"),
            Some(&["config".to_owned()][..])
        );
        let path = ["config".to_owned(), "X".to_owned()];
        assert_eq!(index.absolute("app", false, &path), None);
        assert_eq!(
            index.absolute("app", true, &path),
            Some(vec!["app".to_owned(), "config".to_owned(), "X".to_owned()])
        );
        let reader = index.reader("src/m.rs", "use self::inner;\n");
        assert_eq!(
            index.absolute_in(&reader, &["inner".to_owned(), "Y".to_owned()]),
            Some(["app", "m", "inner", "Y"].map(str::to_owned).to_vec())
        );
    }

    /// Fails by: a token any non-comment is read as an identifier, a token
    /// glued to the colon before it read as a path's start, or anything after
    /// a `::` taken as its next segment.
    #[test]
    fn a_token_path_is_identifiers_joined_by_adjacent_colons() {
        assert_eq!(
            token_paths("a::b"),
            [(0, vec!["a".to_owned(), "b".to_owned()], 4)]
        );
        assert_eq!(token_paths("\"s\"::x"), []);
        assert_eq!(token_paths("x::1::y::z"), []);
        assert_eq!(token_paths("a:: b"), []);
    }

    /// Fails by: a `use` already gated to test builds gated again, its own
    /// `#[cfg(test)]` read as no reason to leave it alone.
    #[test]
    fn a_use_already_gated_to_tests_is_left_alone() {
        let changed = respelled(&[
            ROOT,
            ("src/lib.rs", "pub mod config;\npub mod action;\n"),
            ("src/config.rs", "pub fn other() {}\n"),
            (
                "src/action.rs",
                "fn run() {}\n#[cfg(test)]\nuse crate::config;\n#[cfg(test)]\nmod tests {\n    use super::*;\n    fn t() { config::other() }\n}\n",
            ),
        ]);
        assert!(
            !changed.contains_key("src/action.rs"),
            "{:?}",
            changed.get("src/action.rs")
        );
    }

    /// Fails by: a comment's path judged by the byte at it rather than the one
    /// before it, so no comment path is ever found.
    #[test]
    fn a_comment_path_is_found_after_a_space_and_not_inside_a_word() {
        let found: Vec<(usize, Vec<String>)> = paths_in("// see crate::a::b\n")
            .into_iter()
            .map(|(at, segments, _)| (at, segments))
            .collect();
        assert_eq!(
            found,
            [(7, vec!["crate".to_owned(), "a".to_owned(), "b".to_owned()])]
        );
        // After a `:` is the tail of a path already passed, never a new one.
        assert!(paths_in("// x:crate::a::b\n").is_empty());
    }

    /// Fails by: a comment span shifted by the wrapper's length.
    #[test]
    fn a_comment_span_is_in_the_bodys_own_offsets() {
        assert_eq!(comment_spans("x // c\n"), [(2, 6)]);
    }

    /// Fails by: a `use` leaf asked about at anything but its file offset.
    #[test]
    fn a_use_leaf_is_respelled_at_its_file_offset() {
        let asked = std::cell::RefCell::new(Vec::new());
        let _ = respell_body_with("{ use a::b; }", 10, &|at, _| {
            asked.borrow_mut().push(at);
            None
        });
        assert_eq!(*asked.borrow(), [12]);
    }
}
