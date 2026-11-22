//! `cut-crate`: move a dependency-closed set of crate-root modules out of one
//! workspace package into a new sibling package, rewriting every path to them
//! and leaving no re-export shim (CLOUD-2789 phase 2, plan step 8).
//!
//! The earlier cuts (`batten-base`, `batten-core`, `batten-facts`) left a
//! `pub use` per moved module in the old crate, the shim shape CLOUD-2793
//! counts and retires. A cut here instead respells every path that reaches a
//! moved module, so the old name stops existing in the same change.
//!
//! The set must be closed downward: a moved file naming an unmoved module of
//! the old crate, or the old crate itself, is REFUSED with each site, because
//! the new crate would have to depend on the crate it was cut from. That is the
//! levelization rule (Lakos, *Large-Scale C++ Software Design*, §1.10): a
//! component's level is one more than the highest level it depends on, so a
//! cut is legal only along a level boundary.
//!
//! The rewrite walks the lossless token stream of one parse per file, so a
//! comment or a string is never touched, while a path inside a macro's token
//! tree is. A use group mixing moved and unmoved modules is the one shape it
//! does not split, and is reported as remainder by `path:line`.

use std::collections::{BTreeMap, BTreeSet};

use batten::module_graph::use_leaves;
use batten::source::rust_parse;
use ra_ap_syntax::ast::{HasModuleItem as _, HasName as _};
use ra_ap_syntax::{AstNode as _, SyntaxKind, SyntaxToken, ast};
use toml_edit::{DocumentMut, InlineTable, Item, Value};

/// One cut: the package directory cut from, the new package's name and the
/// crate-root modules that move.
#[derive(Debug, Clone, Copy)]
pub struct Cut<'a> {
    /// The source package's directory, relative to the workspace root.
    pub from: &'a str,
    /// The new package's name; it lands beside `from`.
    pub name: &'a str,
    /// The crate-root modules that move, by name.
    pub modules: &'a [&'a str],
}

/// What a cut does to the tree, or why it does nothing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Each file to write, created or rewritten, by path.
    pub writes: BTreeMap<String, String>,
    /// Each file the move empties.
    pub removes: BTreeSet<String>,
    /// Each reason the cut was refused, as `path:line` and the path written.
    /// Non-empty means `writes` and `removes` are empty.
    pub refused: Vec<String>,
    /// Each site the rewrite could not respell, as `path:line`.
    pub remainder: Vec<String>,
}

/// One reference `root::…` in a file: the children it names (one for a path,
/// each first segment for a use group) and the byte range of `root`.
struct Reach {
    children: Vec<String>,
    root: std::ops::Range<usize>,
    offset: usize,
}

/// The names one cut is spelled in, shared by its phases.
struct Names<'a> {
    cut: &'a Cut<'a>,
    src: String,
    home: String,
    manifest: String,
    old: String,
    old_ident: String,
    new_ident: String,
    modules: BTreeSet<&'a str>,
}

impl Names<'_> {
    /// The path under the new crate's `src/` of a moved file, or `None`.
    fn moved(&self, path: &str) -> Option<String> {
        let rest = path.strip_prefix(&self.src)?;
        self.modules
            .iter()
            .any(|module| rest == format!("{module}.rs") || rest.starts_with(&format!("{module}/")))
            .then(|| rest.to_owned())
    }
}

/// Plan `cut` over `files` (every `.rs` by path) and `manifests` (every
/// `Cargo.toml` by path, the workspace root's as `Cargo.toml`). Running the
/// plan's output through it again plans nothing.
#[must_use]
pub fn cut_crate(
    cut: &Cut<'_>,
    files: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
) -> Plan {
    let mut plan = Plan::default();
    let manifest = format!("{}/Cargo.toml", cut.from);
    let Some(old) = manifests.get(&manifest).and_then(|text| package_name(text)) else {
        plan.refused.push(format!("{manifest}: no [package] name"));
        return plan;
    };
    let parent = cut.from.rsplit_once('/').map_or("", |(dir, _)| dir);
    let names = Names {
        cut,
        src: format!("{}/src/", cut.from),
        home: if parent.is_empty() {
            cut.name.to_owned()
        } else {
            format!("{parent}/{}", cut.name)
        },
        manifest,
        old_ident: old.replace('-', "_"),
        new_ident: cut.name.replace('-', "_"),
        old,
        modules: cut.modules.iter().copied().collect(),
    };
    let moved: BTreeMap<&String, String> = files
        .keys()
        .filter_map(|path| names.moved(path).map(|rest| (path, rest)))
        .collect();
    if moved.is_empty() {
        if !files.contains_key(&format!("{}/src/lib.rs", names.home)) {
            plan.refused.push(format!(
                "{}: none of {} is a module here",
                names.src,
                cut.modules.join(", ")
            ));
        }
        return plan;
    }
    let used_roots = refuse_open(&names, &moved, files, &mut plan);
    if !plan.refused.is_empty() {
        return plan;
    }
    move_files(&names, &moved, files, &mut plan);
    let needs = respell(&names, &moved, files, manifests, &mut plan);
    wire_manifests(&names, needs, manifests, &used_roots, &mut plan);
    plan
}

/// Refuse each site in a moved file that reaches an unmoved module or the old
/// crate; return the crates the moved files name.
fn refuse_open(
    names: &Names<'_>,
    moved: &BTreeMap<&String, String>,
    files: &BTreeMap<String, String>,
    plan: &mut Plan,
) -> BTreeSet<String> {
    let mut used_roots = BTreeSet::new();
    for path in moved.keys() {
        let text = &files[*path];
        let Some(tree) = parsed(text) else {
            plan.refused.push(format!("{path}: could not look"));
            continue;
        };
        for reach in reaches(&tree, "crate") {
            for child in reach
                .children
                .iter()
                .filter(|child| !names.modules.contains(child.as_str()))
            {
                plan.refused.push(format!(
                    "{path}:{} crate::{child}",
                    line_of(text, reach.offset)
                ));
            }
        }
        for reach in reaches(&tree, &names.old_ident) {
            for child in &reach.children {
                plan.refused.push(format!(
                    "{path}:{} {}::{child}",
                    line_of(text, reach.offset),
                    names.old_ident
                ));
            }
        }
        used_roots.extend(path_roots(&tree));
    }
    used_roots
}

/// Each moved file to its new home, and the new crate's root module.
fn move_files(
    names: &Names<'_>,
    moved: &BTreeMap<&String, String>,
    files: &BTreeMap<String, String>,
    plan: &mut Plan,
) {
    for (path, rest) in moved {
        plan.removes.insert((*path).clone());
        plan.writes
            .insert(format!("{}/src/{rest}", names.home), files[*path].clone());
    }
    let old = &names.old;
    let mut lib = format!(
        "//! Cut from `{old}` by `cut-crate` (CLOUD-2789): the modules below\n\
         //! form a set no module left in `{old}` is reached from.\n\n"
    );
    for module in &names.modules {
        lib.push_str("pub mod ");
        lib.push_str(module);
        lib.push_str(";\n");
    }
    plan.writes
        .insert(format!("{}/src/lib.rs", names.home), lib);
}

/// Respell every path left behind; return each package now naming the new
/// crate, and whether its library (not only its tests) does.
fn respell(
    names: &Names<'_>,
    moved: &BTreeMap<&String, String>,
    files: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
    plan: &mut Plan,
) -> BTreeMap<String, bool> {
    let mut needs: BTreeMap<String, bool> = BTreeMap::new();
    for (path, text) in files {
        if moved.contains_key(path) {
            continue;
        }
        let Some((edited, respelled)) = respell_file(names, path, text, plan) else {
            continue;
        };
        if respelled && let Some(package) = package_of(path, manifests) {
            let dir = package.strip_suffix("Cargo.toml").unwrap_or_default();
            let in_src = path.starts_with(&format!("{dir}src/"));
            *needs.entry(package).or_insert(false) |= in_src;
        }
        plan.writes.insert(path.clone(), edited);
    }
    needs
}

/// One file left behind, respelled, and whether any path moved; `None` when
/// nothing changed.
fn respell_file(
    names: &Names<'_>,
    path: &str,
    text: &str,
    plan: &mut Plan,
) -> Option<(String, bool)> {
    let root = if path.starts_with(&names.src) {
        "crate"
    } else {
        names.old_ident.as_str()
    };
    let mut edited = text.to_owned();
    if path == format!("{}lib.rs", names.src) {
        let Some(dropped) = drop_module_items(&edited, &names.modules) else {
            plan.remainder.push(format!("{path}: could not look"));
            return None;
        };
        edited = dropped;
    }
    let Some(tree) = parsed(&edited) else {
        if names.modules.iter().any(|module| text.contains(module)) {
            plan.remainder.push(format!("{path}: could not look"));
        }
        return None;
    };
    let mut splices: Vec<std::ops::Range<usize>> = Vec::new();
    for reach in reaches(&tree, root) {
        let moving = reach
            .children
            .iter()
            .filter(|child| names.modules.contains(child.as_str()))
            .count();
        if moving == reach.children.len() && moving > 0 {
            splices.push(reach.root);
        } else if moving > 0 {
            plan.remainder
                .push(format!("{path}:{}", line_of(&edited, reach.offset)));
        }
    }
    if splices.is_empty() && edited == text {
        return None;
    }
    splices.sort_by_key(|range| std::cmp::Reverse(range.start));
    splices.dedup();
    let respelled = !splices.is_empty();
    for range in splices {
        edited.replace_range(range, &names.new_ident);
    }
    Some((edited, respelled))
}

/// Each package naming the new crate gains its dependency; the new crate gets
/// its manifest.
fn wire_manifests(
    names: &Names<'_>,
    needs: BTreeMap<String, bool>,
    manifests: &BTreeMap<String, String>,
    used_roots: &BTreeSet<String>,
    plan: &mut Plan,
) {
    let version = manifests
        .get("Cargo.toml")
        .and_then(|text| text.parse::<DocumentMut>().ok())
        .and_then(|doc| {
            doc["workspace"]["package"]["version"]
                .as_str()
                .map(str::to_owned)
        });
    for (package, in_src) in needs {
        let Ok(mut doc) = manifests[&package].parse::<DocumentMut>() else {
            plan.remainder.push(format!("{package}: could not look"));
            continue;
        };
        let relative = relative_to(&package, &names.home);
        add_dependency(
            &mut doc,
            names.cut.name,
            &relative,
            version.as_deref(),
            in_src,
        );
        plan.writes.insert(package, doc.to_string());
    }
    let built = new_manifest(
        &manifests[&names.manifest],
        names.cut.name,
        &names.old,
        &names.modules,
        used_roots,
    );
    if let Some(text) = built {
        plan.writes
            .insert(format!("{}/Cargo.toml", names.home), text);
    } else {
        plan.remainder
            .push(format!("{}: could not look", names.manifest));
    }
}

/// The file's tree, or `None` when the parser reports any error.
fn parsed(text: &str) -> Option<ast::SourceFile> {
    let parse = rust_parse(text, ra_ap_syntax::Edition::Edition2024);
    parse.errors().is_empty().then(|| parse.tree())
}

/// The significant tokens of a tree, trivia (whitespace, comments) dropped.
fn significant(tree: &ast::SourceFile) -> Vec<SyntaxToken> {
    tree.syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

/// Every `root::…` in a tree, macro token trees included: a path names one
/// child, a use group `root::{…}` each first segment under it.
fn reaches(tree: &ast::SourceFile, root: &str) -> Vec<Reach> {
    let tokens = significant(tree);
    let mut found = Vec::new();
    for (at, head) in tokens.iter().enumerate() {
        if head.text() != root || after_separator(&tokens, at) {
            continue;
        }
        let Some(next) = separator_end(&tokens, at + 1).and_then(|end| tokens.get(end)) else {
            continue;
        };
        let range = head.text_range();
        let root_range = usize::from(range.start())..usize::from(range.end());
        let children: Vec<String> = if next.kind() == SyntaxKind::L_CURLY {
            group_children(head, root).into_iter().collect()
        } else {
            vec![next.text().to_owned()]
        };
        found.push(Reach {
            children,
            offset: root_range.start,
            root: root_range,
        });
    }
    found
}

/// The index past a `::` starting at `at`: one `::` token in parsed code, or
/// two `:` tokens inside a macro's token tree, where the lexer keeps
/// punctuation one character per token.
fn separator_end(tokens: &[SyntaxToken], at: usize) -> Option<usize> {
    match tokens.get(at)?.kind() {
        SyntaxKind::COLON2 => Some(at + 1),
        SyntaxKind::COLON if tokens.get(at + 1)?.kind() == SyntaxKind::COLON => Some(at + 2),
        _ => None,
    }
}

/// Whether the token at `at` follows a `::`, so it is a later segment rather
/// than a path's root.
fn after_separator(tokens: &[SyntaxToken], at: usize) -> bool {
    match at.checked_sub(1).map(|before| tokens[before].kind()) {
        Some(SyntaxKind::COLON2) => true,
        Some(SyntaxKind::COLON) => at >= 2 && tokens[at - 2].kind() == SyntaxKind::COLON,
        _ => false,
    }
}

/// The distinct first segments under `root` in the use tree `head` opens.
fn group_children(head: &SyntaxToken, root: &str) -> BTreeSet<String> {
    let Some(tree) = head
        .parent_ancestors()
        .filter_map(ast::UseTree::cast)
        .last()
    else {
        return BTreeSet::new();
    };
    use_leaves(&tree)
        .into_iter()
        .filter(|leaf| leaf.path.first().is_some_and(|first| first == root))
        .filter_map(|leaf| leaf.path.get(1).cloned())
        .collect()
}

/// The first segment of every path in a tree: the crates a file names.
fn path_roots(tree: &ast::SourceFile) -> BTreeSet<String> {
    let tokens = significant(tree);
    let mut roots = BTreeSet::new();
    for (at, head) in tokens.iter().enumerate() {
        if head.kind() == SyntaxKind::IDENT
            && !after_separator(&tokens, at)
            && separator_end(&tokens, at + 1).is_some()
        {
            roots.insert(head.text().to_owned());
        }
    }
    for item in tree
        .syntax()
        .descendants()
        .filter_map(ast::ExternCrate::cast)
    {
        if let Some(name) = item.name_ref() {
            roots.insert(name.text().to_string());
        }
    }
    roots
}

/// `lib` without its `mod m;` items for each moved `m`, attributes and doc
/// comments included, or `None` when it does not parse.
fn drop_module_items(lib: &str, modules: &BTreeSet<&str>) -> Option<String> {
    let tree = parsed(lib)?;
    let mut ranges: Vec<std::ops::Range<usize>> = tree
        .items()
        .filter_map(|item| match item {
            ast::Item::Module(module) => Some(module),
            _ => None,
        })
        .filter(|module| module.item_list().is_none())
        .filter(|module| {
            module
                .name()
                .is_some_and(|name| modules.contains(name.text().to_string().as_str()))
        })
        .map(|module| {
            let range = module.syntax().text_range();
            let end = usize::from(range.end());
            let end = if lib[end..].starts_with('\n') {
                end + 1
            } else {
                end
            };
            usize::from(range.start())..end
        })
        .collect();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut edited = lib.to_owned();
    for range in ranges {
        edited.replace_range(range, "");
    }
    Some(edited)
}

/// The 1-based line of a byte offset.
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

/// The `[package] name` of a manifest.
fn package_name(manifest: &str) -> Option<String> {
    let doc = manifest.parse::<DocumentMut>().ok()?;
    doc["package"]["name"].as_str().map(str::to_owned)
}

/// The manifest of the package `path` sits in: the longest manifest directory
/// that prefixes it.
fn package_of(path: &str, manifests: &BTreeMap<String, String>) -> Option<String> {
    manifests
        .keys()
        .filter(|manifest| manifest.as_str() != "Cargo.toml")
        .filter(|manifest| {
            path.starts_with(manifest.strip_suffix("Cargo.toml").unwrap_or_default())
        })
        .max_by_key(|manifest| manifest.len())
        .cloned()
}

/// The path from the directory of `manifest` to `home`, as a manifest's
/// `path =` writes it.
fn relative_to(manifest: &str, home: &str) -> String {
    let dir = manifest
        .strip_suffix("Cargo.toml")
        .unwrap_or_default()
        .trim_end_matches('/');
    let from: Vec<&str> = dir.split('/').filter(|part| !part.is_empty()).collect();
    let to: Vec<&str> = home.split('/').collect();
    let shared = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    format!(
        "{}{}",
        "../".repeat(from.len() - shared),
        to[shared..].join("/")
    )
}

/// Add `name` to `[dependencies]` (or `[dev-dependencies]` when only tests
/// name it), as the workspace's internal dependencies are written.
fn add_dependency(
    doc: &mut DocumentMut,
    name: &str,
    path: &str,
    version: Option<&str>,
    in_src: bool,
) {
    let table = if in_src {
        "dependencies"
    } else {
        "dev-dependencies"
    };
    if doc
        .get("dependencies")
        .and_then(|deps| deps.get(name))
        .is_some()
    {
        return;
    }
    let mut entry = InlineTable::new();
    entry.insert("path", Value::from(path));
    if let Some(version) = version {
        entry.insert("version", Value::from(format!("={version}")));
    }
    if doc.get(table).is_none() {
        doc[table] = toml_edit::table();
    }
    if let Some(deps) = doc[table].as_table_like_mut()
        && deps.get(name).is_none()
    {
        deps.insert(name, Item::Value(Value::InlineTable(entry)));
    }
}

/// The new package's manifest: the source package's `[package]` and `[lints]`
/// with a new name and description, and only the dependencies the moved
/// files name.
fn new_manifest(
    source: &str,
    name: &str,
    old: &str,
    modules: &BTreeSet<&str>,
    used: &BTreeSet<String>,
) -> Option<String> {
    let mut doc = source.parse::<DocumentMut>().ok()?;
    doc.as_table_mut().retain(|key, _| {
        matches!(
            key,
            "package" | "dependencies" | "dev-dependencies" | "lints"
        )
    });
    for (_, item) in doc.as_table_mut().iter_mut() {
        if let Some(table) = item.as_table_mut() {
            table.decor_mut().clear();
            for (mut key, _) in table.iter_mut() {
                key.leaf_decor_mut().clear();
            }
        }
    }
    let list: Vec<&str> = modules.iter().copied().collect();
    doc["package"]["name"] = toml_edit::value(name);
    doc["package"]["description"] = toml_edit::value(format!(
        "Cut from `{old}` by `cut-crate`: {}.",
        list.join(", ")
    ));
    for table in ["dependencies", "dev-dependencies"] {
        if let Some(deps) = doc.get_mut(table).and_then(Item::as_table_like_mut) {
            let unused: Vec<String> = deps
                .iter()
                .map(|(key, _)| key.to_owned())
                .filter(|key| !used.contains(&key.replace('-', "_")))
                .collect();
            for key in unused {
                deps.remove(&key);
            }
        }
    }
    Some(doc.to_string())
}
