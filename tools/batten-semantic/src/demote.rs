//! `demote [root] [--write]`: fold each extension trait whose bodies name
//! nothing above its type's layer back into an inherent impl beside the type
//! (Lakos demotion; CLOUD-2803).
//!
//! Every decision is `hir`'s: which layers a body names, which names the
//! type's module already has in scope, the path to import one from, and every
//! usage of the trait. Anything it cannot do exactly (a trait named inside a
//! grouped `use`, a qualified call) is counted and left for the compiler to
//! name, never guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ops::Range;

use ra_ap_hir::{
    Adt, AsAssocItem as _, Crate, FindPathConfig, Module, ModuleDef, PathResolution, Semantics,
    Trait,
};
use ra_ap_syntax::ast::{HasGenericParams as _, HasVisibility as _};
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::defs::Definition;
use ra_ap_syntax::{AstNode, Edition, SyntaxKind, SyntaxNode, TextRange, ast};
use ra_ap_vfs::{FileId, Vfs};

use crate::top_level;

/// One text edit: replace `range` of a file with `text`.
#[derive(Debug, Clone)]
struct Edit {
    range: Range<usize>,
    text: String,
}

/// What a dry run or a write did, as counts.
#[derive(Debug, Default)]
struct Tally {
    demoted: usize,
    held: usize,
    imports: usize,
    uses_removed: usize,
    left: usize,
}

const FIND: FindPathConfig = FindPathConfig {
    prefer_no_std: false,
    prefer_prelude: true,
    prefer_absolute: false,
    allow_unstable: true,
};

pub fn run(db: &RootDatabase, vfs: &Vfs, write: bool) -> Result<(), Box<dyn Error>> {
    let sema = Semantics::new(db);
    let Some(batten) = Crate::all(db)
        .into_iter()
        .find(|krate| krate.display_name(db).is_some_and(|name| name.to_string() == "batten"))
    else {
        println!("demote: no batten crate");
        return Ok(());
    };
    let mut edits: BTreeMap<FileId, Vec<Edit>> = BTreeMap::new();
    let mut imports: BTreeMap<FileId, BTreeSet<String>> = BTreeMap::new();
    let mut tally = Tally::default();
    for module in batten.modules(db) {
        for implementation in module.impl_defs(db) {
            let Some(trait_) = implementation.trait_(db) else {
                continue;
            };
            if !trait_.name(db).as_str().ends_with("Ext") || trait_.module(db).krate(db) != batten {
                continue;
            }
            let Some(adt) = implementation.self_ty(db).as_adt() else {
                continue;
            };
            let home_module = adt.module(db);
            let Some(home) = top_level(db, home_module) else {
                continue;
            };
            let (Some(impl_src), Some(trait_src)) =
                (sema.source(implementation), sema.source(trait_))
            else {
                tally.left += 1;
                continue;
            };
            let impl_node = impl_src.value.clone();
            if !names_only_below(db, &sema, impl_node.syntax(), trait_, batten, &home) {
                tally.held += 1;
                continue;
            }
            let (Some(impl_file), Some(trait_file), Some((adt_file, adt_end))) = (
                file_of(db, impl_src.file_id),
                file_of(db, trait_src.file_id),
                adt_end(db, &sema, adt),
            ) else {
                tally.left += 1;
                continue;
            };
            let (needed, renames) =
                needed_imports(db, &sema, impl_node.syntax(), trait_, home_module);
            let inherent = inherent_impl(&impl_node, &trait_src.value, &renames);
            edits.entry(adt_file).or_default().push(Edit {
                range: adt_end..adt_end,
                text: format!("\n\n{inherent}"),
            });
            edits.entry(impl_file).or_default().push(removal(impl_node.syntax()));
            edits.entry(trait_file).or_default().push(removal(trait_src.value.syntax()));
            tally.imports += needed.len();
            imports.entry(adt_file).or_default().extend(needed);
            remove_usages(db, &sema, trait_, &mut edits, &mut tally);
            tally.demoted += 1;
        }
    }
    for (file, wanted) in imports {
        let Some(at) = import_point(db, &sema, file) else {
            tally.left += wanted.len();
            continue;
        };
        let text: String = wanted.iter().map(|line| format!("{line}\n")).collect();
        edits.entry(file).or_default().push(Edit { range: at..at, text });
    }
    let mut files = 0_usize;
    if write {
        for (file, mut list) in edits {
            let Some(path) = vfs.file_path(file).as_path().map(|path| path.to_string()) else {
                tally.left += 1;
                continue;
            };
            let mut text = std::fs::read_to_string(&path)?;
            list.sort_by(|a, b| b.range.start.cmp(&a.range.start).then(b.range.end.cmp(&a.range.end)));
            let mut floor = usize::MAX;
            for edit in list {
                // Overlapping edits would corrupt the file: refuse the file.
                if edit.range.end > floor {
                    return Err(format!("demote: overlapping edits in {path}").into());
                }
                text.replace_range(edit.range.clone(), &edit.text);
                floor = edit.range.start;
            }
            std::fs::write(&path, text)?;
            files += 1;
        }
    }
    println!(
        "demote: {} demoted, {} held, {} import(s) added, {} use(s) removed, {} left, {} file(s) written",
        tally.demoted, tally.held, tally.imports, tally.uses_removed, tally.left, files
    );
    Ok(())
}

/// Whether every `batten` item the impl's bodies name sits in the type's own
/// layer (or another crate), the trait itself aside.
fn names_only_below(
    db: &RootDatabase,
    sema: &Semantics<'_, RootDatabase>,
    node: &SyntaxNode,
    trait_: Trait,
    batten: Crate,
    home: &str,
) -> bool {
    let layer_ok = |module: Module| {
        module.krate(db) != batten || top_level(db, module).as_deref() == Some(home)
    };
    // AN UNRESOLVED NAME HOLDS THE TRAIT. "Could not resolve" is could-not-
    // look, never "names nothing upward": the first write moved a body
    // calling `matchers`, a method of the held `UnclaimedExt`, because that
    // call did not resolve and the check read the silence as a pass.
    for path in node.descendants().filter_map(ast::Path::cast) {
        // A qualifier is judged as part of the path it qualifies.
        if path.syntax().parent().and_then(ast::Path::cast).is_some() {
            continue;
        }
        match sema.resolve_path(&path) {
            Some(PathResolution::Def(def)) => {
                if def != ModuleDef::Trait(trait_)
                    && let Some(owner) = def.module(db)
                    && !layer_ok(owner)
                {
                    return false;
                }
            }
            Some(_) => {}
            None => return false,
        }
    }
    for call in node.descendants().filter_map(ast::MethodCallExpr::cast) {
        match sema.resolve_method_call(&call) {
            Some(function) if layer_ok(function.module(db)) => {}
            _ => return false,
        }
    }
    true
}

/// The `FileId` of a source that is a real file, not a macro expansion.
fn file_of(db: &RootDatabase, file: ra_ap_hir::HirFileId) -> Option<FileId> {
    file.file_id().map(|editioned| editioned.file_id(db))
}

/// Where an ADT's declaration ends, to insert the inherent impl after it.
fn adt_end(db: &RootDatabase, sema: &Semantics<'_, RootDatabase>, adt: Adt) -> Option<(FileId, usize)> {
    let (file, node) = match adt {
        Adt::Struct(it) => sema.source(it).map(|src| (src.file_id, src.value.syntax().clone()))?,
        Adt::Enum(it) => sema.source(it).map(|src| (src.file_id, src.value.syntax().clone()))?,
        Adt::Union(it) => sema.source(it).map(|src| (src.file_id, src.value.syntax().clone()))?,
    };
    Some((file_of(db, file)?, usize::from(node.text_range().end())))
}

/// An item's whole span plus the newline after it, so no blank line is left.
fn removal(node: &SyntaxNode) -> Edit {
    let range = node.text_range();
    let mut end = usize::from(range.end());
    if let Some(next) = node.next_sibling_or_token()
        && next.kind() == SyntaxKind::WHITESPACE
        && let Some(token) = next.as_token()
        && token.text().starts_with('\n')
    {
        end += 1;
    }
    Edit {
        range: usize::from(range.start())..end,
        text: String::new(),
    }
}

/// The leading doc comments and attributes of an item, verbatim.
fn leading(node: &SyntaxNode) -> String {
    node.children_with_tokens()
        .take_while(|child| {
            matches!(child.kind(), SyntaxKind::COMMENT | SyntaxKind::WHITESPACE | SyntaxKind::ATTR)
        })
        .map(|child| child.to_string())
        .collect()
}

/// The text of an item from its first non-doc, non-attribute token, with each
/// rename inside it applied (an alias the destination does not have).
fn body_of(node: &SyntaxNode, renames: &[(TextRange, String)]) -> String {
    let skip = leading(node).len();
    let start = usize::from(node.text_range().start()) + skip;
    let mut text = node.text().to_string()[skip..].to_owned();
    let mut inside: Vec<&(TextRange, String)> = renames
        .iter()
        .filter(|(range, _)| node.text_range().contains_range(*range))
        .collect();
    inside.sort_by_key(|(range, _)| std::cmp::Reverse(range.start()));
    for (range, name) in inside {
        let from = usize::from(range.start()) - start;
        let to = usize::from(range.end()) - start;
        text.replace_range(from..to, name);
    }
    text
}

/// `impl<..> Type { .. }` with each item carrying the trait's docs and
/// visibility, so the folded method keeps the contract the trait stated.
fn inherent_impl(
    implementation: &ast::Impl,
    trait_: &ast::Trait,
    renames: &[(TextRange, String)],
) -> String {
    let visibility = trait_
        .visibility()
        .map(|vis| format!("{} ", vis.syntax().text()))
        .unwrap_or_default();
    let docs: BTreeMap<String, String> = trait_
        .assoc_item_list()
        .map(|list| {
            list.assoc_items()
                .filter_map(|item| Some((item_name(&item)?, leading(item.syntax()))))
                .collect()
        })
        .unwrap_or_default();
    let generics = implementation
        .generic_param_list()
        .map(|list| list.syntax().text().to_string())
        .unwrap_or_default();
    let self_ty = implementation
        .self_ty()
        .map(|ty| ty.syntax().text().to_string())
        .unwrap_or_default();
    let mut out = format!("impl{generics} {self_ty} {{\n");
    if let Some(list) = implementation.assoc_item_list() {
        for item in list.assoc_items() {
            let name = item_name(&item).unwrap_or_default();
            let doc = docs.get(&name).map(String::as_str).unwrap_or("");
            let own = leading(item.syntax());
            out.push_str(&format!(
                "    {}{}{}{}\n",
                doc.trim_start(),
                own.trim_start(),
                visibility,
                body_of(item.syntax(), renames)
            ));
        }
    }
    out.push_str("}\n");
    out
}

fn item_name(item: &ast::AssocItem) -> Option<String> {
    use ast::HasName as _;
    match item {
        ast::AssocItem::Fn(it) => it.name(),
        ast::AssocItem::Const(it) => it.name(),
        ast::AssocItem::TypeAlias(it) => it.name(),
        ast::AssocItem::MacroCall(_) => None,
    }
    .map(|name| name.text().to_string())
}

/// The `use` lines the type's module needs for the folded bodies: each
/// single-segment name it does not already have in scope, and each other
/// trait whose method a body calls.
fn needed_imports(
    db: &RootDatabase,
    sema: &Semantics<'_, RootDatabase>,
    node: &SyntaxNode,
    trait_: Trait,
    home: Module,
) -> (BTreeSet<String>, Vec<(TextRange, String)>) {
    let mut renames: Vec<(TextRange, String)> = Vec::new();
    let in_scope: BTreeSet<String> = home
        .scope(db, None)
        .into_iter()
        .map(|(name, _)| name.as_str().to_owned())
        .collect();
    let mut wanted = BTreeSet::new();
    let render = |def: ModuleDef| {
        home.find_path(db, def, FIND)
            .map(|path| path.display(db, Edition::Edition2024).to_string())
    };
    // THE LEFTMOST SEGMENT OF EVERY PATH is the name the scope must hold:
    // `Progress::Done` and `Path::new` need `Progress` and `Path` imported.
    // Skipping qualified paths missed both on the first corrected write.
    for path in node.descendants().filter_map(ast::Path::cast) {
        if path.qualifier().is_some() {
            continue;
        }
        // THE NAME, NEVER THE SEGMENT: a segment carries its generic
        // arguments, so `Option<String>` read as an alias of `Option` and was
        // rewritten to a bare `Option` on the fourth write.
        let Some(name) = path.segment().and_then(|segment| segment.name_ref()) else {
            continue;
        };
        let text = name.text().to_string();
        if matches!(text.as_str(), "Self" | "self" | "super" | "crate") || in_scope.contains(&text) {
            continue;
        }
        if let Some(PathResolution::Def(def)) = sema.resolve_path(&path)
            && def != ModuleDef::Trait(trait_)
            && !matches!(def, ModuleDef::BuiltinType(_))
            && let Some(rendered) = render(def)
        {
            if rendered.contains("::") {
                wanted.insert(format!("use {rendered};"));
            } else if rendered != text {
                // `hir` names it in one segment at the destination, but not
                // as the source spelled it: an alias (`ExecProgress as
                // Progress`) the destination does not import.
                renames.push((name.syntax().text_range(), rendered));
            }
        }
    }
    for call in node.descendants().filter_map(ast::MethodCallExpr::cast) {
        if let Some(function) = sema.resolve_method_call(&call)
            && let Some(other) = function
                .as_assoc_item(db)
                .and_then(|item| item.container_trait(db))
            && other != trait_
            && !in_scope.contains(other.name(db).as_str())
            && let Some(rendered) = render(ModuleDef::Trait(other))
            && rendered.contains("::")
        {
            wanted.insert(format!("use {rendered} as _;"));
        }
    }
    (wanted, renames)
}

/// Delete every `use` of the trait; count any usage it cannot fold exactly.
fn remove_usages(
    db: &RootDatabase,
    sema: &Semantics<'_, RootDatabase>,
    trait_: Trait,
    edits: &mut BTreeMap<FileId, Vec<Edit>>,
    tally: &mut Tally,
) {
    let usages = Definition::Trait(trait_).usages(sema).all();
    for (file, references) in usages.references {
        let file = file.file_id(db);
        let source = sema.parse_guess_edition(file);
        for reference in references {
            let Some(token) = source
                .syntax()
                .token_at_offset(reference.range.start())
                .right_biased()
            else {
                tally.left += 1;
                continue;
            };
            let Some(use_item) = token.parent_ancestors().find_map(ast::Use::cast) else {
                // A path naming the trait outside a `use`: inside the impl
                // header it goes with the impl; elsewhere it is left.
                if !token.parent_ancestors().any(|node| ast::Impl::can_cast(node.kind()) || ast::Trait::can_cast(node.kind())) {
                    tally.left += 1;
                }
                continue;
            };
            let single = use_item
                .use_tree()
                .is_some_and(|tree| tree.use_tree_list().is_none());
            if single {
                edits.entry(file).or_default().push(removal(use_item.syntax()));
                tally.uses_removed += 1;
            } else {
                tally.left += 1;
            }
        }
    }
    let _ = TextRange::default;
}

/// Where new `use` lines go: after the file's last top-level `use`, else
/// before its first item.
fn import_point(db: &RootDatabase, sema: &Semantics<'_, RootDatabase>, file: FileId) -> Option<usize> {
    let _ = db;
    let source = sema.parse_guess_edition(file);
    let items: Vec<ast::Item> = ra_ap_syntax::ast::HasModuleItem::items(&source).collect();
    if let Some(last) = items.iter().filter_map(|item| match item {
        ast::Item::Use(it) => Some(it.syntax().text_range().end()),
        _ => None,
    }).last() {
        return Some(usize::from(last) + 1);
    }
    items.first().map(|item| usize::from(item.syntax().text_range().start()))
}
