//! Lossless Rust rewrites, the substrate a Rust `fix` writes through (CLOUD-1580).
//!
//! # Why this exists
//!
//! A class-2 security remedy is a one-line migration from a retired form to the
//! correct one: `OsRng.gen()` to `.random()`, `#[allow]` to `#[expect]`. A `fix`
//! that makes one must write the file back with every comment, string literal
//! and indent intact. Every byte-splicing or pattern-only rewriter measured on
//! the row fails that: a text match for `.gen(` hits a doc comment or a string
//! literal before it reaches the call. `ra_ap_syntax`'s rowan CST prints back
//! byte-identical outside the edit, so an edit made on the tree changes exactly
//! the token it names.
//!
//! # The contract
//!
//! **Output differs from input only at the edited tokens.** An input with nothing
//! to edit returns byte-identical. Input the parser reports errors over is
//! **could-not-look**, never a silent no-op: a codemod over a tree it did not
//! understand is a confident wrong rewrite, and `errors()` is what lets this one
//! abstain instead.
//!
//! **The edition is a required input**, with no default. The same source can
//! parse cleanly under one edition and fail under another: `gen` is a keyword
//! in 2024, which is why `rand` renamed the method. A default edition would
//! quietly choose which of those two answers a caller gets.
//!
//! # Effect
//!
//! Pure: text in, text out, no IO. A `fix` running under `enforce` writes the
//! result, and parsing alone is a read. This module reaches nothing else in the
//! crate.

use std::collections::BTreeSet;
use std::fmt;

use ra_ap_syntax::ast::HasModuleItem as _;
use ra_ap_syntax::syntax_editor::{SyntaxEdit, SyntaxEditor};
use ra_ap_syntax::{AstNode as _, ast};

/// The Rust edition a source is parsed under. There is deliberately no
/// `Default`: see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    /// Rust 2015.
    E2015,
    /// Rust 2018.
    E2018,
    /// Rust 2021.
    E2021,
    /// Rust 2024.
    E2024,
}

impl Edition {
    fn parser(self) -> ra_ap_syntax::Edition {
        match self {
            Self::E2015 => ra_ap_syntax::Edition::Edition2015,
            Self::E2018 => ra_ap_syntax::Edition::Edition2018,
            Self::E2021 => ra_ap_syntax::Edition::Edition2021,
            Self::E2024 => ra_ap_syntax::Edition::Edition2024,
        }
    }
}

/// The parser reported errors, so the codemod declined to rewrite the source.
///
/// Carries a count rather than the messages: output is a pointer, never the
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CouldNotLook {
    /// How many errors the parser reported.
    pub errors: usize,
}

impl fmt::Display for CouldNotLook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the source does not parse ({} error(s)), so no rewrite was attempted",
            self.errors
        )
    }
}

impl std::error::Error for CouldNotLook {}

/// Rename every method call named `from` to `to`, and nothing else.
///
/// Only a method-call's own name is matched, so `from` inside a comment, a
/// string literal, a path or a longer identifier (`gen_range` for `gen`) is
/// left alone.
///
/// # Errors
///
/// [`CouldNotLook`] when the parser reports any error over `source` under
/// `edition`. The source is then not rewritten at all.
pub fn rename_method_calls(
    source: &str,
    edition: Edition,
    from: &str,
    to: &str,
) -> Result<String, CouldNotLook> {
    let parse = batten_facts::source::rust_parse(source, edition.parser());
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    let root = parse.syntax_node();
    let targets: Vec<ast::NameRef> = root
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
        .filter_map(|call| call.name_ref())
        .filter(|name| name.text() == from)
        .collect();
    if targets.is_empty() {
        return Ok(source.to_owned());
    }
    let edited = render(&edit(root, &targets, to));
    Ok(edited)
}

/// Redirect every call whose callee is one of `from`'s paths to `to`, and
/// nothing else (CLOUD-2692): `fs::read_to_string(x)` becomes
/// `crate::io::read_to_string(x)`, arguments untouched.
///
/// Only a call expression's own callee path is matched, compared as written
/// with whitespace removed. A path in a `use`, a comment, a string literal, a
/// longer path (`fs::read_to_string_lossy`) or a method call of the same name
/// is left alone.
///
/// # Errors
///
/// [`CouldNotLook`] when the parser reports any error over `source` under
/// `edition`. The source is then not rewritten at all.
pub fn redirect_calls(
    source: &str,
    edition: Edition,
    from: &[&str],
    to: &str,
) -> Result<String, CouldNotLook> {
    let parse = batten_facts::source::rust_parse(source, edition.parser());
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    let root = parse.syntax_node();
    let targets: Vec<ast::Path> = root
        .descendants()
        .filter_map(ast::CallExpr::cast)
        .filter_map(|call| match call.expr()? {
            ast::Expr::PathExpr(callee) => callee.path(),
            _ => None,
        })
        .filter(|path| {
            let written: String = path
                .syntax()
                .text()
                .to_string()
                .split_whitespace()
                .collect();
            from.contains(&written.as_str())
        })
        .collect();
    // INSIDE A MACRO'S ARGUMENTS TOO. A macro call's arguments are a token tree,
    // not expressions, so the call-expression match above cannot see
    // `assert_eq!(fs::read_to_string(p)…)`. There the match is the token run
    // that spells a `from` path, followed by `(`, and the edit is that run's
    // byte range, so every other byte of the macro is kept.
    let mut ranges: Vec<std::ops::Range<usize>> = targets
        .iter()
        .map(|path| {
            let range = path.syntax().text_range();
            usize::from(range.start())..usize::from(range.end())
        })
        .collect();
    for tree in root.descendants().filter_map(ast::TokenTree::cast) {
        // Direct children only: a nested tree is visited on its own, and here
        // it stands as its opening delimiter, which is how a call's `(p)`
        // follows its path inside a macro.
        let tokens: Vec<(String, ra_ap_syntax::TextRange)> = tree
            .syntax()
            .children_with_tokens()
            .filter_map(|child| match child {
                ra_ap_syntax::NodeOrToken::Token(token) => (!token.kind().is_trivia())
                    .then(|| (token.text().to_owned(), token.text_range())),
                ra_ap_syntax::NodeOrToken::Node(node) => node
                    .first_token()
                    .map(|open| (open.text().to_owned(), node.text_range())),
            })
            .collect();
        for path in from {
            for start in 0..tokens.len() {
                // The run is the tokens whose texts concatenate to the path,
                // however the lexer split its `::`.
                let mut spelled = String::new();
                let mut end = start;
                while end < tokens.len() && spelled.len() < path.len() {
                    spelled.push_str(&tokens[end].0);
                    end += 1;
                }
                if spelled != *path || end >= tokens.len() || tokens[end].0 != "(" {
                    continue;
                }
                // Not the tail of a longer path (`x::fs::read`) or a method.
                let preceded = start
                    .checked_sub(1)
                    .is_some_and(|before| matches!(tokens[before].0.as_str(), ":" | "::" | "."));
                if !preceded {
                    let first = tokens[start].1.start();
                    let last = tokens[end - 1].1.end();
                    ranges.push(usize::from(first)..usize::from(last));
                }
            }
        }
    }
    if ranges.is_empty() {
        return Ok(source.to_owned());
    }
    // Spliced from the end, so each range's offsets still hold when it is cut.
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    ranges.dedup();
    let mut edited = source.to_owned();
    for range in ranges {
        edited.replace_range(range, to);
    }
    Ok(edited)
}

/// How many attributes in `source` escape `lint`: each `#[expect(..)]` or
/// `#[allow(..)]` (outer or inner) whose lint list names it, read off the parsed
/// syntax tree (#1276).
///
/// One per attribute, however many times its list repeats the lint. A comment,
/// a string, a doc line naming the lint, and a different lint sharing a prefix
/// (`clippy::disallowed_types_x`) are not escapes, because only an attribute's
/// own token tree is read and each entry is compared whole. A file the parser
/// rejects is counted over the tree it still builds: the count is the ratchet's
/// question, and a partial file is the author's to fix, not a reason to count
/// nothing.
#[must_use]
pub fn lint_escapes(source: &str, edition: Edition, lint: &str) -> usize {
    lint_attributes(source, edition, lint)
        .iter()
        .filter(|found| matches!(found.level.as_str(), "expect" | "allow"))
        .count()
}

/// A lint-level attribute naming a lint, as [`lint_attributes`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintAttribute {
    /// The 1-based line the attribute opens on.
    pub line: usize,
    /// Its level: `expect`, `allow`, `warn`, `deny` or `forbid`.
    pub level: String,
    /// The attribute's whole source text, `#[` to `]`.
    pub text: String,
    /// Whether it stands in `#[cfg(test)]` code: on, or inside, an item
    /// carrying that attribute (CLOUD-2789). Read off the tree by
    /// [`crate::module_graph::cfg_test`], so a test module's annotation is
    /// told from the library's without a text scan for the marker.
    pub in_test: bool,
}

/// Every lint-level attribute in `source` (outer or inner, any of the five
/// levels) whose lint list names `lint`, in source order, read off the parsed
/// syntax tree.
///
/// The census's reader (#1276): a text scan read an attribute spelled inside a
/// string literal or a raw string as a row, and a parse cannot. The same
/// comparison as [`lint_escapes`]: each list entry whole, whitespace removed.
#[must_use]
pub fn lint_attributes(source: &str, edition: Edition, lint: &str) -> Vec<LintAttribute> {
    let wanted: String = lint.split_whitespace().collect();
    batten_facts::source::rust_parse(source, edition.parser())
        .syntax_node()
        .descendants()
        .filter_map(ast::TokenTreeMeta::cast)
        .filter_map(|meta| {
            let attr = meta
                .syntax()
                .parent()
                .filter(|parent| ast::Attr::can_cast(parent.kind()))?;
            let level = meta.path()?.syntax().text().to_string();
            if !matches!(
                level.as_str(),
                "expect" | "allow" | "warn" | "deny" | "forbid"
            ) {
                return None;
            }
            let tree = meta.token_tree()?;
            // The list's entries at its own depth, each the run of its
            // non-trivia tokens between commas; the outer parentheses are the
            // tree's first and last tokens.
            let mut entries = vec![String::new()];
            for child in tree.syntax().children_with_tokens() {
                match child {
                    ra_ap_syntax::NodeOrToken::Token(token) => {
                        let text = token.text();
                        if token.kind().is_trivia() || text == "(" || text == ")" {
                            continue;
                        }
                        if text == "," {
                            entries.push(String::new());
                        } else if let Some(entry) = entries.last_mut() {
                            entry.push_str(text);
                        }
                    }
                    ra_ap_syntax::NodeOrToken::Node(node) => {
                        if let Some(entry) = entries.last_mut() {
                            entry.push_str(&node.text().to_string());
                        }
                    }
                }
            }
            if !entries.contains(&wanted) {
                return None;
            }
            let start = usize::from(attr.text_range().start());
            Some(LintAttribute {
                line: source[..start].matches('\n').count() + 1,
                level,
                text: attr.text().to_string(),
                in_test: crate::module_graph::cfg_test(&attr),
            })
        })
        .collect()
}

/// Every leaf a `use` tree imports, as its full path with whitespace removed and
/// any rename after ` as `: `use a::{b::{X}, self, Y as _};` yields `a::b::X`,
/// `a`, `a::Y as _`. A glob leaf is `<prefix>::*`.
fn use_leaves(tree: &ast::UseTree, prefix: &str, out: &mut BTreeSet<String>) {
    let squeezed = |text: String| text.split_whitespace().collect::<String>();
    let path = tree
        .path()
        .map(|path| squeezed(path.syntax().text().to_string()));
    let full = match (prefix.is_empty(), path.as_deref()) {
        (_, Some("self") | None) => prefix.to_owned(),
        (true, Some(path)) => path.to_owned(),
        (false, Some(path)) => format!("{prefix}::{path}"),
    };
    if let Some(list) = tree.use_tree_list() {
        for inner in list.use_trees() {
            use_leaves(&inner, &full, out);
        }
    } else if tree.star_token().is_some() {
        out.insert(format!("{full}::*"));
    } else {
        // `as _` or `as Name`: the alias is what follows the keyword.
        match tree.rename() {
            Some(rename) => {
                let text = squeezed(rename.syntax().text().to_string());
                let alias = text.strip_prefix("as").unwrap_or(&text);
                out.insert(format!("{full} as {alias}"));
            }
            None => {
                out.insert(full);
            }
        }
    }
}

/// The leaves the `use` items among `items` import, together.
fn held_leaves(items: &[ast::Item]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        if let ast::Item::Use(held) = item
            && let Some(tree) = held.use_tree()
        {
            use_leaves(&tree, "", &mut out);
        }
    }
    out
}

/// Whether every leaf of the `use` line `item` is already imported by `held`,
/// exactly or under a glob of its parent. `None` when `item` is not one `use`.
///
/// A whole-line comparison saw `use a::X;` as missing beside `use a::{X, Y};`
/// and inserted a second import of `X`, which the compiler rejects (E0252).
fn already_imported(held: &BTreeSet<String>, item: &str, edition: Edition) -> Option<bool> {
    let parse = batten_facts::source::rust_parse(item, edition.parser());
    let tree = parse.tree().items().find_map(|top| match top {
        ast::Item::Use(wanted) => wanted.use_tree(),
        _ => None,
    })?;
    let mut wanted = BTreeSet::new();
    use_leaves(&tree, "", &mut wanted);
    Some(wanted.iter().all(|leaf| {
        let path = leaf
            .split_once(" as ")
            .map_or(leaf.as_str(), |(path, _)| path);
        let parent = path.rsplit_once("::").map_or("", |(parent, _)| parent);
        held.contains(leaf) || held.contains(&format!("{parent}::*"))
    }))
}

/// Put `item` (a whole `use …;` line) in scope at the top of the file, once.
///
/// A rename to a trait method needs the trait imported wherever the rename
/// landed. Only TOP-LEVEL `use` items count: one inside an inline module, a
/// comment or a string puts nothing in scope for the file, and is neither a
/// match nor an insertion point. The line goes immediately before the first
/// top-level `use`, or, in a file with none, before its first item, so inner
/// attributes and `//!` docs stay first. A file already importing `item`,
/// compared with whitespace removed, is returned unchanged.
///
/// # Errors
///
/// [`CouldNotLook`] when the parser reports any error over `source` under
/// `edition`. The source is then not rewritten at all.
pub fn ensure_use(source: &str, edition: Edition, item: &str) -> Result<String, CouldNotLook> {
    let parse = batten_facts::source::rust_parse(source, edition.parser());
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    let file = parse.tree();
    let items: Vec<ast::Item> = file.items().collect();
    if already_imported(&held_leaves(&items), item, edition) == Some(true) {
        return Ok(source.to_owned());
    }
    let anchor = items
        .iter()
        .find(|top| matches!(top, ast::Item::Use(_)))
        .or_else(|| items.first());
    let at = anchor.map_or(source.len(), |top| {
        usize::from(top.syntax().text_range().start())
    });
    let mut edited = source.to_owned();
    edited.insert_str(at, &format!("{item}\n"));
    Ok(edited)
}

/// Rewrite every path written exactly `from` to `to`, keeping every other byte
/// (#1276): an item moved between modules. `use a::b::T as _;` becomes
/// `use c::T as _;` and `a::b::T { x }` becomes `c::T { x }` when `from` is
/// `a::b::T` and `to` is `c::T`; a longer path through it (`a::b::T::new`)
/// moves with it, since its qualifier is that path.
///
/// Only a parsed path node is matched, compared as written with whitespace
/// removed. A different path sharing a prefix (`a::b::Tx`), a comment, a string,
/// a path split across a use group (`use a::b::{T}`) and a path inside a macro's
/// token tree are left alone; the last two are the primitive's remainder, read
/// by the caller.
///
/// # Errors
///
/// [`CouldNotLook`] when the parser reports any error over `source` under
/// `edition`. The source is then not rewritten at all.
pub fn rewrite_paths(
    source: &str,
    edition: Edition,
    from: &str,
    to: &str,
) -> Result<String, CouldNotLook> {
    let parse = batten_facts::source::rust_parse(source, edition.parser());
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    let root = parse.syntax_node();
    let mut ranges: Vec<std::ops::Range<usize>> = root
        .descendants()
        .filter_map(ast::Path::cast)
        .filter(|path| {
            let written: String = path
                .syntax()
                .text()
                .to_string()
                .split_whitespace()
                .collect();
            written == from
        })
        .map(|path| {
            let range = path.syntax().text_range();
            usize::from(range.start())..usize::from(range.end())
        })
        .collect();
    if ranges.is_empty() {
        return Ok(source.to_owned());
    }
    // Spliced from the end, so each range's offsets still hold when it is cut.
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut edited = source.to_owned();
    for range in ranges {
        edited.replace_range(range, to);
    }
    Ok(edited)
}

/// Put `item` (a whole `use …;` line) in scope in EVERY module that calls
/// `method`, once each: the innermost inline module around each call, or the
/// file itself.
///
/// A file-level import is wrong both ways for a call inside an inline module.
/// Where the module has its own imports and no `use super::*`, the file's import
/// does not reach it; where the only calls sit in `#[cfg(test)] mod tests`, the
/// file's import is unused in the library build and `-D warnings` refuses it.
/// Measured on #1276: one of each in 198 rewritten files. So the import goes
/// where the call is. In each such module the line lands before its first
/// `use`, or before its first item, at that item's indentation; a module already
/// importing `item` (whitespace removed) is left alone.
///
/// # Errors
///
/// [`CouldNotLook`] when the parser reports any error over `source` under
/// `edition`. The source is then not rewritten at all.
pub fn import_for_calls(
    source: &str,
    edition: Edition,
    item: &str,
    method: &str,
) -> Result<String, CouldNotLook> {
    let parse = batten_facts::source::rust_parse(source, edition.parser());
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    let root = parse.syntax_node();
    // Each scope a call sits in, once: an inline module's item list, or the file.
    let mut scopes: Vec<Vec<ast::Item>> = Vec::new();
    let mut seen: Vec<Option<usize>> = Vec::new();
    for call in root
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
        .filter(|call| call.name_ref().is_some_and(|name| name.text() == method))
    {
        let module = call
            .syntax()
            .ancestors()
            .filter_map(ast::Module::cast)
            .find_map(|module| module.item_list());
        // A SCOPE'S IDENTITY: the module's item list by where it starts, or
        // the file itself, which no item list can be mistaken for.
        let (key, items): (Option<usize>, Vec<ast::Item>) = match module {
            Some(list) => (
                Some(usize::from(list.syntax().text_range().start())),
                list.items().collect(),
            ),
            None => (None, parse.tree().items().collect()),
        };
        if !seen.contains(&key) {
            seen.push(key);
            scopes.push(items);
        }
    }
    let mut inserts: Vec<(usize, String)> = Vec::new();
    for items in scopes {
        if already_imported(&held_leaves(&items), item, edition) == Some(true) {
            continue;
        }
        let Some(anchor) = items
            .iter()
            .find(|held| matches!(held, ast::Item::Use(_)))
            .or_else(|| items.first())
        else {
            continue;
        };
        let at = usize::from(anchor.syntax().text_range().start());
        let line_start = source[..at].rfind('\n').map_or(0, |newline| newline + 1);
        let indent: String = source[line_start..at]
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();
        inserts.push((at, format!("{item}\n{indent}")));
    }
    inserts.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    let mut edited = source.to_owned();
    for (at, text) in inserts {
        edited.insert_str(at, &text);
    }
    Ok(edited)
}

/// Rewrite each call of `method` by what its receiver chain already called:
/// `rewrite` is handed the chain's method names, nearest the call last, and
/// answers the replacement for the call's own name and arguments, or `None`
/// to leave it. `cmd.arg(x).stdout(p).output()` hands `["arg", "stdout"]`.
///
/// For a migration whose target depends on how the value was BUILT, which a
/// rename cannot see: on #1276 `output`'s defaults applied only to the streams
/// a chain had not set, and the chain is where that is written down. A chain
/// broken by a `let` is not followed; the compiler, or a reading of the
/// remainder, owns those.
///
/// # Errors
///
/// [`CouldNotLook`] when the parser reports any error over `source` under
/// `edition`. The source is then not rewritten at all.
pub fn rewrite_calls_by_chain(
    source: &str,
    edition: Edition,
    method: &str,
    rewrite: &dyn Fn(&[String]) -> Option<String>,
) -> Result<String, CouldNotLook> {
    let parse = batten_facts::source::rust_parse(source, edition.parser());
    let errors = parse.errors();
    if !errors.is_empty() {
        return Err(CouldNotLook {
            errors: errors.len(),
        });
    }
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    for call in parse
        .syntax_node()
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
    {
        let Some(name) = call.name_ref().filter(|name| name.text() == method) else {
            continue;
        };
        let mut chain = Vec::new();
        let mut receiver = call.receiver();
        while let Some(ast::Expr::MethodCallExpr(inner)) = receiver {
            if let Some(called) = inner.name_ref() {
                chain.push(called.text().to_string());
            }
            receiver = inner.receiver();
        }
        chain.reverse();
        let Some(replacement) = rewrite(&chain) else {
            continue;
        };
        let start = usize::from(name.syntax().text_range().start());
        let end = usize::from(call.syntax().text_range().end());
        edits.push((start..end, replacement));
    }
    edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut edited = source.to_owned();
    for (range, replacement) in edits {
        edited.replace_range(range, &replacement);
    }
    Ok(edited)
}

/// Replace each target's name token on the tree itself.
fn edit(root: ra_ap_syntax::SyntaxNode, targets: &[ast::NameRef], to: &str) -> SyntaxEdit {
    let (editor, _) = SyntaxEditor::new(root);
    for target in targets {
        editor.replace(target.syntax(), editor.make().name_ref(to).syntax());
    }
    editor.finish()
}

/// The edited tree as text. The CST keeps every token it was not asked to
/// change, whitespace and comments included.
fn render(edit: &SyntaxEdit) -> String {
    edit.new_root().to_string()
}
