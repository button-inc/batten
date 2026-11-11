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

use std::fmt;

use ra_ap_syntax::syntax_editor::{SyntaxEdit, SyntaxEditor};
use ra_ap_syntax::{AstNode as _, SourceFile, ast};

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
    let parse = SourceFile::parse(source, edition.parser());
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
    let parse = SourceFile::parse(source, edition.parser());
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
