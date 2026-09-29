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
//MUTANT-SUITE crates/batten/tests/it/codemod.rs
//MUTANT codemod-ignores-parse-errors|s@^    if !errors.is_empty() {$@    if false {@|invalid_rust_is_could_not_look
//MUTANT codemod-splices-bytes|s@^    let edited = render(&edit(root, &targets, to));$@    let edited = { let _ = (edit, render, root, targets); source.replacen(\&format!(".{from}("), \&format!(".{to}("), 1) };@|a_rename_changes_only_the_edited_token
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
