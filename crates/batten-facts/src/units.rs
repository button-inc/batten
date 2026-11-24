//! [`crate::facts::Fact::Units`] for Rust: every non-test function, comment and
//! string literal in a file, as CLOUD-1009's D4 node with A2's counts
//! (CLOUD-1008, CLOUD-2821).
//!
//! **MEASUREMENT, NEVER JUDGEMENT.** A node is a pointer — its kind, its
//! syntactic position, its line — plus integers and booleans counted off the
//! one lossless parse ([`crate::source::rust_tree`]). Nothing is weighted,
//! thresholded or folded here: which count matters for which outcome, and where
//! a line is drawn, is the preset's, with its evidence cited on the rule. No
//! composite index is computed, because each one on offer is a judgement whose
//! evidence the preset must answer for (CLOUD-2821's evidence comments).
//!
//! **Never a byte of source** (non-negotiable rule 4): a function's name is an
//! identifier the reader already sees at `path:line`, and a comment or string is
//! a span and a size, never its text.
//!
//! Test code is not measured: an item carrying `#[cfg(test)]` or `#[test]` is
//! pruned with everything under it. A nested `fn` item is its own unit; a
//! closure is part of the function that holds it, and nests.
//!
//! Tokens are NOT counted here: this crate carries no tokenizer, and a token
//! count must come from the counter the capture-view reader prints, over the
//! slice that reader would serve. Each unit carries its byte `offset` and
//! `bytes` so the acquirer can count exactly that slice.

use ra_ap_syntax::ast::{HasAttrs as _, HasName as _, HasVisibility as _};
use ra_ap_syntax::{AstNode as _, NodeOrToken, SyntaxKind, SyntaxNode, ast};
use serde::Serialize;

/// One measured unit: a D4 node with its counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unit {
    /// `fn`, `comment`, `doc-comment` or `string`.
    pub kind: &'static str,
    /// Where it sits: `item`, `impl`, `trait`, `nested` (a `fn`); `code` for a
    /// comment or string inside a function body, `item` outside one.
    pub position: &'static str,
    /// The 1-based line it starts on.
    pub line: usize,
    /// A function's name; empty for a comment or string.
    pub name: String,
    /// The byte offset it starts at. The acquirer's handle on the slice it
    /// counts tokens over; projected so a reader can recut the same slice.
    pub offset: usize,
    /// Its length in bytes, attributes and doc comments included for a `fn`.
    pub bytes: usize,
    /// The counts, all zero for a comment or string beyond `lines`.
    pub counts: Counts,
}

/// A unit's counts (A2). Integers and booleans only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Lines the unit spans.
    pub lines: usize,
    /// `let` and expression statements in a function's body, closures
    /// included.
    pub statements: usize,
    /// The deepest nesting of control structures and closures.
    pub nesting: usize,
    /// Decision points: each `if` and `else if`, `while`, `for`, `loop`, each
    /// `match` arm after the first, each run of one logical operator.
    pub decisions: usize,
    /// Parameters, `self` excluded.
    pub params: usize,
    /// `.unwrap()` / `.expect(…)` calls and `panic!`, `unreachable!`, `todo!`,
    /// `unimplemented!` invocations.
    pub panics: usize,
    /// Indexing expressions (`a[i]`), which panic out of bounds.
    pub indexing: usize,
    /// Places an error is dropped rather than handled: `let _ = …`, a
    /// `.ok()` whose value is discarded, `.unwrap_or_default()`, and a match
    /// arm `Err(_) => {}`. Counted beside `panics` so a ratchet on one cannot
    /// be met by trading it for the other.
    pub swallows: usize,
    /// `unsafe` keywords: blocks, and the function itself if it is `unsafe`.
    pub unsafe_sites: usize,
    /// Single-character parameter and `let` binding names, `_` excluded.
    pub short_names: usize,
    /// Whether the function carries a doc comment.
    pub documented: bool,
    /// Whether the function is declared with any `pub` visibility.
    pub public: bool,
}

/// Every unit in `source`, in source order, or could-not-look when the one
/// lossless parse refused the text — never an empty list for a file it could
/// not read, which would score as a clean file.
#[must_use]
pub fn units(source: &str) -> crate::facts::Look<Vec<Unit>> {
    let crate::facts::Look::Is(tree) =
        crate::source::rust_tree(source, ra_ap_syntax::Edition::Edition2024)
    else {
        return crate::facts::Look::CouldNotLook;
    };
    let starts = line_starts(source);
    let mut out = Vec::new();
    collect(tree.syntax(), &starts, false, &mut out);
    out.sort_by_key(|unit| unit.offset);
    crate::facts::Look::Is(out)
}

/// The byte offset each line starts at.
fn line_starts(source: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(source.match_indices('\n').map(|(at, _)| at + 1))
        .collect()
}

fn line_of(starts: &[usize], offset: usize) -> usize {
    starts.partition_point(|start| *start <= offset)
}

fn lines_spanned(starts: &[usize], offset: usize, bytes: usize) -> usize {
    line_of(starts, offset + bytes.saturating_sub(1)) + 1 - line_of(starts, offset)
}

/// Whether `node` carries `#[cfg(test)]` or `#[test]` itself. Ancestors are not
/// read: the walk prunes top-down, so an ancestor's mark was already seen and
/// the walk stays linear in the tree.
fn marked_test(node: &SyntaxNode) -> bool {
    ast::AnyHasAttrs::cast(node.clone()).is_some_and(|item| {
        item.attrs().any(|attr| {
            let text: String = attr
                .syntax()
                .text()
                .to_string()
                .split_whitespace()
                .collect();
            text == "#[cfg(test)]" || text == "#[test]"
        })
    })
}

fn position_of(function: &ast::Fn) -> &'static str {
    let mut parent = function.syntax().parent();
    while let Some(node) = parent {
        match node.kind() {
            SyntaxKind::FN => return "nested",
            SyntaxKind::IMPL => return "impl",
            SyntaxKind::TRAIT => return "trait",
            _ => parent = node.parent(),
        }
    }
    "item"
}

fn collect(node: &SyntaxNode, starts: &[usize], in_body: bool, out: &mut Vec<Unit>) {
    if marked_test(node) {
        return;
    }
    // THE BODY BEGINS AT THE FUNCTION'S BLOCK, not at its node: a doc comment
    // and attributes sit inside the `fn` node but belong to its declaration.
    let in_body = in_body
        || (node.kind() == SyntaxKind::BLOCK_EXPR
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == SyntaxKind::FN));
    if let Some(function) = ast::Fn::cast(node.clone()) {
        let range = function.syntax().text_range();
        let offset = usize::from(range.start());
        let bytes = usize::from(range.len());
        let mut counts = Counts {
            lines: lines_spanned(starts, offset, bytes),
            params: function
                .param_list()
                .map_or(0, |list| list.params().count()),
            unsafe_sites: usize::from(function.unsafe_token().is_some()),
            documented: function.doc_comments().next().is_some(),
            public: function.visibility().is_some(),
            ..Counts::default()
        };
        if let Some(params) = function.param_list() {
            counts.short_names += params
                .params()
                .filter_map(|param| param.pat())
                .filter(|pat| short_binding(pat.syntax()))
                .count();
        }
        if let Some(body) = function.body() {
            body_counts(body.syntax(), 0, &mut counts);
        }
        out.push(Unit {
            kind: "fn",
            position: position_of(&function),
            line: line_of(starts, offset),
            name: function
                .name()
                .map(|name| name.text().to_string())
                .unwrap_or_default(),
            offset,
            bytes,
            counts,
        });
    }
    for element in node.children_with_tokens() {
        match element {
            NodeOrToken::Node(child) => collect(&child, starts, in_body, out),
            NodeOrToken::Token(token) => {
                let kind = match token.kind() {
                    SyntaxKind::COMMENT => "comment",
                    SyntaxKind::INNER_DOC_COMMENT | SyntaxKind::OUTER_DOC_COMMENT => "doc-comment",
                    SyntaxKind::STRING | SyntaxKind::BYTE_STRING | SyntaxKind::C_STRING => "string",
                    _ => continue,
                };
                let range = token.text_range();
                let offset = usize::from(range.start());
                let bytes = usize::from(range.len());
                out.push(Unit {
                    kind,
                    position: if in_body { "code" } else { "item" },
                    line: line_of(starts, offset),
                    name: String::new(),
                    offset,
                    bytes,
                    counts: Counts {
                        lines: lines_spanned(starts, offset, bytes),
                        ..Counts::default()
                    },
                });
            }
        }
    }
}

/// A binding pattern whose name is one character, `_` excluded.
fn short_binding(pat: &SyntaxNode) -> bool {
    ast::IdentPat::cast(pat.clone())
        .and_then(|ident| ident.name())
        .is_some_and(|name| {
            let text = name.text();
            text.chars().count() == 1 && text != "_"
        })
}

/// The counts of one function's body, `nest` deep. Stops at a nested `fn`
/// (its own unit) and at test code.
fn body_counts(node: &SyntaxNode, nest: usize, counts: &mut Counts) {
    for element in node.children_with_tokens() {
        let child = match element {
            NodeOrToken::Token(token) => {
                counts.unsafe_sites += usize::from(token.kind() == SyntaxKind::UNSAFE_KW);
                continue;
            }
            NodeOrToken::Node(child) => child,
        };
        let kind = child.kind();
        if kind == SyntaxKind::FN || marked_test(&child) {
            continue;
        }
        let mut deeper = nest;
        match kind {
            SyntaxKind::LET_STMT => {
                counts.statements += 1;
                if let Some(pat) = ast::LetStmt::cast(child.clone()).and_then(|stmt| stmt.pat()) {
                    if pat.syntax().kind() == SyntaxKind::WILDCARD_PAT {
                        counts.swallows += 1;
                    } else {
                        counts.short_names += usize::from(short_binding(pat.syntax()));
                    }
                }
            }
            SyntaxKind::EXPR_STMT => {
                counts.statements += 1;
                // A `.ok()` that is the whole statement throws its value away.
                let discarded_ok = ast::ExprStmt::cast(child.clone())
                    .and_then(|stmt| stmt.expr())
                    .and_then(|expr| ast::MethodCallExpr::cast(expr.syntax().clone()))
                    .and_then(|call| call.name_ref())
                    .is_some_and(|name| name.text() == "ok");
                counts.swallows += usize::from(discarded_ok);
            }
            SyntaxKind::IF_EXPR => {
                counts.decisions += 1;
                // `else if` sits at its `if`'s own level.
                if node.kind() != SyntaxKind::IF_EXPR {
                    deeper = nest + 1;
                }
            }
            SyntaxKind::WHILE_EXPR | SyntaxKind::FOR_EXPR | SyntaxKind::LOOP_EXPR => {
                counts.decisions += 1;
                deeper = nest + 1;
            }
            SyntaxKind::MATCH_EXPR => {
                let arms = ast::MatchExpr::cast(child.clone())
                    .and_then(|found| found.match_arm_list())
                    .map_or(0, |list| list.arms().count());
                counts.decisions += arms.saturating_sub(1);
                deeper = nest + 1;
            }
            SyntaxKind::MATCH_ARM => {
                counts.swallows += usize::from(empty_error_arm(&child));
            }
            SyntaxKind::CLOSURE_EXPR => deeper = nest + 1,
            SyntaxKind::INDEX_EXPR => counts.indexing += 1,
            SyntaxKind::BIN_EXPR => {
                if let Some(op) = logical(&child) {
                    let continues = logical(node).is_some_and(|outer| outer == op);
                    counts.decisions += usize::from(!continues);
                }
            }
            SyntaxKind::METHOD_CALL_EXPR => {
                let name = ast::MethodCallExpr::cast(child.clone())
                    .and_then(|call| call.name_ref())
                    .map(|name| name.text().to_string());
                match name.as_deref() {
                    Some("unwrap" | "expect") => counts.panics += 1,
                    Some("unwrap_or_default") => counts.swallows += 1,
                    _ => {}
                }
            }
            SyntaxKind::MACRO_CALL => {
                let name = ast::MacroCall::cast(child.clone())
                    .and_then(|call| call.path())
                    .and_then(|path| path.segment())
                    .map(|segment| segment.syntax().text().to_string());
                counts.panics += usize::from(matches!(
                    name.as_deref(),
                    Some("panic" | "unreachable" | "todo" | "unimplemented")
                ));
            }
            _ => {}
        }
        counts.nesting = counts.nesting.max(deeper);
        body_counts(&child, deeper, counts);
    }
}

/// A match arm `Err(_) => {}` or `Err(_) => ()`: the error is matched and
/// dropped.
fn empty_error_arm(arm: &SyntaxNode) -> bool {
    let Some(arm) = ast::MatchArm::cast(arm.clone()) else {
        return false;
    };
    let pattern: String = arm
        .pat()
        .map(|pat| pat.syntax().text().to_string())
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let body: String = arm
        .expr()
        .map(|expr| expr.syntax().text().to_string())
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    pattern == "Err(_)" && matches!(body.as_str(), "{}" | "()")
}

/// The logical operator of a binary expression, `None` for any other node.
fn logical(node: &SyntaxNode) -> Option<ast::LogicOp> {
    match ast::BinExpr::cast(node.clone())?.op_kind()? {
        ast::BinaryOp::LogicOp(op) => Some(op),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn functions(source: &str) -> Vec<Unit> {
        let crate::facts::Look::Is(found) = units(source) else {
            panic!("the fixture parses");
        };
        found.into_iter().filter(|unit| unit.kind == "fn").collect()
    }

    fn one(source: &str) -> Counts {
        let mut found = functions(source);
        assert_eq!(found.len(), 1, "{found:?}");
        found.remove(0).counts
    }

    /// Fails by: an unparseable file read as an empty, clean one.
    #[test]
    fn a_file_that_does_not_parse_is_could_not_look() {
        assert!(matches!(units("fn f( {"), crate::facts::Look::CouldNotLook));
        assert!(matches!(units(""), crate::facts::Look::Is(found) if found.is_empty()));
    }

    /// Fails by: a nested structure not deepening, or an `else if` chain read
    /// as nesting.
    #[test]
    fn nesting_deepens_through_structures_and_not_through_else_if() {
        let nested = one("fn f(xs: &[u8]) { for x in xs { if *x > 0 { g(); } } }");
        assert_eq!((nested.nesting, nested.decisions), (2, 2));
        let chain = one("fn f(x: u8) { if x == 0 { g(); } else if x == 1 { g(); } else { g(); } }");
        assert_eq!((chain.nesting, chain.decisions), (1, 2));
    }

    /// Fails by: a run of one operator counted per operand, the first match
    /// arm counted, or a change of operator merged into the run.
    #[test]
    fn decisions_count_runs_and_arms_after_the_first() {
        assert_eq!(
            one("fn f(a: bool, b: bool, c: bool) -> bool { a && b && c }").decisions,
            1
        );
        assert_eq!(
            one("fn f(a: bool, b: bool, c: bool) -> bool { a && b || c }").decisions,
            2
        );
        assert_eq!(
            one("fn f(x: u8) -> u8 { match x { 0 => 1, 1 => 2, _ => 3 } }").decisions,
            2
        );
    }

    /// Fails by: a panic, swallow, index or `unsafe` site missed, or counted
    /// against the wrong function.
    #[test]
    fn panic_swallow_index_and_unsafe_sites_belong_to_their_function() {
        let counts = one("unsafe fn a(v: Vec<u8>, r: Result<u8, ()>) {\n\
             unsafe { x() };\n\
             v[0];\n\
             let _ = r;\n\
             r.ok();\n\
             r.unwrap_or_default();\n\
             match r { Ok(_) => {}, Err(_) => {} }\n\
             r.unwrap();\n\
             todo!();\n\
             }");
        assert_eq!(
            (
                counts.unsafe_sites,
                counts.indexing,
                counts.swallows,
                counts.panics
            ),
            (2, 1, 4, 2)
        );
    }

    /// Fails by: `self` counted, a short name missed, the doc or visibility
    /// misread, or the line or span wrong.
    #[test]
    fn shape_names_docs_and_pointers_are_read() {
        let found =
            functions("\n\n/// doc\npub fn f(&self, a: u8, bb: u8) { let c = a; g(c); bb; }");
        let unit = found.first().expect("one function");
        assert_eq!(
            (unit.line, unit.name.as_str(), unit.position),
            (3, "f", "item")
        );
        let counts = &unit.counts;
        assert_eq!(
            (counts.params, counts.statements, counts.short_names),
            (2, 3, 2)
        );
        assert!(counts.documented && counts.public);
    }

    /// Fails by: a nested `fn` folded into its parent, test code measured, or
    /// an impl method's position misread.
    #[test]
    fn nested_impl_and_test_code_are_apart() {
        let found = functions(
            "fn f() { fn inner() { if true {} } g(); }\n\
             struct S; impl S { fn m(&self) {} }\n\
             #[cfg(test)] mod tests { fn t() { x.unwrap(); } }\n\
             #[test] fn u() { y.unwrap(); }\n",
        );
        let shape: Vec<_> = found
            .iter()
            .map(|unit| (unit.name.as_str(), unit.position))
            .collect();
        assert_eq!(shape, [("f", "item"), ("inner", "nested"), ("m", "impl")]);
        let decisions: Vec<_> = found.iter().map(|unit| unit.counts.decisions).collect();
        assert_eq!(decisions.get(..2), Some(&[0, 1][..]));
    }

    /// Fails by: a comment or string missed (the half `syn` cannot give), its
    /// text leaking into the fact, or its position misread.
    #[test]
    fn comments_and_strings_are_spans_never_text() {
        let crate::facts::Look::Is(found) =
            units("// lead\n/// doc\nfn f() { let s = \"hi\"; } // tail\n")
        else {
            panic!("parses");
        };
        let spans: Vec<_> = found
            .iter()
            .filter(|unit| unit.kind != "fn")
            .map(|unit| (unit.kind, unit.position, unit.line, unit.bytes))
            .collect();
        assert_eq!(
            spans,
            [
                ("comment", "item", 1, 7),
                ("doc-comment", "item", 2, 7),
                ("string", "code", 3, 4),
                ("comment", "item", 3, 7),
            ]
        );
        assert!(
            found
                .iter()
                .all(|unit| unit.kind == "fn" || unit.name.is_empty())
        );
    }

    /// Fails by: the span's line count off its last line, or every function
    /// read as one line — this one opens on line 2 and spans three.
    #[test]
    fn a_function_spans_the_lines_from_its_first_to_its_last() {
        let found = functions("\nfn f() {\n    g();\n}\n");
        let spans: Vec<(usize, usize)> = found
            .iter()
            .map(|unit| (unit.line, unit.counts.lines))
            .collect();
        assert_eq!(spans, [(2, 3)]);
    }

    /// Fails by: a trait's provided method read as a free item.
    #[test]
    fn a_trait_method_is_positioned_in_its_trait() {
        let found = functions("trait T { fn f() {} }\n");
        let positions: Vec<&str> = found.iter().map(|unit| unit.position).collect();
        assert_eq!(positions, ["trait"]);
    }
}
