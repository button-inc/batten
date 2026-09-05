//! Rust call sites, parsed — the syntactic POSITION of a token (CLOUD-914).
//!
//! `facts.rs` stays the one authority on what [`crate::facts::Fact::Invocations`]
//! IS and what it costs; this module is where the argv is actually read, which
//! is the split that row's §1 asks for.
//!
//! **It lives here rather than in `facts.rs` because of a gate, and the gate was
//! right.** `tests/facts.rs`'s `no_axis_match_carries_a_wildcard_arm` refuses a
//! wildcard arm anywhere in `facts.rs`, so that a fact added later fails to
//! compile instead of classifying itself. The walk below matches on
//! `syn::Expr`, which has some forty variants and gains more with every minor
//! release of the parser — a wildcard there is correct, and enumerating it would
//! be a list that breaks on an upgrade for no property gained. Two matches with
//! opposite right answers do not belong in one file, and moving this out is the
//! honest resolution rather than widening the gate.

/// One call site: what it invokes, and the literal arguments it passes.
///
/// Pointer-bearing by construction (non-negotiable rule 4). `line` is what a
/// finding reports; `program` and `arguments` are what a PREDICATE decides on
/// and are never rendered into a finding by the engine. That split is
/// [`Fact::Prospective`]'s exactly — a rule may decide over content, and what is
/// reported is `path:line` and a rule id.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Invocation {
    /// The callee as written — `Command::new`, `arg`, `git::query`. The path or
    /// method name, never a resolved type: this is the syntactic tier, and
    /// claiming resolution it does not do is how `grep` counted 14 `Command`
    /// sites where name resolution finds 9.
    pub program: String,
    /// The string literals passed as ARGUMENTS to this call, in source order.
    ///
    /// Arguments only, never the receiver — the whole discriminator. A literal
    /// in an array initialiser or in a method call's receiver is not an argument
    /// and does not appear here, which is why a needle table reads as silent
    /// while the same token passed to `.arg(..)` does not.
    pub arguments: Vec<String>,
    /// 1-indexed line of the call site, for the pointer a finding carries.
    pub line: usize,
}

/// The visitor's accumulator, at module scope rather than inside
/// [`invocations`]: it holds no borrow from that function, and an item declared
/// after a statement reads as if it were scoped to what precedes it when it is
/// not (`clippy::items_after_statements`).
#[derive(Default)]
struct Sites {
    found: Vec<Invocation>,
}

/// The literals a call PASSES. Descends through the grouping expressions an
/// argument can legally wear — a reference, a parenthesis, a cast, an array or
/// tuple built inline at the call — because a borrowed array of string literals
/// is one argument spelled four nodes deep, and is the ordinary way this tree
/// passes an argv.
///
/// It deliberately does NOT descend into a nested CALL: that call's own
/// arguments belong to it, and the visitor reaches it separately. Folding them
/// upward would attribute an inner call's literals to its caller.
fn literals(expr: &syn::Expr, out: &mut Vec<String>) {
    match expr {
        syn::Expr::Lit(lit) => {
            if let syn::Lit::Str(text) = &lit.lit {
                out.push(text.value());
            }
        }
        syn::Expr::Reference(inner) => literals(&inner.expr, out),
        syn::Expr::Paren(inner) => literals(&inner.expr, out),
        syn::Expr::Group(inner) => literals(&inner.expr, out),
        syn::Expr::Cast(inner) => literals(&inner.expr, out),
        syn::Expr::Array(array) => {
            for element in &array.elems {
                literals(element, out);
            }
        }
        syn::Expr::Tuple(tuple) => {
            for element in &tuple.elems {
                literals(element, out);
            }
        }
        _ => {}
    }
}

impl<'ast> syn::visit::Visit<'ast> for Sites {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let mut arguments = Vec::new();
        for argument in &call.args {
            literals(argument, &mut arguments);
        }
        self.found.push(Invocation {
            program: callee(&call.func),
            arguments,
            line: line_of(call.paren_token.span.open()),
        });
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let mut arguments = Vec::new();
        for argument in &call.args {
            literals(argument, &mut arguments);
        }
        // The RECEIVER is not an argument, and not descending into it here is
        // not an omission: `visit_expr_method_call` below walks it, so a call
        // inside the receiver is still found as its own site. What is excluded
        // is the receiver's LITERALS being read as this call's arguments —
        // which is exactly what makes a concatenated needle array silent and
        // the same token passed to `.arg(..)` loud.
        self.found.push(Invocation {
            program: call.method.to_string(),
            arguments,
            line: line_of(call.method.span()),
        });
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// Every call site in a Rust source text, or the reason there are none.
///
/// [`Look::CouldNotLook`] when the text is not parseable Rust — **never an empty
/// list**, which is the parse-coverage obligation CLOUD-310 attached to any
/// embedded matcher after measuring silent partial parses that emitted zero
/// error nodes. Rego reads an undefined path as "does not hold", so a gate whose
/// corpus failed to parse would report clean; that is CLOUD-845's vacuous pass
/// and CLOUD-251 named the class before it.
///
/// A file that parses and calls nothing is `Is(vec![])` — looked, and there are
/// no call sites. The two are different answers and this function keeps them so.
#[must_use]
pub fn invocations(source: &str) -> crate::facts::Look<Vec<Invocation>> {
    use syn::visit::Visit;

    // THE ONE PARSE (CLOUD-1008). This read `syn::parse_file` directly, as did
    // two sites in `uses.rs`; three call sites are three error mappings that
    // agreed only by luck, which is CLOUD-849's measured argument one grammar
    // over.
    let crate::facts::Look::Is(file) = crate::source::rust_or_could_not_look(source) else {
        return crate::facts::Look::CouldNotLook;
    };
    let mut sites = Sites::default();
    sites.visit_file(&file);
    crate::facts::Look::Is(sites.found)
}

/// The callee as written, flattened to a path string.
fn callee(func: &syn::Expr) -> String {
    match func {
        syn::Expr::Path(path) => path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        // A call whose callee is computed — a closure variable, an index, a
        // field. There is a call site and its program is not a name, which is a
        // different answer from "no call site" and is spelled as one.
        _ => String::new(),
    }
}

/// 1-indexed source line of a span.
fn line_of(span: proc_macro2::Span) -> usize {
    span.start().line
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Invocation, invocations};
    use crate::facts::Look;

    /// Every call site's arguments, flattened, for a case that only cares what
    /// reached the argument tier at all.
    fn arguments(source: &str) -> Vec<String> {
        match invocations(source) {
            Look::Is(sites) => sites.into_iter().flat_map(|site| site.arguments).collect(),
            other => panic!("expected a parse, got {}", other.as_str()),
        }
    }

    /// THE DISCRIMINATOR THE FACT EXISTS FOR, and the fixture is the tree's own
    /// shape rather than an invented one.
    ///
    /// The same token in four places: passed to a call, sitting in a needle
    /// array, in a line comment, and in a doc comment. A line predicate — which
    /// is what every argv-shaped guard in this crate is today — reports all
    /// four. This reports one.
    ///
    /// Fails by: descending into a method call's receiver in `visit_expr_method_
    /// call`, which is the one-line change that makes the needle array read as
    /// an argument and collapses the distinction.
    #[test]
    fn a_token_in_command_position_is_told_from_the_same_token_elsewhere() {
        let source = r#"
            // banned-token in a line comment
            /// banned-token in a doc comment
            fn f() {
                let needles = ["banned-token", "other"].concat();
                run().arg("banned-token");
                let _ = needles;
            }
        "#;
        let found = arguments(source);
        assert_eq!(
            found.iter().filter(|arg| *arg == "banned-token").count(),
            1,
            "exactly the call-position occurrence, got {found:?}"
        );
    }

    /// A receiver is not an argument, stated on its own because it is the half a
    /// reader is most likely to assume works the other way.
    #[test]
    fn a_receivers_literals_are_not_the_calls_arguments() {
        assert_eq!(
            arguments(r#"fn f() { let _ = ["a", "b"].concat(); }"#),
            Vec::<String>::new()
        );
        assert_eq!(arguments(r#"fn f() { g("a"); }"#), vec!["a".to_owned()]);
    }

    /// A borrowed array IS one argument, four nodes deep — the ordinary way this
    /// tree passes an argv, and the case a shallow reading would miss.
    #[test]
    fn a_borrowed_array_of_literals_is_read_as_arguments() {
        assert_eq!(
            arguments(r#"fn f() { query(&repo, &["rev-list", "--count"]); }"#),
            vec!["rev-list".to_owned(), "--count".to_owned()]
        );
    }

    /// COULD-NOT-LOOK IS NOT AN EMPTY SET, and the two are asserted against each
    /// other rather than each alone — a test that checked only one would pass
    /// over an implementation that collapsed them.
    ///
    /// This is CLOUD-310's parse-coverage obligation and CLOUD-914's §2 three-
    /// valued clause meeting at one case: Rego reads an undefined path as "does
    /// not hold", so a corpus that failed to parse would report clean.
    ///
    /// Fails by: returning `Look::Is(vec![])` from the parse-failure arm.
    #[test]
    fn an_unparseable_file_could_not_look_rather_than_finding_no_call_sites() {
        let refused = invocations("fn f( {{{ this is not rust");
        assert!(
            refused.could_not_look(),
            "unparseable source is could-not-look, got {}",
            refused.as_str()
        );

        let parsed_and_empty = invocations("struct S { field: u8 }");
        assert_eq!(
            parsed_and_empty,
            Look::Is(Vec::new()),
            "a file that parses and calls nothing is a real answer"
        );
        assert!(
            !parsed_and_empty.could_not_look(),
            "looked-and-found-nothing must not read as could-not-look"
        );
        assert_ne!(
            refused.as_str(),
            parsed_and_empty.as_str(),
            "the two answers must not share a token"
        );
    }

    /// The pointer a finding carries is a real line, not a constant.
    ///
    /// Fails by: dropping the `span-locations` feature, which silently makes
    /// every `Span::start()` report line 0 — a pointer-only finding whose
    /// pointer is the same for every hit.
    #[test]
    fn a_call_site_carries_the_line_it_sits_on() {
        let Look::Is(sites) = invocations("fn f() {\n\n    g(\"x\");\n}") else {
            panic!("expected a parse");
        };
        let site: &Invocation = sites.first().expect("one call site");
        assert_eq!(site.program, "g");
        assert_eq!(
            site.line, 3,
            "1-indexed, and not the 0 an unfeatured build gives"
        );
    }
}
