//! The one Rust parse in the crate, and what a caller may know about it
//! (CLOUD-1008).
//!
//! # Why this module exists at all
//!
//! `facts.rs` stays the one authority on what a source-backed fact IS and what
//! it costs. This is where the text actually becomes a syntax tree, which is the
//! split CLOUD-1008's §1 asks for — and the argument for collapsing it is not
//! this row's invention. `rules.rs`'s [`crate::rules::parse_node`] is "the one
//! `Format::read` call in the crate" (CLOUD-849), extracted because **a second
//! call site is a second error mapping, and two mappings diverge.** That was
//! measured rather than feared: `Fact::Document` was acquired at three sites,
//! and one of them could not tell a non-UTF-8 file from a missing one while its
//! siblings could.
//!
//! The Rust parse was in exactly that state when this landed — **three
//! `syn::parse_file` calls across two modules**, one in
//! [`crate::invocation::invocations`] and two in [`crate::uses`]. They agreed
//! today, which is the only reason nothing had broken yet; nothing held them to
//! it, and a file declared for both `Fact::Uses` and `Fact::Invocations` was
//! parsed twice for one answer. `tests::one_rust_parse_exists` is what keeps
//! this one, on the source-level model that gate already sets.
//!
//! # `Refused` is the grammar, never the bytes
//!
//! A caller here has already read the text, so "unreadable" is not one of this
//! module's answers and must not be invented as one. What it reports is the
//! parse: the bytes arrived and the grammar refused them. `rules.rs` maps that
//! onto [`crate::rules::NotAcquired::Unparsed`], which is spelled apart from
//! `Unreadable` for the same reason one level up — a file that will not parse
//! says nothing about what it contains, and collapsing the two would let a
//! policy mistake "could not parse" for "not there".
//!
//! **Never an empty result.** A parse failure is [`crate::facts::Look::CouldNotLook`]
//! and a file that parses and contains nothing is `Is(empty)`. Rego reads an
//! undefined path as _does not hold_, so a corpus that failed to parse would
//! report clean — CLOUD-845's vacuous pass, which CLOUD-251 named before it.
//!
//! # What this backend CANNOT give, measured rather than assumed
//!
//! CLOUD-1008's §2 asks for "canonical comment/string spans". **String spans are
//! reachable and ordinary comment spans are not**, and the reason is the pinned
//! backend rather than an unfinished implementation: CLOUD-1009's D4 pins `syn`
//! for Rust with no new parser dependency, and Rust lexes a `//` comment as
//! trivia — it produces no token and therefore no AST node.
//!
//! Measured 2026-09-05 against the pinned `syn`, parsing a file carrying one
//! ordinary comment, one doc comment and one string literal: the doc comment
//! survives as a `#[doc]` attribute and is findable in the tree; the ordinary
//! comment is absent from it entirely. So a comment-span fact over this backend
//! could report doc comments and would silently report nothing for every `//`
//! line — a fact that answers for a tenth of its subject while looking total,
//! which is the shape this repository refuses everywhere else.
//!
//! That half is therefore **not built here rather than half-built**, and the
//! measurement is on CLOUD-1008 so the next author meets it instead of
//! rediscovering it. It is a statement about the backend, not about the row: a
//! lexer that retains trivia would answer it, and adopting one is a decision
//! D4 made in the other direction.

/// The grammar refused the text.
///
/// A unit type rather than a message, and deliberately: a parser's own
/// diagnostic is a span of the SOURCE, which non-negotiable rule 4 keeps out of
/// a finding. The caller already holds the path, which is the pointer a reader
/// needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// Parse Rust source text into a syntax tree — **the one `syn::parse_file` call
/// in the crate**.
///
/// # Errors
///
/// [`Refused`] when the grammar refused the text. The bytes were the caller's
/// and were fine; this reports only that they are not Rust.
pub fn rust(source: &str) -> Result<syn::File, Refused> {
    syn::parse_file(source).map_err(|_| Refused)
}

/// [`rust`] in the shape the fact producers want: a parsed file, or the
/// could-not-look arm.
///
/// Exists so the three former call sites share the MAPPING as well as the parse.
/// Collapsing the parse and leaving each caller to turn a failure into a `Look`
/// would keep the divergence this module exists to remove — which is the half
/// CLOUD-849's own gate is careful about, since its needle is the parse pair
/// rather than the read.
#[must_use]
pub fn rust_or_could_not_look(source: &str) -> crate::facts::Look<syn::File> {
    match rust(source) {
        Ok(file) => crate::facts::Look::Is(file),
        Err(Refused) => crate::facts::Look::CouldNotLook,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_parse_failure_is_could_not_look_and_an_empty_file_is_not() {
        // THE DISTINCTION THE WHOLE MODULE EXISTS TO KEEP, asserted at the one
        // place it is now decided. An empty file is a real answer — looked, and
        // there is nothing — and a file that will not parse is not an answer at
        // all. Rego reads an undefined path as "does not hold", so collapsing
        // them reports a corpus that never parsed as a clean tree.
        assert!(matches!(
            rust_or_could_not_look(""),
            crate::facts::Look::Is(_)
        ));
        assert!(matches!(
            rust_or_could_not_look("fn f() {}\n"),
            crate::facts::Look::Is(_)
        ));
        assert!(matches!(
            rust_or_could_not_look("fn ("),
            crate::facts::Look::CouldNotLook
        ));
    }

    #[test]
    fn one_rust_parse_exists() {
        // THE GATE THAT SHIPS WITH THE RULE (non-negotiable rule 2), on the
        // source-level model `rules::tests::one_document_acquisition_exists`
        // set for document acquisition and `no_second_git_invoker_exists` set
        // for spawning. Collapsing three call sites into one is worth nothing
        // if a fourth can be added tomorrow, and nothing but a gate stops that.
        //
        // The needle is the CALL — the name followed by its open paren — never
        // the bare name, which appears in this module's own prose four times
        // and in `invocation.rs`'s. A gate that counted mentions would be
        // noisy here and would have to be relaxed until it was vacuous.
        //
        // Split and rejoined so this file's own needle is not itself a match,
        // which is the same trick the document gate uses for the same reason.
        //
        // Fails by: adding a second call to the parser anywhere in the crate,
        // which is the mutation this row's §7 names. Spelled WITHOUT the
        // needle, because this gate caught its own comment the first time it
        // ran -- a mention carrying the open paren is indistinguishable from a
        // call, and the honest fix is prose that does not imitate one rather
        // than a needle loosened until it stops seeing this file.
        let needle = ["syn::parse", "_file("].concat();
        let mut sites: Vec<String> = Vec::new();
        // WALKS THE SUBTREE rather than one directory, for the reason the
        // document gate's own walker states: `read_dir` does not descend, so a
        // `.rs` file under a future `src/<module>/` would go unscanned and the
        // gate would stop holding SILENTLY. The crate is flat today, which is
        // exactly when this is cheap to get right.
        let mut pending = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension() != Some(std::ffi::OsStr::new("rs")) {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                for _ in 0..source.matches(needle.as_str()).count() {
                    sites.push(path.display().to_string());
                }
            }
        }

        // ANTI-VACUITY, in the same function (CLOUD-418): a needle that stopped
        // matching would report "one" as "zero" and pass forever, so zero fails
        // here exactly as two does.
        assert_eq!(
            sites.len(),
            1,
            "exactly one Rust parse may exist in the crate; found {sites:?}"
        );
    }

    #[test]
    fn an_ordinary_comment_is_not_in_the_tree_and_a_doc_comment_is() {
        // THE MEASUREMENT BEHIND THE UNBUILT HALF (CLOUD-1008 §2), pinned here
        // rather than left in a commit message, because it is the reason a
        // comment-span fact is absent and the next author will otherwise read
        // that absence as an oversight.
        //
        // Fails by: the pinned backend gaining trivia retention, which is
        // exactly when this decision should be revisited — so this case turning
        // red is a prompt rather than a defect.
        // Asserted STRUCTURALLY rather than by rendering the tree, and that is
        // not a workaround: the pinned `syn` carries no `extra-traits`, so
        // there is no `Debug` to print — and an attribute census is the
        // stronger statement anyway, because it names the mechanism (a doc
        // comment BECOMES an attribute) instead of matching text.
        let file = rust("// ordinary\n/// doc\nfn f() {}\n").unwrap();
        let [syn::Item::Fn(item)] = file.items.as_slice() else {
            panic!("one function is the whole fixture");
        };
        let docs = item
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("doc"))
            .count();
        assert_eq!(docs, 1, "the doc comment survives as a `#[doc]` attribute");
        assert_eq!(
            item.attrs.len(),
            1,
            "and the ordinary comment reaches no node at all -- it is trivia, so \
             a comment-span fact over this backend would answer for doc comments \
             and silently report nothing for every `//` line"
        );
    }
}
