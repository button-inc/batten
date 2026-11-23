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

/// Parse Rust source text into the LOSSLESS syntax tree — **the one
/// `ra_ap_syntax` parse call in the workspace** (CLOUD-1008).
///
/// Lossless is the reason it exists beside [`rust`]: every byte of the input,
/// comments and whitespace included, is a token of this tree, so a comment span
/// and a string span are both answerable — the half `syn` measurably cannot
/// give (this module's header). `ra_ap_syntax` has been pinned since CLOUD-1580,
/// so this answers CLOUD-1008's open question with no new parser dependency,
/// which is the condition CLOUD-1009's D4 set.
///
/// The parse itself, errors and all: a codemod reports how many errors the
/// parser found and declines to rewrite. A fact producer wants [`rust_tree`],
/// which maps a refused parse to could-not-look.
#[must_use]
pub fn rust_parse(
    source: &str,
    edition: ra_ap_syntax::Edition,
) -> ra_ap_syntax::Parse<ra_ap_syntax::SourceFile> {
    ra_ap_syntax::SourceFile::parse(source, edition)
}

/// [`rust_parse`] in the shape a fact producer wants: the tree, or
/// could-not-look when the parser reported any error. **Never a partial tree**:
/// a tree with error nodes in it answers for less of its file than it looks
/// like it does, which is the vacuous pass this module refuses.
#[must_use]
pub fn rust_tree(
    source: &str,
    edition: ra_ap_syntax::Edition,
) -> crate::facts::Look<ra_ap_syntax::SourceFile> {
    // THE LAST TEXT'S TREE ANSWERS ITS REPEAT (CLOUD-2830). One file is read
    // into several facts, call sites, `use` edges and units, and each producer
    // asks for its tree; acquired back to back, the second ask is the same
    // text, and parsing it again measured 14% of `policy test`. One entry, so
    // the memo holds one tree and never grows with the tree it walks. The tree
    // is immutable, and a clone shares it.
    type Last = Option<(
        String,
        ra_ap_syntax::Edition,
        crate::facts::Look<ra_ap_syntax::SourceFile>,
    )>;
    thread_local! {
        static LAST: std::cell::RefCell<Last> = const { std::cell::RefCell::new(None) };
    }
    let hit = LAST.with(|last| {
        last.borrow()
            .as_ref()
            .filter(|(text, parsed_as, _)| *parsed_as == edition && text == source)
            .map(|(_, _, tree)| tree.clone())
    });
    if let Some(tree) = hit {
        return tree;
    }
    let parse = rust_parse(source, edition);
    let tree = if parse.errors().is_empty() {
        crate::facts::Look::Is(parse.tree())
    } else {
        crate::facts::Look::CouldNotLook
    };
    LAST.with(|last| *last.borrow_mut() = Some((source.to_owned(), edition, tree.clone())));
    tree
}

/// The 1-based line of any byte offset in one source text, answered by binary
/// search over the line starts, which are found once per text.
///
/// THE ONE LINE TABLE the tree producers share. Each producer had its own
/// `line_of(source, offset)` that counted the newlines before `offset`, so a
/// file with N call sites paid N scans of its head: quadratic in file size.
/// Measured on `policy test`, that count was 49% of the verb's samples and took
/// it from 12 s to 143 s once the call-site facts moved onto this lossless
/// tree, whose offsets carry no line the way a `syn` span did.
#[derive(Debug)]
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    /// Index `source`'s line starts.
    #[must_use]
    pub fn new(source: &str) -> Self {
        Self {
            starts: std::iter::once(0)
                .chain(source.match_indices('\n').map(|(at, _)| at + 1))
                .collect(),
        }
    }

    /// The 1-based line `offset` falls on.
    #[must_use]
    pub fn line(&self, offset: usize) -> usize {
        self.starts.partition_point(|start| *start <= offset)
    }
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
    use std::collections::BTreeMap;

    /// Fails by: a line table that disagrees with counting the newlines before
    /// the offset (the answer every producer gave before the table), at a line
    /// start, mid-line, on a newline byte, past a blank line, or at the end.
    #[test]
    fn the_line_table_answers_as_counting_newlines_does() {
        let source = "fn a() {}\n\nfn b() {\n    c();\n}\n";
        let lines = LineIndex::new(source);
        for offset in 0..=source.len() {
            let counted = source[..offset].bytes().filter(|b| *b == b'\n').count() + 1;
            assert_eq!(lines.line(offset), counted, "offset {offset}");
        }
        assert_eq!(LineIndex::new("").line(0), 1);
    }

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
        //
        // EVERY CRATE'S LIBRARY SOURCE, AND BOTH PARSERS (CLOUD-1008). This gate
        // walked only its own crate's `src`, so once the crate split moved the
        // parse here it saw none of the five crates that read Rust; and it
        // counted only `syn`, while `ra_ap_syntax` was parsed at 25 sites across
        // six modules, each with its own edition and error mapping. Integration
        // tests under `tests/` are not library code and keep their own parses.
        let needles = [
            ["syn::parse", "_file("].concat(),
            ["SourceFile::", "parse("].concat(),
        ];
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crate sits in the workspace's crates directory");
        let mut sites: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        // WALKS THE SUBTREE rather than one directory, for the reason the
        // document gate's own walker states: `read_dir` does not descend, so a
        // `.rs` file under a `src/<module>/` would go unscanned and the gate
        // would stop holding SILENTLY.
        let mut pending: Vec<std::path::PathBuf> = std::fs::read_dir(crates)
            .unwrap()
            .map(|entry| entry.unwrap().path().join("src"))
            .filter(|src| src.is_dir())
            .collect();
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
                let source = crate::fsio::read_to_string(&path).unwrap();
                for needle in &needles {
                    for _ in 0..source.matches(needle.as_str()).count() {
                        sites
                            .entry(needle.as_str())
                            .or_default()
                            .push(path.display().to_string());
                    }
                }
            }
        }

        // ANTI-VACUITY, in the same function (CLOUD-418): a needle that stopped
        // matching would report "one" as "zero" and pass forever, so zero fails
        // here exactly as two does, per parser.
        for needle in &needles {
            let found = sites.get(needle.as_str()).cloned().unwrap_or_default();
            assert_eq!(
                found.len(),
                1,
                "exactly one {needle}...) may exist across the workspace's library source; found {found:?}"
            );
        }
    }

    /// Fails by: a refused parse handed back as a partial tree, or an empty
    /// file read as could-not-look.
    #[test]
    fn the_lossless_parse_is_could_not_look_on_any_error_and_keeps_comments() {
        use ra_ap_syntax::AstNode as _;
        let edition = ra_ap_syntax::Edition::Edition2024;
        assert!(matches!(rust_tree("", edition), crate::facts::Look::Is(_)));
        assert!(matches!(
            rust_tree("fn (", edition),
            crate::facts::Look::CouldNotLook
        ));
        // LOSSLESS: the ordinary comment `syn` drops is a token here, which is
        // the comment span CLOUD-1008 asks for.
        let crate::facts::Look::Is(tree) = rust_tree("// ordinary\nfn f() {}\n", edition) else {
            panic!("the fixture parses");
        };
        let comments = tree
            .syntax()
            .descendants_with_tokens()
            .filter(|element| element.kind() == ra_ap_syntax::SyntaxKind::COMMENT)
            .count();
        assert_eq!(comments, 1);
        assert_eq!(tree.syntax().to_string(), "// ordinary\nfn f() {}\n");
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
