//! The instrument taxonomy is present in the tree, not only on the board
//! (CLOUD-844).
//!
//! CLOUD-310 evaluated the syntax-matching candidates against this tree and
//! returned a per-component disposition — the thing that decides which scanner
//! answers which question. It is Done and it lives entirely in Linear: nothing
//! in the working tree named it, so an agent with a syntax question reached for
//! `grep` and cited that rejection as cover. `.claude/rules/scanning.md` is
//! where the three-row taxonomy now binds, at the trigger.
//!
//! WHAT THIS FILE ASSERTS, AND WHAT IT CANNOT. It asserts **presence**: the
//! rules file still names an instrument for each of the three question classes,
//! still names the gate over the substitution axis, still keeps row one free of
//! a bare product name, still points at CLOUD-310 for the disposition rather
//! than restating it, still states the no-extension-and-exits-`0` defect beside
//! the recommendation, and is still routed to from `AGENTS.md`'s index. That
//! catches deletion and drift in the prose.
//!
//! It does **not** catch a misused instrument. Which of text, syntax or names a
//! question belongs to is a judgement, and non-negotiable rule 3 says a gate
//! resolves to a command and an exit code, never a model verdict — so that axis
//! is feedforward, the rule says so on its own row, and a §7 claiming otherwise
//! here would be the same defect CLOUD-844 is about.
//!
//! **The substitution axis is a different matter, and saying otherwise was a
//! defect of its own** (CLOUD-998). This file used to state flatly that it was
//! "not a gate over tool choice"; `no-tool-substitution` is exactly that, over
//! the command line, and its refusal redirects to the rules file. So the claim
//! here is narrowed to the axis it holds for, and one assertion now pins the
//! gate's name into the prose. This is otherwise the same shape as
//! `spawn_census.rs`'s assertion that `clippy.toml` names the spawn type: the
//! prose carries the position, and the test keeps the prose from evaporating.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::at_root;

/// The rules file the taxonomy lives in.
const RULES: &str = ".claude/rules/scanning.md";

/// The always-loaded file whose index has to route a reader to [`RULES`].
///
/// `CLAUDE.md` is a symlink to this; the tracked path is the one asserted.
const INDEX: &str = "AGENTS.md";

/// The instrument each of the three question classes resolves to.
///
/// One row per class, in the order the table states them: text, syntax, names.
/// The third names three tools that do the same job here, so any one of them
/// standing in the table is the class being answered.
///
/// ROW ONE NAMES A CAPABILITY, NOT A PRODUCT, and that is the correction
/// CLOUD-998 landed. It used to pin the literal `` `grep` `` — the utility
/// `no-tool-substitution` refuses over a tracked path — so the gate's own
/// redirect sent a reader back to the refused call, and this assertion held the
/// wrong answer in place. Naming a first-class tool instead would have been the
/// same defect one layer over: which instruments a session carries varies, so
/// any product name is wrong in the sessions that have the other one. See
/// [`a_capability_row_names_no_bare_product`], which is the half that stops it
/// regressing.
const INSTRUMENTS: &[(&str, &[&str])] = &[
    (
        "does this file contain this literal string",
        &["a structured text search"],
    ),
    (
        "is this token in command position",
        &["tree-sitter matcher"],
    ),
    (
        "which type does this name resolve to",
        &["clippy", "rust-analyzer", "Serena"],
    ),
    // ROW FOUR'S SUBJECT IS THE BOARD, NOT THE TREE, and it is here because the
    // failure it names is not picking the wrong scanner — it is reaching for no
    // instrument at all, since recall feels like an answer where a search feels
    // like a detour. Measured over one session: three assertions stated as fact
    // to a human, each one command from being checked, and each wrong.
    //
    // Its instrument cell names the board rather than a product for row one's
    // reason — which connector answers is a property of the session — so it is
    // the SECOND row `a_capability_row_names_no_bare_product` iterates. That
    // was claimed here as holding "by construction" while the test read row one
    // alone, which is the shape this file exists to catch, committed in its own
    // margin: a coverage claim nothing checked.
    //
    // CAPABILITY_ROWS is what makes it true rather than asserted, so a fifth row
    // naming a capability joins it there rather than inheriting the guarantee.
    (
        "has this already been filed, decided, or measured",
        &["the board, before the tree"],
    ),
];

/// The issue that owns the per-component disposition this file must point at
/// rather than copy.
const DISPOSITION: &str = "CLOUD-310";

/// The gate that decides the substitution axis, whose refusal redirects here.
///
/// The rules file must name it. For its whole life the file asserted that no
/// gate existed over instrument choice, which was true when written and false
/// once this row landed — and a reader who believes no gate exists has no reason
/// to expect the refusal (CLOUD-998).
const SUBSTITUTION_GATE: &str = "no-tool-substitution";

/// The bare product names row one must not answer with.
///
/// Both directions: the shell utility the gate refuses, and the first-class
/// tools that are absent in some sessions. Row one names the capability, so
/// neither belongs in that cell.
const BARE_PRODUCTS: &[&str] = &["`grep`", "`rg`", "`Grep`", "`Read`", "`Glob`"];

/// The [`INSTRUMENTS`] rows whose instrument cell answers with a CAPABILITY.
///
/// Row one, because which search surface a session carries varies; and row four,
/// because which connector answers the board does. Rows two and three are
/// deliberately absent: row two names a class whose winner CLOUD-310 owns, and
/// row three names the three tools that do name resolution here.
const CAPABILITY_ROWS: &[usize] = &[0, 3];

fn rules_text() -> String {
    fs::read_to_string(at_root(RULES)).expect("`.claude/rules/scanning.md` is committed")
}

#[test]
fn the_rules_name_an_instrument_for_each_question_class() {
    let text = rules_text();
    for (question, instruments) in INSTRUMENTS {
        assert!(
            text.contains(question),
            "{RULES} must still ask `{question}` — the three classes are the taxonomy, and a \
             dropped row leaves the question it answered to whichever scanner is closest to hand"
        );
        assert!(
            instruments.iter().any(|name| text.contains(name)),
            "{RULES} asks `{question}` and must name the instrument that answers it \
             (one of {instruments:?})"
        );
    }
}

#[test]
fn the_rules_point_at_the_disposition_instead_of_restating_it() {
    let text = rules_text();
    assert!(
        text.contains(DISPOSITION),
        "{RULES} must cite {DISPOSITION}, which owns the per-component scanner disposition — \
         a second copy of that evaluation is what this file exists to avoid"
    );
}

#[test]
fn the_rules_state_the_no_extension_defect_beside_the_recommendation() {
    let text = rules_text();
    // Both halves or the note licenses the failure it is warning about: a
    // matcher CLI is rejected AS A GATE because the extensionless programs are
    // invisible to it and the run still exits 0 — a silent empty answer, worse
    // than a wrong one — and that is not an argument against a tree-sitter
    // matcher run interactively with the language pinned.
    assert!(
        text.contains("no extension") && text.contains("exits `0`"),
        "{RULES} must state CLOUD-310's measured defect where it recommends the instrument: \
         the programs under `mise-tasks/` carry no extension, so a run pointed at that \
         directory scans nothing and exits `0`"
    );
    assert!(
        text.contains("rejected as a gate"),
        "{RULES} must say a matcher CLI is rejected AS A GATE — an unscoped rejection is what \
         got read as \"scanners are the wrong tool\", and then `grep` was used anyway"
    );
}

#[test]
fn the_rules_name_the_gate_over_the_substitution_axis() {
    let text = rules_text();
    assert!(
        text.contains(SUBSTITUTION_GATE),
        "{RULES} must name `{SUBSTITUTION_GATE}` — its refusal redirects a reader here to choose \
         between the question classes, and a file that does not mention the gate tells that \
         reader no refusal is coming"
    );
}

/// A capability row's cell names the capability; a product name there is the
/// CLOUD-998 defect returning.
///
/// Scoped to those rows' own lines rather than the whole file, because the file
/// legitimately discusses `grep` elsewhere — as the habit behind the wrong reach,
/// and as what a tree-sitter matcher beats on a syntax question. Only the
/// instrument cell is the answer a reader acts on.
///
/// TWO ROWS, NOT ONE, AND THAT WAS A COVERAGE CLAIM NOTHING CHECKED. Row four's
/// own margin said this test reached its cell "by construction" while the body
/// read `INSTRUMENTS[0]` alone — the file's subject committed inside the file.
/// The rows are named rather than inferred, because "the ones that name a
/// capability" is a judgement and an index is not.
#[test]
fn a_capability_row_names_no_bare_product() {
    let text = rules_text();
    for index in CAPABILITY_ROWS {
        let (question, _) = INSTRUMENTS[*index];
        let row = text
            .lines()
            .find(|line| line.contains(question) && line.starts_with('|'))
            .unwrap_or_else(|| {
                panic!("the taxonomy table still carries the row asking {question}")
            });
        for product in BARE_PRODUCTS {
            assert!(
                !row.contains(product),
                "{RULES} answers `{question}` with the product {product}, which is what CLOUD-998 \
                 corrected: a shell utility there is the call the gate refuses, and a first-class \
                 tool there is absent in the sessions that carry only the utility. Name the \
                 capability"
            );
        }
    }
}

#[test]
fn the_rules_say_in_as_many_words_that_they_are_feedforward() {
    let text = rules_text();
    assert!(
        text.contains("feedforward"),
        "{RULES} must admit on its own row that the rule is feedforward and that this test \
         proves presence, not correct use — non-negotiable rule 2 is satisfied by a real \
         mechanism or by an honest admission, never by a decorative one"
    );
}

#[test]
fn the_index_routes_a_reader_to_the_rules() {
    let index = fs::read_to_string(at_root(INDEX)).expect("`AGENTS.md` is committed");
    assert!(
        index.contains("scanning.md"),
        "{INDEX}'s `.claude/rules/` index must carry a row for `scanning.md`; a rules file \
         nothing routes to is the board copy again, one directory in"
    );
}
