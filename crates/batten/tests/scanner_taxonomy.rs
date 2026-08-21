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
//! still points at CLOUD-310 for the disposition rather than restating it,
//! still states the no-extension-and-exits-`0` defect beside the
//! recommendation, and is still routed to from `AGENTS.md`'s index. That
//! catches deletion and drift.
//!
//! It does **not** catch misuse, and it is not a gate over tool choice. There
//! is no honest exit code over "did the agent pick the right scanner" — the
//! object is a judgement, and non-negotiable rule 3 says a gate resolves to a
//! command and an exit code, never a model verdict. The rule is feedforward and
//! says so on its own row; a §7 claiming otherwise here would be the same
//! defect CLOUD-844 is about. This is the same shape as
//! `spawn_census.rs`'s assertion that `clippy.toml` names the spawn type: the
//! prose carries the position, and the test keeps the prose from evaporating.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

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
const INSTRUMENTS: &[(&str, &[&str])] = &[
    ("does this file contain this literal string", &["`grep`"]),
    (
        "is this token in command position",
        &["tree-sitter matcher"],
    ),
    (
        "which type does this name resolve to",
        &["clippy", "rust-analyzer", "Serena"],
    ),
];

/// The issue that owns the per-component disposition this file must point at
/// rather than copy.
const DISPOSITION: &str = "CLOUD-310";

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
