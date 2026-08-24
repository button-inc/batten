//! The mapping ledger for a case a live suite INVERTED rather than lost
//! (CLOUD-908's column, this bundle's three).
//!
//! `bats-tests-not-deleted` conserves case NAMES, not counts: a case name that
//! disappears between `origin/main` and the head tree owes exactly one arm in
//! `crates/batten/tests/*.rs`, whatever the suite's total did. That is the right
//! reading and it is what caught this branch — three board-gate cases asserted a
//! contract a row here REVERSES, so each was rewritten in place with the reason
//! in the case, and a rewritten title is a vanished name.
//!
//! `contract_drift.rs` carries the other ledger block, for a suite that was
//! retired outright. This one is the in-place shape: every target below is the
//! same living suite the case was declared in, and the successor is the case that
//! now asserts the opposite. CLOUD-908's own measurement named exactly this as
//! the thing nothing marked — "one whose behaviour was deliberately inverted with
//! nothing marking it" — so recording it here is the column working, not a toll.
//!
//! WHAT THE ASSERTIONS BUY, which is what stops the arms being three comments. An
//! arm claiming an inversion is a claim about the tree, and both halves of it are
//! checkable: the successor case must EXIST under its new name, and the old name
//! must be GONE. Without the second half an arm would pass while the rewrite was
//! reverted, and without the first it would pass while the successor was never
//! written — the phantom-target shape the column already refuses one level up.
//!
//! THE ARMS ARE ORDINARY COMMENTS, NOT PART OF THE DOC BLOCK ABOVE, and that is
//! mechanical rather than stylistic: the engine reads an arm by
//! `strip_prefix("// changed:")` after trimming leading whitespace, so a line
//! spelled `//! // changed: …` inside a doc comment claims nothing at all. An arm
//! that claims nothing leaves its case unmapped, which is a refusal — the quiet
//! way to write three comments and still be red.

// changed: "could not look outranks a refusal, so a half-run sweep is never exit 1" tests/board-sweep.bats CLOUD-921 reverses it: a clone-scoped abstention no longer suppresses a refusal, so the tag-less half-run IS exit 1 and only a board-scoped could-not-look outranks one
// changed: "a blocker noted as closed needs no relation" tests/ready-lint.bats the exemption's premise is false — Linear does not drop the relation when a blocker completes, measured on CLOUD-661 Done since 2026-08-18 with both dependents still carrying the edge
// changed: "a closed blocker in Linear's rendered-mention form is exempt" tests/ready-lint.bats the same premise, in the rendered-mention spelling: the form a blocker is written in decides nothing about whether its relation exists

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;

use common::at_root;

/// One inversion: the suite, the name that went, and the name that replaced it.
///
/// The tuple is the arm's own three fields minus the reason, which is prose for a
/// reader and decides nothing. Keeping them in one table is what lets a single
/// assertion hold every arm rather than one test per row — a shape that would go
/// stale the moment a fourth inversion lands.
const INVERSIONS: &[(&str, &str, &str)] = &[
    (
        "tests/board-sweep.bats",
        "could not look outranks a refusal, so a half-run sweep is never exit 1",
        "a board-scoped could-not-look outranks a refusal, so a half-run sweep is never exit 1",
    ),
    (
        "tests/ready-lint.bats",
        "a blocker noted as closed needs no relation",
        "a blocker noted as closed still needs its relation",
    ),
    (
        "tests/ready-lint.bats",
        "a closed blocker in Linear's rendered-mention form is exempt",
        "a closed blocker in Linear's rendered-mention form is judged like any other",
    ),
];

/// The case names a bats suite declares, read the way the engine reads them.
///
/// `@test "` opens and the first `"` closes, which is `Conserves`' own
/// `case`/`close` pair. A second reading of that grammar here would be a copy
/// that drifts, so this is deliberately the same two tokens and nothing more.
fn case_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim_start().strip_prefix("@test \""))
        .filter_map(|rest| rest.split_once('"'))
        .map(|(case, _)| case.to_owned())
        .collect()
}

#[test]
fn every_inverted_case_has_a_successor_in_its_own_suite() {
    for (suite, _, successor) in INVERSIONS {
        let text = fs::read_to_string(at_root(suite)).unwrap();
        let names = case_names(&text);
        assert!(
            names.iter().any(|name| name == successor),
            "{suite} must declare the case that replaced an inverted one, or the arm claiming the inversion names a successor the tree does not have: {successor}"
        );
    }
}

#[test]
fn no_inverted_case_still_stands_under_its_old_name() {
    for (suite, retired, _) in INVERSIONS {
        let text = fs::read_to_string(at_root(suite)).unwrap();
        let names = case_names(&text);
        assert!(
            !names.iter().any(|name| name == retired),
            "{suite} still declares a case an arm records as inverted, so either the rewrite was reverted or the arm is wrong: {retired}"
        );
    }
}

#[test]
fn the_two_halves_disagree_about_every_row() {
    // Anti-vacuity, and the one assertion that would catch a copy-paste row whose
    // two names are the same string: such a row passes both tests above trivially
    // — the successor exists and the retired name is therefore present, which the
    // second test would then fail on. Asserting the distinctness directly says so
    // once rather than leaving a reader to derive it from a confusing failure.
    for (suite, retired, successor) in INVERSIONS {
        assert_ne!(
            retired, successor,
            "{suite}: an arm whose retired and successor names are identical records no inversion"
        );
    }
}
