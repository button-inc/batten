//! The board's read discipline is present in the tree, not only in a habit
//! (CLOUD-1305).
//!
//! CLOUD-1253 builds the gate for the closing half: a closed retirement row is
//! judged against the tree, from the `conserves` arms that already exist. It
//! cannot carry the READING half, and the reading half is where the loss
//! happens — a gate runs at `verify` and at close, where an agent consults a
//! row's state continuously and acts on it at once. Between two runs of any
//! gate, a wrong state is load-bearing prose that an agent trusts.
//!
//! WHAT THIS FILE ASSERTS, AND WHAT IT CANNOT. It asserts **presence**: the
//! always-loaded file still carries the claim, still names the destination a
//! refuted row moves to, still demands a comment, and still refuses the
//! annotate-in-place shortcut. That catches deletion and drift in the prose.
//!
//! It does **not** catch an agent who does not check, and it cannot.
//! Non-negotiable rule 3 says a gate resolves to a command and an exit code over
//! an object it decides, never a model verdict — and "did the agent consult the
//! tree before believing a row" is exactly a model verdict. So that axis is
//! feedforward, the rule says so where it lives, and a §7 claiming otherwise
//! here would be the defect `rules/scanning.md` already records for its
//! own case.
//!
//! Same shape as `scanner_taxonomy.rs`: the prose carries the position, and the
//! test keeps the prose from evaporating.
//!
//! # Measured, and why the third clause is asserted separately
//!
//! Both instances are 2026-09-01. `CLOUD-1162` sat In Review with
//! `board-diff-overlap.sh` still tracked, and the first correction attempted was
//! **a warning paragraph inside the body with the state left alone** — which is
//! that row's own recorded finding one level up, where a correction block does
//! not correct a title. `CLOUD-1160` sat In Progress with nothing shipped and no
//! PR, its only attachment belonging to a different row, and was reported as
//! another session's live work.
//!
//! So `refuses_the_annotate_in_place_shortcut` is not decoration on the move
//! clause: annotating is the failure that actually happened, and a reader who
//! takes "move it back" as satisfied by an explanatory paragraph has made the
//! same mistake.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::at_root;

/// The always-loaded file the rule has to live in.
///
/// `.claude/rules/*` load at a trigger, and "I am about to trust a row's state"
/// has no file to trigger on — which is why this binds every turn instead.
/// `CLAUDE.md` is a symlink to this; the tracked path is the one asserted.
const INDEX: &str = "AGENTS.md";

fn index() -> String {
    fs::read_to_string(at_root(INDEX)).unwrap()
}

#[test]
fn the_tree_outranks_the_state() {
    // The claim itself. Asserted on the two load-bearing halves rather than the
    // whole sentence, so rewording survives and deletion does not.
    let text = index();
    assert!(
        text.contains("A STATE IS A CLAIM ABOUT THE TREE"),
        "{INDEX} no longer says a board state is a claim about the tree"
    );
    assert!(
        text.contains("THE TREE WINS"),
        "{INDEX} states the claim without saying which side settles it"
    );
}

#[test]
fn a_refuted_row_moves_back_and_the_destination_is_named() {
    // BACKLOG, not Todo, and the distinction is the point: Todo is the ready
    // queue, so parking an unpullable row there hands the next agent work that
    // cannot be started. Naming the destination is what stops "move it back"
    // resolving to whichever column is nearest.
    let text = index();
    assert!(
        text.contains("BACK to Backlog"),
        "{INDEX} no longer names where a row refuted by the tree goes"
    );
}

#[test]
fn the_move_owes_a_comment() {
    // The state change says a row is wrong; only the comment says what was read.
    // Without it the next reader re-derives the check, which is the cost this
    // whole class keeps charging.
    let text = index();
    assert!(
        text.contains("with a comment"),
        "{INDEX} moves the row without recording what the tree said"
    );
}

#[test]
fn refuses_the_annotate_in_place_shortcut() {
    // The clause that names the failure that actually happened, rather than the
    // one it is easy to imagine. See the header: the first attempt at correcting
    // CLOUD-1162 was a paragraph, not a state change.
    let text = index();
    assert!(
        text.contains("never a note inside it"),
        "{INDEX} no longer refuses correcting a state with prose in the body"
    );
}

#[test]
fn the_rule_lives_where_it_binds_every_turn() {
    // ANTI-VACUITY, and it is the one that stops the four above passing over a
    // file nobody loads: the assertions read `AGENTS.md`, so they would all hold
    // just as well if the section were moved into a rules file that loads at a
    // trigger — where "I am about to trust a row's state" has none. This pins
    // that the text sits inside the board section of the always-loaded file, not
    // merely somewhere in it.
    let text = index();
    let board = text
        .split("## The board: move the issue as you move the work")
        .nth(1)
        .expect("AGENTS.md still has a board section");
    let board = board.split("\n## ").next().unwrap();
    assert!(
        board.contains("A STATE IS A CLAIM ABOUT THE TREE"),
        "the rule left the board section of {INDEX}"
    );
}
