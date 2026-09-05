//! Hand-stepping the landing loop, over the compiled binary and the committed
//! policy (CLOUD-1461).
//!
//! `mise run land` drives the whole loop, and AGENTS.md puts that above the
//! agent's own judgement — run the lifecycle tasks "as written, never wrapped in
//! bespoke retry or pre-check logic", because "`main` advancing under your
//! branch is this loop working, not a race to engineer around". That rule was
//! prose with nothing behind it, which non-negotiable rule 2 calls half a
//! change.
//!
//! **Measured 2026-09-05 rather than imagined.** `verify` refused with "main
//! moved under this branch — rebase and verify again, there is nothing here to
//! fix", naming its own remedy, and the session hand-stepped `git fetch origin
//! main`, `git rebase origin/main` and `git push` instead of handing the lap
//! back to `land`. Nothing refused any of it. A `git push --force-with-lease`
//! minutes earlier WAS refused by `leased-push`, which is what makes this a gap
//! rather than a decision somebody took.
//!
//! **Judged against the committed `batten.toml`, not a fixture**, on
//! `gh_guard.rs`'s precedent and for its reason: a fixture policy tests the
//! engine and says nothing about the TABLE, so deleting the row would break none
//! of it.
//!
//! # The allow is the load-bearing half
//!
//! AGENTS.md names exactly one hand spelling that stays legitimate — on a
//! conflict, "resolve and `git rebase --continue`, never a fresh `git rebase
//! origin/main`". A `shape` row compares operand words with flags already
//! DROPPED, so `pattern = "git rebase"` alone cannot tell the two apart and
//! would refuse the one step the contract requires by hand. `contains` matches
//! the raw text of the same segment, which is what separates them.
//!
//! So the deny case alone proves nothing: a row that refused every `git rebase`
//! passes it while breaking conflict resolution, which is this defect pointed
//! the other way. The pair is the assertion.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use crate::common::{run_with_stdin_at_real_root, stdout};

/// The row under test. Named rather than inferred from the verdict, because a
/// refusal from any OTHER row is a different question.
const ROW: &str = "rebase-not-hand-stepped";

/// The repository root, whose committed `batten.toml` is the policy under test.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

/// The decision document this harness emits, as text.
fn decision(command: &str) -> String {
    stdout(&run_with_stdin_at_real_root(
        &root(),
        // `adjudicate`, not `hook`. The rename ships no alias and an unknown
        // subcommand is clap exit 1 — which every host reads as ALLOW — so this
        // file failed with three "must refuse" assertions the moment the rename
        // landed, over a policy that was refusing correctly. That is the same
        // failure mode a stale binary produces in production, seen from inside
        // the suite.
        &["adjudicate", "--harness", "claude-code"],
        &bash_payload(command),
    ))
}

fn denied_by_the_row(command: &str) {
    let out = decision(command);
    assert!(
        out.contains("\"deny\""),
        "the committed policy must refuse: {command}\n{out}"
    );
    assert!(
        out.contains(ROW),
        "the refusal for `{command}` must come from `{ROW}`\n{out}"
    );
}

/// This row did not refuse the command.
///
/// Weaker than a blanket allow on purpose: another row may legitimately fire on
/// a command this one must leave alone, and reading the aggregate verdict would
/// make that arrival look like this row's regression.
fn not_refused_by_the_row(command: &str) {
    let out = decision(command);
    assert!(
        !out.contains(ROW),
        "`{ROW}` must not refuse `{command}`\n{out}"
    );
}

// --- refused: a lap the task owns ---------------------------------------------

/// THE MEASURED SHAPE. This is the command the session ran after `verify` had
/// already said there was nothing to fix.
#[test]
fn a_fresh_rebase_onto_main_is_refused() {
    denied_by_the_row("git rebase origin/main");
}

/// The same lap behind an env prefix and inside a compound command, because an
/// agent reaching around a refusal reaches for these first and `segments` is
/// what the engine decides over rather than the first word of the line.
#[test]
fn the_lap_is_refused_however_it_is_spelled() {
    denied_by_the_row("cd /home/user/batten && git rebase origin/main");
    denied_by_the_row("GIT_EDITOR=true git rebase origin/main");
    // THE ONE ACTUALLY TYPED, and it arrives here from another suite rather than
    // from imagination: `pipeline_shapes.rs` used this exact string to show an
    // `&&` chain is allowed, which it no longer is — this row refuses it. The
    // command moved to the file that decides it instead of being deleted, so the
    // coverage follows the verdict.
    //
    // It is also the CLOUD-857 shape, which is why it is worth its own line: a
    // predicate anchored on `input.call.command` reads the first word of the
    // whole LINE, so `git push --force origin main` was denied while
    // `cd /tmp && git push --force origin main` was allowed, with a green suite
    // over it. Anchoring on segments is what makes the fetch-then-rebase pair
    // refuse on its SECOND element.
    denied_by_the_row("git fetch origin main && git rebase origin/main");
}

/// A NEWLINE IS NOT AN ESCAPE HATCH (CLOUD-1381).
///
/// `segments` treats a newline as whitespace, so a two-line call is ONE segment
/// whose first word is the first line's program — and every `shape` row was
/// evaded by writing two lines instead of one. Measured over the running hook
/// before the fix: this exact command was ALLOWED while its single-line twin
/// was refused.
///
/// It needs no intent to reach. A two-line bash block is how anyone writes two
/// commands, so the bypass arrives by accident, which is worse than one needing
/// a deliberate quoting trick: nothing signals that it happened.
#[test]
fn a_second_line_does_not_escape_the_row() {
    denied_by_the_row("echo starting\ngit rebase origin/main");
    denied_by_the_row("cd /home/user/batten\ngit rebase origin/main");
}

/// THE FALSE DENY THE FIX WAS BUILT AROUND, and the reason `line_bounded_units`
/// carries each line's raw rather than reusing the segment's.
///
/// `contains` is matched against the text AS WRITTEN, because what it looks for
/// sits inside a quoted argument. Resolve the program per line but match the
/// needle across the whole segment and one line qualifies another line's
/// program: here line two is `git` with the operand `rebase` — flags are
/// dropped, so `--continue` is not among the words — while `origin/main` is
/// found on line one. A segment-wide needle refuses the conflict exit that this
/// row's own `contains` exists to protect, which is the direction that gets a
/// guard switched off rather than the sanctioned one.
#[test]
fn a_needle_on_another_line_does_not_qualify_this_one() {
    not_refused_by_the_row("echo origin/main\ngit rebase --continue");
    not_refused_by_the_row("git fetch origin main\ngit rebase --abort");
}

/// A BACKSLASH CONTINUATION IS ONE COMMAND, and splitting it would be a bypass
/// rather than a false refusal: line one would be `git rebase` with no operand
/// and line two an operand with no program, so the row would judge neither.
///
/// `joined_lines` is what keeps that whole, and its header records the case
/// being caught in review rather than in the field. This is the landing lap's
/// instance of it.
#[test]
fn a_continued_line_is_judged_as_the_one_command_it_is() {
    denied_by_the_row("git rebase \\\n  origin/main");
}

// --- allowed: the one step the contract keeps by hand -------------------------

/// THE ANTI-VACUITY HALF, and the reason `contains` exists on this row.
///
/// A conflict is the only stop `land` has, and resolving it is the caller's.
/// Refusing this spelling would make the contract's own remedy unrunnable —
/// strictly worse than the hand-stepping the row exists to catch, because it
/// would strand a branch mid-rebase with no sanctioned way forward.
#[test]
fn continuing_a_conflicted_rebase_is_left_alone() {
    not_refused_by_the_row("git rebase --continue");
}

/// The other two spellings of the same step, so the row cannot be narrowed to
/// the literal `--continue` and still pass.
#[test]
fn the_other_conflict_exits_are_left_alone() {
    not_refused_by_the_row("git rebase --abort");
    not_refused_by_the_row("git rebase --skip");
}

/// A rebase that names something other than the landing target is not a lap of
/// this loop. Squashing a branch's own history is the ordinary case, and a row
/// that refused it would be pricing an operation nobody asked it to judge.
#[test]
fn a_rebase_that_is_not_the_landing_lap_is_left_alone() {
    not_refused_by_the_row("git rebase -i HEAD~3");
}

/*
The obligation CLOUD-1461's Ready block declares, in the shape
`crates/batten/tests/it/mcp_dispatch.rs` already uses.

NOTE ON SPELLING: Rust block comments NEST, so a bare glob written as a slash
followed by a star opens a level that never closes. The paths below are spelled
with a space for that reason, not by accident — the first draft of this block
was an unterminated comment (E0758).

`mutate::subjects()` enumerates the shell gates under `mise-tasks/ *.sh`, the
consumer modules under `policy/ *.rego` and the preset directories, never
`crates/batten/tests/`, so no sweep reaches this row today — exactly as none
reaches `mcp_dispatch.rs`'s. `obligations-bound` is satisfied and the sweep half
is not; naming that here keeps the declaration from reading as coverage it does
not have.

#MUTANT fresh-rebase-allowed|s@"git rebase --continue"@"git rebase origin/main"@|continuing_a_conflicted_rebase_is_left_alone
*/
