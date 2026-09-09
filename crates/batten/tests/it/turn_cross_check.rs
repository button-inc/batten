//! The per-turn cross-triple check keeps the four properties that make it an
//! alarm rather than a log (CLOUD-1731).
//!
//! **Why a test and not a careful author.** Every property below was got wrong
//! once while the row was being written, and each wrong version still *worked*:
//! the failure was written, the marker was cleared, the task exited 0. What
//! differed was only whether a human ever saw it. A regression here is therefore
//! invisible by construction — the handler goes on running, silently, and the
//! first anyone learns of a broken triple is CI, which is the exact failure the
//! row exists to move earlier.
//!
//! **The executable surface, never the block.** These read `run` and discard the
//! commentary around it, for `session_provisioning`'s recorded reason: the
//! comment above this task NAMES the stderr mistake while explaining why it is
//! wrong, so a prose scan would find `>&2` in a manifest that is correct.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::at_root;

/// The `run =` line of one task, without its surrounding comments.
fn run_body(name: &str) -> String {
    let manifest =
        std::fs::read_to_string(at_root("mise.toml")).expect("the task manifest is readable");
    let headers = [
        format!("\n[tasks.\"{name}\"]\n"),
        format!("\n[tasks.{name}]\n"),
    ];
    let block = headers
        .iter()
        .find_map(|header| manifest.split(header.as_str()).nth(1))
        .unwrap_or_else(|| panic!("`{name}` is declared in mise.toml"));
    let block = block.split("\n[").next().unwrap_or(block);
    let rest = block
        .split("\nrun = ")
        .nth(1)
        .unwrap_or_else(|| panic!("`{name}` declares a run body"));
    rest.strip_prefix("'''").map_or_else(
        || rest.lines().next().unwrap_or_default().to_owned(),
        |triple| triple.split("'''").next().unwrap_or(triple).to_owned(),
    )
}

/// The failure reaches the AGENT, which means stdout.
///
/// `handler.rs` states the contract a handler is read under: "Exit `0` with
/// stdout: advisory text, to be merged into Batten's own". stderr goes to a log
/// nobody opens. The first draft `cat`-ed the marker to stderr, which printed the
/// failure, cleared it, and showed it to no one.
///
/// Fails by: redirecting the marker read to `>&2`.
#[test]
fn the_failure_is_announced_on_stdout_and_not_into_a_log() {
    let body = run_body("cross-turn");
    let marker_read = body
        .split("cat $f")
        .nth(1)
        .expect("the body reads the marker back");
    let statement = marker_read.split(';').next().unwrap_or(marker_read);
    assert!(
        !statement.contains(">&2"),
        "the marker is announced on stderr, which no agent reads: {statement}"
    );
}

/// One failure is announced once, not on every turn until it is fixed.
///
/// This is what keeps the row under `[hook_output] max_repeats = 1`, and it is
/// also what stops the line becoming furniture the reader learns to skip.
///
/// Fails by: dropping the `rm -f`, which leaves the marker to be re-announced.
#[test]
fn the_marker_is_cleared_once_it_has_been_announced() {
    let body = run_body("cross-turn");
    assert!(
        body.contains("rm -f $f"),
        "a marker that is never cleared re-announces one failure every turn: {body}"
    );
}

/// The window cost of a failing turn is bounded.
///
/// Pointer-only is non-negotiable rule 4, and here the payload is a compiler's
/// whole output: without the cap a single broken triple could put a build log
/// into the agent's context. `hookcost::judge` REPORTS an over-budget hook rather
/// than truncating it, so nothing downstream would save this.
///
/// Fails by: removing the `head`, or raising it to an unbounded count.
#[test]
fn the_pointers_are_capped_so_a_build_log_cannot_reach_the_window() {
    let body = run_body("cross-turn");
    assert!(
        body.contains("head -3"),
        "the pointer list is uncapped, so a compiler's full output can reach the window: {body}"
    );
    assert!(
        body.contains("target/cross-turn.log"),
        "the capped list names no path to the rest, so the cap costs the reader the detail"
    );
}

/// The compiler does the reduction, rather than a grep guessing at it.
///
/// `--message-format=short` emits one `path:line:col: error: …` per diagnostic.
/// The draft this replaced scraped `-->` spans, which belong to notes and helps
/// as much as to errors — so it could report a note's location as the failure.
///
/// Fails by: dropping the flag, which restores the span art this cannot parse.
#[test]
fn the_cross_check_asks_the_compiler_for_one_line_per_diagnostic() {
    let body = run_body("cross-check");
    assert!(
        body.contains("--message-format=short"),
        "cross-check emits span art, which the per-turn extractor cannot reduce: {body}"
    );
}

/// Colour cannot defeat the extractor.
///
/// `[env]` sets `CARGO_TERM_COLOR = "always"` repo-wide, so a machine-read log
/// carries escapes between `: ` and `error`. Three drafts died on this, each
/// announcing a break with NO pointer and a clean exit code: `-->` scraping,
/// then `: error`, then `CARGO_TERM_COLOR=never` on the invocation — which a
/// task's own environment overrides. The pattern must therefore tolerate the
/// decoration rather than assume it away.
///
/// Fails by: anchoring on a literal `: error`, which the escapes split.
#[test]
fn the_pointer_pattern_survives_a_coloured_log() {
    let body = run_body("cross-turn");
    assert!(
        body.contains(":[0-9]+:[0-9]+: .*error"),
        "the pattern does not span the colour escapes, so a break announces no pointer: {body}"
    );
}

/// The turn is never blocked on a type-check.
///
/// The verdict is not needed before the turn proceeds; it is needed before the
/// author stops thinking about the change. A handler that waited would tax every
/// turn by the cost of the check, which is the thing measurement showed is 54s
/// when it must re-derive.
///
/// Fails by: dropping the `&`, which makes the handler wait for cargo.
#[test]
fn the_check_is_detached_so_the_handler_cannot_tax_the_turn() {
    let body = run_body("cross-turn");
    assert!(
        body.contains(") &"),
        "the type-check is not detached, so every turn pays for it: {body}"
    );
}

/// A second copy is refused by the declared lock, never by a process probe.
///
/// `polls-a-local-process` refuses reading the process table to answer "is one
/// already running", and `batten singleton` is the mechanism that answers it.
/// Both spellings of the probe self-match, which this session measured twice.
///
/// Fails by: swapping the lock for a `pgrep`/`pkill` guard.
#[test]
fn the_second_copy_is_refused_by_the_lock_rather_than_a_process_probe() {
    let body = run_body("cross-turn");
    assert!(
        body.contains("batten singleton acquire cross-turn"),
        "the declared lock is gone: {body}"
    );
    for probe in ["pgrep", "pkill", "ps -", "jobs"] {
        assert!(
            !body.contains(probe),
            "`{probe}` answers 'is one running' by a process probe, which self-matches: {body}"
        );
    }
}
