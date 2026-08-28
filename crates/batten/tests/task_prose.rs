//! The rules file's description of a lifecycle task matches what the task runs.
//!
//! `.claude/rules/toolchain.md` described `fmt` as "the formatters-only subset"
//! for its whole life. `[tasks.fmt]` is `hk fix --all`, which drives every hk
//! step — `test:bats` and `cargo-clippy` included — so reaching for it to
//! reformat one file costs a full gate run. Measured 2026-08-28: roughly ten
//! minutes of wall clock spent on a one-file reflow, by an agent complying with
//! the sentence exactly.
//!
//! WHY A TEST AND NOT A CORRECTED SENTENCE. Non-negotiable rule 2 — a rule
//! without a runnable gate is half a change. The sentence was wrong for long
//! enough to cost somebody a run, and a second corrected sentence has exactly
//! the same shelf life as the first unless something holds it to the mechanism.
//!
//! WHAT THIS ASSERTS, AND WHAT IT CANNOT. It asserts **agreement**: the task
//! body in `mise.toml` is the authority, and the prose has to name the command
//! that body actually runs. So a change to either side without the other is a
//! finding, in both directions — the drift `rules-drift` does not reach here,
//! because its restated-default scan is over declared defaults rather than over
//! a task's own body.
//!
//! It does **not** assert the prose is a good explanation, and it cannot: that
//! is a judgement, and non-negotiable rule 3 says a gate resolves to a command
//! and an exit code, never a model verdict. It catches the specific, checkable
//! thing that went wrong — a description naming a narrower command than the one
//! that runs.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;

use common::at_root;

/// The rules file carrying the workshop's task descriptions.
const RULES: &str = ".claude/rules/toolchain.md";

/// The one authority for what a task runs.
const TASKS: &str = "mise.toml";

/// The command `[tasks.fmt]` runs. Read from the manifest rather than restated,
/// so this constant cannot itself become the drift it exists to catch.
fn fmt_body(manifest: &str) -> String {
    let table = manifest
        .split("[tasks.fmt]")
        .nth(1)
        .expect("mise.toml declares [tasks.fmt]");
    let run = table
        .lines()
        .find(|line| line.starts_with("run = "))
        .expect("[tasks.fmt] declares a `run`");
    run.trim_start_matches("run = ")
        .trim_matches('"')
        .to_owned()
}

/// The prose names the command the task actually runs.
///
/// The assertion is over the COMMAND, not over any adjective: an author may
/// describe `fmt` however reads best, as long as a reader can see what it
/// invokes. That keeps the gate narrow enough to survive a rewrite of the
/// paragraph and specific enough to have caught the defect it was written for.
#[test]
fn the_rules_file_names_the_command_fmt_runs() {
    let manifest = fs::read_to_string(at_root(TASKS)).unwrap();
    let prose = fs::read_to_string(at_root(RULES)).unwrap();
    let body = fmt_body(&manifest);

    assert_eq!(
        body, "hk fix --all",
        "[tasks.fmt] changed; update {RULES} and this assertion together"
    );
    assert!(
        prose.contains(&body),
        "{RULES} describes `fmt` without naming `{body}`, the command it runs — \
         a reader cannot tell it drives the whole gate"
    );
}

/// The retired claim does not come back.
///
/// `fmt` is a subset of `fix` — it omits clippy's autofixes and the derived
/// artifacts — and that is what the corrected sentence says. What it is NOT is
/// formatters-only, and naming the superset relation is exactly how the wrong
/// sentence read as true to its author. This is the half that stops the
/// regression, in the shape `scanner_taxonomy.rs` uses for the same job.
#[test]
fn fmt_is_not_described_as_formatters_only() {
    let prose = fs::read_to_string(at_root(RULES)).unwrap();
    assert!(
        !prose.contains("formatters-only subset"),
        "{RULES} calls `fmt` the formatters-only subset again; it is `hk fix --all` \
         and runs every hk step, which is what made that sentence cost a full gate run"
    );
}
