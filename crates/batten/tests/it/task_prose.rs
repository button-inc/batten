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

use crate::common;

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

/// The claim holds again, and this case is INVERTED rather than deleted.
///
/// It was written as `fmt_is_not_described_as_formatters_only`, and it was right:
/// `fmt` drove every hk step, so calling it formatters-only was a sentence that
/// cost a full gate run, and the assertion existed to stop that sentence coming
/// back. CLOUD-681 fixed the thing the sentence was wrong ABOUT — `hk.pkl` hands
/// the `fix` hook a fixer subset now, measured 58 steps to 7 and 931s to 2s — so
/// the prose is true and the old assertion had become a gate holding the tree to
/// a defect it no longer has.
///
/// INVERTED, NOT DROPPED, and the direction is the point. Deleting it would leave
/// the regression unguarded in both directions; asserting the opposite keeps one
/// case on the sentence and moves which way it points. What now stops the
/// regression on the CONFIG side — where it actually lives — is
/// `hk-fix-selection`, whose `V-FMT-DESCRIBED-AS-THE-GATE` reads this same clause
/// and `fix-selection-complete`, which holds hk's own selection to the gate's
/// fixer-bearing steps in both directions. Prose alone was never the mechanism;
/// it is the half a reader sees.
#[test]
fn fmt_is_described_as_the_formatters_only_subset_it_now_is() {
    let prose = fs::read_to_string(at_root(RULES)).unwrap();
    assert!(
        prose.contains("formatters-only subset"),
        "{RULES} stopped calling `fmt` the formatters-only subset; it IS one since \
         CLOUD-681, and `hk-fix-selection` reads this clause to keep the config and \
         the prose from drifting apart"
    );
}
