//! A runner transports the engine's verdict; it does not replace one (CLOUD-1090).
//!
//! `[tasks.batten-check]` is consumer #1's gate — the task that evaluates the
//! committed `batten.toml` with batten's own engine. For its whole life it ended
//! `if ! cargo run … enforce; then exit 1; fi`, which collapsed a policy denial
//! (`2`), a config error (`1`) and an internal error (`3`) into one code. `2` is
//! what the entire contract is numbered around (house style §7), so the one place
//! it should be observable was the one place that erased it.
//!
//! **WHY THIS ASSERTS THE BODY'S SHAPE RATHER THAN OBSERVING AN EXIT CODE**, stated
//! rather than discovered. An end-to-end assertion needs a ruleset that DENIES, and
//! this repository's committed ruleset passes by construction — that is the point of
//! it. Producing a denial would mean running the task against a fixture config,
//! which `batten-check` has no flag for: it is hard-wired to `cargo run … enforce`
//! over the working tree. So the honest cheap predicate is the one
//! `tests/task-fail-closed.bats` already uses for `verify`'s body — read the
//! committed task body and assert the property over it. That suite's own case, *"a
//! captured exit code is checked and exited on, never merely recorded"*, is this
//! predicate one task over.
//!
//! **WHY IT IS NOT IN THAT BATS SUITE**, which is where it belongs on subject. The
//! `shell retire partial` row (`severity = "deny"`) refuses an EDITED `tests/**/*.bats`
//! as `shell edit refused` and an ADDED one as `shell add refused`, and the one
//! admitted edit is a line whose removal names a path the same change deletes. So
//! the bats corpus is closed to an addition like this one. That is CLOUD-1088 —
//! *"the campaign's own door-tier suites have no landable spelling"* — and this file
//! is that gap being routed around rather than argued with. When 1088 lands, this
//! belongs beside the `verify` cases and should move.
//!
//! The bound, so nothing is read as stronger than it is: this proves the body
//! propagates rather than replaces. It does not prove the engine returns `2` for a
//! denial — `crates/batten/src/exit.rs`'s own table test owns that — and it cannot
//! prove the two compose without a denying ruleset to run.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The `run` body of one task, through the shared extractor (CLOUD-1914).
///
/// This file used to carry its own scan, keyed on the header and ended at the
/// closing `'''`. It was a second definition of where a task starts and ends, one
/// of four such copies. `common::task_block` is the sweep's own boundary, so a
/// mutation staged under `mutate sweep` is what these cases read.
fn task_body(name: &str) -> String {
    let block = common::task_block(name).unwrap_or_else(|| panic!("{name} is a declared task"));
    let body = common::task_value(&block, "run");
    assert!(!body.is_empty(), "[tasks.{name}] carries a `run` body");
    body
}

fn batten_check_body() -> String {
    task_body("batten-check")
}

/// The `run` entries of `[tasks.batten-check]`, parsed: the body is an argv
/// chain, so each entry is one command mise runs in order and stops on.
fn batten_check_entries() -> Vec<String> {
    let block = common::task_block("batten-check").expect("batten-check is a declared task");
    let parsed: toml::Value = toml::from_str(&block).expect("a task block is a TOML table");
    parsed["tasks"]["batten-check"]["run"]
        .as_array()
        .expect("batten-check's `run` is an argv chain")
        .iter()
        .map(|entry| entry.as_str().expect("each entry is a string").to_owned())
        .collect()
}

/// ANTI-VACUITY, and it is not ceremony: every assertion below is over a string
/// this file located by scanning, so a rename of the table or of the literal
/// delimiter would leave them all passing over an empty body.
#[test]
fn the_batten_check_body_was_found_at_all() {
    let body = batten_check_body();
    assert!(
        body.contains("enforce"),
        "the batten-check body invokes the engine"
    );
}

/// NOT RECEIPT-GATED, and the reason is what `enforce` reads (CLOUD-843 review).
///
/// CHANGED WITH CLOUD-843: the retired body skipped `enforce` on a
/// `step-receipt` hit keyed to the tracked tree. But `enforce` also reads state
/// no pathspec names: the record stores under the git directory
/// (`input.tree.records`), captures, the forge's recorded answers. A record
/// flipping to a deny value with no tracked change hit the receipt and skipped
/// the gate. A `[[step]]` row can key only index entries, tool answers and
/// arguments, so the honest cache for this step is none.
#[test]
fn the_engine_is_never_answered_from_a_step_receipt() {
    let body = batten_check_body();
    assert!(
        !body.contains("step run batten-check")
            && !body.contains("step check batten-check")
            && !body.contains("step-receipt"),
        "batten-check must not be receipt-gated: `enforce` reads record and capture \
         stores outside the tracked tree, which no `[[step]]` row can key"
    );
}

/// The defect itself. `if ! <engine>; then exit 1; fi` is the shape that discards
/// the verdict, and it is refused by name rather than by a general pattern: this is
/// the exact spelling the task carried, so a reader meeting a failure here sees what
/// regressed.
#[test]
fn the_engine_invocation_is_not_wrapped_in_a_replacing_guard() {
    let body = batten_check_body();
    let replacing_guard = body
        .lines()
        .map(str::trim)
        .find(|line| line.contains("enforce") && line.starts_with("if !"));
    assert!(
        replacing_guard.is_none(),
        "the batten-check body guards `enforce` with `if ! …; then exit 1; fi`, \
         which replaces every non-zero code the engine emits with 1 — a policy \
         denial (2) and an internal error (3) become indistinguishable. Capture \
         the status and exit with it instead (CLOUD-1090)."
    );
}

/// The positive half, and it is what stops the assertion above being satisfiable by
/// deleting the invocation.
///
/// CHANGED WITH CLOUD-843: the capture-and-re-exit (`verdict=$?` / `exit
/// "$verdict"`) existed only so a receipt could be written after a zero exit.
/// With no receipt, the engine is the chain's TERMINATING entry, so its code is
/// the task's with nothing after it to replace one.
#[test]
fn the_engine_status_is_the_chains_last_entry_so_it_passes_through_unchanged() {
    let entries = batten_check_entries();
    assert_eq!(
        entries.last().map(String::as_str),
        Some("cargo run --quiet -p batten -- enforce"),
        "`enforce` must be the last entry, bare, so its code is the task's: {entries:?}"
    );
    let body = batten_check_body();
    assert!(
        !body.contains("verdict=$?") && !body.contains("|| true"),
        "no shell remains between the engine and the task's exit to replace its code"
    );
}

/// CLOUD-407 must stay fixed, and this file is where a reader would look for it:
/// `verify` deliberately maps a content failure to `1` so its own `2` can mean
/// "main moved under this branch". CLOUD-1090 preserves a verdict one layer down
/// and must not be read as licence to reverse that.
#[test]
fn verify_still_reserves_exit_2_for_the_rebase_race() {
    let body = task_body("verify");
    assert!(
        body.contains("exit 2"),
        "verify still has an exit-2 path — CLOUD-407's rebase-race signal"
    );
    assert!(
        body.contains(r#"if [ "$linear_rc" = 2 ]; then"#),
        "verify's exit 2 is reached from linear-check's status, not from a gate's verdict"
    );
}
