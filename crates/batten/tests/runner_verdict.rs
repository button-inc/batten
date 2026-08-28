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
//! `shell-retirement` row (`severity = "deny"`) refuses an EDITED `tests/**/*.bats`
//! as `V-SHELL-RULE-EDITED` and an ADDED one as `V-SHELL-RULE-ADDED`, and the one
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

use std::path::PathBuf;

fn mise_toml() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("mise.toml");
    std::fs::read_to_string(&path).expect("the workspace mise.toml is readable")
}

/// The `run = '''…'''` body of one `[tasks.<name>]` table.
///
/// Keyed on the table header and terminated by the closing `'''`, which is the
/// same span `tests/task-fail-closed.bats` takes with `awk`. Written as a scan
/// rather than a TOML parse so a body that stops being a literal block — the shape
/// every assertion here depends on — fails loudly instead of resolving to some
/// other string.
fn task_body(toml: &str, header: &str) -> String {
    let mut lines = toml.lines().skip_while(|line| line.trim_end() != header);
    assert!(lines.next().is_some(), "{header} is present in mise.toml");
    let mut body = lines.skip_while(|line| !line.starts_with("run = '''"));
    assert!(
        body.next().is_some(),
        "{header} carries a `run = '''` literal block"
    );
    body.take_while(|line| line.trim_end() != "'''")
        .collect::<Vec<_>>()
        .join("\n")
}

fn batten_check_body() -> String {
    task_body(&mise_toml(), "[tasks.batten-check]")
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
    assert!(
        body.contains("step-receipt.sh"),
        "the batten-check body is receipt-gated"
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
/// deleting the invocation. The status is captured and re-exited with the SAME
/// value — a body that captured it and exited `1` would pass a mere "captures `$?`"
/// test while keeping the defect.
#[test]
fn the_engine_status_is_captured_and_re_exited_unchanged() {
    let body = batten_check_body();
    assert!(
        body.contains("verdict=$?"),
        "the batten-check body captures the engine's exit status"
    );
    assert!(
        body.contains(r#"exit "$verdict""#),
        "the batten-check body exits with the status it captured, unchanged"
    );

    // ORDER IS THE PROPERTY, not mere presence: a capture that is never tested, or
    // tested after the receipt is written, leaves the defect in place. mise task
    // bodies do not run under `set -e`, so nothing else enforces this.
    let capture = body.find("verdict=$?").expect("the capture is present");
    let propagate = body
        .find(r#"exit "$verdict""#)
        .expect("the exit is present");
    let record = body
        .find("step-receipt.sh record")
        .expect("the receipt write is present");
    assert!(
        capture < propagate,
        "the status is captured before it is propagated"
    );
    assert!(
        propagate < record,
        "a non-zero verdict exits before the receipt is written — a denied run must \
         leave no receipt, or the next run answers from a cache of the failure"
    );
}

/// CLOUD-407 must stay fixed, and this file is where a reader would look for it:
/// `verify` deliberately maps a content failure to `1` so its own `2` can mean
/// "main moved under this branch". CLOUD-1090 preserves a verdict one layer down
/// and must not be read as licence to reverse that.
#[test]
fn verify_still_reserves_exit_2_for_the_rebase_race() {
    let toml = mise_toml();
    let body = task_body(&toml, "[tasks.verify]");
    assert!(
        body.contains("exit 2"),
        "verify still has an exit-2 path — CLOUD-407's rebase-race signal"
    );
    assert!(
        body.contains(r#"if [ "$linear_rc" = 2 ]; then"#),
        "verify's exit 2 is reached from linear-check's status, not from a gate's verdict"
    );
}
