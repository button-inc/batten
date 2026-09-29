//! `cross-check`'s coverage, asserted over the committed task (CLOUD-395,
//! CLOUD-397), ported from `tests/cross-check.bats` under CLOUD-843.
//!
//! `cross-check` carries this repository's cross-platform claim, and for its
//! whole life it checked only half of what it claimed: `cargo check` without
//! `--all-targets` compiles lib and bins — no `#[cfg(test)]` module, nothing
//! under `tests/`. The half it skipped is the half most likely to break, since
//! test code reaches for `PermissionsExt`, `#!/bin/sh` fixtures and Unix paths as
//! a matter of course.
//!
//! Asserted over the committed task, not over a run. A green `cross-check`
//! cannot tell the two coverages apart — that is exactly how the narrower one
//! survived — so the flag itself is the predicate.
//!
//! # Read as commands, whichever way the task is spelled
//!
//! The retired suite read a shell body with `awk`. CLOUD-843 moves task bodies to
//! argv lists one package at a time, so this reads the task's COMMANDS through
//! [`common::task_commands`]: every `cargo check` the task runs is held to the
//! same flags, whether it arrives as a line of a body or an entry of a list.

// CLOUD-1268's fifth arm: `mise.toml` does not die, so every arm names it.
//
// ported: tests/cross-check.bats subject:mise.toml crates/batten/tests/it/cross_check.rs
// ported: "cross-check.bats::cross-check type-checks test code, not only the library and bins" crates/batten/tests/it/cross_check.rs subject:mise.toml
// ported: "cross-check.bats::the check is still target-scoped, so the flag widened coverage rather than replacing it" crates/batten/tests/it/cross_check.rs subject:mise.toml
// ported: "cross-check.bats::it stays a check, never a build — no linker and no SDK for a foreign triple" crates/batten/tests/it/cross_check.rs subject:mise.toml
// ported: "cross-check.bats::cross-check denies warnings, so a dead cfg-gated helper fails rather than prints" crates/batten/tests/it/cross_check.rs subject:mise.toml

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// Every command of `[tasks.cross-check]` that runs `cargo check`.
///
/// Asserted non-empty by every caller, so a task that stopped type-checking
/// altogether reads as a failure rather than as nothing to hold to a flag.
fn checks() -> Vec<String> {
    let checks: Vec<String> = common::task_commands("cross-check")
        .into_iter()
        .filter(|command| command.contains("cargo check"))
        .collect();
    assert!(
        !checks.is_empty(),
        "[tasks.cross-check] runs no `cargo check` at all"
    );
    checks
}

#[test]
fn cross_check_type_checks_test_code_not_only_the_library_and_bins() {
    // Every `cargo check` in the task, not merely one of them — a second triple
    // added later must carry the same coverage.
    for check in checks() {
        assert!(
            check.contains("--all-targets"),
            "a cross-check without --all-targets: {check}"
        );
    }
}

#[test]
fn the_check_is_still_target_scoped_so_the_flag_widened_coverage() {
    for check in checks() {
        assert!(check.contains("--target"), "an unscoped check: {check}");
        assert!(check.contains("--workspace"), "a partial check: {check}");
    }
}

#[test]
fn it_stays_a_check_never_a_build() {
    // `cargo check` stops at codegen-to-metadata, which is what makes
    // cross-platform coverage affordable on a Linux runner at all. A `cargo
    // build` or `cargo test` here would need a target linker, and the Darwin
    // triples' real link is `darwin-link`'s job by design.
    let build = regex::Regex::new(r"cargo (build|test|run)").expect("a valid expression");
    let commands = common::task_commands("cross-check");
    assert!(!commands.is_empty(), "[tasks.cross-check] runs nothing");
    for command in commands {
        assert!(
            !build.is_match(&command),
            "cross-check builds rather than checks: {command}"
        );
    }
}

#[test]
fn cross_check_denies_warnings_so_a_dead_cfg_gated_helper_fails() {
    // CLOUD-397. The flag is the predicate and not the run's exit code, because a
    // green run cannot distinguish "no warnings" from "warnings tolerated".
    for check in checks() {
        assert!(check.contains("RUSTFLAGS="), "no RUSTFLAGS: {check}");
        assert!(check.contains("-D warnings"), "warnings tolerated: {check}");
    }
}
