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

/// Every check is target-scoped, and together they cover the WHOLE workspace.
///
/// Per-package rows since the split (CLOUD-2789: `cross-check:facts`, `:base`,
/// `:core`, each keyed on its own package so it re-runs only when that package
/// moves), so "every command says `--workspace`" stopped being the property.
/// The property is the union: exactly one `--workspace` row, and every package
/// it `--exclude`s is checked by a `-p` row of its own — an exclude nothing
/// picks up is a package the task silently stopped checking.
#[test]
fn the_check_is_still_target_scoped_so_the_flag_widened_coverage() {
    let checks = checks();
    let mut packages = std::collections::BTreeSet::new();
    let mut excluded = std::collections::BTreeSet::new();
    let mut workspace_rows = 0;
    for check in &checks {
        assert!(check.contains("--target"), "an unscoped check: {check}");
        let words: Vec<&str> = check.split_whitespace().collect();
        for pair in words.windows(2) {
            match pair[0] {
                "-p" | "--package" => {
                    packages.insert(pair[1].to_owned());
                }
                "--exclude" => {
                    excluded.insert(pair[1].to_owned());
                }
                _ => {}
            }
        }
        if words.contains(&"--workspace") {
            workspace_rows += 1;
        }
    }
    assert_eq!(
        workspace_rows, 1,
        "exactly one row checks the workspace: {checks:?}"
    );
    let unchecked: Vec<&String> = excluded.difference(&packages).collect();
    assert!(
        unchecked.is_empty(),
        "excluded from the workspace row and checked by no package row: {unchecked:?}"
    );
    // AND THE UNION IS THE WORKSPACE, read from the workspace and not the task
    // (CLOUD-2789): the `--workspace` row checks every member it does not
    // exclude, so what the checks cover is `(members - excluded) ∪ packages`,
    // and it must be exactly the members — no member dropped, and no `-p` or
    // `--exclude` naming a package that is not one.
    let root: toml::Table = toml::from_str(
        &std::fs::read_to_string(common::at_root("Cargo.toml")).expect("the root manifest"),
    )
    .expect("the root manifest parses");
    let workspace = root.get("workspace").expect("a workspace");
    // The members ARE the `crates/*` directories only while the workspace says
    // so and excludes none: `cargo metadata`'s own membership, read without a
    // spawn.
    assert_eq!(
        workspace.get("members"),
        Some(&toml::Value::Array(vec![toml::Value::from("crates/*")])),
        "the workspace's membership moved: read it here as cargo does"
    );
    assert!(
        workspace.get("exclude").is_none(),
        "the workspace excludes a member"
    );
    let members: std::collections::BTreeSet<String> = common::workspace_members()
        .iter()
        .map(|dir| {
            let manifest: toml::Table = toml::from_str(
                &std::fs::read_to_string(dir.join("Cargo.toml")).expect("a member manifest"),
            )
            .expect("a member manifest parses");
            manifest["package"]["name"]
                .as_str()
                .expect("a member names its package")
                .to_owned()
        })
        .collect();
    let covered: std::collections::BTreeSet<String> = members
        .difference(&excluded)
        .cloned()
        .chain(packages.iter().cloned())
        .collect();
    assert_eq!(
        covered, members,
        "the cross-check covers exactly the workspace's members"
    );
    let strangers: Vec<&String> = excluded.difference(&members).collect();
    assert!(
        strangers.is_empty(),
        "excluded but not a workspace member: {strangers:?}"
    );
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
    // The engine's own launcher is not the gate: a body spells batten through
    // `{{vars.batten}}`, rendered as `cargo run … --` when `BATTEN_BIN` is
    // unset, and what this pins is the command the step then runs.
    let launcher = common::rendered("{{vars.batten}}");
    for command in commands {
        let command = command.replace(&launcher, "batten");
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

/// The compiler does the reduction to one `path:line:col: error: …` line per
/// diagnostic, so a failure names its line and not a page of span art.
///
/// `main` held this as `the_cross_check_asks_the_compiler_for_one_line_per_diagnostic`
/// in `turn_cross_check.rs`, which was deleted whole with the per-turn detached
/// check (229841f43) while the flag it pinned stayed on the task.
///
/// Fails by: dropping the flag from any `cargo check` of the task.
#[test]
fn the_cross_check_asks_the_compiler_for_one_line_per_diagnostic() {
    for check in checks() {
        assert!(
            check.contains("--message-format=short"),
            "cross-check emits span art, not one line per diagnostic: {check}"
        );
    }
}
