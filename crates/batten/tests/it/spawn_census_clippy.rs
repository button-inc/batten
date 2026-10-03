//! The spawn census, shown able to fail (CLOUD-743 §7, CLOUD-418) — ported from
//! `tests/spawn-census.bats` under CLOUD-843.
//!
//! `spawn_census.rs` holds the gate's SHAPE — the level in the manifest, the
//! entry in `clippy.toml`, a verdict on every annotation. What it cannot hold is
//! that clippy behaves as the design claims, because the crate it runs over is
//! green by construction: every assertion there passes over a tree where the gate
//! does nothing at all.
//!
//! So this file drives real clippy over a throwaway crate and makes each arm go
//! red on purpose:
//!
//!   (a) a new spawn with no annotation is refused;
//!   (b) a STALE annotation over a deleted spawn is refused, which is what
//!       `#[expect]` buys over `#[allow]` and the direction a count table is
//!       blind to;
//!   (c) a bare `Command` that is NOT std's needs no annotation — the
//!       discriminator, and the reason this gate is clippy and not a string scan;
//!   (d) at `warn`, an invocation that omits `-D warnings` reports CLEAN over an
//!       unannotated spawn. That is CLOUD-822's measurement reproduced, and it is
//!       why the level lives in `[workspace.lints.clippy]`.
//!
//! A throwaway crate with NO dependencies, outside this repository's tree: the
//! subject is the MECHANISM, not any real module's coverage, and a crate under
//! `target/` would be read as a member of this workspace. It also keeps the case
//! offline — cargo fetches nothing for a crate that declares nothing.
//!
//! # The pinned cargo, and where there is none
//!
//! Resolved through `mise which cargo` at this repository's root, as the retired
//! suite did: the toy crate lives outside the tree, so a bare `cargo` there would
//! resolve to whatever is ambient — the exact defect `no-bare-cargo` refuses. A
//! host with no pinned cargo FAILS (`common::require_tool`): it used to return,
//! and every case here passed over a clippy it never ran (CLOUD-2059).
//!
//! The ambient compiler flags are scrubbed for the reason the retired suite gave
//! for not passing `-D warnings`: the level under test is the manifest's, and an
//! inherited `RUSTFLAGS` would answer a question nobody is asking — case (d) is
//! precisely about the flag being absent.

// CLOUD-1268's fifth arm: `clippy.toml` does not die, so every arm names it.
//
// ported: tests/spawn-census.bats subject:clippy.toml crates/batten/tests/it/spawn_census_clippy.rs
// ported: "spawn-census.bats::a new spawn with no annotation is refused" crates/batten/tests/it/spawn_census_clippy.rs subject:clippy.toml
// ported: "spawn-census.bats::an annotated spawn passes" crates/batten/tests/it/spawn_census_clippy.rs subject:clippy.toml
// ported: "spawn-census.bats::a stale annotation over a deleted spawn is refused" crates/batten/tests/it/spawn_census_clippy.rs subject:clippy.toml
// ported: "spawn-census.bats::an allow in place of an expect goes quiet, which is why expect is the shape" crates/batten/tests/it/spawn_census_clippy.rs subject:clippy.toml
// ported: "spawn-census.bats::a bare Command import that is not std's needs no annotation" crates/batten/tests/it/spawn_census_clippy.rs subject:clippy.toml
// ported: "spawn-census.bats::at warn the gate reports clean, and at deny the same source is refused" crates/batten/tests/it/spawn_census_clippy.rs subject:clippy.toml

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The toy crate's own disallowed-type table: the census entry, and nothing
/// else, so the only thing clippy can refuse is the thing under test.
const TOY_CLIPPY: &str = r#"disallowed-types = [
  { path = "std::process::Command", reason = "a spawn is an inventory row" },
]
"#;

/// An unannotated spawn — case (a)'s source, and case (d)'s.
const BARE_SPAWN: &str = r#"pub fn spawn() {
    let _ = std::process::Command::new("true").status();
}
"#;

/// The toy manifest, with BOTH halves of the census at `level`.
///
/// Two lints, because `#[expect]` is two arms and each needs its own severity:
/// `disallowed_types` refuses a new spawn, and `unfulfilled_lint_expectations`
/// refuses a stale annotation over a spawn that is gone. The second is
/// warn-by-default, which is what case (b) measured — so the workspace denies it
/// explicitly rather than leaning on `-D warnings`.
fn manifest(dir: &Path, level: &str) {
    let text = format!(
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [lints.rust]\nunfulfilled_lint_expectations = \"{level}\"\n\n\
         [lints.clippy]\ndisallowed_types = \"{level}\"\n"
    );
    fs::write(dir.join("Cargo.toml"), text).expect("write the toy manifest");
}

/// A toy crate named for `case`, at `deny`, carrying `source` as its library.
fn toy(case: &str, source: &str) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-spawn-census", case);
    fs::create_dir_all(dir.join("src")).expect("create the toy source dir");
    fs::write(dir.join("clippy.toml"), TOY_CLIPPY).expect("write the toy clippy.toml");
    fs::write(dir.join("src/lib.rs"), source).expect("write the toy source");
    manifest(&dir, "deny");
    dir
}

/// Drive clippy over the toy crate, deliberately WITHOUT `-D warnings`.
///
/// Its own target directory, or every case contends on the lock this
/// workspace's build holds. Returns whether it passed, and everything it said.
fn toy_clippy(cargo: &Path, dir: &Path) -> (bool, String) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: the subject is clippy's verdict over a crate, which only clippy can give; the retired suite made this same spawn"
    )]
    let output = std::process::Command::new(cargo)
        .args(["clippy", "--quiet", "--offline"])
        .current_dir(dir)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CLIPPY_CONF_DIR")
        .output()
        .expect("cargo clippy runs");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), said)
}

#[test]
fn a_new_spawn_with_no_annotation_is_refused() {
    let cargo = common::require_tool("cargo");
    let dir = toy("unannotated", BARE_SPAWN);
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(!passed, "an unannotated spawn passed: {said}");
    assert!(said.contains("disallowed type"), "{said}");
    assert!(said.contains("std::process::Command"), "{said}");
}

#[test]
fn an_annotated_spawn_passes() {
    // The other side of (a): the annotation is what clears it, so the refusal
    // above is about the missing verdict rather than about the file.
    let cargo = common::require_tool("cargo");
    let dir = toy(
        "annotated",
        r#"#[expect(clippy::disallowed_types, reason = "stays: the toy case")]
pub fn spawn() {
    let _ = std::process::Command::new("true").status();
}
"#,
    );
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(passed, "an annotated spawn was refused: {said}");
}

#[test]
fn a_stale_annotation_over_a_deleted_spawn_is_refused() {
    // WHY `expect` AND NOT `allow`. The spawn is gone and the annotation was left
    // behind; under `#[allow]` this is silent forever, and the census accumulates
    // rows describing code that is not there.
    let cargo = common::require_tool("cargo");
    let dir = toy(
        "stale",
        r#"#[expect(clippy::disallowed_types, reason = "stays: the spawn this described is gone")]
pub fn spawn() {}
"#,
    );
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(!passed, "a stale expectation passed: {said}");
    assert!(said.contains("unfulfilled"), "{said}");
}

#[test]
fn an_allow_in_place_of_an_expect_goes_quiet_which_is_why_expect_is_the_shape() {
    // The same source as the case above, with one word changed. It PASSES — and
    // that pass is the measurement behind the choice.
    // `spawn_census.rs::every_annotation_is_an_expect_carrying_a_verdict` is what
    // keeps the word from being changed in the real tree.
    let cargo = common::require_tool("cargo");
    let dir = toy(
        "allow",
        r#"#[allow(clippy::disallowed_types, reason = "stays: the spawn this described is gone")]
pub fn spawn() {}
"#,
    );
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(passed, "an allow was refused: {said}");
}

#[test]
fn a_bare_command_import_that_is_not_std_s_needs_no_annotation() {
    // THE DISCRIMINATOR. `surface.rs` imports clap's `Command` bare, so the token
    // names two types in one crate. clippy matches the fully resolved path, so
    // this file is green with no annotation anywhere in it.
    let cargo = common::require_tool("cargo");
    let dir = toy(
        "other-command",
        r#"mod other {
    #[derive(Debug)]
    pub struct Command;
    impl Command {
        #[must_use]
        pub fn new(_name: &str) -> Self {
            Self
        }
    }
}

use other::Command;

#[must_use]
pub fn build() -> Command {
    Command::new("check")
}
"#,
    );
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(passed, "a non-std Command was refused: {said}");
}

#[test]
fn at_warn_the_gate_reports_clean_and_at_deny_the_same_source_is_refused() {
    // CLOUD-822's measurement, reproduced as the argument for where the level
    // lives. Under `warn` a lint reports clean over an unannotated spawn, and the
    // agent then quotes the clean run as verification.
    let cargo = common::require_tool("cargo");
    let dir = toy("warn-then-deny", BARE_SPAWN);
    manifest(&dir, "warn");
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(passed, "at warn the run should report clean: {said}");
    // The refusal is IN THE OUTPUT and not in the status, which is precisely the
    // reading that makes a `warn` gate quotable as verification.
    assert!(said.contains("disallowed type"), "{said}");

    // The same bytes at `deny`, with no flag added — which is what makes the pass
    // above a statement about the LEVEL rather than about clippy having missed it.
    manifest(&dir, "deny");
    let (passed, said) = toy_clippy(&cargo, &dir);
    assert!(!passed, "at deny the same source passed: {said}");
}
