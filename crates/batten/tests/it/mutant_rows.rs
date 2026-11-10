//! The Rust tier is cargo-mutants' alone (CLOUD-2253): the tree-level half.
//!
//! The marker and argv refusals are the build's (`build.rs` over
//! `batten::mutation_markers`), so nothing compiles that carries one. These are
//! the facts about the tree a build of one crate cannot see: every tracked `.rs`
//! is owned by cargo-mutants under the registry `mise.toml` declares, and the
//! `preset-overlay` feature is enabled by the sweep alone.

use std::path::Path;

use crate::common;

/// EVERY TRACKED RUST SOURCE IS CARGO-MUTANTS', by the registry `mise.toml`
/// declares, so the sweep refuses a hand-written row in any of them
/// (`runner-owned`) wherever it is written. Fails by: a glob that leaves a `.rs`
/// file (a bench, an example, a new crate) to the declared runner, which would
/// quietly accept rows there.
#[test]
fn every_tracked_rust_source_is_owned_by_cargo_mutants() {
    let root = common::at_root(".");
    let manifest = std::fs::read_to_string(root.join("mise.toml")).expect("the manifest reads");
    let declared = manifest
        .lines()
        .find_map(|line| line.strip_prefix("MUTANT_RUNNERS = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("mise.toml declares the runner registry in [env]");
    let registry = batten::mutate::Registry::parse(declared).expect("the registry parses");
    let tracked = batten::git::tracked_paths(&root).expect("the tracked set");
    let unowned: Vec<&String> = tracked
        .iter()
        .filter(|path| Path::new(path).extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| registry.owner(path).ok() != Some(batten::mutate::RunnerKind::CargoMutants))
        .collect();
    assert!(
        unowned.is_empty(),
        "every Rust source is cargo-mutants' alone: {unowned:?}"
    );
}

/// The tracked files under `root` whose text contains `needle`, sorted.
fn files_naming(root: &Path, needle: &str) -> Vec<String> {
    let tracked = batten::git::tracked_paths(root).expect("the tracked set");
    let mut found: Vec<String> = tracked
        .into_iter()
        .filter(|path| {
            std::fs::read_to_string(root.join(path)).is_ok_and(|text| text.contains(needle))
        })
        .collect();
    found.sort();
    found
}

/// THE OVERLAY VARIABLE REACHES THE `batten` A SUITE SPAWNS. A suite judges a
/// preset row through a child `batten`, and that child reads the mutant only
/// through the overlay variable. Fails by: the test harness scrubbing it, which
/// judged every preset row against the embedded text — 85 false survivors.
#[test]
fn the_overlay_reaches_the_batten_a_suite_spawns() {
    // The variable the sweep declares as its overlay, read from the task, so a
    // rename cannot leave this case asserting about a name nothing sets.
    let tasks = std::fs::read_to_string(common::at_root("mise.toml")).expect("reads");
    let Some(name) = tasks.lines().find_map(|line| {
        let rest = line.split("MUTANT_OVERLAY_ENV = \"").nth(1)?;
        rest.split('"').next()
    }) else {
        panic!("mise.toml declares MUTANT_OVERLAY_ENV");
    };
    let command = common::batten();
    let removed = command
        .get_envs()
        .any(|(key, value)| key == name && value.is_none());
    assert!(
        !removed,
        "`common::batten` strips {name}, so every suite judges the embedded preset, never the mutant"
    );
}

/// `preset-overlay` NEVER SHIPS: it lets a file replace a shipped rule, so only
/// the mutation sweep's suite build enables it. Fails by: the feature reaching a
/// default feature set, a release workflow, a dist config or any task but the
/// sweep's.
#[test]
fn the_preset_overlay_is_enabled_by_the_sweep_alone() {
    let root = common::at_root(".");
    let allowed = [
        // The asked ledger records what was said, never what is enabled.
        ".batten/asked.jsonl",
        "crates/batten/Cargo.toml",
        "crates/batten/src/mutate.rs",
        "crates/batten/src/preset.rs",
        "crates/batten/tests/it/mutant_rows.rs",
        "mise.toml",
    ];
    let naming = files_naming(&root, "preset-overlay");
    let stray: Vec<&String> = naming
        .iter()
        .filter(|path| !allowed.contains(&path.as_str()))
        .collect();
    assert!(
        stray.is_empty(),
        "preset-overlay named outside the sweep: {stray:?}"
    );
    let manifest = std::fs::read_to_string(root.join("crates/batten/Cargo.toml")).expect("reads");
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("default") && line.contains("preset-overlay")),
        "preset-overlay in the default feature set"
    );
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("reads");
    let enabling: Vec<&str> = tasks
        .lines()
        .filter(|line| line.contains("preset-overlay") && !line.trim_start().starts_with('#'))
        .collect();
    assert_eq!(enabling.len(), 1, "one task enables it: {enabling:?}");
    assert!(
        enabling[0].contains("MUTANT_OVERLAY_FEATURES"),
        "and it is the sweep's: {enabling:?}"
    );
}
