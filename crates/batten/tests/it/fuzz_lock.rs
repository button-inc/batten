//! `fuzz/Cargo.lock` pins nothing the root lock has not judged, except the
//! fuzz harness's own crates (CLOUD-2538).
//!
//! The fuzz workspace is detached, so nothing in the landing path re-resolves
//! it and `cargo deny check` never reads it. THIS CASE IS HOW `deny` REACHES
//! THE CRATES THE TWO LOCKS SHARE: each may pin only a version, from a source,
//! the root lock carries, and every such pin is one `deny` already judged. The
//! harness's own crates are named in [`HARNESS`] and judged by no gate
//! (CLOUD-2539); any other name the root lock lacks is a stale pin.
//!
//! A SUBSET, NOT AN EQUALITY: the fuzz lock prunes what its harness does not
//! reach, so only a pin the root lock does not carry is drift.
//!
//! SOURCED CRATES ONLY: a release bumps `batten` in the root lock alone
//! (`release-plz release-pr`), and the fuzz build re-resolves that path crate
//! itself, so a path entry's version is not drift. That re-resolution is also
//! why `deny` is not pointed at `fuzz/Cargo.toml` directly: unlocked it
//! rewrites the tracked lock after every release, and `--locked` refuses it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use crate::common;

/// The crates only the fuzz harness pulls in: `libfuzzer-sys` and what it
/// alone depends on.
const HARNESS: [&str; 3] = ["arbitrary", "jobserver", "libfuzzer-sys"];

/// Every sourced package in the lock at `path`, with the `version source`
/// pins it carries.
fn pinned(path: &str) -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(common::at_root(path)).expect("the lock reads");
    let lock: toml::Value = toml::from_str(&text).expect("the lock is TOML");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("the lock lists packages")
    {
        let field = |key: &str| package.get(key).and_then(toml::Value::as_str);
        let Some(source) = field("source") else {
            continue;
        };
        let (name, version) = field("name")
            .zip(field("version"))
            .expect("a package carries a name and a version");
        out.entry(name.to_owned())
            .or_default()
            .insert(format!("{version} {source}"));
    }
    out
}

/// Fails by: a fuzz lock left behind the root's resolution, still pinning a
/// version the root lock moved past, or a crate the root lock dropped.
#[test]
fn the_fuzz_lock_resolves_shared_crates_as_the_root_does() {
    let root = pinned("Cargo.lock");
    let fuzz = pinned("fuzz/Cargo.lock");
    assert!(
        fuzz.keys().any(|name| root.contains_key(name)),
        "the premise: the two locks share crates"
    );
    let drifted: Vec<String> = fuzz
        .iter()
        .filter_map(|(name, pins)| match root.get(name) {
            Some(carried) if pins.is_subset(carried) => None,
            None if HARNESS.contains(&name.as_str()) => None,
            carried => {
                let stray: Vec<&String> = carried.map_or_else(
                    || pins.iter().collect(),
                    |carried| pins.difference(carried).collect(),
                );
                Some(format!("{name} {stray:?}"))
            }
        })
        .collect();
    assert!(
        drifted.is_empty(),
        "fuzz/Cargo.lock pins what Cargo.lock does not: {drifted:?}"
    );
}
