//! `fuzz/Cargo.lock` resolves every crate it shares with the root lock as the
//! root does (CLOUD-2538).
//!
//! The fuzz workspace is detached, so nothing in the landing path re-resolves
//! it: measured 2026-10-26, it still pinned `batten 0.0.125` and five crates
//! behind the root lock's versions. `deny` now reads its advisories, which
//! catches a known-bad pin; this case catches the drift that precedes one,
//! offline and on every leg.
//!
//! A SUBSET, NOT AN EQUALITY: the fuzz lock prunes what its harness does not
//! reach and adds the harness's own crates, so only a version the root lock
//! does not carry is drift.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use crate::common;

/// Every package name in the lock at `path`, with the versions it pins.
fn pinned(path: &str) -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(common::at_root(path)).expect("the lock reads");
    let lock: toml::Value = toml::from_str(&text).expect("the lock is TOML");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("the lock lists packages")
    {
        let field = |key: &str| {
            package
                .get(key)
                .and_then(toml::Value::as_str)
                .expect("a package carries a name and a version")
                .to_owned()
        };
        out.entry(field("name"))
            .or_default()
            .insert(field("version"));
    }
    out
}

/// Fails by: a fuzz lock left behind the root's resolution, which is how it
/// came to carry tokio 1.53.1 after the root took 1.53.3.
#[test]
fn the_fuzz_lock_resolves_shared_crates_as_the_root_does() {
    let root = pinned("Cargo.lock");
    let fuzz = pinned("fuzz/Cargo.lock");
    let shared = fuzz.keys().filter(|name| root.contains_key(*name)).count();
    assert!(shared > 0, "the premise: the two locks share crates");
    let drifted: Vec<String> = fuzz
        .iter()
        .filter_map(|(name, versions)| {
            let carried = root.get(name)?;
            let stray: Vec<&String> = versions.difference(carried).collect();
            (!stray.is_empty()).then(|| format!("{name} {stray:?}"))
        })
        .collect();
    assert!(
        drifted.is_empty(),
        "fuzz/Cargo.lock pins versions Cargo.lock does not: {drifted:?}"
    );
}
