//! The toolchain installs from `mise.lock` with no GitHub API read (CLOUD-2395).
//!
//! `toolchain-is-provisioned`'s repair installs locked, so every download is a
//! `releases/download` URL pinned by sha256 and needs no credential. What still
//! read the API was the attestation check: `mise.lock` recorded
//! `github-attestations` provenance, verifying it reads api.github.com for the
//! upstream repo, and a cloud session's proxy refuses that for a third party.
//! Measured on `aqua:taiki-e/cargo-llvm-cov`: downloaded, then 403'd at "verify
//! GitHub artifact attestations", so `toolchain-check` refused every `verify` and
//! every `land` stopped on lap 1.
//!
//! The two halves hold each other: switching verification off while the lock still
//! records the provenance is refused by mise as a downgrade, and dropping the
//! provenance while the repair still verifies reaches the API anyway. So this
//! case reads both, and a scheduled `mise lock` that writes provenance back fails
//! here on its own PR rather than in the next session.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The `toolchain-is-provisioned` row's repair argv.
fn repair() -> Vec<String> {
    let text =
        std::fs::read_to_string(common::at_root("batten.toml")).expect("batten.toml is readable");
    let config: toml::Value = toml::from_str(&text).expect("batten.toml parses");
    let rows = config
        .get("startup")
        .and_then(toml::Value::as_array)
        .expect("batten.toml declares [[startup]] rows");
    let row = rows
        .iter()
        .find(|row| row.get("id").and_then(toml::Value::as_str) == Some("toolchain-is-provisioned"))
        .expect("the toolchain-is-provisioned row exists");
    row.get("repair")
        .and_then(toml::Value::as_array)
        .expect("the row carries a repair")
        .iter()
        .map(|arg| {
            arg.as_str()
                .expect("the repair is an argv of strings")
                .to_owned()
        })
        .collect()
}

#[test]
fn the_lock_installs_without_an_attestation_read() {
    let lock =
        std::fs::read_to_string(common::at_root("mise.lock")).expect("mise.lock is readable");
    let attested = lock
        .lines()
        .filter(|line| line.trim() == r#"provenance = "github-attestations""#)
        .count();
    assert_eq!(
        attested, 0,
        "mise.lock records github-attestations provenance on {attested} entr(ies); verifying it reads api.github.com, which a cloud session cannot"
    );

    let argv = repair();
    for setting in [
        "MISE_LOCKFILE=true",
        "MISE_LOCKED=1",
        "MISE_AQUA_GITHUB_ATTESTATIONS=false",
    ] {
        assert!(
            argv.iter().any(|arg| arg == setting),
            "the toolchain repair must install locked with no attestation read; missing {setting}: {argv:?}"
        );
    }
}
