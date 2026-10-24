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

/// The `toolchain-is-provisioned` row's repair argv, as the engine loads it.
fn repair() -> Vec<String> {
    batten::config::load(&common::at_root("batten.toml"))
        .expect("the committed config loads")
        .startup
        .into_iter()
        .find(|row| row.id == "toolchain-is-provisioned")
        .expect("the toolchain-is-provisioned row exists")
        .repair
        .expect("the row carries a repair")
}

/// The provenance mise verifies by reading api.github.com.
const ATTESTATIONS: &str = "github-attestations";

/// Push the path of every value or key under `value` that names [`ATTESTATIONS`],
/// whichever key mise records it under and however the TOML spells it.
fn attestations(value: &toml::Value, path: &str, found: &mut Vec<String>) {
    match value {
        toml::Value::String(text) if text == ATTESTATIONS => found.push(path.to_owned()),
        toml::Value::Table(table) => {
            for (key, inner) in table {
                let here = if path.is_empty() {
                    format!("{key:?}")
                } else {
                    format!("{path}.{key:?}")
                };
                if key == ATTESTATIONS {
                    found.push(here);
                } else {
                    attestations(inner, &here, found);
                }
            }
        }
        toml::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                attestations(item, &format!("{path}[{index}]"), found);
            }
        }
        _ => {}
    }
}

/// Fails by: a spelling of the provenance going unread, or another provenance
/// being taken for it.
#[test]
fn every_spelling_of_the_attestation_provenance_is_named() {
    let lock = r#"
[[tools.jq]]
version = "1.7"

[tools.jq."platforms.macos-arm64"]
provenance = 'github-attestations' # single-quoted, commented

# a key, which an inline table parses to as well
[tools.jq."platforms.linux-x64".provenance.github-attestations]

# an array element
[tools.jq."platforms.windows-x64"]
provenance = ["slsa", "github-attestations"]

# a renamed field
[tools.jq."platforms.linux-arm64-musl"]
verified_by = "github-attestations"

# a key naming it whose value names it again: one entry, not two
[tools.jq."platforms.macos-x64".provenance]
github-attestations = "github-attestations"

# near misses, which must not match: another provenance, a longer value, a longer key
[tools.jq."platforms.linux-arm64"]
provenance = "slsa"

[tools.jq."platforms.windows-arm64"]
provenance = "github-attestations-v2"

[tools.jq."platforms.freebsd-x64".provenance.github-attestations-v2]
"#;
    let mut found = Vec::new();
    attestations(&toml::from_str(lock).unwrap(), "", &mut found);
    found.sort();
    assert_eq!(
        found,
        [
            r#""tools"."jq"[0]."platforms.linux-arm64-musl"."verified_by""#,
            r#""tools"."jq"[0]."platforms.linux-x64"."provenance"."github-attestations""#,
            r#""tools"."jq"[0]."platforms.macos-arm64"."provenance""#,
            r#""tools"."jq"[0]."platforms.macos-x64"."provenance"."github-attestations""#,
            r#""tools"."jq"[0]."platforms.windows-x64"."provenance"[1]"#,
        ]
    );
}

#[test]
fn the_lock_installs_without_an_attestation_read() {
    let lock =
        std::fs::read_to_string(common::at_root("mise.lock")).expect("mise.lock is readable");
    // Parsed rather than matched by line, so every TOML spelling of the key is
    // read, and each one is named by its path: a lock that gained one mid-run
    // (CLOUD-2527) says which tool, version and platform it was.
    let mut attested = Vec::new();
    attestations(
        &toml::from_str(&lock).expect("mise.lock is TOML"),
        "",
        &mut attested,
    );
    assert!(
        attested.is_empty(),
        "mise.lock records github-attestations provenance on {} entr(ies); verifying it reads api.github.com, which a cloud session cannot: {}",
        attested.len(),
        attested.join(", ")
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
