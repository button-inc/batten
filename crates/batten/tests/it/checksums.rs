//! `[tasks.checksums]` — CLOUD-278's release manifest, over the task's own body
//! (CLOUD-1717).
//!
//! The program moved whole into `mise.toml`: it is an effect with no decision in
//! it, so there was nothing for a module to take. This tier runs the body the
//! manifest declares, exactly as mise does — the `usage` spec's `usage_names` and
//! `usage_tag` in the environment, the `{% raw %}` fence stripped — against a
//! stub `gh` serving a fixture release. The properties are the ones a packager
//! depends on: `sha256sum -c` reads the manifest with no flags, two runs are
//! identical bytes, it never hashes itself, and it is never written empty.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/checksums.sh crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: tests/checksums.bats crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "--names answers with no tag, no network and no download" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "the manifest covers every asset the release carries" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "the manifest never lists itself" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "two runs over one release produce identical bytes" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "sha256sum -c accepts the manifest with no flags, in a directory of assets" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "corrupting one byte of one asset makes that check fail" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "a release carrying no assets writes no manifest" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "an unreadable release exits 2, not 1" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "no tag given falls back to the latest release" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "an EMPTY tag argument falls back too, which is what the workflow passes" crates/batten/tests/it/checksums.rs subject:mise.toml
// ported: "no tag resolvable exits 2 rather than hashing nothing" crates/batten/tests/it/checksums.rs subject:mise.toml

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{at_root, scratch, write};

/// `[tasks.checksums]`'s body, fence stripped, as mise renders it.
fn body() -> String {
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"]["checksums"]["run"]
        .as_str()
        .expect("[tasks.checksums] declares a run body")
        .lines()
        .filter(|line| !line.contains("{% raw %}") && !line.contains("{% endraw %}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A scratch directory with a stub `gh` whose `release download` copies
/// `release/` into `--dir`, and whose tag lookup answers `v9.9.9`. A marker file
/// makes either half fail.
fn bench(name: &str, assets: &[&str]) -> PathBuf {
    let dir = scratch(&format!("checksums-{name}"));
    std::fs::create_dir_all(dir.join("release")).expect("release dir");
    for asset in assets {
        write(
            &dir,
            &format!("release/{asset}"),
            &format!("bytes of {asset}\n"),
        );
    }
    let root = dir.display();
    write(
        &dir,
        "bin/gh",
        &format!(
            r#"#!/usr/bin/env bash
[ ! -f "{root}/gh.fails" ] || exit 1
case "$*" in
  *"release download"*)
    [ ! -f "{root}/download.fails" ] || exit 1
    dir=""
    while [ $# -gt 0 ]; do [ "$1" != --dir ] || dir="$2"; shift; done
    mkdir -p "$dir"
    cp -R "{root}/release/." "$dir/"
    ;;
  *tagName*) printf 'v9.9.9\n' ;;
esac
"#
        ),
    );
    make_executable(&dir.join("bin/gh"));
    dir
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(path).expect("stat").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("chmod");
    }
}

/// Run the body in `dir`, with `names`/`tag` as the `usage` spec delivers them.
fn run_task(dir: &Path, names: bool, tag: Option<&str>) -> Output {
    let mut paths = vec![dir.join("bin")];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(paths).expect("PATH");
    let mut command = Command::new("bash");
    command
        .args(["-c", &body()])
        .current_dir(dir)
        .env("PATH", path)
        .env("CHECKSUMS_OUT_DIR", dir.join("out"))
        .env("usage_names", if names { "true" } else { "false" });
    match tag {
        Some(tag) => command.env("usage_tag", tag),
        None => command.env_remove("usage_tag"),
    };
    command.output().expect("run the task body")
}

fn sums(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out/SHA256SUMS")).unwrap_or_default()
}

const RELEASE: &[&str] = &[
    "batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz",
    "batten-9.9.9-aarch64-apple-darwin.tar.gz",
    "batten.schema.json",
];

#[test]
fn names_answers_with_no_tag_no_network_and_no_download() {
    let dir = bench("names", RELEASE);
    write(&dir, "gh.fails", "");
    let out = run_task(&dir, true, None);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("sums="));
    assert!(!dir.join("out").exists(), "nothing written");
}

#[test]
fn the_manifest_covers_every_asset_never_itself_and_is_byte_stable() {
    let dir = bench("covers", RELEASE);
    // A manifest already on the release must not be hashed into the next one.
    write(&dir, "release/SHA256SUMS", "stale\n");
    assert!(run_task(&dir, false, Some("v9.9.9")).status.success());
    let first = sums(&dir);
    for asset in RELEASE {
        assert!(first.contains(asset), "{asset} in {first}");
    }
    assert!(!first.contains("SHA256SUMS"), "never lists itself: {first}");
    assert!(run_task(&dir, false, Some("v9.9.9")).status.success());
    assert_eq!(first, sums(&dir), "two runs, identical bytes");
}

#[test]
fn sha256sum_accepts_the_manifest_and_a_corrupted_asset_fails_it() {
    let dir = bench("verify", RELEASE);
    assert!(run_task(&dir, false, Some("v9.9.9")).status.success());
    std::fs::copy(dir.join("out/SHA256SUMS"), dir.join("release/SHA256SUMS")).expect("copy");
    let ok = Command::new("sha256sum")
        .args(["-c", "SHA256SUMS"])
        .current_dir(dir.join("release"))
        .output()
        .expect("sha256sum");
    assert!(ok.status.success(), "no flags needed: {ok:?}");
    write(&dir, &format!("release/{}", RELEASE[0]), "tampered\n");
    let bad = Command::new("sha256sum")
        .args(["-c", "SHA256SUMS"])
        .current_dir(dir.join("release"))
        .output()
        .expect("sha256sum");
    assert!(!bad.status.success(), "one corrupt byte fails the check");
}

#[test]
fn a_release_with_no_assets_writes_no_manifest() {
    let dir = bench("empty", &[]);
    let out = run_task(&dir, false, Some("v9.9.9"));
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!dir.join("out/SHA256SUMS").exists());
}

#[test]
fn an_unreadable_release_exits_2_not_1() {
    let dir = bench("unreadable", RELEASE);
    write(&dir, "download.fails", "");
    assert_eq!(run_task(&dir, false, Some("v9.9.9")).status.code(), Some(2));
}

#[test]
fn no_tag_or_an_empty_tag_falls_back_to_the_latest_release() {
    for (name, tag) in [("absent", None), ("empty", Some(""))] {
        let dir = bench(&format!("latest-{name}"), RELEASE);
        let out = run_task(&dir, false, tag);
        assert!(out.status.success(), "{name}: {out:?}");
        assert!(sums(&dir).contains(RELEASE[0]), "{name}");
    }
}

#[test]
fn no_tag_resolvable_exits_2_rather_than_hashing_nothing() {
    let dir = bench("unresolvable", RELEASE);
    write(&dir, "gh.fails", "");
    let out = run_task(&dir, false, None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!dir.join("out/SHA256SUMS").exists());
}
