//! The committed `install.sh` is `install::render_bootstrap`'s output and
//! nothing else (CLOUD-2203).
//!
//! The script runs on a host with nothing installed yet, so it stays POSIX
//! shell — but it is generated, never hand-written. Its behaviour is pinned end
//! to end in `install_web.rs`; this file pins its BYTES. Following rust-analyzer's
//! `ensure_file_contents`, the case rewrites the file from the generator and
//! fails when any byte differed: a stale or hand-edited `install.sh` is both
//! repaired and refused in one run, and the diff to commit is the generator's.
//!
//! The suite's cases until CLOUD-2203 drove the 748-line hand-written script.
//! Every behaviour the generated bootstrap keeps is pinned where it now lives —
//! the download, digest, retry, exit-class and CA cases in `install_web.rs`, the
//! placement and version-from-ref cases in `engine_install.rs` and `engine.rs` —
//! and the ledger below names each case's file. The API route, its query flags
//! and its proxy-credential fallback have no surface left, which this file's one
//! case pins.

// CLOUD-1268's fifth arm: `install.sh` is one of the four files that stay bash,
// so every arm names it as the survivor it still accounts for.
//
// Each arm names the file that carries the case NOW (CLOUD-2203). An arm naming
// this file is a case whose surface the generated bootstrap does not have — the
// GitHub API payload, the query flags, `--help`, and the proxy and token fallback,
// which existed only because the API route sent a credential — and the one case
// here pins that: `install.sh` is the generator's bytes and nothing else.
//
// ported: tests/install.bats subject:install.sh crates/batten/tests/it/install_script.rs
// ported: "install.bats::--targets lists the targets a POSIX installer can serve" crates/batten/tests/it/release_install.rs subject:install.sh
// ported: "install.bats::--asset-name is name-vversion-target with a per-target extension" crates/batten/src/install.rs subject:install.sh
// ported: "install.bats::the query flags install nothing" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a release whose digest matches installs the binary" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::BATTEN_VERSION selects a tag rather than the latest release" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::THE DEFECT: a digest that does not match the bytes installs nothing" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::THE DEFECT: an asset the API reports no digest for is refused, not installed unverified" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a release carrying no asset for this target is exit 1, naming the asset" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a target no release leg builds is refused before any request" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::an unreadable release is exit 2 — could not look, not a broken release" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a payload with no tag_name is exit 2, never a guessed version" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::the compact payload shape parses too — neither wire form is assumed" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::--help explains the surface and exits 0" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::THE DEFECT: installing off PATH is a refusal, not a warning over exit 0" crates/batten/tests/it/engine_install.rs subject:install.sh
// ported: "install.bats::the off-PATH refusal has an opt-out, for a deliberate destination" crates/batten/tests/it/engine_install.rs subject:install.sh
// ported: "install.bats::a declared CA bundle reaches curl, for a proxy that re-terminates TLS" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::CURL_CA_BUNDLE outranks SSL_CERT_FILE when both are declared" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::no CA declaration means no cacert line — an unproxied host is untouched" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::the retry is bounded and reports rather than looping forever" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a proxy refusal is retried around the proxy with the operator's own credential" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::an ordinary failure never leaves the proxy" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a refusal from an authority the operator chose is honoured, not bypassed" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the fallback can be switched off entirely" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the ordinary token order still wins on the first attempt" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the version comes from the ref's manifest when one is named" crates/batten/tests/it/engine_install.rs subject:install.sh
// ported: "install.bats::a ref naming an unreleased version falls back to the latest release" crates/batten/src/engine.rs subject:install.sh
// ported: "install.bats::an explicitly named version never falls back" crates/batten/tests/it/engine_install.rs subject:install.sh

use crate::common;

/// THE ACTION INSTALLS THE RELEASE ITS REF PINS, NEVER THE MANIFEST'S VERSION
/// (CLOUD-2033). `action.yml` resolves the version from `batten.toml`'s
/// `engine = { release = … }` beside it; the manifest names the release the
/// NEXT cut will carry, which may not exist. The resolution lines are read out
/// of the committed `action.yml` and run against a scratch action directory
/// whose two files disagree, so the case judges the shipped text. Unix only,
/// decided by `cfg!`: the lines are POSIX shell.
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the action's own shell lines are what is under test, and `sh` is the program that runs them"
)]
fn the_action_installs_its_refs_pin() {
    if cfg!(not(unix)) {
        return;
    }
    let action = std::fs::read_to_string(common::at_root("action.yml")).expect("read action.yml");
    let lines: Vec<&str> = action.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == r#"version="$INPUT_VERSION""#)
        .expect("the action resolves its version");
    let end = start
        + lines
            .get(start..)
            .and_then(|rest| rest.iter().position(|line| line.trim() == "fi"))
            .expect("the resolution's `if` closes");
    let resolution: Vec<&str> = lines
        .get(start..=end)
        .unwrap_or_default()
        .iter()
        .map(|line| line.trim_start())
        .collect();

    let dir = common::scratch("action-version-from-pin");
    common::write(
        &dir,
        "Cargo.toml",
        "[workspace.package]\nversion = \"9.9.9\"\n",
    );
    common::write(
        &dir,
        "batten.toml",
        "version = 1\nengine = { release = \"v1.2.3\" }\n",
    );
    let script = format!(
        "set -eu\nmanifest=\"$ACTION_PATH/Cargo.toml\"\n{}\nprintf '%s' \"$version\"\n",
        resolution.join("\n")
    );
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .env("ACTION_PATH", &dir)
        .env("INPUT_VERSION", "")
        .output()
        .expect("run the action's resolution");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "1.2.3",
        "the pin, not the manifest's version: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// THE RELEASED INSTALLER IS CARGO-DIST'S, GENERATED FROM ONE CONFIG
/// (CLOUD-2297). Each release ships `batten-installer.sh` and
/// `batten-installer.ps1` from `dist build --artifacts=global`, so the config
/// must declare both installers over exactly the targets the release matrix
/// builds (a target dist does not know is one its installer cannot serve, and
/// one it knows that no leg builds is an installer pointing at nothing), the
/// release job must run that step and upload both files, and the tool CI runs
/// must be the version the config names.
#[test]
fn install_sh_is_the_released_dist_installer() {
    let config = common::dist_config();
    let dist = config["dist"].as_table().expect("a [dist] table");
    let listed = |key: &str| -> std::collections::BTreeSet<String> {
        dist[key]
            .as_array()
            .unwrap_or_else(|| panic!("[dist] {key} is a list"))
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    };
    let installers = listed("installers");
    for installer in ["shell", "powershell"] {
        assert!(
            installers.contains(installer),
            "dist generates the POSIX installer and the same installer as ps1: {installers:?}"
        );
    }

    let workflow =
        std::fs::read_to_string(common::at_root(".github/workflows/release-artifacts.yml"))
            .expect("read release-artifacts.yml");
    // The matrix is `dist.yml`'s since CLOUD-2554; the global steps stay here.
    let legs = std::fs::read_to_string(common::at_root(".github/workflows/dist.yml"))
        .expect("read dist.yml");
    assert_eq!(
        listed("targets"),
        batten::install::matrix_targets(&legs),
        "dist's targets are the release matrix's, no more and no fewer"
    );
    for needle in [
        "dist build --artifacts=global",
        "target/distrib/batten-installer.sh",
        "target/distrib/batten-installer.ps1",
        "target/distrib/sha256.sum",
    ] {
        assert!(
            workflow.contains(needle),
            "release-artifacts.yml must carry `{needle}`"
        );
    }

    let mise = std::fs::read_to_string(common::at_root("mise.toml")).expect("read mise.toml");
    let pinned = format!(
        "\"aqua:axodotdev/cargo-dist\" = \"{}\"",
        dist["cargo-dist-version"]
            .as_str()
            .expect("a cargo-dist-version")
    );
    assert!(
        mise.contains(&pinned),
        "mise.toml pins the cargo-dist dist-workspace.toml names: {pinned}"
    );
}

#[test]
fn install_sh_is_the_generated_bootstrap() {
    let path = common::at_root("install.sh");
    // FROM THE COMMITTED LOCK (CLOUD-2287): the release bakes `install.lock` and
    // regenerates this file in one commit, so the two can never disagree.
    let lock = batten::install::Lock::parse(
        &std::fs::read_to_string(common::at_root(batten::install::LOCK_FILE))
            .expect("read install.lock"),
    )
    .expect("install.lock parses");
    let generated =
        batten::install::render_bootstrap("batten", env!("CARGO_PKG_REPOSITORY"), &lock);
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    if committed != generated {
        std::fs::write(&path, &generated).expect("rewrite install.sh");
        panic!(
            "install.sh differed from install::render_bootstrap's output and has been \
             regenerated; commit the rewritten file — it is never edited by hand"
        );
    }
}
