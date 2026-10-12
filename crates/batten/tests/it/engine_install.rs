//! `batten engine install` (CLOUD-2203): the generated bootstrap's last step,
//! run as the compiled binary over scratch directories.
//!
//! Everything after the bootstrap's verified download lives here, in Rust, so
//! this is where the install path's behaviour is pinned: the binary lands in a
//! directory `PATH` finds, a destination off `PATH` is refused unless that is
//! declared deliberate, and a caller-named directory wins.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// Run `engine install` with `PATH` set to exactly `path` plus the ambient one
/// (so `cargo`-built binaries still resolve their own tools), `HOME` in the
/// case's scratch tree, and `env` on top.
fn install(home: &Path, path: &[PathBuf], env: &[(&str, &str)]) -> std::process::Output {
    // EXACTLY these directories: a root host's ambient PATH carries a writable
    // `/usr/local/bin`, which `engine install` would rightly choose.
    let joined = std::env::join_paths(path).expect("a PATH entry carries no separator");
    let mut command = common::batten();
    command
        .args(["engine", "install"])
        .current_dir(home)
        .env("HOME", home)
        .env_remove("XDG_BIN_HOME")
        .env_remove("BATTEN_INSTALL_DIR")
        .env_remove("BATTEN_ALLOW_OFF_PATH")
        .env_remove("BATTEN_VERSION_FROM_REF")
        .env_remove("BATTEN_REQUIRE")
        .env("PATH", joined);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run batten engine install")
}

/// The file `engine install` places: `batten.exe` on Windows.
fn binary() -> String {
    format!("batten{}", std::env::consts::EXE_SUFFIX)
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_binary_lands_in_the_per_user_directory_when_path_finds_it() {
    let home = common::scratch_repo("engine-install-user");
    let user = home.join(".local").join("bin");
    std::fs::create_dir_all(&user).unwrap();
    let output = install(&home, std::slice::from_ref(&user), &[]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("installed={}", user.join(binary()).display())),
        "{}",
        stdout(&output)
    );
    assert!(user.join(binary()).is_file());
}

#[test]
fn a_named_directory_wins() {
    let home = common::scratch_repo("engine-install-named");
    let named = home.join("named");
    let named_str = named.display().to_string();
    let output = install(
        &home,
        std::slice::from_ref(&named),
        &[("BATTEN_INSTALL_DIR", &named_str)],
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(named.join(binary()).is_file());
}

#[test]
fn a_destination_off_path_is_refused() {
    // Every hook registration names `batten` bare, so a binary the shell cannot
    // resolve is not installed: exit 1, naming the directory.
    let home = common::scratch_repo("engine-install-off-path");
    let output = install(&home, &[], &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("not on PATH"),
        "{}",
        common::stderr(&output)
    );
}

#[test]
fn an_off_path_destination_declared_deliberate_is_admitted() {
    let home = common::scratch_repo("engine-install-off-path-allowed");
    let output = install(&home, &[], &[("BATTEN_ALLOW_OFF_PATH", "1")]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(stdout(&output).contains("off-path="), "{}", stdout(&output));
    assert!(home.join(".local").join("bin").join(binary()).is_file());
}

/// The repository path the TLS fixture serves the release from.
#[cfg(target_os = "linux")]
const REPO: &str = "example/pkg";

/// The release a ref's manifest names in the fixture, never this binary's own.
#[cfg(target_os = "linux")]
const WANTED: &str = "v9.9.9";

/// The bytes the fixture release ships as its binary.
#[cfg(target_os = "linux")]
const SHIPPED: &[u8] = b"#!/bin/sh\necho the fixture release\n";

/// Serve, over loopback TLS, a ref `main` whose manifest names [`WANTED`], and
/// [`WANTED`]'s release for this build's target. Returns the host and the
/// environment `engine install` needs to reach and trust it.
#[cfg(target_os = "linux")]
fn ref_release_host(home: &Path) -> (common::TlsWww, Vec<(String, String)>) {
    use std::os::unix::fs::PermissionsExt as _;
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: `engine install` untars what it fetches, so the fixture release has to be a real gzipped tar and `tar` is what writes one"
    )]
    use std::process::Command;

    let root = home.join("www");
    let repo = root.join(REPO);
    std::fs::create_dir_all(repo.join("main")).unwrap();
    std::fs::write(
        repo.join("main").join("Cargo.toml"),
        format!("[workspace.package]\nversion = \"{}\"\n", &WANTED[1..]),
    )
    .unwrap();

    let stage = home.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let bin = stage.join(binary());
    std::fs::write(&bin, SHIPPED).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let archive = home.join("release.tar.gz");
    let packed = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&stage)
        .arg(binary())
        .status()
        .expect("run tar");
    assert!(packed.success(), "the fixture archive must build");
    let bytes = std::fs::read(&archive).unwrap();

    let asset = batten::engine::release_asset(WANTED, &batten::engine::running_target());
    let download = repo.join("releases").join("download").join(WANTED);
    std::fs::create_dir_all(&download).unwrap();
    std::fs::write(download.join(&asset), &bytes).unwrap();
    std::fs::write(
        download.join("SHA256SUMS"),
        format!("{}  {asset}\n", batten::provision::digest(&bytes)),
    )
    .unwrap();

    let tls = home.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let host = common::tls_www(&tls, &root);
    let env = vec![
        (
            "BATTEN_RELEASES".to_owned(),
            format!("https://localhost:{}/{REPO}", host.port),
        ),
        (
            "SSL_CERT_FILE".to_owned(),
            tls.join("ca.pem").display().to_string(),
        ),
    ];
    (host, env)
}

/// `BATTEN_VERSION_FROM_REF` installs the release the ref's manifest names,
/// fetched and verified, rather than the binary that is running.
#[cfg(target_os = "linux")]
#[test]
fn the_version_comes_from_the_refs_manifest() {
    let home = common::scratch_repo("engine-install-ref");
    let named = home.join("bin");
    let (_host, served) = ref_release_host(&home);
    let named_str = named.display().to_string();
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", &named_str));
    env.push(("BATTEN_VERSION_FROM_REF", "main"));

    let output = install(&home, std::slice::from_ref(&named), &env);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("version={WANTED}")),
        "{}",
        stdout(&output)
    );
    assert_eq!(
        std::fs::read(named.join(binary())).unwrap(),
        SHIPPED,
        "the installed bytes are the ref's release, not the running binary"
    );
}

/// A named `BATTEN_VERSION` always wins: the bootstrap fetched and verified that
/// release, so the ref is never read and the running binary is what lands.
#[cfg(target_os = "linux")]
#[test]
fn an_explicitly_named_version_is_never_replaced_by_the_ref() {
    let home = common::scratch_repo("engine-install-named-wins");
    let named = home.join("bin");
    let (_host, served) = ref_release_host(&home);
    let named_str = named.display().to_string();
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", &named_str));
    env.push(("BATTEN_VERSION_FROM_REF", "main"));
    env.push(("BATTEN_VERSION", &running));

    let output = install(&home, std::slice::from_ref(&named), &env);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("version={running}")),
        "{}",
        stdout(&output)
    );
    assert_ne!(
        std::fs::read(named.join(binary())).unwrap(),
        SHIPPED,
        "the ref's release must not replace the named one"
    );
}

/// A ref whose manifest names no version is a refusal, never a quiet install of
/// whatever binary is running.
#[cfg(target_os = "linux")]
#[test]
fn a_ref_naming_no_version_installs_nothing() {
    let home = common::scratch_repo("engine-install-ref-unreadable");
    let named = home.join("bin");
    let (_host, served) = ref_release_host(&home);
    let named_str = named.display().to_string();
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", &named_str));
    // `s_server -WWW` answers 200 with an error body for a path it cannot
    // open, so this ref reads as a manifest that names no version.
    env.push(("BATTEN_VERSION_FROM_REF", "absent"));

    let output = install(&home, std::slice::from_ref(&named), &env);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("names no version"),
        "{}",
        common::stderr(&output)
    );
    assert!(!named.join(binary()).exists(), "nothing was installed");
}
