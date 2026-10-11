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

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_binary_lands_in_the_per_user_directory_when_path_finds_it() {
    let home = common::scratch_repo("engine-install-user");
    let user = home.join(".local/bin");
    std::fs::create_dir_all(&user).unwrap();
    let output = install(&home, std::slice::from_ref(&user), &[]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("installed={}/batten", user.display())),
        "{}",
        stdout(&output)
    );
    assert!(user.join("batten").is_file());
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
    assert!(named.join("batten").is_file());
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
    assert!(home.join(".local/bin/batten").is_file());
}
