//! The engine updates itself to its pin, off the hook path only (CLOUD-2062).
//!
//! Driven through a private COPY of the compiled binary, because the update
//! replaces the running binary and stamps it — doing that to the shared test
//! binary would change what every other case runs. The source build is a stub
//! `cargo` on `PATH` that writes the "built" engine where the real one would, so
//! the case measures the update's wiring and not a compile.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

/// A repository with one tracked engine input, so a source digest exists.
fn repo(name: &str) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "batten.toml", "version = 1\n");
    common::write(&dir, "crates/x/src/lib.rs", "fn a() {}\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "batten.toml", "crates/x/src/lib.rs"]);
    dir
}

/// A private copy of the binary, so its replacement and stamp are its own.
fn private_binary(dir: &Path) -> PathBuf {
    let copy = dir.join("engine").join("batten");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_batten"), &copy).unwrap();
    copy
}

/// A `cargo` stub that records it ran and writes the "built" engine.
fn stub_cargo(dir: &Path) {
    let stub = dir.join("bin").join("cargo");
    std::fs::create_dir_all(stub.parent().unwrap()).unwrap();
    common::write(
        &dir.join("bin"),
        "cargo",
        "#!/bin/sh\n: > \"$STUB_RAN\"\nmkdir -p \"$CARGO_TARGET_DIR/release\"\nprintf 'the built engine\\n' > \"$CARGO_TARGET_DIR/release/batten\"\n",
    );
    make_executable(&stub);
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("stat the stub")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("chmod the stub");
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the update replaces the binary it runs, so each case runs a private COPY of the compiled binary, which `common::batten` cannot target"
)]
fn run(binary: &Path, dir: &Path, args: &[&str], stdin: &str) -> Output {
    use std::io::Write as _;
    let path = std::env::join_paths(
        std::iter::once(dir.join("bin")).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )),
    )
    .unwrap();
    let mut command = std::process::Command::new(binary);
    common::state_dir(&mut command, &dir.join("state"));
    let mut child = command
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env("STUB_RAN", dir.join("cargo-ran"))
        .env_remove("BATTEN_ENGINE_UPDATED")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run batten");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for batten")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn pin_source(dir: &Path, digest: &str) {
    common::write(
        dir,
        "batten.toml",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
}

#[test]
fn an_unpinned_repo_updates_nothing() {
    let dir = repo("engine-update-unpinned");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let before = std::fs::read(&binary).unwrap();
    let output = run(&binary, &dir, &["engine", "update"], "");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(std::fs::read(&binary).unwrap(), before, "nothing replaced");
    assert!(!dir.join("cargo-ran").exists(), "nothing built");
}

#[test]
fn a_source_pin_builds_installs_and_stamps() {
    let dir = repo("engine-update-source");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let digest = text(&run(&binary, &dir, &["engine", "digest"], ""))
        .trim()
        .to_owned();
    pin_source(&dir, &digest);
    let output = run(&binary, &dir, &["engine", "update"], "");
    assert!(output.status.success(), "{}", text(&output));
    assert!(dir.join("cargo-ran").exists(), "the source pin was built");
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"the built engine\n",
        "the built engine replaced the running one"
    );
    let stamp = std::fs::read_to_string(dir.join("engine").join("batten.source")).unwrap();
    assert_eq!(
        stamp.trim(),
        digest,
        "and it is stamped with the tree it came from"
    );
}

/// A binary inside the checkout is `cargo`'s output, never an installed engine:
/// the startup update leaves it alone and the pre-parse refusal names the update
/// instead (CLOUD-2063). Measured before the guard: `verify`'s own `cargo run`
/// overwrote `target/debug/batten` with the pinned release.
#[test]
fn a_build_inside_the_checkout_is_never_replaced() {
    let dir = repo("engine-update-checkout-build");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let before = std::fs::read(&binary).unwrap();
    pin_source(&dir, &"0".repeat(64));
    let output = run(&binary, &dir, &["config", "show"], "");
    assert!(
        !dir.join("cargo-ran").exists(),
        "a build of this checkout must not rebuild itself: {}",
        text(&output)
    );
    assert_eq!(std::fs::read(&binary).unwrap(), before, "nothing replaced");
    assert!(
        text(&output).contains("install:local"),
        "the stale build is refused and the update named: {}",
        text(&output)
    );
}

#[test]
fn the_hook_path_never_updates() {
    let dir = repo("engine-update-hook");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    pin_source(&dir, &"0".repeat(64));
    let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let output = run(
        &binary,
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        envelope,
    );
    assert!(
        !dir.join("cargo-ran").exists(),
        "a hook must never build inline: {}",
        text(&output)
    );
    assert!(
        text(&output).contains("install:local"),
        "the stale engine refuses and names the update: {}",
        text(&output)
    );
}
