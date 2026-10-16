//! The engine pin, read before the parse (CLOUD-2061).
//!
//! Driven through the compiled binary over scratch configs. The source-pin cases
//! run a COPY of the binary in their own scratch directory, so the stamp each
//! writes sits beside that copy alone — a stamp beside the shared test binary
//! would be read by every case running in parallel.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

const RELEASE: &str = concat!("v", env!("CARGO_PKG_VERSION"));

fn repo(name: &str, config: &str) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "batten.toml", config);
    common::init_repo(&dir);
    // An INDEX, which a fresh `git init` lacks and `engine digest` reads.
    common::git_in(&dir, &["add", "batten.toml"]);
    dir
}

fn run(binary: &Path, dir: &Path, args: &[&str]) -> Output {
    run_engine(binary, dir, args, false)
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the source-pin cases run a private COPY of the compiled binary so its stamp is its own, which `common::batten` cannot target because it names the shared binary"
)]
fn run_engine(binary: &Path, dir: &Path, args: &[&str], local: bool) -> Output {
    let mut command = std::process::Command::new(binary);
    command
        .args(args)
        .current_dir(dir)
        // These cases measure the pre-parse refusal, which is what a stale engine
        // answers once its one update has run; without this the startup update
        // (CLOUD-2062) would download or build before the refusal is reached.
        .env("BATTEN_ENGINE_UPDATED", "1")
        // ENFORCEMENT IS THE SUBJECT, so the suite's `BATTEN_ENGINE=local`
        // (CLOUD-2232) is not inherited; a case that wants it asks for it.
        .env_remove(batten::engine::LOCAL_ENV);
    if local {
        command.env(batten::engine::LOCAL_ENV, "local");
    }
    // A just-copied binary can be briefly unexecutable (ETXTBSY) while a sibling
    // case's fork holds its write handle; see `common::spawn_copy`.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    common::spawn_copy(&mut command)
        .wait_with_output()
        .expect("run batten")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A private copy of the binary, so its stamp is its own.
fn private_binary(dir: &Path) -> PathBuf {
    let copy = dir.join("bin").join("batten");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_batten"), &copy).unwrap();
    copy
}

fn shared() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_batten"))
}

/// The release a verified install placed loads under its own pin: the stamp is
/// the identity (CLOUD-2398).
#[test]
fn a_release_pin_naming_this_build_loads() {
    let dir = repo(
        "engine-pin-release-same",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let installed = common::scratch("engine-pin-release-same-installed");
    let binary = private_binary(&installed);
    batten::engine::stamp_release(&binary, RELEASE).unwrap();
    let output = run(&binary, &dir, &["config", "show"]);
    assert!(output.status.success(), "{}", text(&output));
}

/// A BUILD REPORTING THE PIN'S VERSION IS NOT THE RELEASE (CLOUD-2398),
/// `#MUTANT release-pin-by-version`. Installed outside the checkout with no
/// release stamp, the same binary that loads above is refused, by name.
#[test]
fn an_installed_build_reporting_the_pins_version_is_not_the_release() {
    let dir = repo(
        "engine-pin-release-unstamped",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let installed = common::scratch("engine-pin-release-unstamped-installed");
    let binary = private_binary(&installed);
    let output = run(&binary, &dir, &["config", "show"]);
    let said = text(&output);
    assert!(
        !output.status.success(),
        "a build is not the release: {said}"
    );
    assert!(
        said.contains("not that release") && said.contains("`batten engine install`"),
        "the refusal says why and names the install: {said}"
    );
}

/// A BINARY REPLACED BESIDE A RELEASE STAMP IS NOT THE RELEASE (CLOUD-2398),
/// `#MUTANT release-stamp-unbound`: the stamp carries the length it was
/// written for, so a copy that changed under it no longer reads as stamped.
#[test]
fn a_binary_replaced_beside_a_release_stamp_is_not_the_release() {
    let dir = repo(
        "engine-pin-release-replaced",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let installed = common::scratch("engine-pin-release-replaced-installed");
    let binary = private_binary(&installed);
    batten::engine::stamp_release(&binary, RELEASE).unwrap();
    // Trailing bytes leave an executable runnable and change its length.
    let mut bytes = std::fs::read(&binary).unwrap();
    bytes.extend_from_slice(b"\0replaced");
    std::fs::write(&binary, bytes).unwrap();
    let output = run(&binary, &dir, &["config", "show"]);
    assert!(
        !output.status.success(),
        "a replaced binary is not the release its stamp named: {}",
        text(&output)
    );
}

#[test]
fn a_release_pin_naming_another_build_is_refused_with_its_install() {
    let dir = repo(
        "engine-pin-release-other",
        "version = 1\nengine = { release = \"v0.0.1\" }\n",
    );
    let output = run(&shared(), &dir, &["config", "show"]);
    let said = text(&output);
    assert!(
        !output.status.success(),
        "a stale engine must not load: {said}"
    );
    // THE ENGINE'S OWN VERB, never a consumer installer (CLOUD-2116): it is the one
    // command the hook's floor admits over this same skew, so it is the only
    // remedy a refused session can actually run.
    assert!(
        said.contains("v0.0.1") && said.contains("`batten engine install`"),
        "the refusal names the pin and the install: {said}"
    );
    assert!(
        !said.contains("install.sh"),
        "an installer the floor refuses is not a remedy: {said}"
    );
}

#[test]
fn a_source_pin_matching_the_stamp_loads() {
    let dir = repo("engine-pin-source-same", "version = 1\n");
    // An engine input, so the digest names a source rather than nothing
    // (CLOUD-2230).
    common::write(&dir, "crates/engine/src/lib.rs", "// the engine\n");
    common::git_in(&dir, &["add", "crates"]);
    let binary = private_binary(&dir);
    let stamped = run(&binary, &dir, &["engine", "stamp"]);
    assert!(stamped.status.success(), "{}", text(&stamped));
    let digest = text(&run(&binary, &dir, &["engine", "digest"]))
        .trim()
        .to_owned();
    assert_eq!(digest.len(), 64, "a digest is 64 hex: {digest}");
    common::write(
        &dir,
        "batten.toml",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
    let output = run(&binary, &dir, &["config", "show"]);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_stamp_over_no_inputs_is_refused() {
    // CLOUD-2230. A tree tracking no engine input hashes to SHA-256's empty
    // value, which names no source; measured on #1132 a debug binary carried
    // that stamp and every `cargo run -p batten` task refused under a source pin.
    let dir = repo("engine-pin-stamp-empty", "version = 1\n");
    let binary = private_binary(&dir);
    let stamped = run(&binary, &dir, &["engine", "stamp"]);
    assert!(!stamped.status.success(), "{}", text(&stamped));
    assert!(
        text(&stamped).contains("no engine input"),
        "{}",
        text(&stamped)
    );
    assert!(
        !batten::engine::stamp_path(&binary).exists(),
        "nothing is written over no inputs"
    );
}

/// `BATTEN_ENGINE=local` RUNS THIS BINARY AS IT IS (CLOUD-2232), Go's
/// `GOTOOLCHAIN=local`: the same unstamped installed engine the case below
/// refuses loads under it. A release pin it does not name is still refused,
/// so the variable is no general bypass.
#[test]
fn the_local_engine_runs_under_a_source_pin() {
    let dir = repo(
        "engine-pin-source-local",
        &format!(
            "version = 1\nengine = {{ source = \"{}\" }}\n",
            "0".repeat(64)
        ),
    );
    let installed = common::scratch("engine-pin-source-local-installed");
    let binary = private_binary(&installed);
    let output = run_engine(&binary, &dir, &["config", "show"], true);
    assert!(output.status.success(), "{}", text(&output));

    common::write(
        &dir,
        "batten.toml",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    let output = run_engine(&binary, &dir, &["config", "show"], true);
    assert!(
        !output.status.success(),
        "a release pin is enforced under `local` too: {}",
        text(&output)
    );
}

/// UNDER `local`, A RELEASE PIN HOLDS THIS BUILD TO ITS VERSION (CLOUD-2398),
/// `#MUTANT local-release-by-version-ignored`: the suite's own build carries no
/// release stamp, so without this every fixture pinning the suite's version
/// would follow the pin to the published release instead of testing the build.
/// `an_installed_build_reporting_the_pins_version_is_not_the_release` is the
/// same binary refused without the variable.
#[test]
fn the_local_engine_holds_a_release_pin_to_its_version() {
    let dir = repo(
        "engine-pin-release-local",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let installed = common::scratch("engine-pin-release-local-installed");
    let binary = private_binary(&installed);
    let output = run_engine(&binary, &dir, &["config", "show"], true);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_source_pin_without_a_stamp_is_refused() {
    let digest = "0".repeat(64);
    let dir = repo(
        "engine-pin-source-unstamped",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
    // AN INSTALLED ENGINE, OUTSIDE THE CHECKOUT: one built inside it is that
    // tree's own build and satisfies its source pin (CLOUD-2232).
    let installed = common::scratch("engine-pin-source-unstamped-installed");
    let binary = private_binary(&installed);
    let output = run(&binary, &dir, &["config", "show"]);
    let said = text(&output);
    assert!(
        !output.status.success(),
        "an unstamped engine must not load: {said}"
    );
    assert!(
        said.contains("`batten engine install`"),
        "the refusal names the build: {said}"
    );
}

#[test]
fn a_config_without_a_pin_loads() {
    let dir = repo("engine-pin-none", "version = 1\n");
    let output = run(&shared(), &dir, &["config", "show"]);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_pin_naming_both_or_neither_is_refused() {
    for (name, pin) in [
        (
            "engine-pin-both",
            "{ release = \"v0.0.1\", source = \"00\" }",
        ),
        ("engine-pin-neither", "{}"),
    ] {
        let dir = repo(name, &format!("version = 1\nengine = {pin}\n"));
        let output = run(&shared(), &dir, &["config", "show"]);
        assert!(!output.status.success(), "{pin}: {}", text(&output));
    }
}

#[test]
fn the_digest_moves_when_a_tracked_engine_file_changes_and_not_for_an_untracked_one() {
    let dir = repo("engine-pin-digest", "version = 1\n");
    common::write(&dir, "crates/x/src/lib.rs", "fn a() {}\n");
    common::git_in(&dir, &["add", "crates/x/src/lib.rs"]);
    let digest = |dir: &Path| text(&run(&shared(), dir, &["engine", "digest"]));
    let before = digest(&dir);
    common::write(&dir, "crates/x/src/scratch.rs", "untracked\n");
    assert_eq!(
        digest(&dir),
        before,
        "an untracked file is not an engine input"
    );
    common::write(&dir, "crates/x/src/lib.rs", "fn b() {}\n");
    assert_ne!(digest(&dir), before, "a tracked engine input changed");
}

#[test]
fn a_local_override_cannot_set_the_pin() {
    let dir = repo("engine-pin-local", "version = 1\n");
    common::write(
        &dir,
        "batten.local.toml",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let output = run(&shared(), &dir, &["config", "show"]);
    let said = text(&output);
    assert!(!output.status.success(), "{said}");
    assert!(
        said.contains("`engine`"),
        "the refusal names the key: {said}"
    );
}
