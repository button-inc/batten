//! End-to-end tests over the compiled `batten` binary.
//!
//! These assert the parts of the interface that consumers depend on — the
//! exit-code contract and that `--version`/`--help` resolve — so that filling in
//! the command tree cannot silently break them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn batten() -> Command {
    Command::new(env!("CARGO_BIN_EXE_batten"))
}

/// Create a fresh temp directory under the test target dir containing a
/// `batten.toml` with `contents`, and return its path so a command can run there.
fn repo_with_config(name: &str, contents: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::create_dir_all(&dir).expect("create temp repo dir");
    fs::write(dir.join("batten.toml"), contents).expect("write batten.toml");
    dir
}

#[test]
fn no_args_exits_success() {
    let status = batten().status().expect("run batten");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn version_flag_succeeds() {
    let output = batten()
        .arg("--version")
        .output()
        .expect("run batten --version");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("batten"));
}

#[test]
fn unknown_flag_is_a_usage_error() {
    // clap reports argument errors with exit code 2, matching ExitCode::Usage.
    let status = batten().arg("--nope").status().expect("run batten --nope");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn spec_emits_parseable_json_on_stdout() {
    let output = batten().arg("spec").output().expect("run batten spec");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("spec stdout is valid JSON");
    assert_eq!(value["path"], "batten");
    // The surface is data: `spec` describes itself, with its effect merged in.
    let subs = value["subcommands"].as_array().expect("subcommands array");
    let spec_node = subs
        .iter()
        .find(|node| node["path"] == "spec")
        .expect("spec appears in its own surface");
    assert_eq!(spec_node["effect"], "read");
}

#[test]
fn spec_json_is_byte_stable_across_runs() {
    // §6: identical input yields identical bytes — no timestamps or ordering drift.
    let first = batten().arg("spec").output().expect("run batten spec");
    let second = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn spec_default_format_matches_explicit_json() {
    let bare = batten().arg("spec").output().expect("run batten spec");
    let explicit = batten()
        .args(["spec", "--format", "json"])
        .output()
        .expect("run batten spec --format json");
    assert_eq!(bare.stdout, explicit.stdout);
}

#[test]
fn config_show_prints_the_effective_config() {
    let dir = repo_with_config(
        "config-show-ok",
        "version = 1\nmin_batten_version = \"0.0.0\"\n",
    );
    let output = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show stdout is JSON");
    assert_eq!(value["version"], 1);
    assert_eq!(value["min_batten_version"], "0.0.0");
}

#[test]
fn config_show_rejects_unsupported_version_with_usage_code() {
    let dir = repo_with_config("config-bad-version", "version = 2\n");
    let status = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .status()
        .expect("run batten config show");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn config_show_rejects_unknown_key_with_usage_code() {
    let dir = repo_with_config("config-unknown-key", "version = 1\nbogus = true\n");
    let status = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .status()
        .expect("run batten config show");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn config_show_without_a_config_file_is_a_usage_error() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("config-missing");
    fs::create_dir_all(&dir).expect("create empty temp dir");
    let status = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .status()
        .expect("run batten config show");
    assert_eq!(status.code(), Some(2));
}
