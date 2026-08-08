//! End-to-end tests over the compiled binary for the command surface as data
//! (CLOUD-27).
//!
//! `surface.rs`'s own unit tests assert that the declaration and the built
//! `clap` tree agree. These assert the half a consumer actually depends on: that
//! the binary emits completions derived from that surface, byte-stably, and that
//! the scripts committed to this repository are the ones it emits.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn batten() -> Command {
    Command::new(env!("CARGO_BIN_EXE_batten"))
}

/// The shells the repository commits a completion script for.
const SHELLS: [&str; 3] = ["bash", "zsh", "fish"];

fn generate(shell: &str) -> Output {
    batten()
        .args(["generate", "completions", "--shell", shell])
        .output()
        .expect("run batten generate completions")
}

/// The committed completion script for `shell`, located from this crate's
/// manifest directory.
///
/// Deliberately not a repo-root resolver: `git::repo_root` is the one
/// implementation of that (CLOUD-34), and a test helper that rediscovered the
/// root would be a second one. This only needs a fixed relative path.
fn committed_completion(shell: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../completions/batten.{shell}"))
}

#[test]
fn completions_are_emitted_for_every_committed_shell() {
    for shell in SHELLS {
        let output = generate(shell);
        assert_eq!(output.status.code(), Some(0), "{shell} completions");
        assert!(!output.stdout.is_empty(), "{shell} completions were empty");
    }
}

#[test]
fn completions_are_byte_stable_across_runs() {
    // §6: identical input, identical bytes. Without this the drift gate would
    // fail at random and teach everyone to re-run it until it passed.
    for shell in SHELLS {
        assert_eq!(
            generate(shell).stdout,
            generate(shell).stdout,
            "{shell} completions were not byte-stable"
        );
    }
}

#[test]
fn the_committed_completions_are_the_ones_the_binary_emits() {
    // DoR §4's byte-for-byte drift assertion, over the compiled binary rather
    // than through the shell gate — so a stale committed script fails the Rust
    // suite too, and cannot land while only `hk` is skipped.
    for shell in SHELLS {
        let committed = committed_completion(shell);
        let bytes = fs::read(&committed)
            .unwrap_or_else(|err| panic!("read {}: {err}", committed.display()));
        assert_eq!(
            bytes,
            generate(shell).stdout,
            "completions/batten.{shell} differs from the surface; run `mise run completions`"
        );
    }
}

#[test]
fn generate_writes_no_file() {
    // What makes `generate`'s `read` effect structurally honest (§5) rather than
    // a promise about behaviour: the verb emits on stdout and touches nothing.
    // Asserted by running it from a scratch directory and finding that
    // directory still empty.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("generate-writes-no-file");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    let output = batten()
        .args(["generate", "completions", "--shell", "bash"])
        .current_dir(&dir)
        .output()
        .expect("run batten generate completions");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::read_dir(&dir).expect("read scratch dir").count(),
        0,
        "a read-effect verb wrote to the working directory"
    );
}

#[test]
fn an_unknown_shell_is_a_usage_error() {
    // Exit 1 is the config-or-usage code; 2 is the policy verdict and must not
    // be reachable from a malformed invocation (§7).
    let output = generate("klingon");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
}

#[test]
fn a_bare_noun_lists_its_sub_verbs_and_performs_no_action() {
    // §2: a noun never performs a default action. `clap` renders the listing on
    // its error path, so this is a usage error with an empty stdout.
    let output = batten()
        .arg("generate")
        .output()
        .expect("run batten generate");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("completions"),
        "the listing must name the sub-verb"
    );
}

#[test]
fn the_spec_carries_the_new_verbs_with_their_declared_effects() {
    // The surface is the source; `batten spec` is the derivation an agent reads.
    // A verb that exists but is absent from (or misclassified in) the spec is
    // the drift the one-declaration design exists to prevent.
    let output = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(output.status.code(), Some(0));
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");

    let generate = spec["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "generate")
        .expect("generate is in the spec");
    assert_eq!(generate["effect"], "read");

    let completions = generate["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "generate completions")
        .expect("generate completions is in the spec");
    assert_eq!(completions["effect"], "read");
    assert_eq!(completions["flags"][0]["long"], "shell");
    assert_eq!(completions["flags"][0]["takes_value"], true);
}
