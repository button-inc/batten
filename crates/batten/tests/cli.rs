//! End-to-end tests over the compiled `batten` binary.
//!
//! These assert the parts of the interface that consumers depend on — the
//! exit-code contract and that `--version`/`--help` resolve — so that filling in
//! the command tree cannot silently break them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn batten() -> Command {
    Command::new(env!("CARGO_BIN_EXE_batten"))
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
