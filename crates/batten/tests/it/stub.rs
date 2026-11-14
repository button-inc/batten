//! The test-only stand-in, `examples/stub.rs` (CLOUD-2336), on its own terms.
//!
//! Every suite that used to author a `#!/bin/sh` stub now runs this program
//! under a plan, so what it does with a plan is the contract those suites rest
//! on. Each case drives the built example as a test would.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Output;

use crate::common;

/// Run the stand-in installed at `path` with `args`, feeding `stdin`.
fn run(path: &Path, args: &[&str], stdin: &str) -> Output {
    use std::io::Write as _;
    #[expect(
        clippy::disallowed_types,
        reason = "the subject is the stand-in program itself, so these cases must execute it (CLOUD-2336)"
    )]
    let mut child = std::process::Command::new(path)
        .args(args)
        .current_dir(path.parent().expect("a parent"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the stand-in runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("feed stdin");
    child.wait_with_output().expect("the stand-in exits")
}

#[test]
fn no_matching_rule_exits_127_naming_the_argv() {
    let dir = common::scratch("stub-unmatched");
    let path = dir.join("tool");
    common::stub_at(
        &path,
        &serde_json::json!([{"argv": ["known"], "steps": [{"exit": 0}]}]),
    );
    let out = run(&path, &["other", "word"], "");
    assert_eq!(out.status.code(), Some(127));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("tool other word"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The invoked NAME selects the rule, so one plan can fake two programs.
#[test]
fn a_rule_is_matched_by_the_invoked_name() {
    let dir = common::scratch("stub-named");
    let plan = serde_json::json!([
        {"name": "cargo", "steps": [{"stdout": "cargo"}, {"exit": 3}]},
        {"name": "syft", "steps": [{"stdout": "syft"}]},
    ]);
    common::stub_at(&dir.join("cargo"), &plan);
    common::stub_at(&dir.join("syft"), &plan);
    let cargo = run(&dir.join("cargo"), &[], "");
    assert_eq!(
        (
            cargo.status.code(),
            String::from_utf8_lossy(&cargo.stdout).into_owned()
        ),
        (Some(3), "cargo".to_owned())
    );
    let syft = run(&dir.join("syft"), &[], "");
    assert_eq!(
        (
            syft.status.code(),
            String::from_utf8_lossy(&syft.stdout).into_owned()
        ),
        (Some(0), "syft".to_owned())
    );
}

/// What a test asserts on is what the stand-in recorded: its argv, its stdin and
/// its own pid, each written to a file.
#[test]
fn argv_stdin_and_pid_are_each_written_to_a_file() {
    let dir = common::scratch("stub-records");
    let path = dir.join("tool");
    common::stub_at(
        &path,
        &serde_json::json!([{
            "stdin_contains": "payload",
            "steps": [
                {"write": ["argv.txt", "{argv}|{argv:2}|{argv-after:--to}|{argv-strip:--key=}"]},
                {"append": ["stdin.txt", "saw stdin"]},
                {"write": ["pid.txt", "{pid}"]},
            ],
        }]),
    );
    let out = run(&path, &["a", "b", "--to", "c", "--key=v"], "the payload");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("argv.txt")).unwrap(),
        "a b --to c --key=v|b|c|v"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("stdin.txt")).unwrap(),
        "saw stdin"
    );
    let pid: u32 = std::fs::read_to_string(dir.join("pid.txt"))
        .unwrap()
        .parse()
        .expect("a pid");
    assert!(pid > 0);

    // Stdin that does not carry the text matches no rule.
    assert_eq!(run(&path, &[], "nothing").status.code(), Some(127));
}

/// A `spawn` step does not wait: the child is still running after the
/// stand-in has exited, which is what a process-group case needs.
#[test]
fn a_spawned_child_outlives_the_stand_in() {
    if !cfg!(unix) {
        return;
    }
    let dir = common::scratch("stub-spawn");
    let path = dir.join("tool");
    common::stub_at(
        &path,
        &serde_json::json!([
            {"argv": ["start"], "steps": [{"spawn": {"argv": ["sleep", "30"], "pid": "child.pid"}}]},
            {"argv": ["probe"], "steps": [{"probe-pid": {"pid": "child.pid", "to": "state.txt"}}]},
        ]),
    );
    assert_eq!(run(&path, &["start"], "").status.code(), Some(0));
    assert_eq!(run(&path, &["probe"], "").status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(dir.join("state.txt")).unwrap(),
        "alive"
    );
    let pid = std::fs::read_to_string(dir.join("child.pid")).unwrap();
    #[expect(
        clippy::disallowed_types,
        reason = "reaps the child this case spawned through the stand-in, so the run leaves no sleeper behind (CLOUD-2336)"
    )]
    let _ = std::process::Command::new("kill").arg(pid.trim()).status();
}
