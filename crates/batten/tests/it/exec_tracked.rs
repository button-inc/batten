//! `batten exec --tracked` over the compiled binary (CLOUD-1991): the
//! `git ls-files -z <spec> | xargs -0 -r <tool>` five task bodies carried in
//! shell, as a flag on the verb that already runs a caller's command.
//!
//! `lint_deno.rs` drives the selection and the `--except` exclusions through a
//! real task's argv; these cases pin the arms that argv never reaches.
//!
// carried: "xargs -r: an empty selection runs nothing and passes" crates/batten/src/lib.rs kind:mechanism crates/batten/tests/it/exec_tracked.rs
// carried: "git ls-files: only TRACKED paths reach the tool, never an untracked one" crates/batten/src/lib.rs kind:mechanism crates/batten/tests/it/exec_tracked.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

fn repo(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("exec-tracked-{name}"));
    common::init_repo(&dir);
    dir
}

fn exec(dir: &Path, args: &[&str]) -> Output {
    common::batten()
        .arg("exec")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run batten exec")
}

/// `false` as the child: if the verb ran it, the exit is `1`, so a `0` proves
/// the child never started.
#[test]
fn an_empty_selection_runs_nothing_and_passes() {
    let dir = repo("empty");
    let output = exec(&dir, &["--tracked", "*.no-such-extension", "--", "false"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "nothing tracked matched, so nothing ran: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The child sees the tracked path and never the untracked one — the property
/// that kept a formatter off a corrupt fixture a suite wrote under `target/`.
#[test]
fn only_tracked_paths_are_appended() {
    let dir = repo("selection");
    common::write(&dir, "kept.toml", "a = 1\n");
    common::write(&dir, "loose.toml", "a = 1\n");
    common::git_in(&dir, &["add", "kept.toml"]);
    let output = exec(&dir, &["--tee", "--tracked", "*.toml", "--", "echo"]);
    assert_eq!(output.status.code(), Some(0));
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("kept.toml"),
        "the tracked path reached the child: {said}"
    );
    assert!(
        !said.contains("loose.toml"),
        "an untracked path never does: {said}"
    );
}

#[test]
fn an_except_glob_removes_a_tracked_path() {
    let dir = repo("except");
    common::write(&dir, "keep.json", "{}\n");
    common::write(&dir, "fixtures/drop.json", "{}\n");
    common::git_in(&dir, &["add", "-A"]);
    let output = exec(
        &dir,
        &[
            "--tee",
            "--tracked",
            "*.json",
            "--except",
            "fixtures/*",
            "--",
            "echo",
        ],
    );
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("keep.json"), "{said}");
    assert!(
        !said.contains("drop.json"),
        "the excluded path is dropped: {said}"
    );
}

#[test]
fn a_magic_pathspec_is_refused_rather_than_read_as_a_literal() {
    let dir = repo("magic");
    let output = exec(&dir, &["--tracked", ":(exclude)src", "--", "true"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "a magic pathspec read as a literal selects nothing and reports clean"
    );
}

#[test]
fn except_without_tracked_is_a_usage_error() {
    let dir = repo("except-alone");
    let output = exec(&dir, &["--except", "*.json", "--", "true"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code())
    );
}
