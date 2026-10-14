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
#[cfg(target_os = "linux")]
use common::StateHome as _;

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

/// The processes whose command line carries `marker`, read from `/proc`.
#[cfg(target_os = "linux")]
fn carrying(marker: &str) -> Vec<String> {
    std::fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter(|entry| {
            std::fs::read(entry.path().join("cmdline"))
                .is_ok_and(|line| String::from_utf8_lossy(&line).contains(marker))
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

/// A CHILD IS NEVER ABANDONED BY AN ERROR (CLOUD-2238).
///
/// The live spool's directory is a regular file here, so opening the spool —
/// after the spawn, before the wait — fails. `exec` used to return that error
/// past a child it never signalled; measured, a supervisor left that way held
/// the landing lock and kept building on a full disk for 1h47m.
#[cfg(target_os = "linux")]
#[test]
fn a_teed_child_is_reaped_when_its_output_cannot_be_written() {
    let dir = repo("reap-on-error");
    let data = common::scratch("exec-reap-on-error-data");
    let captures = data
        .join(env!("CARGO_PKG_NAME"))
        .join(batten::state::derive_repo_name(&dir).expect("derive the repo state segment"))
        .join("captures");
    std::fs::create_dir_all(&captures).expect("create the capture store");
    std::fs::write(captures.join("live"), "not a directory").expect("block the spool");
    // A duration no other process carries, so `sleep`'s own argv is the marker.
    let marker = format!("3599.{}", std::process::id());
    let output = common::batten()
        .args(["exec", "--", "sleep", &marker])
        .current_dir(&dir)
        .state_dir(&data)
        .output()
        .expect("run batten exec");
    let survivors = carrying(&marker);
    for pid in &survivors {
        #[expect(
            clippy::disallowed_types,
            reason = "stays: a survivor the case found is ended so a red run leaks no process"
        )]
        let _ = std::process::Command::new("kill")
            .args(["-9", pid])
            .status();
    }
    assert_ne!(
        output.status.code(),
        Some(0),
        "the spool could not open, so exec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        survivors.is_empty(),
        "exec returned its error and left {survivors:?} running"
    );
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
