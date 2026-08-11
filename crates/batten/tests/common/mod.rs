//! The one fixture materializer for every integration target (CLOUD-63).
//!
//! Before this module each `tests/*.rs` file re-typed its own command builder
//! and its own scratch-repo builder, and the copies had already diverged on the
//! two behaviours that decide whether a suite is hermetic:
//!
//! * **Clearing the scratch directory before writing it.** Most copies did;
//!   `cli.rs`'s did not. `312b320 test(fail-on-warning): start each fixture from
//!   an empty directory` is that drift being repaired one file at a time, its
//!   message recording a suite turned red by a stray source file an earlier run
//!   left behind. Here it is unconditional: [`scratch`] wipes first, always.
//! * **Scrubbing the ambient environment.** The copied `fn batten()` scrubbed
//!   nothing at all, so an exported `BATTEN_FAIL_ON_WARNING` in a developer's
//!   shell could move a verdict. [`batten`] removes **every** `BATTEN_`
//!   variable the surface declares — derived by walking [`ROOT`] and [`SURFACE`]
//!   rather than copied into a list here, so a flag that mints a new variable is
//!   scrubbed the day it lands and cannot be forgotten.
//!
//! Cargo compiles a `tests/` subdirectory as a test target only when it holds a
//! `main.rs`, so this module is included by `mod common;` and is not itself a
//! target.
//!
//! **`GIT_CEILING_DIRECTORIES` fences the fixture's own `git` invocations**
//! ([`git_in`]), not the `batten` child: `git::repo_root` scrubs that variable
//! from the process it spawns on purpose, so discovery depends on the path and
//! the filesystem and never on ambient state. That is exactly why a fixture
//! whose subject is "this directory is *not* a repository" must be materialized
//! **outside** this repository's tree — [`scratch_outside_tree`] — since a
//! scratch dir under `target/` would discover the real checkout and the case
//! would pass by accident.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Each integration target uses the part of this module it needs; the unused
// remainder is not dead code, it is another target's.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use batten::surface::{ROOT, SURFACE};

/// The scratch root inside this crate's `target/`, where fixtures that *are*
/// repositories live.
#[must_use]
pub(crate) fn target_tmp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// A committed file at the repository root, located from this crate's manifest
/// directory.
///
/// Deliberately not a repo-root resolver: `git::repo_root` is the one
/// implementation of that (CLOUD-34), and a test helper that rediscovered the
/// root would be a second one.
#[must_use]
pub(crate) fn at_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name)
}

/// Every `BATTEN_` variable the command surface declares, derived from the
/// surface itself so the set cannot drift behind a new flag.
fn declared_env_vars() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = std::iter::once(&ROOT)
        .chain(SURFACE.iter())
        .flat_map(|command| command.flags.iter())
        .filter_map(|flag| flag.env.name())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The compiled binary, with the ambient environment scrubbed.
///
/// Unconditional by design: a helper that scrubbed only where a suite
/// remembered to ask is a helper that is wrong exactly where it matters.
#[must_use]
pub(crate) fn batten() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_batten"));
    for name in declared_env_vars() {
        command.env_remove(name);
    }
    command
}

/// Run `batten` with `args` in `dir`.
#[must_use]
pub(crate) fn run(dir: &Path, args: &[&str]) -> Output {
    batten()
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run batten")
}

/// Run `batten` with `args` in `dir`, feeding `input` on stdin.
///
/// Here rather than per-suite for this module's founding reason: `defects add`
/// and `design audit` both read a JSONL stream on stdin, and two copies of a
/// spawn-and-pipe helper are two places the environment scrubbing can drift out
/// of agreement with [`batten`].
#[must_use]
pub(crate) fn run_with_stdin(dir: &Path, args: &[&str], input: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = batten()
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for batten")
}

/// `output.stdout` as a `String`.
#[must_use]
pub(crate) fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

/// `output.stderr` as a `String`.
#[must_use]
pub(crate) fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

/// An empty scratch directory under `target/`, wiped first.
///
/// Wiping is unconditional: a fixture that inherits a previous run's files is a
/// fixture whose assertions are about a tree nobody wrote.
#[must_use]
pub(crate) fn scratch(name: &str) -> PathBuf {
    make_empty(target_tmp().join(name))
}

/// An empty scratch directory **outside** this repository's tree, wiped first.
///
/// For the one fixture shape that cannot live under `target/`: a directory that
/// must not be inside any git repository (see the module doc).
#[must_use]
pub(crate) fn scratch_outside_tree(group: &str, name: &str) -> PathBuf {
    make_empty(std::env::temp_dir().join(group).join(name))
}

fn make_empty(dir: PathBuf) -> PathBuf {
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Write `contents` to `dir/path`, creating parent directories.
pub(crate) fn write(dir: &Path, path: &str, contents: &str) {
    let full = dir.join(path);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(full, contents).expect("write fixture file");
}

/// Run `git` in `dir`, asserting success.
///
/// Global and system config are blanked so a developer's `commit.gpgsign` or
/// `core.hooksPath` cannot break a fixture, and identity comes through `-c` so
/// the fixture's own `.git/config` stays as bare as a fresh clone's.
pub(crate) fn git_in(dir: &Path, args: &[&str]) -> String {
    let output = git_command(dir, args).output().expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git stdout is UTF-8")
        .trim_end()
        .to_owned()
}

/// The fenced, identity-pinned `git` invocation [`git_in`] runs.
#[must_use]
pub(crate) fn git_command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "advice.detachedHead=false",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"));
    for var in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    ] {
        command.env_remove(var);
    }
    command
}

/// A scratch repository: a wiped directory, optionally a git repository,
/// carrying a `batten.toml` and any extra files.
///
/// One builder rather than the seven divergent `repo`/`repo_with_config`/
/// `pr_fixture` signatures it replaces: the differences between those were all
/// in *what is written*, never in *how*, so they become calls rather than
/// copies.
pub(crate) struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    /// A fixture at `target/tmp/<name>`, wiped first.
    #[must_use]
    pub(crate) fn new(name: &str) -> Self {
        Fixture { dir: scratch(name) }
    }

    /// A fixture at an explicit directory, wiped first.
    #[must_use]
    pub(crate) fn at(dir: PathBuf) -> Self {
        Fixture {
            dir: make_empty(dir),
        }
    }

    /// Write `batten.toml`.
    #[must_use]
    pub(crate) fn config(self, contents: &str) -> Self {
        write(&self.dir, "batten.toml", contents);
        self
    }

    /// Write one extra file.
    #[must_use]
    pub(crate) fn file(self, path: &str, contents: &str) -> Self {
        write(&self.dir, path, contents);
        self
    }

    /// Write several extra files.
    #[must_use]
    pub(crate) fn files(mut self, files: &[(&str, &str)]) -> Self {
        for (path, contents) in files {
            self = self.file(path, contents);
        }
        self
    }

    /// `git init` the fixture.
    #[must_use]
    pub(crate) fn git(self) -> Self {
        git_in(&self.dir, &["init", "-q"]);
        git_in(&self.dir, &["branch", "-M", "main"]);
        self
    }

    /// Commit everything present and pin `origin/main` to it — the trusted base
    /// ref a pull request is judged against.
    #[must_use]
    pub(crate) fn base_commit(self) -> Self {
        git_in(&self.dir, &["add", "-A"]);
        git_in(&self.dir, &["commit", "-q", "-m", "base policy"]);
        git_in(&self.dir, &["branch", "-M", "main"]);
        git_in(
            &self.dir,
            &["update-ref", "refs/remotes/origin/main", "HEAD"],
        );
        self
    }

    /// Commit everything present as the work under review.
    ///
    /// `--allow-empty`: a branch that changes nothing is a case the delta must
    /// still report, and it has nothing to commit.
    #[must_use]
    pub(crate) fn work_commit(self) -> Self {
        git_in(&self.dir, &["add", "-A"]);
        git_in(
            &self.dir,
            &["commit", "-q", "--allow-empty", "-m", "the pull request"],
        );
        self
    }

    /// The materialized directory.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }

    /// The materialized directory, by value.
    #[must_use]
    pub(crate) fn build(self) -> PathBuf {
        self.dir
    }
}
