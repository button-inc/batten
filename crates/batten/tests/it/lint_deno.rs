//! `[tasks."lint:deno"]` — which tracked files reach `deno fmt` (CLOUD-104),
//! over the task's own argv in a scratch repository with a `deno` stub first on
//! `PATH` that fails on any file it is handed that is not JSON.
//!
//! Since CLOUD-1991 the task is one `batten exec --tracked` argv rather than a
//! `git ls-files | xargs` body, so this tier runs THAT argv through the engine
//! under test: the selection, the exclusions and the no-match arm are the verb's
//! now, and the task's own spelling is still what decides which files reach the
//! formatter.
//!
//! The retired suite registered its probes in the SHARED `.git/index` of this
//! checkout, and the suite runs files in parallel: it raced another file's git
//! for `index.lock` and failed the bats job on #962 at `f8df73e1`
//! (CLOUD-1923). A scratch repository has no neighbour to race.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: tests/lint-deno.bats subject:mise.toml crates/batten/tests/it/lint_deno.rs
// changed: "lint:deno is green on the committed tree" mise.toml kind:mechanism — the task runs under `lint` on every verify and in CI, so the real formatter over the real tree is that run's verdict, not a copy of it here
// carried: "a corrupt file at a covered path reds it, and removing it greens again" mise.toml kind:mechanism
// carried: "a corrupt file under tests/fixtures leaves it green" mise.toml kind:mechanism
// carried: "the task pins --prose-wrap=preserve, which is a predicate and not a style" mise.toml kind:mechanism
// carried: "the hk step calls this task rather than re-deriving the file set" hk.pkl kind:mechanism
// changed: "the selection is `git ls-files -z` into `xargs -0 -r`" crates/batten/src/lib.rs `exec --tracked` selects from the same index and runs nothing on an empty selection; the `:!:` exclusions are `--except` globs, since a magic pathspec is refused rather than misread

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// A `deno` that fails on any argument naming a file that does not parse as
/// JSON — the predicate the pathspec guards, without a formatter this job may
/// not install.
const STUB: &str = r#"#!/usr/bin/env bash
for f in "$@"; do
	case "$f" in -*|fmt) continue ;; esac
	jq -e . "$f" >/dev/null 2>&1 || { echo "deno-stub: $f is not JSON" >&2; exit 1; }
done
"#;

const CORRUPT: &str = "{ this is not json,,,";
const COVERED: &str = "lint-deno-probe.json";
const EXCLUDED: &str = "crates/batten/tests/fixtures/hooks/lint-deno-probe.json";

#[expect(
    clippy::disallowed_types,
    reason = "stays: git is the task's selection, so the scratch repository is built with it"
)]
fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("git");
    assert!(status.success(), "git {args:?}");
}

struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("lint-deno-{name}"));
        std::fs::create_dir_all(dir.join("bin")).expect("bin");
        let deno = dir.join("bin/deno");
        std::fs::write(&deno, STUB).expect("stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&deno, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        common::init_repo(&dir);
        std::fs::write(dir.join("ok.json"), "{}\n").expect("clean file");
        git(&dir, &["add", "ok.json"]);
        Self { dir }
    }

    /// Write a corrupt probe at `path` and register intent to add it: the task
    /// selects from `git ls-files`, so an untracked file is invisible to it.
    fn probe(&self, path: &str) {
        let at = self.dir.join(path);
        std::fs::create_dir_all(at.parent().expect("a parent")).expect("probe dir");
        std::fs::write(at, CORRUPT).expect("probe");
        git(&self.dir, &["add", "-N", path]);
    }

    /// The task's argv, minus the `cargo run … --` that resolves the engine in
    /// this repository, run through the engine under test with the stub first on
    /// `PATH`. Tokens are single-quoted globs at most, so a whitespace split with
    /// the quotes trimmed is the argv mise hands the shell.
    fn run(&self) -> Option<i32> {
        let body = common::task_body("lint:deno");
        let argv: Vec<String> = body
            .strip_prefix("cargo run --quiet -p batten -- ")
            .expect("the task runs the tree's engine")
            .split_whitespace()
            .map(|word| word.trim_matches('\'').to_owned())
            .collect();
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.dir.join("bin")).chain(std::env::split_paths(&inherited)),
        )
        .expect("a PATH entry carries no separator");
        common::batten()
            .args(&argv)
            .current_dir(&self.dir)
            .env("PATH", path)
            .output()
            .expect("run lint:deno")
            .status
            .code()
    }
}

#[test]
fn a_corrupt_file_at_a_covered_path_reds_it_and_removing_it_greens_again() {
    let repo = Repo::new("covered");
    assert_eq!(repo.run(), Some(0), "a clean tree is green");
    repo.probe(COVERED);
    assert_ne!(repo.run(), Some(0), "a corrupt covered file reds it");
    git(&repo.dir, &["rm", "-q", "--cached", "--force", COVERED]);
    std::fs::remove_file(repo.dir.join(COVERED)).expect("remove the probe");
    assert_eq!(repo.run(), Some(0), "removing it greens again");
}

#[test]
fn a_corrupt_file_under_tests_fixtures_leaves_it_green() {
    let repo = Repo::new("excluded");
    repo.probe(EXCLUDED);
    assert_eq!(repo.run(), Some(0));
}

#[test]
fn the_task_pins_prose_wrap_preserve_which_is_a_predicate_and_not_a_style() {
    // The default (`always`, width 80) reflows AGENTS.md past
    // `[budget.instructions]`'s `max_lines`, so `policy-budget` would red on
    // line count alone.
    assert!(common::task_body("lint:deno").contains("--prose-wrap=preserve"));
}

#[test]
fn the_hk_step_calls_this_task_rather_than_re_deriving_the_file_set() {
    // A comment is not a call site: bounded to the `deno-fmt` step block, up to
    // the next step header.
    let hk = std::fs::read_to_string(common::at_root("hk.pkl")).expect("hk.pkl");
    let step: Vec<&str> = hk
        .lines()
        .skip_while(|line| !line.starts_with("  [\"deno-fmt\"]"))
        .skip(1)
        .take_while(|line| !line.starts_with("  [\""))
        .collect();
    assert!(!step.is_empty(), "the deno-fmt step was found at all");
    assert!(
        step.iter().any(|line| line.contains("mise run lint:deno")
            && !line.trim_start().starts_with("//")),
        "the step invokes the task"
    );
}
