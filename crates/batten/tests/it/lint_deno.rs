//! `[tasks."lint:deno"]` — which tracked files reach `deno fmt` (CLOUD-104),
//! over the task's own argv in a scratch repository with a `deno` stand-in first
//! on `PATH` that records every file it is handed.
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

/// A `deno` that records every argv it is handed, one line per call, to
/// `bin/deno.log` — the file set the pathspec guards, without a formatter this
/// job may not install. A corrupt file the formatter is handed reds the task;
/// so the case asserts which files REACH it, from the record.
fn stub_plan(log: &Path) -> serde_json::Value {
    serde_json::json!([{"steps": [{"append": [log.display().to_string(), "{argv}\n"]}]}])
}

const CORRUPT: &str = "{ this is not json,,,";
const COVERED: &str = "lint-deno-probe.json";
const EXCLUDED: &str = "crates/batten/tests/fixtures/hooks/lint-deno-probe.json";

/// Through [`common::git_in`], so a contributor's global git config, a global
/// hook among it, never reaches the scratch repository.
fn git(dir: &Path, args: &[&str]) {
    common::git_in(dir, args);
}

struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("lint-deno-{name}"));
        common::stub_at(&dir.join("bin/deno"), &stub_plan(&dir.join("bin/deno.log")));
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
    ///
    /// Its exit code, and whether the formatter was handed `path`.
    fn run(&self, path: &str) -> (Option<i32>, bool) {
        let log = self.dir.join("bin/deno.log");
        let _ = std::fs::remove_file(&log);
        let body = common::task_body("lint:deno");
        let argv: Vec<String> = body
            .strip_prefix("cargo run --quiet -p batten -- ")
            .expect("the task runs the tree's engine")
            .split_whitespace()
            .map(|word| word.trim_matches('\'').to_owned())
            .collect();
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let search = std::env::join_paths(
            std::iter::once(self.dir.join("bin")).chain(std::env::split_paths(&inherited)),
        )
        .expect("a PATH entry carries no separator");
        let code = common::batten()
            .args(&argv)
            .current_dir(&self.dir)
            .env("PATH", search)
            .output()
            .expect("run lint:deno")
            .status
            .code();
        let handed = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .split_whitespace()
            .any(|word| word == path);
        (code, handed)
    }
}

#[test]
fn a_corrupt_file_at_a_covered_path_reds_it_and_removing_it_greens_again() {
    let repo = Repo::new("covered");
    assert_eq!(
        repo.run("ok.json"),
        (Some(0), true),
        "a clean tree is formatted"
    );
    repo.probe(COVERED);
    assert_eq!(
        repo.run(COVERED),
        (Some(0), true),
        "a corrupt covered file reaches the formatter, which reds it"
    );
    git(&repo.dir, &["rm", "-q", "--cached", "--force", COVERED]);
    std::fs::remove_file(repo.dir.join(COVERED)).expect("remove the probe");
    assert_eq!(
        repo.run(COVERED),
        (Some(0), false),
        "removing it greens again"
    );
}

#[test]
fn a_corrupt_file_under_tests_fixtures_leaves_it_green() {
    let repo = Repo::new("excluded");
    repo.probe(EXCLUDED);
    assert_eq!(
        repo.run(EXCLUDED),
        (Some(0), false),
        "the formatter is never handed it"
    );
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
