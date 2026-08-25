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
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: this module IS the end-to-end harness — `.claude/rules/rust.md` prefers a test over the compiled binary for anything a consumer depends on, and running a binary is a spawn"
)]
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
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject of an end-to-end test is the compiled binary, so there is nothing to move in-process without testing something else"
)]
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

/// Point Batten's OS data directory at `home`, on **every** platform.
///
/// A third hermeticity behaviour, in the module whose header already names the
/// other two — and it arrived the same way they did, as a per-suite copy that
/// was right about one platform (CLOUD-113's Windows job found it).
///
/// Suites redirect state by exporting `XDG_DATA_HOME`, which is the whole of the
/// answer on Linux and macOS and none of it on Windows: [`state_root`] resolves
/// through `etcetera`, whose Windows strategy reads `%APPDATA%` and has never
/// heard of the XDG variable. So on Windows a suite that "redirected" its state
/// wrote to the **real user's** roaming profile, and only the one test that
/// reads a record back off disk ever noticed — everything else passed while
/// polluting.
///
/// `<home>/data` for both, so the resolved root is the same
/// `<home>/data/batten` path a reader can then assert against without asking
/// which platform it is on. `LOCALAPPDATA` is set too: it is a different known
/// folder from `APPDATA`, and leaving it ambient would let a cache escape the
/// fixture even once the data dir is contained.
///
/// [`state_root`]: ../../src/state.rs
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it configures: scrubbing the ambient state root is a property of the child's environment, not a call this could make in-process"
)]
pub(crate) fn state_home<'a>(command: &'a mut Command, home: &Path) -> &'a mut Command {
    state_dir(command, &home.join("data")).env("HOME", home)
}

/// [`state_home`] and [`state_dir`] as chainable methods.
///
/// A trait rather than only the free functions above, because the free form does
/// not compose with the builder chains every suite already writes: `Command`'s
/// setters return `&mut Self`, so a helper taking `&mut Command` has to be
/// hoisted out into its own statement and the chain restructured around it. That
/// is a rewrite of fourteen call sites to move three lines, and a rewrite is
/// where a site quietly loses its isolation — which is the very defect
/// (CLOUD-619) this helper exists to prevent.
///
/// As a method it is a drop-in: the three `.env(…)` lines become one
/// `.state_home(…)` and nothing else about the site moves.
pub(crate) trait StateHome {
    /// Point the resolved state root at `<home>/data` on every platform, and set
    /// `HOME` to `home`.
    fn state_home(&mut self, home: &Path) -> &mut Self;
    /// Point the resolved state root at `dir` itself, setting no `HOME`.
    fn state_dir(&mut self, dir: &Path) -> &mut Self;
}

#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it extends: the trait exists so a builder chain keeps its isolation in place rather than being hoisted apart (CLOUD-619)"
)]
impl StateHome for Command {
    fn state_home(&mut self, home: &Path) -> &mut Self {
        state_home(self, home)
    }

    fn state_dir(&mut self, dir: &Path) -> &mut Self {
        state_dir(self, dir)
    }
}

/// [`state_home`] for a suite whose state root is a directory it names outright,
/// rather than `<home>/data`.
///
/// `config_epoch`'s fixtures point the data dir at the home itself, so the
/// `/data` join `state_home` performs would send them somewhere nothing writes.
/// Split rather than parameterised with a flag: both callers then say which
/// directory they mean, and neither has to know what the other assumed.
///
/// `HOME` is deliberately NOT set here — it is a fact about the user, not about
/// where state goes, and a helper that set it would be answering a question its
/// caller did not ask. [`state_home`] sets it because a home is exactly what it
/// takes.
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it configures: [`state_home`]'s sibling for a fixture that names its state root outright"
)]
pub(crate) fn state_dir<'a>(command: &'a mut Command, dir: &Path) -> &'a mut Command {
    command
        .env("XDG_DATA_HOME", dir)
        .env("APPDATA", dir)
        .env("LOCALAPPDATA", dir.join("cache"))
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
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: fixtures are built by the reference implementation on purpose, so `git.rs`'s own backend is never asserted against itself"
)]
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

/// A registry declaring `ids` as live classes, for a fixture whose module raises
/// tokens this binary does not vendor (CLOUD-1050).
///
/// Every entry is well formed by construction — a gloss, a class definition and
/// one `document` route — because `verdict::validate` runs at parse and a
/// fixture that had to hand-build a valid row would be testing the validator
/// rather than the thing it came for. The route is a `document` one pointing at
/// the committed authority: `command` would draw
/// `policy/verdict-routes-resolve.rego` into fixtures that are not about routes.
///
/// Returned by value so the caller can borrow it into a
/// [`batten::policy::Vocabulary`], which is a borrowing type on purpose.
#[must_use]
pub(crate) fn verdicts(ids: &[&str]) -> Vec<batten::verdict::DeclaredVerdict> {
    ids.iter()
        .map(|id| batten::verdict::DeclaredVerdict {
            id: (*id).to_owned(),
            gloss: format!("the fixture class {id}"),
            class: format!("What {id} means, at the length `batten policy explain` answers with."),
            routes: vec![batten::verdict::Route {
                id: "R-READ-THE-AUTHORITY".to_owned(),
                kind: batten::verdict::RouteKind::Document,
                target: "batten.toml".to_owned(),
                precondition: None,
            }],
            successor: None,
        })
        .collect()
}

/// Every verdict token the `.rego` modules under `root` name, as a registry.
///
/// **Derived from the fixtures rather than listed beside them**, because
/// registry equality runs in BOTH directions: a table naming a token the
/// modules under test do not raise is dead vocabulary and the load refuses it,
/// which is the check doing its job. A shared hand-written list therefore fails
/// every fixture except the one it was written for — measured, eleven of twelve.
///
/// Non-recursive and text-scanned rather than parsed: a fixture module is a
/// literal in a test file, the tokens are literals in it, and a Rego parser here
/// would be a second one to keep in step with the engine's.
#[must_use]
pub(crate) fn verdicts_in(root: &Path) -> Vec<batten::verdict::DeclaredVerdict> {
    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut roots = vec![root.to_path_buf()];
    while let Some(dir) = roots.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                roots.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rego") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            found.extend(tokens_in(&text));
        }
    }
    // A token this BINARY vendors is already in the registry, so declaring it
    // again is the collision `registry_for` refuses — correctly, because a class
    // with two definitions renders one refusal under words its emitter never
    // wrote. A fixture module raising a vendored class is a legitimate thing to
    // write, so the filter belongs here rather than in the fixtures.
    let vendored: std::collections::BTreeSet<String> = batten::verdict::vendored()
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    let ids: Vec<&str> = found
        .iter()
        .filter(|id| !vendored.contains(*id))
        .map(String::as_str)
        .collect();
    verdicts(&ids)
}

/// Every token a module RAISES, read off the two spellings that raise one.
///
/// **Bound to the raising position, not to the prefix.** A bare `V-…` scan also
/// picks up the tokens a module's own `test_` rules construct as fixture input —
/// `policy/verdict-routes-resolve.rego` carries `V-X` in six of them — and
/// declaring one of those is dead vocabulary the load then refuses. Reading the
/// two positions that actually raise a class is what makes this a projection of
/// what the module emits rather than of what it mentions.
fn tokens_in(text: &str) -> Vec<String> {
    const RAISES: &[&str] = &["\"verdict\": \"", "deny contains \""];
    let mut found = Vec::new();
    for line in text.lines() {
        for opener in RAISES {
            let Some(rest) = line.split_once(opener).map(|(_, rest)| rest) else {
                continue;
            };
            let Some((token, _)) = rest.split_once('"') else {
                continue;
            };
            if token.starts_with("V-") && token.len() > 2 {
                found.push(token.to_owned());
            }
        }
    }
    found
}
