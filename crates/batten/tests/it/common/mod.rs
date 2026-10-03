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
    reason = "stays, and test-only: this module IS the end-to-end harness — `rules/rust.md` prefers a test over the compiled binary for anything a consumer depends on, and running a binary is a spawn"
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
/// This repository's own `[[pattern]]` rows, as TOML a fixture can append to its
/// config.
///
/// **Read from the committed table, never re-typed** (CLOUD-1100). The Ready
/// grammar is the consumer's vocabulary and lives in `batten.toml`; a fixture
/// that spelled those expressions again would be the second implementation the
/// registry exists to remove, and it would drift the moment a token was tuned.
///
/// A fixture without them is not broken — it is a consumer that has not declared
/// a grammar, and `batten ready lint` tells it so by id. That is the behaviour,
/// so a fixture opts IN by calling this rather than getting the rows by default.
pub(crate) fn declared_patterns() -> String {
    // Memoized for the reason `bypass_env_vars` is (CLOUD-1291): one committed
    // file that cannot change during a run. This one only re-READS rather than
    // re-parsing, so its own share is the smaller one — it is here because
    // leaving one of the three unmemoized is how the next reader concludes the
    // pattern was deliberate somewhere and accidental here.
    static ROWS: std::sync::LazyLock<String> = std::sync::LazyLock::new(scan_declared_patterns);
    ROWS.clone()
}

/// The committed `[board]` table, for a fixture that must be judged against a
/// declared board (CLOUD-1623).
///
/// [`declared_patterns`]'s sibling and for its reason: the columns are the
/// consumer's, so a fixture re-spelling them here would be a second authority on
/// this repository's own vocabulary — and one that drifts the first time the
/// board is renamed. Reading the committed table keeps the fixture in step by
/// construction.
pub(crate) fn declared_board() -> String {
    static TABLE: std::sync::LazyLock<String> = std::sync::LazyLock::new(scan_declared_board);
    TABLE.clone()
}

fn scan_declared_board() -> String {
    let text = std::fs::read_to_string(at_root("batten.toml")).expect("the committed config");
    let mut rows = String::new();
    let mut inside = false;
    for line in text.lines() {
        // The close is tested before the open for `scan_declared_patterns`'
        // reason: a table closes at the NEXT header of any kind.
        if inside && line.starts_with('[') {
            inside = false;
        }
        if line.starts_with("[board]") {
            inside = true;
            rows.push('\n');
        }
        if inside {
            rows.push_str(line);
            rows.push('\n');
        }
    }
    assert!(
        rows.contains("ready"),
        "the committed config declares no board, so every fixture built on it \
         would assert about a missing column rather than about a claim"
    );
    rows
}

fn scan_declared_patterns() -> String {
    let text = std::fs::read_to_string(at_root("batten.toml")).expect("the committed config");
    let mut rows = String::new();
    let mut inside = false;
    for line in text.lines() {
        // A row opens at its own header and closes at the NEXT table header of any
        // kind — including the next `[[pattern]]`, which is why the close is
        // tested before the open. Testing the open first drops every row but the
        // last, silently, which is what the first version of this did.
        if inside && line.starts_with('[') {
            inside = false;
        }
        if line.starts_with("[[pattern]]") {
            inside = true;
            rows.push('\n');
        }
        if inside {
            rows.push_str(line);
            rows.push('\n');
        }
    }
    assert!(
        rows.contains("ready-opener"),
        "the committed config declares no Ready grammar, so every fixture built \
         on it would assert about a missing row rather than about a Ready block"
    );
    rows
}

/// The pointers a refusal of `class` printed, between the class and the `rule`
/// that refused, exactly as a reader would copy them — trimmed, NOT rejoined
/// (CLOUD-1826).
///
/// `said` is a run's stdout followed by its stderr. The one place a binary case
/// reads the refusal line's grammar, so a change to that grammar re-points this.
///
/// # Panics
///
/// When no line carries the class, naming what was said.
pub(crate) fn printed_pointers(said: &str, class: &str, rule: &str) -> String {
    // CLOUD-2075's grammar: `verdict '<class>' rule '<rule>' at <subjects>; …`.
    let opener = format!("verdict '{class}' rule '{rule}' at ");
    said.lines()
        .find_map(|line| {
            let rest = line.split(opener.as_str()).nth(1)?;
            let pointers = rest.split("; ").next()?.split(" —").next()?;
            Some(pointers.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("no line refuses as `{class}`: {said}"))
}

/// The rule that refused, read off the labelled finding line through the
/// engine's own reader (CLOUD-2075) — never guessed from word positions.
pub(crate) fn refusing_rule(said: &str) -> Option<String> {
    said.lines()
        .find_map(batten::refusal::parse_finding)
        .map(|parsed| parsed.rule)
}

pub(crate) fn at_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name)
}

/// One task's table out of this repository's `mise.toml`, header included.
///
/// **THE ENGINE'S DEFINITION, NOT A COPY OF IT** (CLOUD-1909). Where a task's table
/// begins and ends is decided once, by `batten::mutate::task_block`, because the
/// sweep reads a `task-` gate's declarations through exactly that boundary. A suite
/// pinning a task's body through a second definition could disagree with the sweep
/// about which lines are the task — and four suites had grown private copies,
/// one of which ended a block at the first column-zero `[`, which is also how a
/// shell test line begins.
///
/// Read through [`at_root`], so under `mutate sweep` it is the STAGED manifest and
/// a mutation of the body is what the suite sees.
pub(crate) fn task_block(name: &str) -> Option<String> {
    let manifest =
        std::fs::read_to_string(at_root("mise.toml")).expect("the task manifest is readable");
    let lines: Vec<String> = manifest.lines().map(str::to_owned).collect();
    batten::mutate::task_block(&lines, name).map(|block| block.join("\n"))
}

/// One declared key's value out of a task block: a string as its contents, any
/// other value in its TOML spelling, and an absent key as empty.
///
/// PARSED, because a block is a standalone TOML table — it ends at the next table
/// header — and the manifest spells `run` as a basic string, a `"""` block and a
/// `'''` literal in different tasks. A text split handles whichever quoting its
/// author had in front of them and silently returns the delimiters for the rest.
pub(crate) fn task_value(block: &str, key: &str) -> String {
    let parsed: toml::Value = toml::from_str(block).expect("a task block is a TOML table");
    let value = parsed
        .get("tasks")
        .and_then(toml::Value::as_table)
        .and_then(|tasks| tasks.values().next())
        .and_then(|task| task.get(key));
    match value {
        None => String::new(),
        Some(toml::Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// `[tasks.<name>]`'s COMMANDS from the committed `mise.toml`, whichever way the
/// task spells its `run`.
///
/// A task body is a shell string or a `run = [...]` argv list, and the campaign
/// that retires the shell (CLOUD-843) moves tasks from the first to the second
/// one at a time — so a tier that pins a property of a task's invocation reads
/// what the task RUNS, never how it happened to be quoted. A string yields its
/// non-blank, non-comment lines; a list yields each entry, with a
/// `{ task = "x" }` entry read as the `mise run x` it means. Comments are
/// dropped because these bodies discuss the flags they carry at length, and a
/// pin that passes on its own documentation is not a pin.
///
/// An absent task or an absent `run` is the empty list, which every caller
/// asserts against rather than reading as a pass.
#[must_use]
pub(crate) fn task_commands(name: &str) -> Vec<String> {
    let manifest = fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    let Some(run) = parsed
        .get("tasks")
        .and_then(|tasks| tasks.get(name))
        .and_then(|task| task.get("run"))
    else {
        return Vec::new();
    };
    match run {
        toml::Value::String(body) => body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| !line.contains("{% raw %}") && !line.contains("{% endraw %}"))
            .map(str::to_owned)
            .collect(),
        toml::Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| match entry {
                toml::Value::String(command) => Some(command.clone()),
                toml::Value::Table(table) => table
                    .get("task")
                    .and_then(toml::Value::as_str)
                    .map(|task| format!("mise run {task}")),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `[tasks.<name>].depends` from the committed `mise.toml`, as task names.
///
/// A single string and a list are both spellings mise accepts, so both read the
/// same here; an absent key is the empty list.
#[must_use]
pub(crate) fn task_depends(name: &str) -> Vec<String> {
    let manifest = fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    match parsed
        .get("tasks")
        .and_then(|tasks| tasks.get(name))
        .and_then(|task| task.get("depends"))
    {
        Some(toml::Value::String(one)) => vec![one.clone()],
        Some(toml::Value::Array(many)) => many
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
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

/// Every BYPASS variable, which the derivation above structurally cannot see
/// (CLOUD-1227).
///
/// # The hole is exactly where it matters most
///
/// [`declared_env_vars`] is derived from the command SURFACE so it "cannot drift
/// behind a new flag". A bypass is not a flag and is never going to be one:
/// `session.rs` records the global hatch as *"ambient context, not settings:
/// there is no config-file spelling … so there is no precedence ladder to
/// declare"*, and CLOUD-437's per-row hatches are a `[[rule]]` COLUMN. So the one
/// class of variable whose entire purpose is **to stop the engine refusing** is
/// the one class that survived the scrub.
///
/// Measured on `ccb40a13`: with the since-retired general hatch exported, `test:cargo` was
/// 1543 passed / **2 failed** — both `board_receipts` cases asserting a refusal,
/// each expecting exit `2` and getting exit `0`. The same tree with nothing
/// exported was 3270/3270. Four `test:bats` record-keying cases went the same way
/// in the same run.
///
/// **Red was the lucky direction.** Those cases assert that a refusal HAPPENS.
/// The general case is the mirror: any case asserting a call is ALLOWED is
/// satisfied by a bypassed engine that never adjudicated — green over a mechanism
/// that never ran, which is CLOUD-418's vacuity arriving inside the harness. It
/// is also invisible in CI forever, because CI exports none of these; that
/// asymmetry is CLOUD-513's, one variable over.
///
/// # Derived from the config, never listed here
///
/// The per-row hatches are read out of the committed `batten.toml` rather than
/// enumerated, for [`declared_env_vars`]'s own reason one table over: a list here
/// stops covering the next row somebody adds, silently, in the direction that
/// weakens the suite. A config that will not load yields nothing rather than a
/// panic — this is a scrub, and a fixture with no committed config is a fixture
/// that has no per-row hatches to inherit.
fn bypass_env_vars() -> Vec<String> {
    // MEMOIZED, AND THE DERIVATION IS UNCHANGED (CLOUD-1291). `batten()` calls
    // this on every fixture command it constructs, and `config::load` over the
    // committed 356 KB authority was measured at **10.48 ms per call** — a full
    // parse plus every `validate` pass, of which the file read is 1.2%
    // (`mise run config-load-bench`). The file is committed and cannot change
    // during a run, so the memoized value is identical by construction.
    //
    // What is memoized is the RESULT of reading the config, never a hand-written
    // list of hatch names. CLOUD-1227 is explicit about why: a list "stops
    // covering the next row somebody adds, silently, in the direction that
    // weakens the suite". The signature is unchanged so no caller has to know.
    static NAMES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        let mut names = Vec::new();
        if let Ok(config) = batten::config::load(&at_root("batten.toml")) {
            names.extend(
                config
                    .rules
                    .iter()
                    .filter_map(|rule| rule.bypass_env.clone()),
            );
        }
        names.sort();
        names.dedup();
        names
    });
    NAMES.clone()
}

/// The compiled binary, with the ambient environment scrubbed.
///
/// Unconditional by design: a helper that scrubbed only where a suite
/// remembered to ask is a helper that is wrong exactly where it matters.
///
/// # `BATTEN_BIN` names the binary UNDER TEST, and it is set here for the same
/// reason
///
/// A `[[hook.handler]]` the binary dispatches can shell out to a batten
/// resolved the way the retired `payload-field` wrapper documented it:
/// `$BATTEN_BIN`, then `<root>/target/{release,debug}/batten`, then whatever
/// `command -v batten` finds — where `<root>` is resolved beside the SCRIPT, so
/// in a fixture repository it is the fixture, which has no `target/`. Without
/// this the extractor resolves off the developer's `PATH` or, finding nothing,
/// exits 1 — and every caller guards that read `|| exit 0`, so the guard allows
/// silently and the door reports nothing at all.
///
/// Measured 2026-08-29: `the_committed_guard_writes_a_host_document_so_its_
/// verdict_is_dropped` passed on a container carrying `batten` on `PATH` and
/// failed on a CI runner that does not, with an empty stderr — a case asserting
/// a defect, green because the mechanism never ran. Set after the scrub so it
/// survives it, and set unconditionally for the reason above: a suite that opted
/// in would be the suites that remembered.
///
/// # The state root is the case's own, on every spawn (CLOUD-2059)
///
/// Pinned to [`scratch_state_root`] here rather than by the suites that
/// remembered to ask. Before, only a suite whose subject was the committed
/// configuration asked, and every other spawn wrote the developer's real store:
/// 768 test segments beside the repository's own under `~/.local/share/batten`
/// on one container, none of them reaped. The case's OWN library calls resolve
/// the same root, because [`scratch_state_root`] contains this process
/// (`batten::testing::contain_state`), so what a child writes is what the case
/// reads back.
#[must_use]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject of an end-to-end test is the compiled binary, so there is nothing to move in-process without testing something else"
)]
pub(crate) fn batten() -> Batten {
    let mut command = Command::new(env!("CARGO_BIN_EXE_batten"));
    for name in declared_env_vars() {
        command.env_remove(name);
    }
    // IN ADDITION TO the derivation, never instead of it (CLOUD-1227). A bypass
    // is not a surface flag and cannot become one, so it is unreachable from
    // `declared_env_vars` by construction — the same shape as `BATTEN_BIN` below,
    // which is set explicitly for the same reason the derivation cannot see it.
    for name in bypass_env_vars() {
        command.env_remove(name);
    }
    command.env("BATTEN_BIN", env!("CARGO_BIN_EXE_batten"));
    // NO `batten` RESOLVABLE BY NAME from anything the binary under test starts
    // (CLOUD-1951) — see [`ambient_path`].
    command.env("PATH", ambient_path());
    pin_mise(&mut command);
    command.envs(batten::testing::state_pins(scratch_state_root()));
    pin_home(&mut command);
    Batten(command)
}

/// The case's own home, and the toolchain the developer's home holds pinned
/// beside it (CLOUD-2059).
///
/// `RUSTUP_HOME` and `CARGO_HOME` are resolved from THIS process — set, or the
/// `~/.rustup` and `~/.cargo` its own home holds — exactly as [`mise_dirs`]
/// resolves mise's, because the `cargo` on `PATH` is a rustup proxy that would
/// otherwise look for a toolchain under the empty home and find none.
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it configures: which home a child resolves is a property of the child's environment"
)]
fn pin_home(command: &mut Command) {
    static TOOLCHAIN: std::sync::LazyLock<Vec<(&'static str, PathBuf)>> =
        std::sync::LazyLock::new(|| {
            let home = std::env::home_dir();
            [("RUSTUP_HOME", ".rustup"), ("CARGO_HOME", ".cargo")]
                .into_iter()
                .filter_map(|(name, default)| {
                    std::env::var_os(name)
                        .map(PathBuf::from)
                        .or_else(|| home.as_ref().map(|home| home.join(default)))
                        .filter(|dir| dir.is_dir())
                        .map(|dir| (name, dir))
                })
                .collect()
        });
    for (name, dir) in TOOLCHAIN.iter() {
        command.env(name, dir);
    }
    command.envs(batten::testing::home_pins(scratch_home()));
}

/// This process's own home directory, for [`batten`]'s pin. Per process for
/// [`scratch_state_root`]'s reason, and created on first use.
pub(crate) fn scratch_home() -> &'static Path {
    static HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        let dir = target_tmp().join(format!("home-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create the scratch home");
        dir
    })
}

/// The home directories a command has been pointed at, as `(name, value)` pairs.
///
/// SPELLED HERE, NOT READ FROM `batten::testing::home_pins`, for
/// [`state_roots`]'s reason: this is the oracle the door is checked against.
#[must_use]
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it reads: the subject is what a child's environment carries"
)]
pub(crate) fn homes(command: &Command) -> Vec<(String, PathBuf)> {
    command
        .get_envs()
        .filter_map(|(name, value)| {
            let name = name.to_str()?.to_owned();
            (name == "HOME" || name == "USERPROFILE")
                .then(|| Some((name, PathBuf::from(value?))))?
        })
        .collect()
}

/// [`batten`]'s command, which refuses to have run where it would FALL THROUGH
/// to the checkout holding this build (CLOUD-2059).
///
/// A fixture under [`target_tmp`] with no repository of its own resolves to this
/// checkout, because `git::repo_root` ignores discovery ceilings by design: the
/// case then reads the real configuration and writes the real `.git` while it
/// believes it judged its fixture. Measured on `cli.rs`'s `repo_with_config`,
/// `fail_on_warning.rs` and `acceptance_corpus.rs`.
///
/// # Refused BEFORE the spawn, with `Drop` behind it
///
/// The builder methods a chain uses are inherent here and hand back `&mut Self`,
/// so `batten().args(…).current_dir(…).output()` never leaves this type and its
/// `output`/`spawn`/`status` refuse before the child exists — a fixture that
/// falls through never touches the checkout at all. Inherent methods win method
/// resolution over [`DerefMut`], which is why all 437 sites compile unchanged.
///
/// A chain CAN still leave through `DerefMut` — a helper taking `&mut Command`
/// and spawning it — so `Drop`, matklad's drop-bomb shape, asserts the same
/// thing once the statement ends. That one has already run; it is the backstop
/// that keeps the exit red, not the guard that keeps the checkout clean.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the door wraps the one spawn of the binary under test"
)]
pub(crate) struct Batten(Command);

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the door hands out the command it wraps"
)]
impl std::ops::Deref for Batten {
    type Target = Command;

    fn deref(&self) -> &Command {
        &self.0
    }
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the door hands out the command it wraps"
)]
impl std::ops::DerefMut for Batten {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.0
    }
}

/// Panic if a spawn in `cwd` would fall through to the checkout holding this
/// build. [`Batten`] applies it before every spawn and again on drop, and both
/// doors hand one out: [`batten`] for the binary, [`task_bash`] for a task body
/// that reaches it through `PATH`.
fn refuse_fall_through_at(cwd: &Path) {
    let cwd = std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    assert!(
        !batten::testing::falls_through(&cwd, &target_tmp()),
        "batten ran in {}, which falls through to the checkout holding this build: \
         make the fixture a repository (`common::init_repo`), or put a fixture whose \
         subject is \"not a repository\" in `common::scratch_outside_tree`",
        cwd.display()
    );
}

//MUTANT-SUITE crates/batten/tests/it/harness_isolation.rs
//MUTANT refused-after-the-spawn|s@^        self.refuse_fall_through();$@@|a_fall_through_is_refused_before_the_child_runs
//MUTANT task-door-unguarded|s@^        self.refuse_fall_through();$@@|a_task_body_redirected_to_a_fall_through_is_refused_before_it_runs
//MUTANT piped-door-unguarded|s@^    refuse_fall_through_at(dir);$@@|a_piped_spawn_into_a_fall_through_is_refused_before_it_runs
impl Batten {
    /// Panic if this command's working directory falls through to the checkout.
    fn refuse_fall_through(&self) {
        if let Some(cwd) = self.0.get_current_dir() {
            refuse_fall_through_at(cwd);
        }
    }

    /// [`std::process::Command::arg`], returning the door so a chain keeps its refusal.
    pub(crate) fn arg<S: AsRef<std::ffi::OsStr>>(&mut self, arg: S) -> &mut Self {
        self.0.arg(arg);
        self
    }

    /// [`std::process::Command::args`], returning the door so a chain keeps its refusal.
    pub(crate) fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.0.args(args);
        self
    }

    /// [`std::process::Command::current_dir`]. Read again when the command
    /// spawns, so moving it after construction is still judged.
    pub(crate) fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.0.current_dir(dir);
        self
    }

    /// [`std::process::Command::env`], returning the door so a chain keeps its refusal.
    pub(crate) fn env<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<std::ffi::OsStr>,
        V: AsRef<std::ffi::OsStr>,
    {
        self.0.env(key, value);
        self
    }

    /// [`std::process::Command::envs`], returning the door so a chain keeps its refusal.
    pub(crate) fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<std::ffi::OsStr>,
        V: AsRef<std::ffi::OsStr>,
    {
        self.0.envs(vars);
        self
    }

    /// [`std::process::Command::env_remove`], returning the door so a chain keeps
    /// its refusal.
    pub(crate) fn env_remove<K: AsRef<std::ffi::OsStr>>(&mut self, key: K) -> &mut Self {
        self.0.env_remove(key);
        self
    }

    /// [`std::process::Command::stdin`], returning the door so a chain keeps its refusal.
    pub(crate) fn stdin<T: Into<std::process::Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.0.stdin(cfg);
        self
    }

    /// [`std::process::Command::stdout`], returning the door so a chain keeps its refusal.
    pub(crate) fn stdout<T: Into<std::process::Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.0.stdout(cfg);
        self
    }

    /// [`std::process::Command::stderr`], returning the door so a chain keeps its refusal.
    pub(crate) fn stderr<T: Into<std::process::Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.0.stderr(cfg);
        self
    }

    /// [`std::process::Command::output`], refused first where it would fall through.
    pub(crate) fn output(&mut self) -> std::io::Result<Output> {
        self.refuse_fall_through();
        self.0.output()
    }

    /// [`std::process::Command::spawn`], refused first where it would fall through.
    pub(crate) fn spawn(&mut self) -> std::io::Result<std::process::Child> {
        self.refuse_fall_through();
        self.0.spawn()
    }

    /// [`std::process::Command::status`], refused first where it would fall through.
    pub(crate) fn status(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.refuse_fall_through();
        self.0.status()
    }
}

/// [`StateHome`] on the door itself, so a chain through `.state_home(…)` stays on
/// this type and keeps its pre-spawn refusal.
impl StateHome for Batten {
    fn state_home(&mut self, home: &Path) -> &mut Self {
        state_home(&mut self.0, home);
        self
    }

    fn state_dir(&mut self, dir: &Path) -> &mut Self {
        state_dir(&mut self.0, dir);
        self
    }

    fn at_home(&mut self, home: &Path) -> &mut Self {
        at_home(&mut self.0, home);
        self
    }
}

impl Drop for Batten {
    fn drop(&mut self) {
        // A second panic while unwinding aborts the process and loses the first
        // one's message, which is the failure the case was reporting.
        if std::thread::panicking() {
            return;
        }
        self.refuse_fall_through();
    }
}

/// This process's `PATH` with no `batten` resolvable by name — every directory
/// holding one swapped for a shadow of its other entries (CLOUD-1951).
///
/// # Why the suite needs it, and why it lives HERE now
///
/// CI's test job has neither this checkout's `target/release` (mise's `_.path`)
/// nor an installed release in `~/.local/bin`; a developer's box has both. So a
/// case — or a hook the binary under test dispatches — that spawns a bare
/// `batten` passed here and failed there; the retired `doctor` handler on #928
/// cost a matrix that way. `test:cargo`'s shell body used to mask the whole
/// suite's `PATH` before `cargo nextest` ran. That body retired to one argv
/// (CLOUD-843), and the mask moved to the doors that hand a child its `PATH`:
/// [`batten`], [`task_bash`] and [`git_command`] set this, and a tier that builds
/// its own `PATH` starts from this rather than from the ambient one.
///
/// NARROWER THAN THE SHELL MASK, and said so rather than implied: that covered
/// the whole nextest process tree. A lib unit test, or a case spawning some
/// other program without one of these doors, inherits the ambient `PATH`.
///
/// A SHADOW, NOT A DROP: `mise` shares `~/.local/bin` with the installed
/// release, so removing the directory would hide the tool runner a case may
/// need along with the binary it must not find. The shadow links every other
/// entry, and is built idempotently because nextest runs each case in a process
/// of its own: a link another process made first is an answer, not a failure.
#[must_use]
pub(crate) fn ambient_path() -> std::ffi::OsString {
    static MASKED: std::sync::LazyLock<std::ffi::OsString> = std::sync::LazyLock::new(|| {
        mask_batten(
            &std::env::var_os("PATH").unwrap_or_default(),
            &target_tmp().join("no-batten-path"),
        )
    });
    MASKED.clone()
}

/// `path` with every directory holding a `batten` replaced by a shadow of its
/// other entries under `shadows`, one shadow per directory.
#[must_use]
pub(crate) fn mask_batten(path: &std::ffi::OsStr, shadows: &Path) -> std::ffi::OsString {
    let entries: Vec<PathBuf> = std::env::split_paths(path)
        .map(|dir| {
            if dir.as_os_str().is_empty() || !holds_batten(&dir) {
                return dir;
            }
            // Named after the directory it shadows, never after its position: a
            // PATH that reorders between runs must not reuse another
            // directory's links.
            let name: String = dir
                .to_string_lossy()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            let shadow = shadows.join(name);
            shadow_of(&dir, &shadow);
            shadow
        })
        .collect();
    std::env::join_paths(entries).unwrap_or_else(|_| path.to_os_string())
}

/// Whether `dir` holds a `batten` a name lookup would find.
fn holds_batten(dir: &Path) -> bool {
    dir.join("batten").exists() || dir.join("batten.exe").exists()
}

/// Link every entry of `dir` but `batten` into `shadow`.
///
/// Its mutation is declared in `test_cargo_path.rs`, the file whose cases
/// observe it (see the block there).
#[cfg(unix)]
fn shadow_of(dir: &Path, shadow: &Path) {
    let _ = fs::create_dir_all(shadow);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == "batten" {
            continue;
        }
        let link = shadow.join(&name);
        if link.symlink_metadata().is_ok() {
            continue;
        }
        let _ = std::os::unix::fs::symlink(entry.path(), &link);
    }
}

/// Where no symlink can be made cheaply, the directory is dropped outright: its
/// other programs are hidden too, which is the cost the shadow exists to avoid,
/// paid only where it cannot be built.
#[cfg(not(unix))]
fn shadow_of(_dir: &Path, shadow: &Path) {
    let _ = fs::create_dir_all(shadow);
}

/// Where mise keeps its installs, cache and state, resolved from THIS process's
/// environment the way mise resolves them, before any case redirects anything.
///
/// # Why a state redirect must never move these (CLOUD-2021)
///
/// [`state_dir`] points `XDG_DATA_HOME` at a fixture so the child's STATE STORE
/// is the suite's own. mise reads the same variable for `$XDG_DATA_HOME/mise`,
/// which is every installed tool, so a mise reached through such a spawn — the
/// `connector-allow-guard` handler runs one for every `mcp__*` payload — saw an
/// empty install tree and installed the whole `[tools]` set before running its
/// task. Measured: **20.87s and 1.8 GB** for one call, against 0.20s ambient;
/// **19.44 CPU-seconds** of `cli::the_committed_shape_rules_fire_on_every_banned_
/// shape`, the most expensive case in the suite. `MISE_*_DIR` outranks the XDG
/// variables, so pinning them here leaves the store redirect intact and the
/// toolchain where it is.
fn mise_dirs() -> &'static [(&'static str, PathBuf)] {
    static DIRS: std::sync::LazyLock<Vec<(&'static str, PathBuf)>> =
        std::sync::LazyLock::new(|| {
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let resolve = |own: &str, xdg: &str, fallback: &[&str]| {
                std::env::var_os(own)
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os(xdg).map(|base| PathBuf::from(base).join("mise")))
                    .or_else(|| {
                        home.as_ref().map(|home| {
                            fallback.iter().fold(home.clone(), |at, part| at.join(part))
                        })
                    })
            };
            // mise's own defaults per platform. UNIX ONLY, because Windows keeps
            // all three under `%LOCALAPPDATA%\mise` and a `HOME`-relative guess
            // would pin a directory mise never reads — an empty tree, which is the
            // defect this exists to remove.
            let cache: &[&str] = if cfg!(target_os = "macos") {
                &["Library", "Caches", "mise"]
            } else {
                &[".cache", "mise"]
            };
            if cfg!(windows) {
                return Vec::new();
            }
            [
                (
                    "MISE_DATA_DIR",
                    "XDG_DATA_HOME",
                    &[".local", "share", "mise"][..],
                ),
                ("MISE_CACHE_DIR", "XDG_CACHE_HOME", cache),
                (
                    "MISE_STATE_DIR",
                    "XDG_STATE_HOME",
                    &[".local", "state", "mise"][..],
                ),
            ]
            .into_iter()
            .filter_map(|(own, xdg, fallback)| resolve(own, xdg, fallback).map(|dir| (own, dir)))
            .collect()
        });
    &DIRS
}

/// [`mise_dirs`] pinned on `command`, and CI's two auto-install settings with them.
///
/// THE SETTINGS ARE THE BAN. `.github/workflows/ci.yml` sets both workflow-wide,
/// so a case reaching a mise with a missing tool fails there naming the tool; left
/// at mise's default here, the same case silently installs for twenty seconds on
/// a developer's machine and nowhere else. The harness now answers the way CI
/// does, so a cold mise is a named failure in both places rather than a cost in one.
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it configures: which mise a child reaches is a property of the child's environment"
)]
fn pin_mise(command: &mut Command) {
    // The declared mutation, in a plain comment because `common/` is harness
    // rather than a sweep route; its kill is shown by hand (CLOUD-2021):
    // MUTANT state-redirect-moves-mise|s@command.env(name, dir);@let _ = (name, dir);@|a_redirected_state_root_leaves_mises_installs_where_they_are
    for (name, dir) in mise_dirs() {
        command.env(name, dir);
    }
    command
        .env("MISE_TASK_RUN_AUTO_INSTALL", "false")
        .env("MISE_EXEC_AUTO_INSTALL", "false");
}

/// The mise data dir [`batten`] pins, for the case asserting a state redirect
/// leaves it alone.
#[must_use]
pub(crate) fn pinned_mise_data_dir() -> Option<&'static Path> {
    mise_dirs()
        .iter()
        .find(|(name, _)| *name == "MISE_DATA_DIR")
        .map(|(_, dir)| dir.as_path())
}

/// The state root a suite whose subject is the REAL repository must run under.
///
/// `[tasks.<name>]`'s `run` body from the committed `mise.toml`, `{% raw %}`
/// fences stripped — the bytes mise hands bash.
///
/// One reader for every task-body tier, so a suite asserts the committed task
/// rather than a copy of it.
#[must_use]
pub(crate) fn task_body(name: &str) -> String {
    let manifest = fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    // A `run` ARRAY is a body too (CLOUD-843): mise runs its entries in order, so
    // the text a tier reads is those entries, one per line — the shape the
    // retired shell bodies took when they became argv.
    let run = &parsed["tasks"][name]["run"];
    let body = match run.as_array() {
        Some(steps) => steps
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>()
            .join("\n"),
        None => run
            .as_str()
            .unwrap_or_else(|| panic!("[tasks.{name}] declares a run body"))
            .to_owned(),
    };
    body.lines()
        .filter(|line| !line.contains("{% raw %}") && !line.contains("{% endraw %}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `[env].<name>` from the committed `mise.toml` — the one declaration a task
/// body and its tier both read, so a tier never restates a shared name.
pub(crate) fn task_env(name: &str) -> String {
    let manifest = fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["env"][name]
        .as_str()
        .unwrap_or_else(|| panic!("[env] declares {name}"))
        .to_owned()
}

/// `bash -c <body>` in `dir`, with `dir/bin` first on `PATH` for the stubs a
/// tier plants there.
#[expect(
    clippy::disallowed_types,
    reason = "stays: a mise task body is shell, so running it is a spawn by definition, and this is the one site every task-body tier shares"
)]
#[must_use]
pub(crate) fn task_bash(dir: &Path, body: &str) -> Batten {
    let inherited = ambient_path();
    let path = std::env::join_paths(
        std::iter::once(dir.join("bin")).chain(std::env::split_paths(&inherited)),
    )
    .expect("a PATH entry carries no separator");
    let mut command = std::process::Command::new("bash");
    command
        .args(["-c", body])
        .current_dir(dir)
        .env("PATH", path)
        // A body that reaches the engine writes the case's own state root, as
        // [`batten`] does (CLOUD-2059) — and so keeps mise's installs pinned,
        // which the XDG redirect would otherwise move ([`pin_mise`]).
        .envs(batten::testing::state_pins(scratch_state_root()));
    pin_mise(&mut command);
    pin_home(&mut command);
    // THE BINARY'S DOOR GUARDS THIS ONE TOO (review of #1089). A task body runs
    // the engine through `PATH` from wherever the command stands WHEN IT SPAWNS,
    // so a fixture that is no repository of its own falls through to this
    // checkout here exactly as it would there. Returned as a `Batten`, the check
    // reads the final directory — a caller's later `current_dir` included.
    Batten(command)
}

/// `[tasks.<task>]` ready to run in `dir` under [`batten`]'s scrubbed
/// environment, for a tier that sets its own readings before running it.
pub(crate) fn task_command(dir: &Path, task: &str) -> Batten {
    let mut command = task_bash(dir, &task_body(task));
    scrub(&mut command, dir);
    command
}

/// `mise run -q <task>` in `dir` against THIS repository's manifest, with
/// `input` on stdin, under [`task_command`]'s environment — for a task whose
/// `run` is an argv array, which has no single body for [`task_body`] to read.
///
/// `MISE_CONFIG_FILE` names the committed manifest so the task resolved is the
/// one under test, and a task declaring `dir = "{{cwd}}"` then runs in `dir`,
/// the fixture — the same seam `board-sweep` composes its gates through. The
/// manifest's `vars.batten` reads `BATTEN_BIN`, which [`batten`] sets to the
/// binary under test, so the task never builds whatever workspace cargo finds.
/// `env` is set last, for the variables a task's own vars read.
///
/// # `MISE_CEILING_PATHS` is what makes `MISE_CONFIG_FILE` the ONLY manifest
///
/// mise still walks up from the working directory and a manifest it finds there
/// OUTRANKS the named one for a task of the same name. A fixture lives under
/// `CARGO_TARGET_TMPDIR`, and with a shared `CARGO_TARGET_DIR` that is inside
/// ANOTHER checkout, whose tasks then answer. Measured 2026-09-29: from
/// `<checkout>/target/tmp/<x>`, `mise run -n done-check` with
/// `MISE_CONFIG_FILE` naming a worktree's manifest printed the parent checkout's
/// `done-check`; with the ceiling at the fixture it printed the worktree's.
#[must_use]
pub(crate) fn mise_task(dir: &Path, task: &str, env: &[(&str, &str)], input: &str) -> Output {
    let mut command = task_bash(dir, &format!("mise run -q {task}"));
    scrub(&mut command, dir);
    command.env("MISE_CONFIG_FILE", at_root("mise.toml"));
    command.env("MISE_CEILING_PATHS", dir);
    command.envs(env.iter().copied());
    stdin_run(&mut command, dir, &[], input)
}

/// Put [`batten`]'s scrubbed environment on a [`task_bash`] command, with the
/// stubs in `dir/bin` and then the engine under test first on `PATH`. It
/// configures the caller's command rather than returning one, so the spawn stays
/// with [`task_bash`], the factory that names it (`policy/spawn-factory.rego`).
#[expect(
    clippy::disallowed_types,
    reason = "stays: configures and never spawns; the command is task_bash's, whose own expect names the program"
)]
fn scrub(command: &mut std::process::Command, dir: &Path) {
    let template = batten();
    for (name, value) in template.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    // The stubs stay first even when the template carries a `PATH` of its own.
    let base = template
        .get_envs()
        .find(|(name, _)| *name == "PATH")
        .and_then(|(_, value)| value.map(std::ffi::OsStr::to_os_string))
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_default();
    // The engine under test follows the stubs, ahead of any installed release.
    let engine = Path::new(env!("CARGO_BIN_EXE_batten"))
        .parent()
        .map(Path::to_path_buf);
    let path = std::env::join_paths(
        std::iter::once(dir.join("bin"))
            .chain(engine)
            .chain(std::env::split_paths(&base)),
    )
    .expect("a PATH entry carries no separator");
    command.env("PATH", path);
    // NO WALL CLOCK IN A TASK BODY'S OUTPUT. `mise.toml` sets `task.timings` so
    // a human reading a gate sees each step's cost (CLOUD-1891), and a body that
    // runs a nested `mise run` then prints `Finished in 96.2ms` — which made a
    // byte-stability case compare two clocks and fail on #1036's macOS leg. The
    // environment setting outranks the file, and the report is the human's, never
    // part of the task's output contract.
    command.env("MISE_TASK_TIMINGS", "0");
}

/// Run `[tasks.<task>]` in `dir` the way `mise run <task>` would, with the
/// engine the suite built and [`batten`]'s scrubbed environment, `stdin` piped
/// in — so a developer's shell cannot move a producer's reading.
pub(crate) fn produce(dir: &Path, task: &str, stdin: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = task_command(dir, task)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the producer");
    let _ = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin.as_bytes());
    child.wait_with_output().expect("run the producer")
}

/// Whether the committed authority declares the OWNER'S protected-path set.
///
/// The owner switched that gate off until admission statements are adjudicated.
/// Cases asserting the COMMITTED gate refuses hold only while it is declared, and
/// return to force the moment it is; an undeclared set must carry the owner's
/// marker, so a set that silently vanished still reds.
///
/// "Declared" means the owner's classes are in it, not merely that a
/// `protected` line exists: since CLOUD-1078 a narrower set guarding only the
/// asked ledger is live, and reading that line as the owner's gate being on sent
/// four cases to assert `rm .serena/memories/core.md` refuses against a set that
/// does not name it.
#[must_use]
pub(crate) fn committed_protected_declared() -> bool {
    let authority = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml"),
    )
    .expect("read the committed config");
    let declared = authority
        .lines()
        .any(|line| line.starts_with("protected = [") && line.contains("\"batten.toml\""));
    assert!(
        declared || authority.contains("# DISABLED by the owner."),
        "the committed protected set vanished without the owner's marker"
    );
    declared
}

/// A fixture carrying the committed `batten.toml` and policy modules, with the
/// protected-path set DECLARED — the engine's protected-path mechanism under
/// this repository's own rows, independent of whether the owner has the
/// committed gate switched on.
#[must_use]
pub(crate) fn committed_fixture_with_protected(name: &str) -> PathBuf {
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let authority =
        std::fs::read_to_string(committed.join("batten.toml")).expect("read the committed config");
    // The owner's three classes, UNIONED into whatever set is declared rather
    // than injected only when none is. Since CLOUD-1078 a narrower set is live —
    // just the asked ledger — and reading "a set is declared" as "the owner's
    // set is on" left this fixture guarding the ledger alone, so every
    // `.serena/memories` case here turned green-for-the-wrong-reason red.
    let owners = [".serena/memories/**", "batten.toml", ".github/workflows/**"];
    let config = if authority
        .lines()
        .any(|line| line.starts_with("protected = ["))
    {
        let line = authority
            .lines()
            .find(|line| line.starts_with("protected = ["))
            .expect("the declared set's line")
            .to_owned();
        let declared: toml::Value =
            toml::from_str(&line).expect("the declared set is one TOML key");
        let mut entries: Vec<String> = declared["protected"]
            .as_array()
            .expect("an array")
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_owned))
            .collect();
        for owner in owners {
            if !entries.iter().any(|entry| entry == owner) {
                entries.push(owner.to_owned());
            }
        }
        let quoted: Vec<String> = entries.iter().map(|entry| format!("\"{entry}\"")).collect();
        authority.replacen(&line, &format!("protected = [{}]", quoted.join(", ")), 1)
    } else {
        authority.replacen(
            "must_land_on = \"origin/main\"\n",
            "must_land_on = \"origin/main\"\nprotected = [\".serena/memories/**\", \
             \"batten.toml\", \".github/workflows/**\"]\n",
            1,
        )
    };
    let dir = Fixture::new(name)
        .config(&config)
        .git()
        .base_commit()
        .build();
    let modules = dir.join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    for entry in std::fs::read_dir(committed.join("policy")).expect("read committed policy") {
        let path = entry.expect("a policy entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(path.file_name().expect("a file name")))
                .expect("copy a policy module");
        }
    }
    dir
}

/// **A THIRD SUPPRESSION CHANNEL, AND THE ONE NEITHER SCRUB IN [`batten`] CAN
/// SEE.** That function removes every `BATTEN_` variable the surface declares and
/// every bypass name beside it, and both of those are walks over ENVIRONMENT
/// VARIABLES. An **admission** is not one: CLOUD-1051 retired
/// `BATTEN_FILED_HERE_BYPASS` and its siblings precisely so that suppressing a
/// refusal would cost a signed record in the state store rather than a knowable
/// string anyone could export. So the channel that replaced the scrubbed ones is
/// unreachable from the scrub by construction — the same shape as `BATTEN_BIN`,
/// and for the same reason.
///
/// **Measured 2026-09-02, and it is a false green in the unsafe direction.** A
/// spent admission for `batten.toml` in the DEVELOPER'S OWN store turned
/// `cli.rs::the_committed_protected_paths_fire_on_a_mutating_verb` green-side:
/// `mv batten.toml elsewhere.toml` answered exit `0` where the case demands `2`,
/// and the case reported that the committed protected-path policy refuses a
/// write while a record on that machine was admitting it.
///
/// **THE DEFAULT IN [`batten`] SINCE CLOUD-2059.** It was first applied only by
/// the suites whose subject is the committed configuration, because a fixture
/// suite reading a record back IN-PROCESS — `admission.rs`'s
/// `a_correctly_answered_override_completes_end_to_end` — resolved the root from
/// the PARENT's environment and missed what the redirected child filed. The fix
/// was to contain the parent too: resolving this root also points the process's
/// own state at it (`batten::testing::contain_state`), so the case and its
/// children read one store and neither writes the developer's.
///
/// **Per PROCESS**, because nextest runs each case in its own process: state one
/// spawn writes is still there for the next spawn in the same case, and no case
/// can reach another's. Under `target/`, so `cargo clean` collects it, and
/// resolved once so the directory is created on the first use rather than every.
pub(crate) fn scratch_state_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = target_tmp().join(format!("state-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create the scratch state root");
        // THIS process's own library calls resolve the same root its children
        // are pinned to, so a case that spawns and calls in-process reads one
        // store, and neither half writes the developer's.
        batten::testing::contain_state(&dir);
        dir
    })
}

/// The state ROOTS a command has been pointed at, as `(name, value)` pairs.
///
/// Here rather than in the asserting suite because this module is the one place
/// the variables may be named at all —
/// `primitives::no_suite_sets_the_state_dir_variables_itself` enforces exactly
/// that, and it is right to: CLOUD-619's defect was fourteen copies of the name,
/// one of which was POSIX-only and redirected nothing on Windows. A suite
/// checking the redirect must therefore ask this module rather than re-type the
/// names, or it becomes the fifteenth copy while asserting that there are none.
///
/// SPELLED HERE, NOT READ FROM `batten::testing::state_pins`, and that is the
/// one copy that must stay a copy: this is the oracle the door is checked
/// against, and an oracle that read the door's own list would agree with any pin
/// that dropped a name.
///
/// `LOCALAPPDATA` is deliberately absent: [`state_dir`] points it at a `cache`
/// subdirectory rather than at the root, so including it would make a caller
/// compare two different things under one name.
#[must_use]
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it reads: the subject is what a child's environment carries, which is a property of the command rather than of anything in-process"
)]
pub(crate) fn state_roots(command: &Command) -> Vec<(String, PathBuf)> {
    command
        .get_envs()
        .filter_map(|(name, value)| {
            let name = name.to_str()?.to_owned();
            (name == "XDG_DATA_HOME" || name == "APPDATA")
                .then(|| Some((name, PathBuf::from(value?))))?
        })
        .collect()
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
    at_home(state_dir(command, &home.join("data")), home)
}

/// Point the child's HOME DIRECTORY at `home`, on **every** platform.
///
/// The fourth hermeticity behaviour, and the same defect as [`state_home`]'s one
/// axis over — a redirect spelled for POSIX and inert on Windows. `HOME` alone
/// is the whole answer on Linux and macOS and none of it on Windows:
/// `etcetera::home_dir()` wraps `std::env::home_dir()`, which reads
/// `USERPROFILE` there. So a suite that "overrode" its home read the **real
/// user's** profile, and only the cases asserting a positive count noticed —
/// the ones asserting an absence passed over a home that simply had nothing in
/// it (CLOUD-113's Windows job, again, on `wiring_reclaim.rs`).
///
/// Separate from [`state_home`] because the two answer different questions: that
/// one contains where Batten WRITES its state, this one contains what
/// `home_dir()` RESOLVES TO for a verb whose subject is a file under it. A suite
/// wanting both calls both; `state_home` calls this so no site can have the
/// data dir contained and the home ambient.
#[expect(
    clippy::disallowed_types,
    reason = "stays with the harness spawn it configures: scrubbing the ambient home is a property of the child's environment, not a call this could make in-process"
)]
pub(crate) fn at_home<'a>(command: &'a mut Command, home: &Path) -> &'a mut Command {
    command.envs(batten::testing::home_pins(home))
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
    /// Point the resolved state root at `<home>/data` on every platform, and the
    /// resolved home directory at `home` on every platform.
    fn state_home(&mut self, home: &Path) -> &mut Self;
    /// Point the resolved state root at `dir` itself, setting no home.
    fn state_dir(&mut self, dir: &Path) -> &mut Self;
    /// Point the resolved home directory at `home` on every platform, leaving
    /// the state root ambient.
    fn at_home(&mut self, home: &Path) -> &mut Self;
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

    fn at_home(&mut self, home: &Path) -> &mut Self {
        at_home(self, home)
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
        .envs(batten::testing::state_pins(dir))
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
    stdin_run(&mut batten(), dir, args, input)
}

/// Run `command` in `dir` with `args`, writing `input` to its stdin and closing
/// it, and capture its output. Refuses a fall-through BEFORE the spawn, since it
/// runs below `Batten`'s own methods.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: this IS the spawn-and-pipe harness, and taking the command lets the two entry points above share one body rather than drifting apart — the founding reason this module exists"
)]
#[must_use]
fn stdin_run(command: &mut Command, dir: &Path, args: &[&str], input: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;

    // BEFORE THE SPAWN, for the reason `Batten::output` checks first (review of
    // #1089): this takes the command as `&mut Command`, so it spawns below the
    // wrapper's own methods, and only the drop check would see a fall-through —
    // after the child had already run. `dir` is the directory set just below.
    refuse_fall_through_at(dir);
    let mut child = command
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    // A CHILD THAT EXITS BEFORE READING STDIN IS A LEGITIMATE OUTCOME, so a
    // closed pipe is not a failure. Several cases assert exactly that shape —
    // `config_in_directory`'s
    // `a_named_directory_with_no_authority_is_could_not_look_never_defaults`
    // reports and exits without ever consuming stdin — and the parent then writes
    // into a pipe nobody holds open, which is `BrokenPipe`.
    //
    // Requiring the write to succeed is a stronger claim than any case makes: the
    // verdict under test is the child's exit code and output, which
    // `wait_with_output` still collects either way. Any other error still fails,
    // so this narrows the assertion rather than removing it.
    //
    // Timing-dependent, which is why it survived until now: measured red once
    // inside a full `test:cargo` with 2100 tests in flight, and green on six
    // consecutive runs of that target alone. Under load the child wins the race.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    if let Err(error) = stdin.write_all(input.as_bytes()) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "write stdin: {error:?}"
        );
    }
    drop(stdin);
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
///
/// # The path is per RUNNER LANE, not just per case (CLOUD-1164)
///
/// The wipe above is what makes this necessary. `CARGO_TARGET_TMPDIR` is shared
/// by every test binary in the workspace, so two processes running the same case
/// name resolve the same directory — and the second one's `remove_dir_all`
/// deletes the tree the first is mid-case in. The failure surfaces as a
/// `NotFound` on a file the fixture had just written, in a case that passes
/// whenever it is run alone.
///
/// That was unreachable while every gate ran its own shell program: no test
/// binary ran twice at once. CLOUD-1164 retired four of those onto `test:*`
/// tasks the `hk` steps call, and `verify` runs `hooks` (whose `test:cargo`
/// covers the whole workspace) CONCURRENTLY with `ci:quick` (whose steps call
/// the narrow tasks) — so four binaries now genuinely do run twice at once, and
/// nothing about a fixture's own name can tell the two runs apart. Measured on
/// `config_schema`, first in a case this change added and then in one that had
/// been landed for months.
///
/// **The qualifier is scoped to the LANE that needs it, and nowhere else.** A
/// lane alone does not separate these runs: `verify` reaches the hk gate through
/// both `hooks` (`hk check --all`) and `ci:quick` (`--profile '!slow'`), and the
/// narrow steps are untagged, so each narrow TASK runs twice at once as well as
/// beside `test:cargo`. Only a per-invocation qualifier separates two runs of one
/// task, so `$BATTEN_TEST_SCRATCH_LANE` carries the pid with it.
///
/// The default lane takes neither, and that is the point: the ~130 binaries only
/// `test:cargo` runs keep byte-identical paths run to run, and randomness is paid
/// exactly where the collision is.
///
/// A pid on EVERY path did separate them, and it also made every path random per
/// run — which is not free, because the engine fingerprints the worktree path.
/// `journal::merge`
/// concatenates shards in path-sort order, and a store's scan shard is named for
/// that fingerprint while its drain shard is named for a constant; so whether
/// evaluations precede presentations in the merged log was decided by comparing a
/// per-run hash against a fixed one. `emission::assess` scopes an identity's
/// emission budget by log POSITION, so on the losing draw every emission sorted
/// below the window and the flap policy silently stopped suppressing. Measured
/// here (1 of 13 stores drew it) and on the Windows job, as
/// `advisory_drain::an_alternating_rule_tracks_state_truthfully_while_its_emissions_stop_at_the_cap`.
/// The engine half is CLOUD-1252's; a deterministic lane keeps this helper from
/// drawing for it every run.
#[must_use]
pub(crate) fn scratch(name: &str) -> PathBuf {
    make_empty(target_tmp().join(in_lane(name)))
}

/// [`scratch`] as a repository of its own: the one shape a directory the binary
/// runs in may take under [`target_tmp`] (CLOUD-2059), since one without a `.git`
/// resolves to the checkout holding this build and [`Batten`] refuses the spawn.
#[must_use]
pub(crate) fn scratch_repo(name: &str) -> PathBuf {
    Fixture::new(name).build()
}

/// An empty scratch directory **outside** this repository's tree, wiped first.
///
/// For the one fixture shape that cannot live under `target/`: a directory that
/// must not be inside any git repository (see the module doc).
#[must_use]
pub(crate) fn scratch_outside_tree(group: &str, name: &str) -> PathBuf {
    // Under `batten::scratch::root()`, which carries this process's pid as a
    // segment and reaps dead ones, rather than a fixed `<tmp>/<group>/<name>`
    // that two concurrent runs share and nothing ever collects (CLOUD-2059).
    make_empty(batten::scratch::root().join(group).join(in_lane(name)))
}

/// `name` qualified by this runner's lane and invocation, so no two concurrent
/// runs covering one binary resolve the same directory. See [`scratch`] for why
/// that happens and why the pid rides the lane rather than every path.
///
/// Absent or empty is the default lane and adds nothing, which is what keeps the
/// ~130 binaries only `test:cargo` runs on the exact paths they have always had.
///
/// **THE COLLECTOR DOES NOT READ THIS NAME** (CLOUD-1912). `clear-scratch` in
/// `.config/nextest.toml` runs at the start of every nextest invocation, and
/// `verify` runs several at once; it protects a live run by deferring while any
/// other `cargo-nextest` is alive, not by sparing names. The qualifier's job is
/// the one above: two concurrent runs of one task never resolve the same path.
fn in_lane(name: &str) -> String {
    match std::env::var("BATTEN_TEST_SCRATCH_LANE") {
        Ok(lane) if !lane.is_empty() => format!("{name}.lane-{lane}-{}", std::process::id()),
        _ => name.to_owned(),
    }
}

fn make_empty(dir: PathBuf) -> PathBuf {
    // Every fixture primitive passes here, so a case that builds one is
    // contained before its first library call can resolve the real store.
    let _ = scratch_state_root();
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
///
/// # Two of the pins are about COST, and they reach every fork rather than a
/// subset
///
/// Measured over one traced run (`GIT_TRACE2_EVENT`, one trace file per git
/// process): the suite spends **9,476 git processes and 25.17s**, and the two
/// flags below are the only change that touches all of them.
///
/// `core.fsync=none` — git 2.36+ defaults to `core.fsync=committed`, so each of
/// the run's **1,741 `commit` processes (12.23s, the single largest git line)**
/// fsyncs its loose objects and its ref update. A fixture under
/// `CARGO_TARGET_TMPDIR` does not outlive the run and has nothing to be durable
/// against; the durability is bought for a directory the next `make_empty`
/// deletes.
///
/// `gc.auto=0` and `maintenance.auto=false` — git runs `maintenance run --auto`
/// after a commit, and the trace counts **1,745 `maintenance` processes against
/// 1,741 commits**, tracking to within four.
///
/// **BOTH KEYS, AND THE FIRST ONE ALONE DOES NOT WORK.** `gc.auto=0` was landed
/// first, on the reasoning that it is the documented way to switch auto-gc off.
/// Measured on git 2.43.0 with only that flag: the count moved 1,745 → **1,747**
/// and the time 0.95s → 0.89s, which is the spawn still happening and finding
/// nothing to do. Modern git gates the auto-maintenance run on
/// `maintenance.auto`, and `gc.auto` reaches only the legacy `gc --auto` path
/// underneath it. A flag that looks right and removes no process is worse than
/// none, because the count is what a later reader checks.
///
/// `gc.auto=0` stays beside it rather than being replaced: it is what guarantees
/// no fixture ever writes `packed-refs`, which is the precondition
/// [`Fixture::base_commit`]'s loose-ref write asserts rather than assumes.
///
/// # `GIT_TEMPLATE_DIR` is scrubbed, and the reason is the template
///
/// The four `GIT_*` names below were always the hermeticity set. `GIT_TEMPLATE_DIR`
/// was not among them, and today an exported one corrupts a single fixture. That
/// stops being true once [`git_init_template`] exists: the first process to build
/// the template bakes the developer's template into a repository every other
/// fixture in the run then copies, so a per-fixture defect becomes a per-run one.
/// The other three are the same class reached by different keys — an inherited
/// index file, object directory or namespace would be shared the same way.
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
            "-c",
            "core.fsync=none",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        // A hook a fixture installs runs under git's PATH, so git gets the
        // CLOUD-1951 mask too: no installed `batten` answers a hook by name.
        .env("PATH", ambient_path())
        // And a hook that reaches the engine writes the case's own state root,
        // as [`batten`] does (CLOUD-2059).
        .envs(batten::testing::state_pins(scratch_state_root()));
    for var in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_TEMPLATE_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(var);
    }
    pin_mise(&mut command);
    command
}

/// The one `git init` this suite pays: an empty repository under
/// `CARGO_TARGET_TMPDIR` that every in-tree fixture copies instead of forking.
///
/// # Per FILESYSTEM, not per process, and that is what makes it work at all
///
/// nextest runs each of the ~2,800 cases in its own process, so a `OnceLock`
/// here is a `OnceLock` per CASE and would fork `git init` once per case —
/// exactly the cost it exists to remove. The shared artefact has to live on the
/// filesystem; the `OnceLock` below memoizes only the resolved PATH within one
/// process.
///
/// # Published by rename, which cannot land on a non-empty directory
///
/// The build goes into a pid-unique staging directory and is published with one
/// `fs::rename`. `rename(2)` of a directory onto a non-empty one fails with
/// `ENOTEMPTY`, so the publish is exclusive by construction: two racing
/// processes each build a COMPLETE repository, exactly one wins, and the loser
/// deletes its own copy and reads the winner's. A partial template is
/// unreachable because nothing is ever written *into* the published path.
///
/// No `fs4` lock: serialising a handful of concurrent builders to save a handful
/// of redundant `git init`s is the wrong trade for a once-per-filesystem cost,
/// and a lock file is one more thing to leak.
///
/// # `None` is an answer, not a failure (CLOUD-1832)
///
/// Every reading of a failed publish that does NOT leave a complete template
/// behind ends here, and the honest report is that this process has no template
/// — not a path it hopes is one. The caller's fallback is the `git init` fork
/// this template exists to avoid, which is a cost rather than a defect, so the
/// suite stays green on a filesystem where the publish cannot land. The state is
/// printed, not swallowed: the next run that hits it says why.
///
/// # The stamp is the `git` binary's own metadata
///
/// A hand-bumped version constant would leave a stale template behind whenever
/// the builder or the local git changed, and the failure would be silent — every
/// fixture inheriting a repository built by a different git. The path carries the
/// resolved binary's length and mtime instead, so a git upgrade mints a new
/// template rather than reusing the old one. Resolved by scanning `PATH` rather
/// than by asking `git --version`, because a fork per process is the thing being
/// removed.
///
/// # The identity lives in the template's own config
///
/// 53 sites spend two extra forks on `git config user.email`/`user.name` after
/// `init`, and those are NOT redundant with [`git_command`]'s `-c` pins: the
/// binary under test reads the value through `git::config_value`, and a `-c`
/// flag on the harness's own git never reaches it. Baking it into the template's
/// `.git/config` is the same values by a cheaper route. A fixture that wants a
/// DIFFERENT identity still sets it after the copy, and one whose subject is an
/// UNSET identity unsets it — `attribution.rs` already does exactly that.
fn git_init_template() -> Option<&'static Path> {
    static TEMPLATE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    TEMPLATE.get_or_init(build_git_init_template).as_deref()
}

/// Establish the template once per process, or report that this process could
/// not — see [`git_init_template`] for why the answer is an `Option`.
#[allow(clippy::print_stderr)]
fn build_git_init_template() -> Option<PathBuf> {
    let published = target_tmp().join(format!("git-init-template-{}", git_stamp()));
    if is_template(&published) {
        return Some(published);
    }
    let staging = target_tmp().join(format!(
        "git-init-template-{}.staging-{}",
        git_stamp(),
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).expect("create the template staging directory");
    fork_the_template_into(&staging);
    // Publish the `.git` itself rather than the work tree around it: what a
    // fixture copies is a repository directory, and lifting it here keeps
    // `init_repo` from having to know the template's internal layout.
    if let Err(error) = fs::rename(staging.join(".git"), &published) {
        // A FAILED RENAME IS NOT A REPORT THAT SOMEBODY ELSE WON (CLOUD-1832).
        // That is the LIKELY reading — `rename(2)` onto a non-empty directory
        // is `ENOTEMPTY` and the winner's copy is complete — but it is not the
        // only one. A `staging/.git` that was never created, a cross-device
        // error, a publish interrupted mid-flight: every one of them arrives
        // here, and returning the path unasked turns "I could not establish a
        // template" into "here is a template". `init_repo` then copies
        // whatever is at that path into a fixture, and the first thing to
        // notice is a `git add -A` three calls later reporting a directory
        // that is not a repository — a could-not-look wearing a result's
        // clothes, which is the one thing this repository refuses.
        //
        // So the loser's branch reports what it could not establish rather
        // than assuming it. It does NOT fail the case: the template is a
        // COST optimisation over a `git init` this module still knows how to
        // fork, so the sound answer is `None` and one fork for this process.
        // Failing here would red a suite whose subject is elsewhere for a
        // reason that is purely about how the fixture was built — the
        // measured CI failure of exactly that shape is why this is a
        // fallback and not an assertion.
        let listing = fs::read_dir(&published).map_or_else(
            |error| format!("unreadable: {error}"),
            |entries| {
                let mut names: Vec<String> = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                format!("[{}]", names.join(" "))
            },
        );
        let staged_git = staging.join(".git").is_dir();
        let _ = fs::remove_dir_all(&staging);
        if is_template(&published) {
            return Some(published);
        }
        // Diagnostics rather than a verdict: this names the state that the
        // assertion used to only assert, so the next run that hits it says
        // WHY instead of that it happened.
        //
        // `print_stderr` is allowed here and only here. The lint exists so the
        // BINARY never writes an ungoverned line to a channel its output
        // contract owns (house-style §6); this is the test harness, whose
        // stderr nextest already captures per process and prints on failure.
        // The alternative is a fallback that leaves no trace at all — a silent
        // change of route, which is the shape that made this defect expensive
        // to see. The allowance sits on the function rather than here because
        // a statement-scoped one does not reach this macro — clippy reports it
        // as an unused attribute.
        eprintln!(
            "note: the template publish at {} failed ({error}; staged .git \
                 present: {staged_git}) and {} is not a complete template \
                 (contents: {listing}), so this process forks `git init` per \
                 fixture instead — see CLOUD-1832",
            staging.display(),
            published.display(),
        );
        return None;
    }
    let _ = fs::remove_dir_all(&staging);
    Some(published)
}

/// Build the repository [`git_init_template`] publishes, by forking, in `dir`.
///
/// The route [`init_repo`] falls back to when no template could be established,
/// and the reason it is a named function rather than three lines inside that
/// `else`: the two `config` calls are not decoration. The template bakes the
/// identity into its own `config`, the binary under test reads it through
/// `git::config_value`, and a fallback that forked `init` alone would hand the
/// fixture an UNSET identity — a difference no fixture asks about and every
/// attribution case would feel. Same commands, same order, same values as the
/// staging build above.
pub(crate) fn fork_the_template_into(dir: &Path) {
    git_in(dir, &["init", "-q"]);
    git_in(dir, &["config", "user.email", "t@example.com"]);
    git_in(dir, &["config", "user.name", "t"]);
}

/// Whether `dir` is a published template this module may copy from.
///
/// Named once so the pre-check, the loser's branch and the post-copy check
/// cannot drift into disagreeing about what "published" means. Deliberately
/// cheap and structural rather than a `git` fork: the question is whether the
/// directory is a repository at all, and a fork per fixture is the cost this
/// template exists to remove.
///
/// # The two directory clauses are what an ARCHIVER drops, and CLOUD-1832 was
/// red without them
///
/// `HEAD` and `config` alone were the whole predicate, and they are the two
/// entries that survive a round trip through an archiver which skips empty
/// directories — because a fresh `init`'s `objects/` and `refs/` contain nothing
/// but empty directories (`branches`, `objects/info`, `objects/pack`,
/// `refs/heads`, `refs/tags`, the list [`copy_tree`]'s own note already carries).
/// So the damaged shape passed every gate CLOUD-1832 added, was copied into each
/// fixture, and git refused them all.
///
/// THAT IS THE MISSING REPRODUCTION, and it is a cache rather than the race
/// CLOUD-1832 looked for — which is why thirty cold-start races found nothing and
/// a wiped scratch root passed. `rust.yml`'s `musl` job restores
/// `target/x86_64-unknown-linux-musl/` from a cache `cache-warm-musl` wrote, on a
/// runner image whose `git` gives [`git_stamp`] the same answer, so the template
/// arrives pre-published from another machine and is adopted before any publish
/// runs. Measured: with those three directories removed from the local template,
/// the musl suite reds on exactly the `adjudicate_absent` cases CI named, with
/// `git ["add", "-A"] failed …: fatal: not a git repository` byte for byte; with
/// these clauses in, that same damaged template passes the suite.
///
/// It asks what git asks and not more. `description`, `hooks/` and `info/` stay
/// out because git opens a repository without any of them, so requiring one would
/// reject a template that works.
pub(crate) fn is_template(dir: &Path) -> bool {
    dir.join("HEAD").is_file()
        && dir.join("config").is_file()
        && dir.join("objects").is_dir()
        && dir.join("refs").is_dir()
}

/// The resolved `git` binary's length and mtime, as one path-safe token.
///
/// Falls back to a literal when `PATH` carries no `git` this can stat — the
/// template is then shared across git versions, which is the pre-existing
/// behaviour rather than a new hazard, and a machine with no `git` on `PATH`
/// fails at the first [`git_in`] regardless.
fn git_stamp() -> String {
    static STAMP: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let Some(path) = std::env::var_os("PATH") else {
            return "unresolved".to_owned();
        };
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("git");
            let Ok(meta) = fs::metadata(&candidate) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let secs = meta
                .modified()
                .ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |since| since.as_secs());
            return format!("{}-{secs}", meta.len());
        }
        "unresolved".to_owned()
    });
    STAMP.clone()
}

/// Copy `from` into `to` recursively — directories, including empty ones, and
/// Unix permission bits.
///
/// Hand-rolled rather than reaching for the walker the engine uses: that one
/// skips `.git` by default, which is the entire subject here. Files-only would
/// be wrong too — `objects/info`, `objects/pack`, `refs/heads`, `refs/tags` and
/// `branches` are all empty in a fresh `init`, and dropping them silently would
/// hand every fixture a repository git has to repair.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create the copy destination");
    for entry in fs::read_dir(from).expect("read the template directory") {
        let entry = entry.expect("a template entry");
        let target = to.join(entry.file_name());
        let kind = entry.file_type().expect("a template entry's type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy a template file");
        }
    }
}

/// Make `dir` a git repository.
///
/// Under `CARGO_TARGET_TMPDIR` this copies [`git_init_template`], at zero forks.
/// Anywhere else it forks a real `git init -q`, and the split is a correctness
/// requirement rather than a shortcut: a template published on one filesystem
/// carries THAT filesystem's answers for `core.filemode` and `core.ignorecase`
/// in its `config`, and the fixtures built by [`scratch_outside_tree`] live
/// under the system temp dir for reasons this module's header records.
///
/// # Panics
///
/// When `dir` is already a repository. `git init` over one is a silent re-init,
/// so the fork tolerated a double call; a copy would merge into the existing
/// `.git` instead and leave a fixture whose state neither caller intended.
pub(crate) fn init_repo(dir: &Path) {
    assert!(
        !dir.join(".git").exists(),
        "{} is already a repository: `git init` was a silent re-init and a \
         template copy is not, so a second initialisation has to be deliberate",
        dir.display()
    );
    if !dir.starts_with(target_tmp()) {
        git_in(dir, &["init", "-q"]);
        return;
    }
    let Some(template) = git_init_template() else {
        // No template could be established (CLOUD-1832): fork what it stands
        // for.
        fork_the_template_into(dir);
        return;
    };
    {
        copy_tree(template, &dir.join(".git"));
        // CHECK WHAT THE COPY PRODUCED, HERE (CLOUD-1832). `copy_tree` creates
        // its destination and copies whatever it finds, so a template that was
        // not a repository yields a `.git` that is not one either — silently.
        // The failure then surfaces wherever the fixture first runs git, which
        // in the measured case was `base_commit`'s `git add -A` reporting
        // "not a git repository" in a case about config loading. Asserting at
        // the point of creation is the difference between a defect that names
        // itself and one that reads as an unrelated test being broken.
        assert!(
            is_template(&dir.join(".git")),
            "copying the template {} into {} did not produce a repository — see \
             CLOUD-1832",
            template.display(),
            dir.display(),
        );
    }
}

/// Point `refs/remotes/origin/main` at `refs/heads/main` by writing the loose
/// ref.
///
/// That is the whole of what `git update-ref` does on a repository this young,
/// minus a reflog nothing in this workspace reads: all of `crates/batten/src`
/// mentions reflogs twice, to switch one off and to say there are none, and no
/// `<ref>@{n}` revision suffix exists in src or tests outside a policy string.
///
/// # Panics
///
/// When the branch ref is not loose, or is not 40 hex characters. Both are
/// ASSERTED rather than assumed: `packed-refs` is written by `pack-refs`, `gc`
/// and `clone`, none of which a [`Fixture`] runs — and [`git_command`]'s
/// `gc.auto=0` closes the auto path — so a fixture that ever packs its refs
/// should fail here by name rather than pin nothing and pass.
pub(crate) fn pin_origin_main(dir: &Path) {
    let git = dir.join(".git");
    assert!(
        !git.join("packed-refs").exists(),
        "{} has packed refs, so a loose-ref write would pin nothing",
        dir.display()
    );
    let head = fs::read_to_string(git.join("refs/heads/main"))
        .expect("the fixture's own branch ref, written by the commit above");
    let sha = head.trim();
    assert!(
        sha.len() == 40 && sha.chars().all(|it| it.is_ascii_hexdigit()),
        "{} does not hold one object id",
        git.join("refs/heads/main").display()
    );
    let remote = git.join("refs/remotes/origin");
    fs::create_dir_all(&remote).expect("create the remote ref directory");
    fs::write(remote.join("main"), format!("{sha}\n")).expect("write the base ref");
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
    /// A fixture at `target/tmp/<name>`, wiped first, and A REPOSITORY from the
    /// start (CLOUD-2059).
    ///
    /// Under `target/tmp` a directory with no `.git` of its own resolves to the
    /// checkout holding this build, so a fixture that skipped [`Fixture::git`]
    /// was judged against the real configuration and wrote the real `.git` —
    /// and [`Batten`]'s door now refuses that spawn. A fixture whose subject is
    /// "not a repository" is [`Fixture::at`] over [`scratch_outside_tree`].
    #[must_use]
    pub(crate) fn new(name: &str) -> Self {
        let dir = scratch(name);
        init_repo(&dir);
        Fixture { dir }
    }

    /// A fixture at an explicit directory, wiped first, and NOT a repository
    /// until [`Fixture::git`] says so: the caller chose the place, so the caller
    /// says what it is — a home beside a repository is the common case.
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

    /// Append to the config this fixture already wrote.
    ///
    /// For a table a fixture wants IN ADDITION to its own, where re-typing the
    /// whole config to add one section would put two spellings of it in the
    /// suite — [`declared_patterns`] is the case this exists for.
    pub(crate) fn config_append(self, contents: &str) -> Self {
        let path = self.dir.join("batten.toml");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        write(&self.dir, "batten.toml", &format!("{existing}\n{contents}"));
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

    /// Make the fixture a git repository.
    ///
    /// ZERO PROCESSES since CLOUD-1419: [`init_repo`] copies the template
    /// [`git_init_template`] publishes once per filesystem. The trace that
    /// motivated it counted **1,819 `init` processes, 4.49s** over one run, from
    /// 79 hand-rolled call sites plus this one — a call site spent roughly twenty
    /// times per run, which is why nothing here counts call sites.
    ///
    /// **THE NAME AND EVERY ONE OF ITS 176 CALL SITES ARE UNCHANGED**, and that
    /// is the point rather than a convenience: the cost moves and the coverage
    /// does not. Every case that built a repository still builds one, asserting
    /// exactly what it asserted before.
    ///
    /// The `branch -M main` that used to follow the fork is deleted rather than
    /// replaced by `-b main` (CLOUD-1290). [`git_command`] pins
    /// `-c init.defaultBranch=main` on every invocation, so the default already
    /// IS `main` and both the rename and the flag restate it. Measured on git
    /// 2.43.0 through those same pinned flags: `init -q` alone leaves `main`, and
    /// it is still `main` after the first commit — and the template is built
    /// through the same pinned invocation, so the copy inherits that default
    /// rather than re-deriving it.
    ///
    /// A no-op on a [`Fixture::new`], which is already one (CLOUD-2059); it
    /// initialises only a [`Fixture::at`] directory.
    #[must_use]
    pub(crate) fn git(self) -> Self {
        if !self.dir.join(".git").exists() {
            init_repo(&self.dir);
        }
        self
    }

    /// Commit everything present and pin `origin/main` to it — the trusted base
    /// ref a pull request is judged against.
    ///
    /// The `branch -M main` this used to spend a third process on is gone for
    /// [`Fixture::git`]'s reason, plus one this call site needs on its own: every
    /// `base_commit()` chain in the suite is preceded by `.git()`, checked with
    /// zero counterexamples, so there is no fixture arriving here through some
    /// other initialisation whose branch the rename was normalising.
    /// TWO PROCESSES, down from three: the `update-ref` is a loose-ref write now
    /// ([`pin_origin_main`], CLOUD-1419), which the trace counted at **1,020
    /// processes** over one run.
    ///
    /// `add -A` and `commit` STAY, and the reasons are checked rather than
    /// assumed. `commit -a` stages modifications and deletions of TRACKED files
    /// only, and a `base_commit()` runs over a tree whose files are all
    /// untracked, so it would commit nothing. `commit -- <pathspec>` is `--only`
    /// semantics and errors on a pathspec matching no known file. The one
    /// remaining single-fork route is writing the blob, tree and commit objects
    /// here, which is a third git implementation — and [`git_command`]'s own
    /// annotation forbids exactly that: fixtures are built by the reference
    /// implementation on purpose.
    #[must_use]
    pub(crate) fn base_commit(self) -> Self {
        git_in(&self.dir, &["add", "-A"]);
        git_in(&self.dir, &["commit", "-q", "-m", "base policy"]);
        pin_origin_main(&self.dir);
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

    /// Cut an ANNOTATED tag at `HEAD`, carrying a tagger header (CLOUD-1789).
    ///
    /// `-m` is what makes it annotated, and that is the whole point rather than
    /// a detail: a lightweight tag is a ref pointing straight at a commit and
    /// carries no identity at all, so a fixture built with `git tag <name>`
    /// would exercise the `Lightweight` arm while looking like it exercised the
    /// accountable one. The tagger is the template's `t <t@example.com>`, which
    /// is why a consumer of this builder declares that identity rather than
    /// `[attribution.identity]`'s.
    #[must_use]
    pub(crate) fn annotated_tag(self, name: &str) -> Self {
        git_in(&self.dir, &["tag", "-a", name, "-m", "release"]);
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
            // Advice, which is the default and what every fixture class wants:
            // a repairing class would make the boundary spawn this row's `fix`
            // in suites whose subject is something else entirely (CLOUD-1639).
            applicability: batten::verdict::Applicability::Advice,
            routes: vec![batten::verdict::Route {
                id: "read the authority".to_owned(),
                kind: batten::verdict::RouteKind::Document,
                target: "batten.toml".to_owned(),
                precondition: None,
            }],
            successor: None,
            withdrawn: None,
        })
        .collect()
}

/// The `[[pattern]]` registry, read out of the **committed** `batten.toml`.
///
/// **Derived rather than restated, for `install_module`'s own reason**
/// (CLOUD-1219). A fixture that copies the committed module in must resolve the
/// committed module's pattern references, and a table hand-written beside it
/// would drift — passing here while the real gate was broken, which is the
/// failure the copy exists to prevent.
///
/// The whole table rather than the subset a given module names: registry
/// equality runs in one direction for patterns — a module referencing an
/// undeclared id fails to load, while a declared row nothing references is
/// simply unused — so handing over everything is safe where `verdicts_in` had to
/// narrow.
///
/// # Panics
///
/// When the committed config cannot be read or does not parse; a fixture that
/// silently got an empty table would pass over a module whose references the
/// engine could never resolve.
#[must_use]
pub(crate) fn committed_patterns() -> Vec<batten::pattern::NamedPattern> {
    // The third of CLOUD-1291's re-reads, memoized on the same reasoning: the
    // committed file cannot change during a run, so the parse is repeated work
    // over identical bytes. The panics above stay panics — they fire on the first
    // call rather than on every one, which is where a reader wants them anyway.
    static PATTERNS: std::sync::LazyLock<Vec<batten::pattern::NamedPattern>> =
        std::sync::LazyLock::new(parse_committed_patterns);
    PATTERNS.clone()
}

fn parse_committed_patterns() -> Vec<batten::pattern::NamedPattern> {
    let text = std::fs::read_to_string(at_root("batten.toml")).expect("batten.toml is committed");
    // `Table` rather than `Value`: this crate's `toml` parses a bare `Value` as a
    // single VALUE, so a whole document comes back as "unexpected content,
    // expected nothing" — measured, and it reddened every case in the tier at
    // once with a message about the config rather than about the parse.
    let config: toml::Table = text.parse().expect("the committed config parses");
    let rows = config
        .get("pattern")
        .and_then(toml::Value::as_array)
        .expect("the committed config declares [[pattern]] rows");
    let patterns: Vec<batten::pattern::NamedPattern> = rows
        .iter()
        .map(|row| batten::pattern::NamedPattern {
            id: row
                .get("id")
                .and_then(toml::Value::as_str)
                .expect("every [[pattern]] row carries an id")
                .to_owned(),
            regex: row
                .get("regex")
                .and_then(toml::Value::as_str)
                .expect("every [[pattern]] row carries a regex")
                .to_owned(),
        })
        .collect();
    assert!(
        !patterns.is_empty(),
        "the pattern registry came back empty, so every module reference would fail to resolve"
    );
    patterns
}

/// Every verdict token the `.rego` modules under `root` name, as a registry.
///
/// **Derived from the fixtures rather than listed beside them**, because
/// registry equality runs in BOTH directions: a table naming a token the
/// modules under test do not raise is dead vocabulary and the load refuses it,
/// which is the check doing its job. A shared hand-written list therefore fails
/// every fixture except the one it was written for — measured, eleven of twelve.
///
/// Text-scanned rather than parsed: a fixture module is a literal in a test
/// file, the tokens are literals in it, and a Rego parser here would be a second
/// one to keep in step with the engine's.
///
/// **Recursive, over the file set the gates see — `batten::rules::tree_files`,
/// never a hand-rolled `read_dir` walk** (CLOUD-2035). Three callers pass the
/// checkout root, and an ignore-blind walk from there descends into `target/`,
/// where the running suite writes and removes other cases' fixture modules: 270
/// of the 406 `.rego` files one census found. That made a case's vocabulary a
/// function of which siblings had run, and let a stale fixture copy satisfy "the
/// committed table declares `<id>`" after the committed module stopped raising
/// it. A scratch fixture carries no `.gitignore`, so it is walked in full as
/// before.
// MUTANT vocabulary-reads-ignored-tree|s@batten::rules::tree_files(root).expect("the vocabulary root is walkable")@std::fs::read_dir(root).into_iter().flatten().flatten().flat_map(\x7cdir\x7c std::fs::read_dir(dir.path()).into_iter().flatten().flatten().map(move \x7cfile\x7c format!("{}/{}", dir.file_name().to_string_lossy(), file.file_name().to_string_lossy()))).collect::<Vec<_>>()@|the_declared_vocabulary_never_reads_an_ignored_directory
#[must_use]
pub(crate) fn verdicts_in(root: &Path) -> Vec<batten::verdict::DeclaredVerdict> {
    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // An absent root declares nothing, as the `read_dir` walk it replaces did; an
    // unreadable PRESENT one is loud, since an empty registry would pass a case
    // asserting that some token is declared nowhere.
    let files = if root.exists() {
        batten::rules::tree_files(root).expect("the vocabulary root is walkable")
    } else {
        Vec::new()
    };
    for relative in files {
        if Path::new(&relative)
            .extension()
            .is_none_or(|ext| ext != "rego")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(&relative)) else {
            continue;
        };
        found.extend(tokens_in(&text));
    }
    // A token this BINARY vendors is already in the registry, so declaring it
    // again is the collision `check` refuses (CLOUD-2089) — the binary's
    // definition is the one that renders, so the row would be dead. A fixture module raising a vendored class is a legitimate thing to
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
/// `policy/verdict-routes-resolve.rego` carries `x probe probex` in six of them — and
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
            // THE SHAPE IS THE ARITY, NOT A PREFIX (CLOUD-1284). `V-` is gone,
            // so what distinguishes a raised class from anything else in this
            // position is that it is exactly three lowercase words. That is also
            // what keeps the bound this function's doc comment claims: a `test_`
            // rule's fixture token — `x probe probex`, `probe`, `one` — is not three words,
            // so it is still filtered out rather than declared as dead
            // vocabulary the load would then refuse.
            let words: Vec<&str> = token.split(' ').collect();
            let shaped = words.len() == 3
                && words
                    .iter()
                    .all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase()));
            if shaped {
                found.push(token.to_owned());
            }
        }
    }
    found
}

/// The text of every attribute in `source` that mentions `lint`, with the
/// 1-based line it starts on.
///
/// A bounded scan rather than a parse: an attribute opens at `#[` or `#![` and
/// closes at the first `)]` before the NEXT opener. That bound is what makes it
/// safe over a file that discusses annotations in prose and names a lint in a
/// `const` — an unbounded search would stitch a doc comment to some later
/// attribute's closer and report a finding about neither. Measured on
/// `spawn_census.rs`: the first version of that scan flagged its own inner
/// `allow` line.
///
/// Enough to tell an `expect` from an `allow` and to find a `reason`, which is
/// all any caller asks. The alternative is a proc-macro parse of the whole crate
/// to check a property clippy has already enforced the hard half of.
///
/// **This lives here because there are two inventories now** — the spawn census
/// over `disallowed_types` and the delay inventory over `disallowed_methods`
/// (CLOUD-1177) — and two copies of a scanner are two authorities that can
/// disagree about what an annotation IS. It is parameterized by the lint for
/// exactly that reason.
pub(crate) fn annotations_naming(source: &str, lint: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = source[cursor..].find("#[") {
        // `#![` opens one character earlier; take the wider span so an inner
        // attribute is not read as a bare one.
        let mut open = cursor + offset;
        if open > 0 && source.as_bytes()[open - 1] == b'!' && open > 1 {
            open -= 1;
        }
        cursor = open + 2;
        let rest = &source[open..];
        let Some(close) = rest.find(")]") else {
            break;
        };
        // The next opener bounds this one. An attribute with no `(` — a bare
        // `#[test]`, or an annotation named without its arguments in a doc
        // comment — has no closer of its own, so its "closer" belongs to
        // something further down and it is skipped.
        let next = rest[2..].find("#[").map_or(rest.len(), |at| at + 2);
        if close + 2 > next {
            continue;
        }
        // AN ATTRIBUTE INSIDE A COMMENT IS PROSE, NOT AN INVENTORY ROW.
        //
        // The bound above handles a doc comment naming an annotation WITHOUT its
        // arguments — that has no closer of its own and is skipped. It does not
        // handle one that spells it in full, and that is the shape a module
        // explaining why its spawn was retired naturally writes: "this was a
        // child process under `#[expect(clippy::disallowed_types)]`". Seven such
        // sentences read as seven annotations carrying no `reason`, so the census
        // reported the prose that RECORDS a retirement as a row that had not
        // been decided.
        //
        // Keyed on the line's own opening rather than on a span search: a
        // comment marker anywhere earlier in the file says nothing about this
        // line, and the question is only ever whether THIS attribute is
        // commented out.
        let line_start = source[..open].rfind('\n').map_or(0, |at| at + 1);
        let before = &source[line_start..open];
        if before.trim_start().starts_with("//") {
            continue;
        }
        // NOR IS ONE INSIDE A STRING LITERAL. `spawn_widening.rs` builds fixture
        // MODULES as string constants, so the escape a case hands the gate under
        // test is spelled in full inside quotes — and the census read three of
        // its own fixtures as undecided rows. An odd number of quotes before the
        // opener means this `#[` is inside one; escaped quotes do not open or
        // close, so they are skipped rather than counted.
        let quotes = before
            .char_indices()
            .filter(|&(at, ch)| ch == '"' && !before[..at].ends_with('\\'))
            .count();
        if quotes % 2 == 1 {
            continue;
        }
        // AND AN ATTRIBUTE THAT IS NOT A LINT LEVEL IS NOT THIS INVENTORY'S.
        //
        // The span bound above stitches a BARE attribute — `#[test]`, which has
        // no closer of its own — to the next `)]` further down, so a case whose
        // body mentions the lint made its own `#[test]` a finding. Requiring the
        // opener to be one of the four level words is what the callers actually
        // mean by an annotation, and it decides in one comparison rather than by
        // guessing where a bare attribute ends.
        let opens_a_level = ["expect(", "allow(", "warn(", "deny("]
            .iter()
            .any(|level| rest[2..].trim_start().starts_with(level));
        if !opens_a_level {
            continue;
        }
        let attribute = &rest[..close + 2];
        if attribute.contains(lint) {
            found.push((source[..open].lines().count() + 1, attribute.to_owned()));
        }
    }
    found
}

/// The `reason` an annotation carries, as the author wrote it rather than as the
/// source spells it.
///
/// Escape-aware in two directions, and both are load-bearing rather than
/// tidiness. A `\"` inside the reason is not its terminator — a naive
/// split-on-the-next-quote truncates there, and a delay verdict that quotes a
/// literal before naming its bound would lose the bound and read as a reason
/// that named nothing. A `\` at end of line is a continuation: Rust eats the
/// newline and the indent that follows it, so joining them here is what lets a
/// wrapped reason be read as the one sentence it is.
pub(crate) fn annotation_reason(attribute: &str) -> Option<String> {
    let (_, rest) = attribute.split_once("reason = \"")?;
    let mut reason = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Some(reason),
            '\\' => match chars.next()? {
                '\n' => while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {},
                other => reason.push(other),
            },
            other => reason.push(other),
        }
    }
    None
}

/// Every Rust source file an `--all-targets` lint run reaches: the library and
/// its test targets.
///
/// `--all-targets` is what `mise run lint:clippy` passes, so a test target's
/// annotation is as much an inventory row as the library's.
///
/// # Panics
///
/// When the sweep finds too few files to be this crate — a silently empty
/// corpus is what makes every shape assertion over it pass vacuously.
#[must_use]
pub(crate) fn rust_sources() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in ["crates/batten/src", "crates/batten/tests"] {
        collect_rust(&at_root(dir), &mut found);
    }
    found.sort();
    assert!(
        found.len() > 40,
        "the source sweep found {} files, which is too few to be the crate",
        found.len()
    );
    found
}

fn collect_rust(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// The schema node a config column resolves to, or `None` (CLOUD-1643).
///
/// `path` is spelled as `batten::config::TEXT_CENSUS` spells one: split on `.`,
/// a segment ending `[]` steps into `properties[key]` and then `items`, and every
/// step dereferences `$ref` into `$defs` and an `anyOf` with exactly one
/// non-null branch into that branch.
pub(crate) fn schema_leaf<'a>(
    schema: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    fn resolve<'a>(
        schema: &'a serde_json::Value,
        mut node: &'a serde_json::Value,
    ) -> Option<&'a serde_json::Value> {
        // Bounded, so a self-referencing `$def` cannot spin.
        for _ in 0..64 {
            if let Some(name) = node
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
            {
                node = schema.get("$defs")?.get(name)?;
                continue;
            }
            if let Some(branches) = node.get("anyOf").and_then(serde_json::Value::as_array) {
                let non_null: Vec<&serde_json::Value> = branches
                    .iter()
                    .filter(|branch| branch.get("type") != Some(&serde_json::json!("null")))
                    .collect();
                if let [only] = non_null.as_slice() {
                    node = only;
                    continue;
                }
            }
            return Some(node);
        }
        None
    }
    let mut node = resolve(schema, schema)?;
    for segment in path.split('.') {
        let (key, element) = match segment.strip_suffix("[]") {
            Some(key) => (key, true),
            None => (segment, false),
        };
        node = resolve(schema, node.get("properties")?.get(key)?)?;
        if element {
            node = resolve(schema, node.get("items")?)?;
        }
    }
    Some(node)
}
