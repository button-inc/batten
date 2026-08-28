//! The paired latency measurement, and the predicate that decides whether to
//! take it (CLOUD-172, CLOUD-697, CLOUD-875).
//!
//! # Why both arms in one run
//!
//! Wall clock is the only metric available — `mise registry valgrind` answers
//! "tool not found in registry", so it cannot be pinned, and `no-source-built-tool`
//! forbids compiling one. A shared runner's absolute wall clock is exactly the
//! number CLOUD-172 warns "both hides real regressions and invents fake ones".
//! The fix is not a better clock, it is a better experiment: build BOTH binaries
//! and measure them on the same machine within the same few seconds, so whatever
//! that machine is doing to one arm it is doing to the other, and the comparison
//! divides the noise out. Measuring the base on some other run, or reading it out
//! of the recorded series, would put a machine change inside the number.
//!
//! # The skip is a correctness argument, not an economy
//!
//! `verify` is the inner loop of every landing lap, and `mem:workflow/agent-fanout`
//! measures that shortening `verify` buys more parallelism than adding sessions —
//! two release builds per lap would be a throughput tax on the whole fleet. But
//! the reason it is safe to skip is not the cost: **a commit that cannot change
//! what gets INVOKED cannot have made the invocation slower.**
//!
//! So the predicate is only as sound as its reading of "what gets invoked", and
//! that reading has been wrong twice, the same way both times.
//!
//! - **CLOUD-697.** `wired` joined the pair and the skip still described the
//!   binary alone, so a commit touching only the launcher changed the measured
//!   cost and skipped the gate it needed.
//! - **CLOUD-875, this module's own reason.** Four arms (`noop`, `check`, `hook`,
//!   `passthrough`) run in a pinned one-rule fixture, so crate source and the
//!   manifests bound them. **`wired` does not** — it adjudicates against the
//!   repository's own committed config, which is the whole of its distinction
//!   from `hook`. That config was not in the set, and neither was any path a
//!   `policy` row registers. Measured on the branch that landed CLOUD-843's first
//!   migration: toggling one row moved `wired` from 5.8 ms to 9.3 ms, and
//!   `perf-gate` refused it at 1.462x against a 1.30x threshold — but only
//!   because that branch happened to carry an unrelated test-fixture edit. Strip
//!   that one incidental file and a 60% regression on the mediated call ships
//!   with the gate reporting "nothing measured". Wave 1 lands ~80 changes whose
//!   terminal shape is exactly a config row plus a module and no crate source.
//!
//! Both fixes have the same form, and it is the one this module exists to make
//! cheap: **the set is DERIVED, never restated.** A registered module's path is a
//! fact the config already holds, so the predicate asks the config. A shell skip
//! could not, which is why the predicate is here.
//!
//! # Why this is Rust rather than a task
//!
//! Its predecessor was `mise-tasks/perf-pair.sh`, retired under CLOUD-1059:
//! that campaign refuses maintaining an authored shell rule in place, and its one
//! route is to port the predicate and delete the file. The measurement moved with
//! it rather than staying behind in a task-manifest body, because bash relocated
//! into the manifest is the same bash under a filename the rule does not watch.
//!
//! # The effect class, and the contract the caller still reads
//!
//! `Cost::Effect` on `Surface::VerifyOnly`: it builds two release binaries,
//! materialises a detached worktree and spawns a benchmark runner, and none of
//! that may EVER be reachable from the mediated call. The skip predicate itself
//! is pure and is exposed separately, so the decision stays exercisable without a
//! build — the same split `perf`/`perf-assert` keeps, and what lets CLOUD-875's
//! cases be asserted at all.
//!
//! `mise-tasks/perf-gate.sh` composes this with `perf-compare` and is itself
//! frozen, so its reading is a contract rather than a convention: **a skip prints
//! one human line, no `arm=` record, and exits 0**; a could-not-look exits
//! non-zero and explains itself on stderr. `perf-gate` distinguishes the two by
//! looking for `^arm=`, never by a second exit code.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::hook::{Event, Harness, WiringFile};

/// The base a comparison is taken against, and the run counts.
///
/// Environment rather than flags, because the caller that sets them is CI and
/// the spelling it already exports is `BENCH_*`. A second spelling here would be
/// a second authority over what the workflow says.
const BASE_REF_VAR: &str = "BENCH_BASE_REF";
const RUNS_VAR: &str = "BENCH_RUNS";
const WARMUP_VAR: &str = "BENCH_WARMUP";
const OUT_DIR_VAR: &str = "BENCH_OUT_DIR";

const DEFAULT_BASE_REF: &str = "origin/main";
const DEFAULT_RUNS: &str = "100";
const DEFAULT_WARMUP: &str = "10";
const DEFAULT_OUT_DIR: &str = "target/perf";

/// What a diff has to touch for the measurement to be worth taking.
///
/// The BINARY's inputs are a property of the crate and belong to the core: crate
/// source, either manifest layer, and the lockfile that pins what they build
/// against. A path outside that set cannot change a byte of the artifact.
const BINARY_PREFIXES: &[&str] = &["crates/"];
const BINARY_PATHS: &[&str] = &["Cargo.toml", "Cargo.lock"];

/// The decision, and what it was decided over.
///
/// It carries the consulted set rather than only the verdict, because the skip
/// message has to be able to name it. The predecessor's line claimed "neither the
/// binary nor its wiring changed" while having consulted neither the config nor
/// the modules — a sentence wider than its evidence, which is how the next
/// surface added outside the set stays silent instead of visible (CLOUD-875 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Whether the pair should be measured.
    pub measure: bool,
    /// Every path or path prefix the predicate consulted, sorted.
    pub consulted: Vec<String>,
    /// The consulted entries this diff touched, sorted. Empty exactly when
    /// `measure` is false.
    pub touched: Vec<String>,
}

impl Selection {
    /// The skip line, naming the set it consulted.
    ///
    /// Pointer-only (non-negotiable rule 4): the entries are path prefixes the
    /// predicate holds, never a line of anybody's diff.
    #[must_use]
    pub fn skip_message(&self, base: &str, head: &str) -> String {
        format!(
            "perf-pair: nothing between {} and {} touched the {} path(s) that can change what gets invoked ({}). Nothing measured.",
            short(base),
            short(head),
            self.consulted.len(),
            self.consulted.join(", ")
        )
    }
}

fn short(sha: &str) -> &str {
    sha.get(..8).unwrap_or(sha)
}

/// Decide whether a diff can have changed what gets invoked.
///
/// Pure over its inputs — no spawn, no clock, no build — which is what keeps the
/// decision exercisable without paying for the measurement it gates.
#[must_use]
pub fn select(changed: &BTreeSet<String>, wiring: &[String], registered: &[String]) -> Selection {
    let mut consulted: BTreeSet<String> = BTreeSet::new();
    for prefix in BINARY_PREFIXES {
        consulted.insert((*prefix).to_owned());
    }
    for path in BINARY_PATHS {
        consulted.insert((*path).to_owned());
    }
    for path in wiring.iter().chain(registered) {
        consulted.insert(path.trim_end_matches('/').to_owned());
    }

    // A consulted entry matches a changed path when it IS that path or is a
    // directory prefix of it. Prefix rather than equality because both halves
    // need it — `crates/` is a tree, and a `bundle` root is a directory whose
    // contents are what the module is compiled from.
    let touched: Vec<String> = consulted
        .iter()
        .filter(|entry| changed.iter().any(|path| matches(entry, path)))
        .cloned()
        .collect();

    Selection {
        measure: !touched.is_empty(),
        consulted: consulted.into_iter().collect(),
        touched,
    }
}

/// Whether a consulted entry covers a changed path.
fn matches(entry: &str, path: &str) -> bool {
    if path == entry {
        return true;
    }
    // The separator is what keeps `crates` from matching `crates-vendored/x`: a
    // prefix test without it widens the predicate silently, which is the failure
    // mode this whole module is about.
    let prefix = if entry.ends_with('/') {
        entry.to_owned()
    } else {
        format!("{entry}/")
    };
    path.starts_with(&prefix)
}

/// Every path the loaded config registers as policy — CLOUD-875's derived half.
///
/// Both spellings CLOUD-833 admits: a row's `module`, and a row's `bundle` root.
/// A bundle is returned as its ROOT rather than as its contents, because
/// [`matches`] treats an entry as a directory prefix — so a file added under it
/// tomorrow is covered by the entry written today, which is what deriving buys
/// over listing.
///
/// A `preset` row registers nothing here, on purpose: a vendored preset is
/// compiled into the binary, so a change to one is already a change to `crates/`.
/// Including it would be a second, weaker spelling of a path already covered.
#[must_use]
pub fn registered_paths(rules: &[crate::rules::Rule]) -> Vec<String> {
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for rule in rules {
        if let Some(module) = rule.module.as_ref() {
            paths.insert(module.clone());
        }
        if let Some(bundle) = rule.bundle.as_ref() {
            paths.insert(bundle.trim_end_matches('/').to_owned());
        }
    }
    paths.into_iter().collect()
}

/// The paths whose change alters what the WIRED arm invokes.
///
/// A harness fact, not a consumer one, which is why it can be read from the core
/// at all: [`Harness::wiring`] already carries each host's settings file, for the
/// reason `TranscriptConfig` states one layer over — *which* file a host writes
/// is a property of the harness, never of any one repository, so non-negotiable
/// rule 1 holds. Deriving it here rather than spelling a path is also what makes
/// the set correct for a repository wired to a different host.
#[must_use]
pub fn wiring_paths() -> Vec<String> {
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for harness in Harness::ALL {
        let Some(wiring) = harness.wiring() else {
            continue;
        };
        match wiring.file {
            WiringFile::Key { path, .. } | WiringFile::Whole(path) => {
                paths.insert(path.to_owned());
                // The directory beside the settings file: a host that routes
                // through a launcher script keeps it there, and CLOUD-697 is the
                // measured instance of a commit touching only that and skipping
                // the gate it needed.
                if let Some((dir, _)) = path.rsplit_once('/') {
                    paths.insert(dir.to_owned());
                }
            }
        }
    }
    paths.into_iter().collect()
}

// ---------------------------------------------------------------------------
// The measurement.
// ---------------------------------------------------------------------------

/// One arm of the plan: its id, the envelope it is handed, and the two commands.
///
/// Named rather than left as a tuple because the shape is read at both ends —
/// the plan below and the loop that runs it — and a four-element tuple is where
/// an argument order silently swaps.
type Arm = (&'static str, Option<PathBuf>, Vec<String>, Vec<String>);

/// One arm's measured record for one path.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub arm: &'static str,
    pub path: String,
    pub p50: f64,
    pub p95: f64,
    pub mean: f64,
    pub runs: usize,
}

impl std::fmt::Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Same units, same rounding and same field order as `perf`, plus the
        // `arm=` field that makes a record half of a pair. `perf-compare` parses
        // this and `perf-gate` greps `^arm=`, so the shape is a CONTRACT with two
        // frozen callers rather than a rendering choice.
        write!(
            f,
            "arm={} path={} p50={} p95={} mean={} runs={}",
            self.arm,
            self.path,
            round2(self.p50),
            round2(self.p95),
            round2(self.mean),
            self.runs
        )
    }
}

fn round2(ms: f64) -> f64 {
    (ms * 100.0).round() / 100.0
}

/// What the caller asked for.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Measure HEAD against ITSELF: two copies of one binary, whose ratio is by
    /// construction 1.0 plus pure noise. That is how `perf-compare`'s threshold
    /// was derived, and the flag exists so the noise floor stays something anyone
    /// can re-measure rather than a number in a comment.
    pub null: bool,
}

/// What a run produced: records, or the reason there are none.
#[derive(Debug)]
pub enum Outcome {
    /// The pair was measured.
    Measured(Vec<Record>),
    /// The measurement was not worth taking, and this says what was consulted.
    /// **Exit 0**, and no `arm=` line — `perf-gate` reads exactly that.
    Skipped(String),
}

/// Run the paired measurement, or explain why it was not worth taking.
///
/// # Errors
///
/// Every failure here is a property of the CHECKOUT rather than a verdict about
/// the branch — an unresolvable base, a build that failed, a missing instrument,
/// a worktree that cannot be created — and each is an error rather than an empty
/// measurement. A gate that answers "regression" because its own setup broke is
/// worse than one that says it could not look.
pub fn pair(repo: &Path, options: Options) -> Result<Outcome> {
    // ABSOLUTE FROM HERE DOWN, and it is a correctness requirement rather than
    // hygiene: every arm is invoked from the pinned fixture directory, so a
    // relative root makes each binary path resolve against the fixture and not
    // against the checkout. Measured on this port's first end-to-end run —
    // hyperfine answered "Failed to run command './target/release/batten
    // --help': No such file or directory", which the gate correctly reported as
    // a could-not-look rather than as a verdict.
    let repo = &repo
        .canonicalize()
        .with_context(|| format!("perf-pair: could not resolve {}", repo.display()))?;

    let head_sha = crate::git::head_commit(repo)?;
    let base_ref = env_or(BASE_REF_VAR, DEFAULT_BASE_REF);

    let base_sha = if options.null {
        head_sha.clone()
    } else {
        base_commit(repo, &base_ref)?
    };

    if !options.null {
        // A branch that has not committed anything yet IS its merge base, so
        // there is nothing to have regressed and the two arms would be the same
        // bytes. Its own answer rather than a case of the skip, because the diff
        // is empty for a different reason — nothing was authored, not "nothing
        // that matters".
        if base_sha == head_sha {
            return Ok(Outcome::Skipped(format!(
                "perf-pair: HEAD is its own merge base ({}) — no change to compare. Nothing measured.",
                short(&head_sha)
            )));
        }

        let changed = changed_between(repo, &base_sha)?;
        let config = crate::config::load(&repo.join("batten.toml"))
            .context("perf-pair: the committed config is what the wired arm adjudicates against, so a config that will not load is a could-not-look rather than a skip")?;
        let mut registered = registered_paths(&config.rules);
        // The authority itself, beside the modules it registers. `wired`'s whole
        // distinction from `hook` is that it reads this file.
        registered.push(String::from("batten.toml"));
        let selection = select(&changed, &wiring_paths(), &registered);
        if !selection.measure {
            return Ok(Outcome::Skipped(
                selection.skip_message(&base_sha, &head_sha),
            ));
        }
    }

    measure(repo, options, &base_sha).map(Outcome::Measured)
}

/// The base to build the comparison arm from, or a could-not-look naming the
/// remedy.
///
/// Through `gix` rather than a spawned `git`, and that is a REQUIREMENT rather
/// than a preference: `ancestry-decides-nothing` refuses a reachability verb in a
/// spawned argv, because that is the surface a merged-ness answer would hide in.
/// Selecting which commit to build is range selection, which `git::merge_base`
/// documents and which the library call keeps structural.
fn base_commit(repo: &Path, base_ref: &str) -> Result<String> {
    let found = crate::git::merge_base(repo, base_ref)?;
    found.ok_or_else(|| {
        anyhow::anyhow!(
            "perf-pair: no common history between HEAD and {base_ref} — fetch it first (`git fetch origin main`). No measurement."
        )
    })
}

/// What this branch changed against the base.
///
/// [`crate::git::base_delta`] rather than a spawned diff, and the difference is
/// not only which library runs it: the delta is taken against the WORKING TREE,
/// which is what `cargo build` is about to compile. The predecessor compared
/// `base..HEAD`, so an uncommitted change could move the measured cost while the
/// skip looked only at what was committed.
fn changed_between(repo: &Path, base: &str) -> Result<BTreeSet<String>> {
    let delta = crate::git::base_delta(repo, base, &[String::from("**")])?.ok_or_else(|| {
        anyhow::anyhow!(
            "perf-pair: could not diff the base against this tree, so the skip could not be decided. No measurement."
        )
    })?;
    Ok(delta
        .added
        .into_iter()
        .chain(delta.edited)
        .chain(delta.deleted)
        .collect())
}

fn env_or(var: &str, fallback: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| fallback.to_owned())
}

/// Whether a program resolves on PATH.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Run a program to completion in `dir`, returning whether it succeeded.
fn run(dir: &Path, program: &str, args: &[String], env: &[(String, String)]) -> Result<bool> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the two release builds and the benchmark runner ARE this module's effect (CLOUD-875). `perf-pair` cannot measure a binary without building it, and Surface::VerifyOnly is the boundary that keeps that off the mediated call"
    )]
    let mut command = std::process::Command::new(program);
    command.args(args).current_dir(dir);
    for (key, value) in env {
        command.env(key, value);
    }
    let status = command
        .status()
        .with_context(|| format!("perf-pair: could not run {program}"))?;
    Ok(status.success())
}

/// The out directory this run owns, emptied first so a previous run's records
/// can never be read as this one's.
fn out_dir(repo: &Path) -> Result<PathBuf> {
    let dir = repo.join(env_or(OUT_DIR_VAR, DEFAULT_OUT_DIR)).join("pair");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("perf-pair: could not clear {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("perf-pair: could not create {}", dir.display()))?;
    dir.canonicalize()
        .with_context(|| format!("perf-pair: could not resolve {}", dir.display()))
}

/// Build `-p batten --release` in `dir`, with an optional target directory.
fn build(dir: &Path, target_dir: Option<&Path>, what: &str) -> Result<()> {
    let args: Vec<String> = ["build", "--quiet", "--release", "-p", "batten"]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
    let env: Vec<(String, String)> = target_dir
        .map(|dir| {
            vec![(
                String::from("CARGO_TARGET_DIR"),
                dir.to_string_lossy().into_owned(),
            )]
        })
        .unwrap_or_default();
    if !run(dir, "cargo", &args, &env)? {
        bail!(
            "perf-pair: the {what} release build failed, so there is nothing to compare. No measurement."
        );
    }
    Ok(())
}

/// The command this tree's harness settings file actually invokes, with this
/// arm's tree and binary substituted in.
///
/// WHICH file that is comes from [`Harness::wiring`] rather than being spelled
/// here, and non-negotiable rule 1 is the reason as much as correctness is: a
/// path named in this module would be a second authority over one the harness
/// table already owns, and `no_artifact_name_reaches_the_core` computes exactly
/// that.
///
/// DERIVED PER TREE rather than hardcoded, and that is what makes the arm survive
/// a change to the wiring itself. CLOUD-824 was exactly that: the head tree
/// invokes the binary directly while the base tree still routed through a
/// launcher script, so a hardcoded launcher path could not measure the pair at
/// all — and did not, which is how it was found.
fn wired_command(tree: &Path, bin: &Path) -> Result<Vec<String>> {
    let harness = Harness::ClaudeCode;
    let Some(wiring) = harness.wiring() else {
        bail!(
            "perf-pair: this harness registers no wiring file, so the wired pair cannot be measured. No measurement."
        );
    };
    let (path, key) = match wiring.file {
        WiringFile::Key { path, key } => (path, Some(key)),
        WiringFile::Whole(path) => (path, None),
    };
    let settings = tree.join(path);
    let text = std::fs::read_to_string(&settings).with_context(|| {
        format!(
            "perf-pair: {} wires no settings the wired pair can read. No measurement.",
            settings.display()
        )
    })?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("perf-pair: {} did not parse.", settings.display()))?;
    let hooks = key.map_or(Some(&parsed), |key| parsed.get(key));
    let spelling = wiring
        .spellings
        .iter()
        .find(|(event, _)| *event == Event::PreTool)
        .map_or("PreToolUse", |(_, name)| *name);

    let command = hooks
        .and_then(|hooks| hooks.get(spelling))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("hooks").and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(|entry| entry.get("command").and_then(serde_json::Value::as_str))
        .find(|command| command.contains("batten"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "perf-pair: {} wires no {spelling} command reaching batten, so the wired pair cannot be measured. No measurement.",
                tree.display()
            )
        })?;

    // The settings file spells the project dir as a variable the harness expands.
    let tree_text = tree.to_string_lossy().into_owned();
    let bin_text = bin.to_string_lossy().into_owned();
    let command = command.replace("$CLAUDE_PROJECT_DIR", &tree_text);

    // A wiring that names the BINARY rather than a path resolves on PATH, and
    // measuring whatever PATH happens to hold would compare two arms against one
    // binary. Each arm is pinned to the build made for it.
    let mut argv: Vec<String> = command.split_whitespace().map(ToOwned::to_owned).collect();
    if argv.first().is_some_and(|first| first == "batten") {
        argv[0].clone_from(&bin_text);
    }

    // `env -C` IS LOAD-BEARING, and it is what replaced the launcher's `cd`.
    // `wired`'s whole distinction from `hook` is that it adjudicates against the
    // REPOSITORY's own config, and since CLOUD-824 the binary resolves that from
    // its cwd. A head arm left in the fixture repo would measure a smaller policy
    // and read as a speedup.
    let mut full = vec![
        String::from("env"),
        format!("-C{tree_text}"),
        format!("CLAUDE_PROJECT_DIR={tree_text}"),
        format!("BATTEN_BIN={bin_text}"),
    ];
    full.extend(argv);
    Ok(full)
}

/// Take the measurement.
fn measure(repo: &Path, options: Options, base_sha: &str) -> Result<Vec<Record>> {
    // THE INSTRUMENT IS REQUIRED HERE, NOT AT THE TOP, and the ordering is the
    // predicate's own logic rather than tidiness: a lap that is going to SKIP
    // needs no benchmark runner, so demanding one before the skip is decided
    // turns "nothing to measure" — a pass — into "could not look".
    //
    // Measured on CI: the `windows` job installs no hyperfine, so the top-of-
    // function check made `a_skip_exits_zero_and_prints_no_record` fail there and
    // pass everywhere else. The predecessor shell task checked in the same wrong
    // order and got away with it because nothing exercised the skip on a host
    // without the tool.
    for tool in ["hyperfine"] {
        if which(tool).is_none() {
            bail!(
                "perf-pair: {tool} is not installed — run `mise install`; it is pinned in the manifest."
            );
        }
    }

    let out = out_dir(repo)?;

    build(repo, None, "head")?;
    let head_bin = repo.join("target/release/batten");

    let (base_bin, base_tree) = if options.null {
        // The null experiment: the same bytes as both arms. COPIED rather than
        // aliased so hyperfine sees two distinct commands and cannot
        // short-circuit anything, and so the two arms differ in exactly nothing.
        let copy = out.join("batten-null");
        std::fs::copy(&head_bin, &copy).context("perf-pair: could not copy the null arm")?;
        (copy, repo.to_path_buf())
    } else {
        // MATERIALISED, NOT A WORKTREE, and that retires a measured defect rather
        // than guarding it. `git worktree add` leaves an ADMIN ENTRY under the git
        // dir, and this gate is killed routinely — `land` races it against
        // `main-watch` and kills the loser, and the harness kills a foreground
        // command at ~2 minutes. Either left the entry behind with its directory
        // gone, after which `git worktree add` refused that path forever and every
        // later `verify` in the clone failed at "could not create a worktree",
        // having measured nothing (2026-08-14). The predecessor answered with a
        // prune-before-add recovery; writing the tree out instead means there is
        // no admin entry to leak, so a killed run leaves a stale directory this
        // function's own `remove_dir_all` clears on the next run.
        let base_tree = out.join("base-tree");
        crate::git::materialize_rev(repo, base_sha, &base_tree)?;
        // Its own target dir: sharing the main one would make the two builds
        // evict each other's artifacts on every lap, and would race the
        // target-dir lock against whatever else `verify` is running.
        let base_target = out.join("base-target");
        build(&base_tree, Some(&base_target), "base")?;
        (base_target.join("release/batten"), base_tree)
    };

    arms(repo, &out, &base_bin, &head_bin, &base_tree)
}

/// Every arm, measured in the pinned fixture.
///
/// EVERY ARM RUNS IN THE FIXTURE REPO, never in this checkout, and that is a
/// correctness requirement rather than tidiness. The two arms are different
/// binaries: the base one predates whatever this branch changed, so a config key
/// added by HEAD is a key the BASE binary rejects at load. Measured: with the
/// arms run from the repo root, a head that added `[worktree]` to the committed
/// config made the base binary exit 1 on "unknown field", hyperfine abort on its
/// first warmup, and the whole gate answer could-not-look — produced by the
/// gate's own setup, on exactly the class of change it exists to judge.
fn arms(
    repo: &Path,
    out: &Path,
    base_bin: &Path,
    head_bin: &Path,
    base_tree: &Path,
) -> Result<Vec<Record>> {
    let fixture = repo.join("crates/batten/tests/fixtures/repos/forbid-clean");
    let hooks = repo.join("crates/batten/tests/fixtures/hooks");
    let check_repo = out.join("check-repo");
    std::fs::create_dir_all(&check_repo).context("perf-pair: could not stage the fixture")?;
    for (from, to) in [("batten.toml.in", "batten.toml"), ("lib.rs.in", "lib.rs")] {
        std::fs::copy(fixture.join(from), check_repo.join(to))
            .with_context(|| format!("perf-pair: could not stage {to}"))?;
    }

    // A HERMETIC STATE ROOT, mandatory rather than tidy: the post-tool arm
    // writes, and this task runs the BASE and HEAD binaries against one tree, so
    // a shared ambient root would leave the store in a state that depends on
    // which arm ran first — making the ratio a fact about ordering.
    let state = out.join("state");
    let state_text = state.to_string_lossy().into_owned();

    let base = base_bin.to_string_lossy().into_owned();
    let head = head_bin.to_string_lossy().into_owned();
    let hook_argv = |bin: &str| {
        vec![
            bin.to_owned(),
            String::from("hook"),
            String::from("--harness"),
            String::from("claude-code"),
        ]
    };

    let wired_base = wired_command(base_tree, base_bin)?;
    let wired_head = wired_command(repo, head_bin)?;

    let plan: Vec<Arm> = vec![
        (
            "noop",
            None,
            vec![base.clone(), String::from("--help")],
            vec![head.clone(), String::from("--help")],
        ),
        (
            "check",
            None,
            vec![base.clone(), String::from("check")],
            vec![head.clone(), String::from("check")],
        ),
        (
            "hook",
            Some(hooks.join("claude-code.json")),
            hook_argv(&base),
            hook_argv(&head),
        ),
        // The pass-through arm (CLOUD-777): under match-all the engine is handed
        // every tool call, so the case a regression would hurt most is the one no
        // rule selects — and `perf-assert` budgets it.
        (
            "passthrough",
            Some(hooks.join("claude-code-passthrough.json")),
            hook_argv(&base),
            hook_argv(&head),
        ),
        // The POST-TOOL path (CLOUD-919): the arm that prices the per-call
        // capture write, and the one where the two binaries genuinely differ in
        // what they do rather than only in how fast.
        (
            "posttool",
            Some(hooks.join("claude-code-posttool.json")),
            hook_argv(&base),
            hook_argv(&head),
        ),
        // THE WIRED PATH (CLOUD-697): what the settings file actually invokes —
        // the number an agent waits on, and CLOUD-875's whole subject.
        (
            "wired",
            Some(hooks.join("claude-code.json")),
            wired_base,
            wired_head,
        ),
    ];

    let mut records = Vec::new();
    for (id, input, base_cmd, head_cmd) in plan {
        records.extend(hyperfine(
            &check_repo,
            out,
            id,
            input.as_deref(),
            &base_cmd,
            &head_cmd,
            &state_text,
        )?);
    }
    Ok(records)
}

/// One hyperfine invocation carrying BOTH commands, so the two arms are measured
/// back to back rather than in separate runs.
///
/// `results[0]` is base and `results[1]` is head, in the order they are passed.
/// Failures are NOT ignored: hyperfine aborts on a non-zero exit unless `-i` is
/// passed, and every path exits 0 on its fixture — so ignoring failures would buy
/// nothing and would publish a binary that had started failing outright as a fast
/// number rather than a broken one.
fn hyperfine(
    dir: &Path,
    out: &Path,
    id: &'static str,
    input: Option<&Path>,
    base_cmd: &[String],
    head_cmd: &[String],
    state: &str,
) -> Result<Vec<Record>> {
    let json = out.join(format!("{id}.json"));
    let mut args: Vec<String> = vec![
        String::from("--warmup"),
        env_or(WARMUP_VAR, DEFAULT_WARMUP),
        String::from("--runs"),
        env_or(RUNS_VAR, DEFAULT_RUNS),
        String::from("--shell=none"),
        String::from("--export-json"),
        json.to_string_lossy().into_owned(),
        String::from("--style"),
        String::from("none"),
    ];
    if let Some(input) = input {
        args.push(String::from("--input"));
        args.push(input.to_string_lossy().into_owned());
    }

    let (base_cmd, head_cmd) = if id == "posttool" {
        // ONE STATE ROOT PER ARM, AND EMPTY BEFORE EVERY RUN. This is the only
        // arm whose binaries WRITE, and both would otherwise share the store: the
        // head arm's capture would then be a blob the base arm's run already
        // created, and the log both arms read would carry the other's rows. Two
        // order-dependencies at once, and neither divides out of a ratio — which
        // is the one thing `perf-compare` reads.
        let base_state = format!("{state}-base");
        let head_state = format!("{state}-head");
        args.push(String::from("--prepare"));
        args.push(format!("rm -rf {base_state} {head_state}"));
        (
            state_prefixed(&base_state, base_cmd),
            state_prefixed(&head_state, head_cmd),
        )
    } else {
        (base_cmd.to_vec(), head_cmd.to_vec())
    };

    args.push(base_cmd.join(" "));
    args.push(head_cmd.join(" "));

    let env = vec![
        (String::from("XDG_DATA_HOME"), state.to_owned()),
        (String::from("APPDATA"), state.to_owned()),
        (String::from("LOCALAPPDATA"), state.to_owned()),
    ];
    if !run(dir, "hyperfine", &args, &env)? {
        bail!("perf-pair: measuring the {id} pair failed. No measurement.");
    }

    let text = std::fs::read_to_string(&json)
        .with_context(|| format!("perf-pair: could not read the {id} pair. No measurement."))?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("perf-pair: the {id} pair did not parse. No measurement."))?;
    let results = parsed
        .get("results")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("perf-pair: the {id} pair carried no results."))?;

    ["base", "head"]
        .iter()
        .enumerate()
        .map(|(index, arm)| {
            let result = results.get(index).ok_or_else(|| {
                anyhow::anyhow!("perf-pair: the {id} pair is missing its {arm} arm.")
            })?;
            record(arm, id, result)
        })
        .collect()
}

/// `env VAR=… <argv>`, which is how a per-arm environment is supplied at all:
/// `--shell=none` runs argv directly, so it can only come from a prefix. The
/// extra exec is identical on both arms and divides out of the ratio.
fn state_prefixed(state: &str, argv: &[String]) -> Vec<String> {
    let mut out = vec![
        String::from("env"),
        format!("XDG_DATA_HOME={state}"),
        format!("APPDATA={state}"),
        format!("LOCALAPPDATA={state}"),
    ];
    out.extend(argv.iter().cloned());
    out
}

/// One arm's record, with `perf`'s own percentile convention.
fn record(arm: &str, id: &'static str, result: &serde_json::Value) -> Result<Record> {
    let mut times: Vec<f64> = result
        .get("times")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("perf-pair: the {id} {arm} arm carried no times."))?
        .iter()
        .filter_map(serde_json::Value::as_f64)
        .collect();
    if times.is_empty() {
        bail!("perf-pair: the {id} {arm} arm carried no times.");
    }
    times.sort_by(f64::total_cmp);

    let n = times.len();
    #[expect(
        clippy::cast_precision_loss,
        reason = "a run count is a small integer and this is an index computation, not a measurement"
    )]
    let last = (n - 1) as f64;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "both products are within [0, n-1] by construction, so the cast cannot truncate meaningfully or go negative"
    )]
    let i50 = (last * 0.5).floor() as usize;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "both products are within [0, n-1] by construction, so the cast cannot truncate meaningfully or go negative"
    )]
    let i95 = (last * 0.95).ceil() as usize;

    let mean = result
        .get("mean")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| anyhow::anyhow!("perf-pair: the {id} {arm} arm carried no mean."))?;

    Ok(Record {
        arm: if arm == "base" { "base" } else { "head" },
        path: id.to_owned(),
        p50: times[i50] * 1000.0,
        p95: times[i95.min(n - 1)] * 1000.0,
        mean: mean * 1000.0,
        runs: n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn changed(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn a_crate_change_is_measured() {
        // The control. Without it every refusal below could come from a predicate
        // that never selects anything.
        let selection = select(
            &changed(&["crates/batten/src/lib.rs"]),
            &wiring_paths(),
            &[],
        );
        assert!(selection.measure);
        assert_eq!(selection.touched, vec![String::from("crates/")]);
    }

    #[test]
    fn a_docs_only_change_is_not() {
        // The economy CLOUD-224 bought, and the half that keeps this from
        // degenerating into "always run".
        assert!(!select(&changed(&["README.md"]), &wiring_paths(), &[]).measure);
    }

    #[test]
    fn the_committed_config_is_measured() {
        // CLOUD-875's first half: `wired` adjudicates against the repository's own
        // config, so a change to it changes the measured cost.
        let registered = vec![String::from("batten.toml")];
        assert!(select(&changed(&["batten.toml"]), &wiring_paths(), &registered).measure);
    }

    #[test]
    fn a_registered_module_is_measured() {
        // CLOUD-875's second half, and the shape of every one of wave 1's ~80
        // migrations: a policy row plus its module, no crate source at all.
        let registered = vec![String::from("policy/run-shape.rego")];
        assert!(
            select(
                &changed(&["policy/run-shape.rego"]),
                &wiring_paths(),
                &registered
            )
            .measure
        );
    }

    #[test]
    fn a_file_under_a_bundle_root_is_measured() {
        // The other spelling CLOUD-833 admits. A bundle is registered by its ROOT,
        // so a file added under it tomorrow is covered by the entry written today
        // — which is what deriving buys over listing.
        let registered = vec![String::from("policy/bundle")];
        assert!(
            select(
                &changed(&["policy/bundle/inner.rego"]),
                &wiring_paths(),
                &registered
            )
            .measure
        );
    }

    #[test]
    fn a_sibling_prefix_is_not_confused_for_a_directory() {
        // `crates` must not match `crates-vendored/`. Without the separator the
        // predicate widens silently rather than visibly, which is the whole class
        // this module is about.
        assert!(!select(&changed(&["crates-vendored/x.rs"]), &wiring_paths(), &[]).measure);
    }

    #[test]
    fn the_wiring_is_derived_from_the_harness_table() {
        // CLOUD-697's half, and the reason it can live in the core at all: which
        // file a host wires is a HARNESS fact `Harness::wiring` already carries,
        // never a consumer one.
        let paths = wiring_paths();
        assert!(
            !paths.is_empty(),
            "the harness table names at least one wiring file"
        );
        // EVERY subject is taken FROM the derived set rather than typed. That is
        // what keeps the case honest for a repository wired to another host, and
        // what keeps a consumer's artifact name out of the core — the property
        // `no_artifact_name_reaches_the_core` computes, which caught the first
        // draft of this very case.
        for path in &paths {
            assert!(
                select(&changed(&[path.as_str()]), &paths, &[]).measure,
                "{path}"
            );
        }
    }

    #[test]
    fn a_launcher_beside_the_settings_file_is_measured() {
        // The measured CLOUD-697 instance: a commit touching only the launcher
        // changed what `wired` invokes and skipped the gate it needed.
        //
        // The directory is DERIVED for the same reason the case above derives its
        // subject: the launcher lives beside the settings file, and which
        // directory that is belongs to the harness table. A directory entry is
        // the one that is a proper prefix of another — no extension test, and
        // nothing typed.
        let paths = wiring_paths();
        let launchers: Vec<String> = paths
            .iter()
            .filter(|dir| {
                paths.iter().any(|other| {
                    other.as_str() != dir.as_str() && other.starts_with(&format!("{dir}/"))
                })
            })
            .map(|dir| format!("{dir}/launcher.sh"))
            .collect();
        assert!(
            !launchers.is_empty(),
            "the harness table names a directory its settings file sits in: {paths:?}"
        );
        for launcher in &launchers {
            assert!(
                select(&changed(&[launcher.as_str()]), &paths, &[]).measure,
                "{launcher}"
            );
        }
    }

    #[test]
    fn the_skip_message_names_the_set_it_consulted() {
        // CLOUD-875 §5. The predecessor claimed "neither the binary nor its wiring
        // changed" having consulted neither the config nor the modules — a
        // sentence wider than its evidence.
        let selection = select(
            &changed(&["README.md"]),
            &wiring_paths(),
            &[String::from("batten.toml")],
        );
        let message = selection.skip_message("abcdef1234", "1234abcdef");
        assert!(message.contains("batten.toml"), "{message}");
        assert!(message.contains("crates/"), "{message}");
        assert!(message.contains("Cargo.lock"), "{message}");
    }
}
