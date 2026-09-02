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
        .with_context(|| format!("perf: could not run {program}"))?;
    Ok(status.success())
}

/// The directory this module owns under the checkout, which is NOT the same
/// thing as [`out_dir`].
///
/// The distinction is the whole of CLOUD-1331, and it is a LIFETIME rather than a
/// layout preference. Everything under [`out_dir`] belongs to one run and is
/// deleted at the start of the next; the keyed base build below is a fact about a
/// COMMIT and outlives every run that reads it.
#[must_use]
pub fn perf_dir(repo: &Path) -> PathBuf {
    repo.join(env_or(OUT_DIR_VAR, DEFAULT_OUT_DIR))
}

/// The base arm's target directory, NAMED FOR THE COMMIT IT IS A BUILD OF.
///
/// # Why it is keyed, and why it is not under [`out_dir`]
///
/// The base binary is a pure function of the merge-base SHA, the pinned
/// toolchain and `[profile.release]`, so rebuilding it per run buys nothing:
/// `main` advances only by fast-forward to already-judged SHAs, so consecutive
/// pull requests share a merge base for hours and every one of them was
/// compiling the identical binary from nothing — 13.5 minutes of the `perf` job's
/// 13.7 (CLOUD-1331, measured over runs 33586699312 and 33584118886).
///
/// It used to live at `out.join("base-target")`, and that placement made the
/// build **unreusable by construction** rather than merely unreused: [`out_dir`]
/// `remove_dir_all`s the whole `pair/` directory at the start of every run, so
/// anything a CI cache had restored there was deleted microseconds before the
/// base build ran. The bytes WERE in the cache — `Swatinem/rust-cache` carries
/// the entire `target/` directory, `target/perf/**` included, and the post-job
/// cleaner walked `target/perf/pair/base-tree/…` on both measured runs. So the
/// key alone would not have been enough; moving out of the wipe is the other
/// half.
///
/// **The SHA is in the path, and that IS the refusal.** A directory built from
/// another base does not answer to this name, so a stale arm cannot be measured
/// as this one — the discriminator is structural rather than a check somebody has
/// to remember to write. `.github/workflows/ci.yml`'s `perf` job keys its
/// `actions/cache` entry on the same SHA plus the toolchain and lockfile hash, so
/// the two authorities over "which base" are one string computed one way.
///
/// The separate target directory itself is unchanged and still carries the
/// reason `measure` gives for it — sharing the main one would have the two builds
/// evict each other's artifacts and race the target-dir lock under `verify`.
#[must_use]
pub fn base_target_dir(perf_dir: &Path, base_sha: &str) -> PathBuf {
    perf_dir.join(format!("base-{base_sha}"))
}

/// The binary [`base_target_dir`] holds once the base arm has been built.
#[must_use]
pub fn base_binary(perf_dir: &Path, base_sha: &str) -> PathBuf {
    base_target_dir(perf_dir, base_sha)
        .join("release")
        .join("batten")
}

/// Whether the base arm can be measured without spawning cargo at all.
///
/// A FILE rather than a path that exists: a build killed mid-link — and this gate
/// is killed routinely — or a cache entry saved from one leaves the directory
/// behind with no binary in it, and reading that as "built" would hand hyperfine
/// a path it cannot execute and report the could-not-look as a measurement.
#[must_use]
pub fn base_arm_is_built(perf_dir: &Path, base_sha: &str) -> bool {
    base_binary(perf_dir, base_sha).is_file()
}

/// The out directory this run owns, emptied first so a previous run's records
/// can never be read as this one's.
fn out_dir(repo: &Path) -> Result<PathBuf> {
    let dir = perf_dir(repo).join("pair");
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
///
/// NOT `--quiet`, and the flag's removal is CLOUD-1331's measurement half rather
/// than a taste. The row's acceptance is a `Compiling` line count per arm read
/// from the job log, and `--quiet` suppresses every one of them — so the count
/// answered `0` on a run that compiled the whole closure twice and would answer
/// `0` again after the fix, which is a reading that cannot tell the two apart.
/// Cargo's progress goes to stderr, so nothing changes for `perf-gate.sh`, which
/// redirects this command's STDOUT to a file and greps `^arm=`.
fn build(dir: &Path, target_dir: Option<&Path>, what: &str) -> Result<()> {
    let args: Vec<String> = ["build", "--release", "-p", "batten"]
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
        //
        // KEYED AND OUTSIDE `out`, which is CLOUD-1331 — see `base_target_dir`
        // for why both halves are load-bearing. The tree is still materialised on
        // the reuse path: `wired_command` reads the BASE tree's own settings file
        // to derive that arm's invocation, so skipping it would measure the head
        // wiring against the base binary.
        let perf = perf_dir(repo);
        let base_bin = base_binary(&perf, base_sha);
        if !base_arm_is_built(&perf, base_sha) {
            build(&base_tree, Some(&base_target_dir(&perf, base_sha)), "base")?;
            // A cargo that exits 0 without leaving the binary is could-not-look,
            // never a measurement: hyperfine would report the missing path as a
            // failed command and `perf-compare` would read the gap as a verdict.
            if !base_arm_is_built(&perf, base_sha) {
                bail!(
                    "perf-pair: the base build left no binary at {} — nothing to measure. No measurement.",
                    base_bin.display()
                );
            }
        }
        (base_bin, base_tree)
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
fn record(arm: &'static str, id: &str, result: &serde_json::Value) -> Result<Record> {
    let times: Vec<f64> = result
        .get("times")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("perf-pair: the {id} {arm} arm carried no times."))?
        .iter()
        .filter_map(serde_json::Value::as_f64)
        .collect();
    if times.is_empty() {
        bail!("perf-pair: the {id} {arm} arm carried no times.");
    }
    let mean = result
        .get("mean")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| anyhow::anyhow!("perf-pair: the {id} {arm} arm carried no mean."))?;
    summarise(arm, id, times, Some(mean))
}

/// A set of SECOND-valued samples reduced to one [`Record`], in milliseconds.
///
/// Extracted from [`record`] rather than re-derived beside it, because the
/// percentile convention is the thing two readings must share: `perf-compare`
/// decides on `p50`, so a second measurement rounding or indexing differently
/// would produce records that look comparable and are not. `mean` is optional
/// only because hyperfine reports its own and an in-process arm has none to
/// quote — the fallback is the arithmetic mean of the same samples.
fn summarise(
    arm: &'static str,
    id: &str,
    mut times: Vec<f64>,
    reported_mean: Option<f64>,
) -> Result<Record> {
    if times.is_empty() {
        bail!("perf: the {id} {arm} arm carried no times.");
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

    #[expect(
        clippy::cast_precision_loss,
        reason = "a sample count is a small integer and this is a divisor, not a measurement"
    )]
    let mean = reported_mean.unwrap_or_else(|| times.iter().sum::<f64>() / n as f64);

    Ok(Record {
        arm,
        path: id.to_owned(),
        p50: times[i50] * 1000.0,
        p95: times[i95.min(n - 1)] * 1000.0,
        mean: mean * 1000.0,
        runs: n,
    })
}

// ---------------------------------------------------------------------------
// The acquisition sweep (CLOUD-935), ported out of `bench/acquisition/sweep.py`
// under CLOUD-1229.
// ---------------------------------------------------------------------------
//
// WHY IT LIVES HERE RATHER THAN IN ITS OWN MODULE, and it is the same argument
// `policy/spawn-adapters.rego` already writes down for `perf`: this is a harness
// whose whole subject is what an EXTERNAL process costs, so the spawns are the
// thing rather than an implementation of it. That table places `perf` and is a
// protected path; a sibling module would be an unplaced spawning module and
// `spawn place missing` would refuse it. Sharing the module is also what stops a
// second percentile convention, a second record shape and a second hyperfine
// invocation from existing — `perf-compare`'s reading is a contract, and two
// spellings of it can disagree.
//
// WHY IT IS NOT A SCRIPT ANY MORE. The predecessor was 327 lines of Python driven
// by a one-line task body, and its own header explained that the shape was forced:
// this consumer's retirement ratchet refuses ADDING an authored shell rule, so the
// measurement went to the one language that ratchet does not watch. A second
// author read that header and added a third instance for the identical stated
// reason (CLOUD-1208). A ratchet's subject is authored shell because that is what
// it was built to retire; that is a statement about its reach, never a licence for
// what sits beside it (CLOUD-1229). So the growth path closes here, and the
// unpinned interpreter goes with it — the toolchain pin never declared one, so
// every such helper ran under whatever the host happened to have.

/// The sweep's own knobs, in `perf`'s `BENCH_*` spelling so a caller who already
/// knows how to turn that task down does not learn a second vocabulary.
const NS_VAR: &str = "BENCH_NS";
const NULL_PAIRS_VAR: &str = "BENCH_NULL_PAIRS";
const BIN_VAR: &str = "BENCH_BIN";

/// The sweep, and its FIRST entry is the ratio base.
///
/// ONE, NOT ZERO, and that correction is the difference between measuring
/// acquisition and measuring "does this tree have a policy row at all". A zero
/// arm carries no rule, so the step from it to any other arm bundles the fixed
/// cost of registering a bundle, compiling a module and evaluating it in with the
/// reads — measured, that step alone read 1.367 at N=16, which would have been
/// published as a per-document cost it is mostly not. Basing the ratios on a tree
/// that already has exactly one rule and one document holds every fixed term
/// constant, so the only thing differing between arms is how many paths that one
/// row declares.
///
/// 256 is chosen to be past the point where a per-document term, if there is one,
/// has to be visible above a ~5 ms process start: at 256 even a 10 µs read is
/// 2.5 ms. `BENCH_NS=0,…` still works and gives the no-policy reference, which is
/// a different question and is not what the verdict is read off.
const DEFAULT_NS: &str = "1,16,64,256";

/// How many identical pairs the null is taken over. Five rather than one, because
/// a single ratio is a point and the sweep has to be read against a WIDTH.
const DEFAULT_NULL_PAIRS: &str = "5";

const DEFAULT_BIN: &str = "target/release/batten";

/// One module, whose body reads whatever was declared. Iterating `documents`
/// rather than naming a path keeps the module identical across every arm, so the
/// only thing differing between arms is the row's declaration.
const SWEEP_MODULE: &str = "package batten.acquisition\n\
     \n\
     import rego.v1\n\
     \n\
     rules contains \"acquisition-bench\"\n\
     \n\
     violation contains {\n\
     \t\"rule\": \"acquisition-bench\",\n\
     \t\"verdict\": \"acquisition bench probe\",\n\
     \t\"subjects\": [{\"path\": path}],\n\
     } if {\n\
     \tsome path, doc in input.tree.documents\n\
     \tdoc.stray\n\
     }\n";

/// The verdict row the module's token needs, because `[[verdict]]` runs in both
/// directions: a raised token no row declares fails the load, and a declared row
/// nothing raises fails it too.
const SWEEP_AUTHORITY_HEAD: &str = r#"version = 1

[[verdict]]
id = "acquisition bench probe"
gloss = "the bench fixture declared a document carrying the sentinel key"
class = """
A generated fixture for CLOUD-935's acquisition sweep. It is never raised: the
documents carry no sentinel, so the run is clean and the number is about reading
rather than about rendering findings.
"""

[[verdict.route]]
id = "regenerate the fixture"
kind = "document"
target = "batten.toml"
"#;

/// One sweep's reading: the arms, the ratios taken over them, the null spread
/// they must be read against, and the per-document term that is the number the
/// verdict is actually about.
///
/// Rendering lives here rather than at the dispatch, so §6 byte-stability has one
/// author. The arm lines are [`Record`]'s own shape, unchanged: a second record
/// spelling is what `perf-compare`'s frozen reading exists to make unwritable.
#[derive(Debug)]
pub struct Sweep {
    arms: Vec<Record>,
    ratios: Vec<(String, f64)>,
    nulls: Vec<f64>,
    per_document: Option<(f64, usize)>,
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

impl std::fmt::Display for Sweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for record in &self.arms {
            writeln!(f, "{record}")?;
        }
        for (label, value) in &self.ratios {
            writeln!(f, "ratio={label} value={:.3}", round3(*value))?;
        }
        for (pair, value) in self.nulls.iter().enumerate() {
            writeln!(f, "ratio=null{pair} value={:.3}", round3(*value))?;
        }
        if !self.nulls.is_empty() {
            let low = self.nulls.iter().copied().fold(f64::INFINITY, f64::min);
            let high = self.nulls.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            writeln!(
                f,
                "null-spread low={:.3} high={:.3} pairs={}",
                round3(low),
                round3(high),
                self.nulls.len()
            )?;
        }
        // THE PER-DOCUMENT TERM, which is the number the verdict is actually
        // about. Reported rather than left to a reader with a calculator, and
        // taken across the widest span in the sweep because that is where the
        // fixed terms matter least. Microseconds, since milliseconds would round
        // it to nothing.
        if let Some((per_document, span)) = self.per_document {
            writeln!(f, "per-document us={per_document:.2} over={span} documents")?;
        }
        Ok(())
    }
}

/// Measure tree-surface acquisition cost as the declared-document count scales.
///
/// # The experiment, and the confound it is built to avoid
///
/// ONE rule, ONE bundle, ONE module — and the row's `documents` array is what
/// grows. A row PER document would have made every step of the sweep add a module
/// compile and an evaluation beside each read, so the curve would price four
/// things and get reported as one. Holding everything but the declared path count
/// fixed is what leaves acquisition as the only term that moves.
/// `crates/batten/tests/it/document_read_count.rs::one_row_declaring_n_paths_acquires_n_documents`
/// pins that the engine really does acquire once per declared path under exactly
/// this shape, because a sweep over a variable the engine ignores would still
/// draw a tidy curve.
///
/// # The null is not optional
///
/// Two IDENTICAL trees at the largest N, measured as a separate pair. Its ratio
/// is 1.0 plus pure noise by construction, which is what makes the spread a
/// measured quantity rather than a number in a comment — exactly how
/// `perf pair --null` derived the 0.966–1.102 spread `perf-compare`'s 1.30
/// threshold clears. A sweep number inside the null spread has measured "no
/// effect", and that is a result rather than a failure to deliver.
///
/// # Errors
///
/// Every failure here is a property of the CHECKOUT rather than a verdict about
/// acquisition — a missing instrument, a binary nobody built, a fixture that
/// would not initialise — and each is an error rather than an empty measurement,
/// for [`pair`]'s reason.
pub fn acquire(repo: &Path) -> Result<Sweep> {
    // ABSOLUTE FROM HERE DOWN, for `pair`'s measured reason: every arm runs
    // hyperfine with the FIXTURE tree as its working directory, so a relative
    // binary path resolves against the fixture and hyperfine dies before it times
    // anything.
    let repo = &repo
        .canonicalize()
        .with_context(|| format!("perf-acquire: could not resolve {}", repo.display()))?;

    if which("hyperfine").is_none() {
        bail!(
            "perf-acquire: hyperfine is not installed — run `mise install`; it is pinned in the manifest. Nothing measured."
        );
    }
    let binary = repo.join(env_or(BIN_VAR, DEFAULT_BIN));
    if !binary.is_file() {
        bail!(
            "perf-acquire: {} is missing — run `mise run build:release`. Nothing measured.",
            binary.display()
        );
    }

    let ns = declared_ns()?;
    let out = acquire_out_dir(repo)?;
    let null_pairs: usize = env_or(NULL_PAIRS_VAR, DEFAULT_NULL_PAIRS)
        .parse()
        .with_context(|| format!("perf-acquire: {NULL_PAIRS_VAR} is not a count"))?;

    // THE SWEEP, measured back to back on one machine so the noise the ratios
    // divide out is the same noise.
    let mut arms = Vec::new();
    let mut p50s = Vec::new();
    for n in &ns {
        let tree = out.join(format!("tree-{n}"));
        sweep_fixture(&tree, *n)?;
        let record = measure_one("acquire", &format!("acquire-{n}"), &tree, &out, &binary)?;
        p50s.push(record.p50);
        arms.push(record);
    }

    // THE NULL, AND IT IS A SPREAD RATHER THAN A NUMBER. Two identical trees at
    // the largest N, built separately so each comparison is between two arms
    // rather than an arm against itself — repeated, because ONE null ratio says
    // nothing about how wide the noise is and a sweep ratio can only be read
    // against a width.
    let largest = ns.iter().copied().max().unwrap_or_default();
    let mut nulls = Vec::new();
    for pair in 0..null_pairs {
        let mut sides = Vec::new();
        for side in ["a", "b"] {
            let id = format!("null{pair}-{side}");
            let tree = out.join(&id);
            sweep_fixture(&tree, largest)?;
            let record = measure_one("null", &id, &tree, &out, &binary)?;
            sides.push(record.p50);
            arms.push(record);
        }
        let (first, second) = (sides[0], sides[1]);
        if first <= 0.0 {
            bail!("perf-acquire: null pair {pair} measured zero, so no ratio can be taken.");
        }
        nulls.push(second / first);
    }

    let base = *p50s.first().unwrap_or(&0.0);
    if base <= 0.0 {
        bail!("perf-acquire: the base arm measured zero, so no ratio can be taken.");
    }
    let ratios = ns
        .iter()
        .zip(&p50s)
        .skip(1)
        .map(|(n, p50)| (format!("acquire-{n}/acquire-{}", ns[0]), p50 / base))
        .collect();

    let span = largest.saturating_sub(ns[0]);
    let per_document = (span > 0).then(|| {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a declared-document count is a small integer and this is a divisor, not a measurement"
        )]
        let width = span as f64;
        ((p50s[p50s.len() - 1] - base) * 1000.0 / width, span)
    });

    Ok(Sweep {
        arms,
        ratios,
        nulls,
        per_document,
    })
}

// ---------------------------------------------------------------------------
// The config-load reading (CLOUD-1291).
// ---------------------------------------------------------------------------
//
// WHY IT LIVES HERE, and it is the acquisition sweep's argument one measurement
// over: `Record` is a CONTRACT with two frozen callers (`perf-compare` parses it,
// `perf-gate` greps `^arm=`), and the percentile convention behind `p50` is the
// thing two readings have to share before their numbers can be put side by side.
// A bench with its own struct and its own idea of a median produces records that
// look comparable and are not.
//
// WHAT MAKES THIS ARM DIFFERENT from every other one in this module: it spawns
// NOTHING. There is no hyperfine, no binary to build, no fixture tree. The
// subject is one function call in this process, which is also why CLOUD-1291
// forbids pricing it through a CLI verb — measured, `batten config show` is
// insensitive to config size, so the verb's 29 ms of startup swallows the answer.

/// The default sample count. Large enough that a sub-millisecond call is not
/// being timed against the clock's own resolution, small enough that the whole
/// reading is seconds.
const DEFAULT_LOAD_SAMPLES: &str = "200";

/// The environment override for it.
const LOAD_SAMPLES_VAR: &str = "BENCH_LOAD_SAMPLES";

/// Price [`crate::config::load`] over one committed authority.
///
/// # The experiment
///
/// Three arms over the same file, back to back in one process so the noise the
/// ratios divide out is the same noise:
///
/// * `load` — the whole of what the harness calls: read plus parse plus every
///   `validate` pass.
/// * `parse` — the same text already in memory, so the difference between the two
///   is the READ rather than a guess about it.
/// * `load-null` — `load` again. Its ratio against the first is 1.0 plus pure
///   noise by construction, which is what makes the spread a measured quantity
///   rather than a number in a comment.
///
/// # Reading it
///
/// The arm records are per-call milliseconds, so the `mean` on the `load` arm IS
/// the per-call cost the row asks for. Multiply by the harness's call count to
/// get the suite delta, and read that against the null spread: a saving inside it
/// has measured no effect, and recording that is the row's sanctioned outcome.
///
/// # Errors
///
/// A file that cannot be read or does not parse — properties of the checkout
/// rather than verdicts about the cost — and a sample count that is zero or
/// unparseable. Never an empty measurement reported as a reading.
pub fn config_load(path: &Path) -> Result<Sweep> {
    let samples: usize = env_or(LOAD_SAMPLES_VAR, DEFAULT_LOAD_SAMPLES)
        .parse()
        .with_context(|| format!("perf-config-load: {LOAD_SAMPLES_VAR} is not a count"))?;
    if samples == 0 {
        bail!("perf-config-load: {LOAD_SAMPLES_VAR} declared no samples. Nothing measured.");
    }

    let source = path.display().to_string();
    // Read once, up front, for two reasons: it is the `parse` arm's input, and a
    // missing or unparseable file is a could-not-look that must be reported
    // BEFORE any timing rather than as a zero.
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("perf-config-load: could not read {source}"))?;
    crate::config::parse(&text, &source)
        .with_context(|| format!("perf-config-load: {source} does not parse"))?;

    let bytes = text.len();

    // WARMUP, discarded. The first call pays page faults on a 354 KB file and
    // whatever the allocator has to grow, and including that in a per-call figure
    // reports a one-off as a recurring cost.
    for _ in 0..samples.min(16) {
        crate::config::load(path)?;
    }

    let time = |mut body: Box<dyn FnMut() -> Result<()>>| -> Result<Vec<f64>> {
        let mut times = Vec::with_capacity(samples);
        for _ in 0..samples {
            let started = std::time::Instant::now();
            body()?;
            times.push(started.elapsed().as_secs_f64());
        }
        Ok(times)
    };

    let load_arm = summarise(
        "load",
        &format!("config-load-{bytes}b"),
        time(Box::new(|| crate::config::load(path).map(|_| ())))?,
        None,
    )?;
    let parse_arm = summarise(
        "parse",
        &format!("config-parse-{bytes}b"),
        time(Box::new(|| {
            crate::config::parse(&text, &source).map(|_| ())
        }))?,
        None,
    )?;
    let null_arm = summarise(
        "null",
        &format!("config-load-null-{bytes}b"),
        time(Box::new(|| crate::config::load(path).map(|_| ())))?,
        None,
    )?;

    if load_arm.p50 <= 0.0 {
        bail!("perf-config-load: the load arm measured zero, so no ratio can be taken.");
    }
    let ratios = vec![("parse/load".to_owned(), parse_arm.p50 / load_arm.p50)];
    let nulls = vec![null_arm.p50 / load_arm.p50];

    Ok(Sweep {
        arms: vec![load_arm, parse_arm, null_arm],
        ratios,
        nulls,
        // There is no swept variable here — one file, one size — so the
        // per-document term has nothing to be about. Reporting a zero would read
        // as a measured slope rather than as an absent one.
        per_document: None,
    })
}

/// The declared sweep points, in order, with the first as the ratio base.
///
/// Split from its environment read so the parse stays exercisable without one,
/// which is [`select`]'s split one concern over: a case that had to export
/// `BENCH_NS` would be asserting over process-global state that every other case
/// in the file shares.
fn parse_ns(declared: &str) -> Result<Vec<usize>> {
    let ns: Vec<usize> = declared
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<usize>()
                .with_context(|| format!("perf-acquire: {NS_VAR} carries a non-count `{entry}`"))
        })
        .collect::<Result<_>>()?;
    if ns.is_empty() {
        bail!("perf-acquire: {NS_VAR} declared no sweep points. Nothing measured.");
    }
    Ok(ns)
}

/// [`parse_ns`] over what the environment declares.
fn declared_ns() -> Result<Vec<usize>> {
    parse_ns(&env_or(NS_VAR, DEFAULT_NS))
}

/// The out directory this sweep owns, emptied first so a previous run's fixtures
/// and JSON can never be read as this one's.
fn acquire_out_dir(repo: &Path) -> Result<PathBuf> {
    let dir = repo
        .join(env_or(OUT_DIR_VAR, DEFAULT_OUT_DIR))
        .join("acquire");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("perf-acquire: could not clear {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("perf-acquire: could not create {}", dir.display()))?;
    dir.canonicalize()
        .with_context(|| format!("perf-acquire: could not resolve {}", dir.display()))
}

/// A repository with one policy row declaring `n` distinct documents.
///
/// **Public for [`select`]'s reason, which is the same reason one axis over**: the
/// measurement needs a benchmark runner and the `windows` job installs none, so a
/// case that ran the sweep would pass on two hosts and fail on the third. What
/// can be asserted everywhere is that the fixture this times is one the ENGINE
/// accepts — a generated authority that fails to load, or a module that refuses,
/// makes every arm time a broken tree and still draws a tidy curve. Exposing the
/// builder is what lets `tests/perf_acquire.rs` put the compiled binary over one
/// of these trees without a second spelling of the fixture.
///
/// # Errors
///
/// Any write that fails, or a `git init` that does — a fixture that did not
/// materialise is a could-not-look, never an arm measured over whatever was
/// there.
pub fn sweep_fixture(root: &Path, n: usize) -> Result<()> {
    if root.exists() {
        std::fs::remove_dir_all(root)
            .with_context(|| format!("perf-acquire: could not clear {}", root.display()))?;
    }
    let bundle = root.join("policy-acquisition");
    std::fs::create_dir_all(&bundle)
        .with_context(|| format!("perf-acquire: could not create {}", bundle.display()))?;
    std::fs::write(bundle.join("gate.rego"), SWEEP_MODULE)
        .context("perf-acquire: could not write the sweep module")?;

    let paths: Vec<String> = (0..n).map(|index| format!("config{index}.toml")).collect();
    for path in &paths {
        // Small and uniform. The cost being priced is the fixed per-document term
        // — open, read, parse, cache — rather than a per-byte one, and a large
        // file would measure the parser instead. Said out loud so the fixture does
        // not grow by accretion.
        std::fs::write(root.join(path), "quiet = true\n")
            .with_context(|| format!("perf-acquire: could not write {path}"))?;
    }

    // THE FLOOR ARM CARRIES NO ROW AND NO VERDICT, which is what makes it the
    // floor: config load, trust resolution and the walk, and not one acquisition.
    // A row declaring zero documents would still compile a module and put that
    // cost into every baseline the ratios are taken against. The verdict row goes
    // with it, and that is the REGISTRY's requirement rather than a choice: with
    // no rule there is no module, so the token is unraised and a floor arm
    // carrying the row would not load at all.
    let authority = if n == 0 {
        String::from("version = 1\n")
    } else {
        let declared = paths
            .iter()
            .map(|path| format!("\"{path}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{SWEEP_AUTHORITY_HEAD}\n[[rule]]\nid = \"acquisition-bench\"\nkind = \"policy\"\n\
             scope = \"tree\"\nbundle = \"policy-acquisition/\"\ndocuments = [{declared}]\n\
             severity = \"deny\"\n"
        )
    };
    std::fs::write(root.join("batten.toml"), authority)
        .context("perf-acquire: could not write the fixture authority")?;

    // `git init` so the walk is a repository walk, matching every other fixture
    // in this tree. No global or system config: a contributor's own git settings
    // must not be able to change what is measured (CLOUD-282).
    let args: Vec<String> = ["init", "-q", "-b", "main"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    let env = vec![
        (String::from("GIT_CONFIG_GLOBAL"), String::from("/dev/null")),
        (String::from("GIT_CONFIG_SYSTEM"), String::from("/dev/null")),
    ];
    if !run(root, "git", &args, &env)? {
        bail!(
            "perf-acquire: could not initialise the fixture at {}. Nothing measured.",
            root.display()
        );
    }
    Ok(())
}

/// One hyperfine run of `batten check` in `tree`, as a record.
///
/// NO `-i`. Every arm's fixture is clean, so a non-zero exit means the binary
/// started failing rather than that the measurement is awkward — and a broken
/// path is still perfectly timeable, which is how it would otherwise be published
/// as a fast number.
fn measure_one(
    arm: &'static str,
    id: &str,
    tree: &Path,
    out: &Path,
    binary: &Path,
) -> Result<Record> {
    let json = out.join(format!("{id}.json"));
    let args: Vec<String> = vec![
        String::from("--warmup"),
        env_or(WARMUP_VAR, DEFAULT_WARMUP),
        String::from("--runs"),
        env_or(RUNS_VAR, DEFAULT_RUNS),
        String::from("--shell=none"),
        String::from("--export-json"),
        json.to_string_lossy().into_owned(),
        String::from("--style"),
        String::from("none"),
        format!("{} check", binary.display()),
    ];
    if !run(tree, "hyperfine", &args, &[])? {
        bail!("perf-acquire: measuring arm {id} failed. No records.");
    }

    let text = std::fs::read_to_string(&json)
        .with_context(|| format!("perf-acquire: could not read arm {id}. No measurement."))?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("perf-acquire: arm {id} did not parse. No measurement."))?;
    let result = parsed
        .get("results")
        .and_then(serde_json::Value::as_array)
        .and_then(|results| results.first())
        .ok_or_else(|| anyhow::anyhow!("perf-acquire: arm {id} carried no results."))?;
    record(arm, id, result)
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

    // --- the acquisition sweep (CLOUD-935, ported under CLOUD-1229) ----------

    #[test]
    fn the_sweep_points_are_read_in_the_order_they_were_declared() {
        // The FIRST entry is the ratio base, so order is load-bearing rather than
        // cosmetic: a parse that sorted or deduplicated would silently re-base
        // every ratio the sweep prints.
        let (Ok(swept), Ok(reversed)) = (parse_ns("1,16,64,256"), parse_ns("256, 1")) else {
            panic!("a well-formed declaration parses");
        };
        assert_eq!(swept, vec![1, 16, 64, 256]);
        assert_eq!(reversed, vec![256, 1]);
    }

    #[test]
    fn a_declaration_that_names_no_sweep_point_is_refused() {
        // COULD-NOT-LOOK RATHER THAN AN EMPTY SWEEP. An empty list would print no
        // arms, no ratios and exit 0 — a measurement that did not happen wearing
        // a clean run's clothes, which is the one shape a bench harness must not
        // produce (CLOUD-1208 measured this class twice).
        assert!(parse_ns("").is_err());
        assert!(parse_ns(",,").is_err());
        assert!(parse_ns("1,many").is_err());
    }

    /// The rendered reading, byte for byte.
    ///
    /// House-style §6 applies to a bench verb's output too, and the fields here
    /// are `Record`'s own plus three lines this harness adds. Pinning the bytes is
    /// what stops the ratio precision or the field order drifting under a reader
    /// who is diffing two runs.
    #[test]
    fn the_reading_renders_arms_then_ratios_then_the_spread_then_the_term() {
        let arm = |path: &str, p50: f64| Record {
            arm: "acquire",
            path: path.to_owned(),
            p50,
            p95: 6.0,
            mean: 5.0,
            runs: 100,
        };
        let sweep = Sweep {
            arms: vec![arm("acquire-1", 4.75), arm("acquire-256", 6.12)],
            ratios: vec![(String::from("acquire-256/acquire-1"), 6.12 / 4.75)],
            nulls: vec![0.958, 1.022],
            per_document: Some((5.37, 255)),
        };
        assert_eq!(
            sweep.to_string(),
            "arm=acquire path=acquire-1 p50=4.75 p95=6 mean=5 runs=100\n\
             arm=acquire path=acquire-256 p50=6.12 p95=6 mean=5 runs=100\n\
             ratio=acquire-256/acquire-1 value=1.288\n\
             ratio=null0 value=0.958\n\
             ratio=null1 value=1.022\n\
             null-spread low=0.958 high=1.022 pairs=2\n\
             per-document us=5.37 over=255 documents\n"
        );
    }

    #[test]
    fn a_sweep_with_no_null_pairs_prints_no_spread_it_cannot_have() {
        // ANTI-VACUITY on the line above. `null-spread` over an empty set would
        // render `low=inf high=-inf`, which reads as a measured width and is the
        // opposite of one — the fold's identities leaking into a published number.
        let sweep = Sweep {
            arms: Vec::new(),
            ratios: Vec::new(),
            nulls: Vec::new(),
            per_document: None,
        };
        assert_eq!(sweep.to_string(), "");
    }

    // The two cases over what `sweep_fixture` WRITES live in
    // `crates/batten/tests/it/perf_acquire.rs` rather than here, and the reason is
    // the workspace lint rather than a preference: reading a file back is a
    // `Result`, and no module under `src/` waives `unwrap_used`. That builder is
    // public for exactly this, so the assertion loses nothing by moving.
}
