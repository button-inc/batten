//! A step's `cargo nextest run` kept case by case, so no case that passed is ever
//! run twice over the same inputs (CLOUD-2772).
//!
//! CRASH-ONLY, CASE BY CASE. `test:cargo` was one all-or-nothing step: a run
//! stopped partway kept nothing, so a stopped landing lap re-ran every case it
//! had already passed. Here the suite runs under a nextest run-wrapper that is
//! this binary: each case's pass is written durably the moment it passes, keyed
//! on what decides it — the build's inputs (every Rust file the checkout holds,
//! by content id, the manifests, lockfile, build scripts, toolchain and build
//! flags), every non-Rust file a case may read, the case's test target and its
//! argv — and a case whose key holds reports a pass without running. A stopped
//! run resumes; a head that moves no input re-runs nothing.
//!
//! THE INPUTS, NEVER THE BINARY'S BYTES: incremental compilation is not
//! byte-reproducible, so a key over the bytes missed on every relink of an
//! unchanged tree (measured 2026-11-15: 9,817 new passes in one journal over an
//! unmoved tree, after the pruner forced a rebuild between laps).
//!
//! ACROSS HEADS, CASE BY CASE (Ekstazi, Gligoric et al. ISSTA 2015): where the
//! mutation sweep's reach run recorded a case — the functions it ran, the files
//! it read — and nothing of that moved since the tree it was recorded on, the
//! case's pass is keyed on that dependency digest, the build's inputs and the
//! environment instead of every Rust file the build reads, so a head that
//! moves any of them still skips each case its change cannot reach. A case with no such record, or one
//! whose record cannot be read, keeps the build key: unknown reruns.
//!
//! The wrapper is the running binary itself (`current_exe`), so the path is right
//! on every platform and the mechanism is the one under test, as every verify
//! step here is (`cargo run -p batten`). CI runs every case: `step::run` skips
//! the journal under `CI` (CLOUD-2850), because CI's job is to confirm
//! independently.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::schema;

/// The first argument of the run-wrapper the suite runs each case under; the
/// journal directory follows it, then the case's argv.
pub const CASE_ARG: &str = "__test-case";

/// The run-wrapper's name in the generated nextest config.
const WRAPPER: &str = "batten-resume";

/// Under the run state: one directory per input state ([`run_key`]), holding
/// the passes keyed on each case's target and argv.
const BIN: &str = "bin";

/// Under the run state: each selected case's dependency half of its key, by
/// [`expect_name`], rewritten at every run's start.
const EXPECT: &str = "expect";

/// Under the run state: every dependency key a run passed over an unmoved
/// tree, one empty file each, outliving the run and the head.
const PASS: &str = "pass";

/// Under the run state: the dependency keys this run passed, promoted into
/// [`PASS`] only if the tree it started on still stands when it ends.
const PENDING: &str = "pending";

/// Under the run state: the tree the run started on ([`schema::tree_ids_digest`]).
const RUN: &str = "run";

/// How long a dependency pass nothing reads stays: every hit renews it.
const PASS_LIFETIME: std::time::Duration = std::time::Duration::from_hours(30 * 24);

/// As the run-wrapper: run the case unless its pass is journaled under its key,
/// and journal the pass. `None` when this process is not the wrapper.
pub fn wrapped(args: impl Iterator<Item = std::ffi::OsString>) -> Option<std::process::ExitCode> {
    let args: Vec<String> = args
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .collect();
    if args.first().map(String::as_str) != Some(CASE_ARG) {
        return None;
    }
    let code = case(args.get(1..).unwrap_or_default()).unwrap_or_else(|why| {
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!("batten: {CASE_ARG}: {why:#}\n"),
        );
        101
    });
    Some(std::process::ExitCode::from(code))
}

/// `command`, a `cargo nextest run`, with every case journaled: the config that
/// wraps each case written under the state directory of the checkout at `root`,
/// and named by `--config-file` ahead of any `--`, past which nextest hands
/// arguments to the test binaries.
///
/// ONE JOURNAL PER INPUT STATE: the build's inputs and the non-Rust files every
/// case may read are digested once here ([`build_inputs`]), not by each of
/// ~10,000 wrappers, and a journal for any other state is stale by construction
/// and goes, so the store stays one run's worth.
///
/// # Errors
///
/// The state directory, the input digest, or the config cannot be made.
pub fn journaled(root: &Path, command: &[String]) -> Result<Vec<String>> {
    let state = crate::state::repo_state_dir(root)?.join("test-run");
    let resources = schema::resource_ids(root)?;
    let inputs = build_inputs(root, &resources)?;
    retire_legacy(&state)?;
    clear_report(root);
    // THE SELECTION IS AN ECONOMY: a store that cannot be read or a digest
    // that cannot be taken leaves every case on the build key, never a skip.
    let held = select(root, &state, &resources, command).ok();
    // WHAT THE SELECTION HELD, for the seed to weigh against what passed
    // ([`seed`]); a selection that could not be made held nothing.
    let _ = crate::durable::replace(state.join(HELD), held.unwrap_or(0).to_string());
    wrap(root, &state, &inputs, command)
}

/// `command` under the journaling run-wrapper: each case's pass kept in the
/// journal for `key` under `state`'s [`BIN`], every other key's journal
/// removed, and the config — `config_root`'s nextest config with the wrapper
/// on every case ([`config_text`]) — written under `state` and named ahead of
/// any `--`.
///
/// ONE WRAPPER, TWO RUNS: `test:cargo` ([`journaled`]) and `test replay`'s
/// union run (`crate::replay`) keep their cases through the same wrapper, each
/// under its own state and key, so a case either finishes is durable the
/// moment it passes.
///
/// # Errors
///
/// The journal or the config cannot be written, or the config does not parse.
pub fn wrap(
    config_root: &Path,
    state: &Path,
    key: &str,
    command: &[String],
) -> Result<Vec<String>> {
    let bins = state.join(BIN);
    let journal = bins.join(key.get(..16).unwrap_or(key));
    prune_others(&bins, &journal)?;
    std::fs::create_dir_all(&journal)?;
    let config = state.join("nextest.toml");
    let wrapper = pinned_wrapper(state, &std::env::current_exe()?, &super::running_image()?)?;
    crate::durable::replace(&config, config_text(config_root, &wrapper, &journal)?)?;
    Ok(with_config(command, &config.to_string_lossy()))
}

/// The wrapper every case execs, PINNED under `state` rather than named where
/// it was built (CLOUD-2789): a hard link to `exe` where the filesystem allows
/// one, else a copy of `image`, the running image ([`super::running_image`]),
/// replacing the last run's. NOT A COPY OF `exe` (CLOUD-2886): once a build
/// has replaced it, `exe` names a deleted file, and only the image still reads.
///
/// THE BUILD DIRECTORY MOVES UNDER A RUN. Cargo replaces `target/debug/batten`
/// by a new file on any build, and a run naming it then execs a path the kernel
/// reports as `… (deleted)`: every case failed `[double-spawn] failed to exec`
/// with exit 70, and the replay read 597 base bodies as expectation changes,
/// measured on #1276. A link keeps the inode the run started with; a copy keeps
/// its bytes.
fn pinned_wrapper(state: &Path, exe: &Path, image: &Path) -> Result<std::path::PathBuf> {
    let pinned = state.join("wrapper");
    match std::fs::remove_file(&pinned) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("retire the last run's wrapper"),
    }
    if std::fs::hard_link(exe, &pinned).is_err() {
        std::fs::copy(image, &pinned).context("pin the run-wrapper")?;
    }
    Ok(pinned)
}

/// The format tag of a run's journal key ([`run_key`]), moved whenever what
/// the key reads changes, so a journal of another reading is never this one's.
const RUN_KEY_FORMAT: &str = "rk1";

/// The key of one run's journal: what every case's build and run are a
/// function of, besides its own target and argv ([`case_key`]) — the non-Rust
/// inputs (`non_rust`, [`schema::resource_digest`]), every Rust file of
/// `resources` by content id, the build's inputs (`build`, [`build_digest`])
/// and the code-generation variables (`flags`, [`flags_digest`]).
#[must_use]
pub fn run_key(
    non_rust: &str,
    resources: &std::collections::BTreeMap<String, String>,
    build: &str,
    flags: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in [RUN_KEY_FORMAT, non_rust, build, flags] {
        hasher.update(part.as_bytes());
        hasher.update(b"\x1f");
    }
    for (path, id) in resources {
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            hasher.update(format!("{path}\x1f{id}\x1e").as_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

/// [`run_key`] over the checkout at `root`, whose content ids are `resources`
/// ([`schema::resource_ids`]), under this process's build variables.
///
/// # Errors
///
/// The checkout cannot be read, or the compiler cannot be asked.
pub fn build_inputs(
    root: &Path,
    resources: &std::collections::BTreeMap<String, String>,
) -> Result<String> {
    let non_rust = schema::resource_digest(root)?;
    let build = build_digest(root, resources).context("the compiler cannot be asked")?;
    Ok(run_key(
        &non_rust,
        resources,
        &build,
        &flags_digest(&schema::build_flags()),
    ))
}

/// The digest of the code-generation variables `flags` ([`schema::build_flags`]).
#[must_use]
pub fn flags_digest(flags: &std::collections::BTreeMap<String, String>) -> String {
    let mut hasher = blake3::Hasher::new();
    for (key, value) in flags {
        hasher.update(format!("{key}={value}\x1e").as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// `command` with `--config-file <config>` ahead of its first `--`, or last.
#[must_use]
pub fn with_config(command: &[String], config: &str) -> Vec<String> {
    let at = command
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(command.len());
    let mut out = command[..at].to_vec();
    out.extend([String::from("--config-file"), config.to_owned()]);
    out.extend(command[at..].iter().cloned());
    out
}

/// Write the run's selection under `state`: the start tree ([`RUN`]), an
/// empty [`PENDING`], [`PASS`] aged, and in [`EXPECT`] the dependency half of
/// the key of every case the sweep's reach store lets this tree select.
/// `resources` is the tree's content ids ([`schema::resource_ids`]).
///
/// # Errors
///
/// The state cannot be written, or the tree cannot be read.
fn select(
    root: &Path,
    state: &Path,
    resources: &std::collections::BTreeMap<String, String>,
    command: &[String],
) -> Result<usize> {
    let expect = state.join(EXPECT);
    let _ = std::fs::remove_dir_all(&expect);
    let _ = std::fs::remove_dir_all(state.join(PENDING));
    let _ = std::fs::remove_dir_all(state.join(RAN));
    let _ = std::fs::remove_file(state.join(RUN_ENV));
    std::fs::create_dir_all(&expect)?;
    std::fs::create_dir_all(state.join(PENDING))?;
    collect_passes(&state.join(PASS), PASS_LIFETIME)?;
    crate::durable::replace(state.join(RUN), schema::tree_ids_digest(resources))?;
    if !builds_as_swept(command) {
        return Ok(0);
    }
    let env = env_digest(std::env::vars_os(), &journal_env(root));
    // THE RUN'S ENVIRONMENT, for a seed that runs under its own to key the
    // passes this run leaves on ([`seed_passes`]).
    crate::durable::replace(state.join(RUN_ENV), &env)?;
    let held = held_cases(root, resources, &env)?;
    for ((name, binary), key) in &held {
        crate::durable::replace(expect.join(expect_name(name, binary)), key)?;
    }
    Ok(held.len())
}

/// Every case of the sweep's reach store under the checkout at `root` whose
/// sealed record still holds on that tree (its selection digest unmoved), with
/// the dependency half of its key ([`expected`]) under the environment digest
/// `env`. `resources` is the tree's content ids ([`schema::resource_ids`]).
///
/// ONE READING OF THE STORE, TWO CONSUMERS: [`select`] writes each into
/// [`EXPECT`] for the run-wrapper, and `test replay` keys each modified test's
/// verdict on it (`crate::replay`'s journal), so neither can drift from the other's
/// notion of what a case depends on. A case missing here is unknown, and each
/// consumer falls back to its own conservative key.
///
/// # Errors
///
/// The store's tree cannot be indexed, or the compiler cannot be asked.
pub fn held_cases(
    root: &Path,
    resources: &std::collections::BTreeMap<String, String>,
    env: &str,
) -> Result<std::collections::BTreeMap<(String, String), String>> {
    let mut held = std::collections::BTreeMap::new();
    let base = crate::state::repo_state_dir(root)?
        .join("mutate")
        .join("schema")
        .join("reach");
    let sealed = schema::sealed_cases(&base);
    if sealed.is_empty() {
        return Ok(held);
    }
    let build = build_digest(root, resources).context("the compiler cannot be asked")?;
    let flags = schema::build_flags();
    let mut formats: std::collections::BTreeMap<&str, Vec<&schema::Sealed>> =
        std::collections::BTreeMap::new();
    for record in &sealed {
        formats.entry(&record.format).or_default().push(record);
    }
    for (key, records) in formats {
        // A FORMAT THAT CANNOT BE READ, OR A SUITE BUILT UNDER OTHER FLAGS, is
        // unknown for every record read in it.
        let Some(format) = schema::Format::load(&base, key).filter(|f| f.flags == flags) else {
            continue;
        };
        let index = schema::dependency_index(root, &format)?;
        let build = format_build(&build, &unprobed_packages_digest(root, resources, &format));
        let cases: std::collections::BTreeMap<(String, String), schema::Ran> = records
            .iter()
            .map(|record| (record.case.clone(), record.ran.clone()))
            .collect();
        let now = schema::test_digests(root, &index, &format.dirs, &cases, resources);
        for record in records {
            if now.get(&record.case).and_then(Option::as_deref) != Some(record.tested.as_str()) {
                continue;
            }
            let (name, binary) = &record.case;
            held.insert(
                record.case.clone(),
                expected(name, binary, &record.tested, &build, env),
            );
        }
    }
    Ok(held)
}

/// The build half of a key for records read in one format: the build's inputs
/// and the sources of every package that format never probed.
fn format_build(build: &str, unprobed: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(build.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(unprobed.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// The digest of every Rust source, by content id, of every workspace package
/// none of whose files `format` probed: everything under the package's
/// directory but its own `tests/`, `benches/` and `examples/`, which no other
/// crate links.
///
/// CONSERVATIVE BY CONSTRUCTION: a record names only the functions the sweep
/// probed, so code a case runs in a package the sweep never rendered (a
/// helper crate it links) is in no record. Folded into every key read in the
/// format, an edit there reruns every selected case rather than skipping one
/// that ran it.
#[must_use]
pub fn unprobed_packages_digest(
    root: &Path,
    resources: &std::collections::BTreeMap<String, String>,
    format: &schema::Format,
) -> String {
    let packages: Vec<String> = resources
        .keys()
        .filter_map(|path| {
            let dir = match path.strip_suffix("Cargo.toml")? {
                "" => "",
                dir => dir.strip_suffix('/')?,
            };
            let manifest = crate::fsio::read_to_string(root.join(path)).ok()?;
            manifest
                .parse::<toml::Table>()
                .ok()?
                .contains_key("package")
                .then(|| dir.to_owned())
        })
        .collect();
    // EACH FILE BELONGS TO ITS INNERMOST PACKAGE, so a nested crate is its own.
    let owner = |path: &str| -> Option<&String> {
        packages
            .iter()
            .filter(|dir| dir.is_empty() || path.starts_with(&format!("{dir}/")))
            .max_by_key(|dir| dir.len())
    };
    let probed: std::collections::BTreeSet<&String> = format
        .probed
        .iter()
        .filter_map(|file| owner(file))
        .collect();
    let mut hasher = blake3::Hasher::new();
    for (path, id) in resources {
        if std::path::Path::new(path)
            .extension()
            .is_none_or(|extension| extension != "rs")
        {
            continue;
        }
        let Some(dir) = owner(path).filter(|dir| !probed.contains(dir)) else {
            continue;
        };
        let inner = if dir.is_empty() {
            path.as_str()
        } else {
            &path[dir.len() + 1..]
        };
        if ["tests/", "benches/", "examples/"]
            .iter()
            .any(|own| inner.starts_with(own))
        {
            continue;
        }
        hasher.update(format!("{path}\x1f{id}\x1e").as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Whether `command` builds the suite as the sweep's reach run did, so what a
/// record saw is what the suite runs: no feature, profile or target chosen
/// on its command line. One that does selects nothing.
#[must_use]
pub fn builds_as_swept(command: &[String]) -> bool {
    let tail = command
        .iter()
        .position(|arg| arg == "--")
        .map_or(command, |at| &command[..at]);
    !tail.iter().any(|arg| {
        let flag = arg.split_once('=').map_or(arg.as_str(), |(flag, _)| flag);
        matches!(
            flag,
            "--features"
                | "--all-features"
                | "--no-default-features"
                | "--release"
                | "-r"
                | "--cargo-profile"
                | "--target"
                | "--config"
        ) || flag.starts_with("-F")
    })
}

/// The file in [`EXPECT`] a case's selection is written to.
#[must_use]
pub fn expect_name(name: &str, binary: &str) -> String {
    blake3::hash(format!("{name}\t{binary}").as_bytes())
        .to_hex()
        .to_string()
}

/// The dependency half of a case's key: its name and binary id, its selection
/// digest, the build's inputs and the environment.
#[must_use]
pub fn expected(name: &str, binary: &str, tested: &str, build: &str, env: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in ["tc1", name, binary, tested, build, env] {
        hasher.update(part.as_bytes());
        hasher.update(b"\x1f");
    }
    hasher.finalize().to_hex().to_string()
}

/// The files whose bytes decide what the suite's build is, besides the Rust
/// a case's selection digest reads: every manifest and build script and what
/// each script includes by `#[path]`, the lockfile, cargo's and nextest's
/// config and the toolchain pin, with the compiler's own `-vV`. `None` where
/// the compiler cannot be asked.
#[must_use]
pub fn build_digest(
    root: &Path,
    resources: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    Some(build_digest_with(root, resources, &compiler_version(root)?))
}

/// [`build_digest`] with the compiler's `-vV` already in hand.
#[must_use]
pub fn build_digest_with(
    root: &Path,
    resources: &std::collections::BTreeMap<String, String>,
    compiler: &[u8],
) -> String {
    let mut paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for path in resources.keys() {
        let file = path.rsplit('/').next().unwrap_or(path);
        if matches!(
            file,
            "Cargo.toml" | "Cargo.lock" | "build.rs" | "rust-toolchain" | "rust-toolchain.toml"
        ) || path.starts_with(".cargo/config")
            || path == ".config/nextest.toml"
        {
            paths.insert(path.clone());
        }
        if file == "build.rs" {
            let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
            let script = crate::fsio::read_to_string(root.join(path)).unwrap_or_default();
            for line in script.lines() {
                if let Some(rest) = line.trim().strip_prefix("#[path = \"")
                    && let Some((included, _)) = rest.split_once('"')
                {
                    paths.insert(if dir.is_empty() {
                        included.to_owned()
                    } else {
                        format!("{dir}/{included}")
                    });
                }
            }
        }
    }
    let mut hasher = blake3::Hasher::new();
    for path in &paths {
        hasher.update(format!("{path}\x1f").as_bytes());
        hasher.update(resources.get(path).map_or("-", String::as_str).as_bytes());
        hasher.update(b"\x1e");
    }
    hasher.update(compiler);
    hasher.finalize().to_hex().to_string()
}

/// `rustc -vV` as the toolchain ladder resolves the compiler, through the
/// placed adapter.
#[must_use]
pub fn compiler_version(root: &Path) -> Option<Vec<u8>> {
    let argv = ["rustc", "-vV"].map(str::to_owned);
    let (code, said) =
        crate::exec::piped_argv(root, &argv, "", crate::exec::Diagnostics::Drop, &[])?;
    // A SUCCESSFUL `-vV` ALWAYS PRINTS its release line; the exit is the test.
    (code == 0).then(|| said.into_bytes())
}

/// The variables a journaled case is keyed on where no step declares its own
/// ([`journal_env`]): Batten's own, Rust's and cargo's, CI, home and path —
/// the fixed list the journal read before a step could declare one.
pub const DEFAULT_ENV: [&str; 6] = ["BATTEN_*", "RUST*", "CARGO_*", "CI", "HOME", "PATH"];

/// The tool line a step declares its keyed environment with (CLOUD-2786):
/// `batten step env [--exclude NAME]... -- PATTERN...`, an entry of the row's
/// committed `tools` array, answered in-process by the step cache as
/// `step base` is. ONE COMMITTED AUTHORITY: the declaration is the row's own
/// tool line, so it needs no key of its own and no task-runner variable.
pub const ENV: [&str; 3] = ["batten", "step", "env"];

/// A step's declared environment: the names and `PREFIX*` patterns its key
/// reads, and the names it leaves out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclaredEnv {
    /// Names, or prefixes ending `*`, whose variables are keyed.
    pub env: Vec<String>,
    /// Names a pattern of `env` matches that are never keyed.
    pub exclude: Vec<String>,
}

impl DeclaredEnv {
    /// Whether the variable `name` is keyed: a declaration matches it and no
    /// exclusion names it.
    #[must_use]
    pub fn keys(&self, name: &str) -> bool {
        self.env.iter().any(|pattern| env_matches(name, pattern))
            && !self.exclude.iter().any(|excluded| excluded == name)
    }

    /// [`DEFAULT_ENV`], excluding nothing.
    #[must_use]
    pub fn fallback() -> Self {
        Self {
            env: DEFAULT_ENV.map(String::from).to_vec(),
            exclude: Vec::new(),
        }
    }
}

/// Whether `name` is `pattern`, or begins with what precedes its `*`.
#[must_use]
pub fn env_matches(name: &str, pattern: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(name == pattern, |prefix| name.starts_with(prefix))
}

/// Whether `name` is `^[A-Z_][A-Z0-9_]*$`.
fn variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_uppercase() || first == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The declaration `env` and `exclude` make, `None` when `env` is empty, an
/// entry of `env` is neither a name nor a `PREFIX*` pattern, or an entry of
/// `exclude` is not a name (an exclusion never carries a `*`).
#[must_use]
pub fn declare(env: Vec<String>, exclude: Vec<String>) -> Option<DeclaredEnv> {
    let patterns_valid = env
        .iter()
        .all(|entry| variable_name(entry.strip_suffix('*').unwrap_or(entry)));
    let names_valid = exclude.iter().all(|entry| variable_name(entry));
    (!env.is_empty() && patterns_valid && names_valid).then_some(DeclaredEnv { env, exclude })
}

/// The [`DeclaredEnv`] a tool line's words after [`ENV`] spell, or `None` for
/// any other shape — which keys nothing, so the step runs. Only the canonical
/// spelling is read: `--exclude NAME` as separate tokens, then `--`.
#[must_use]
pub fn env_ask(words: &[String]) -> Option<DeclaredEnv> {
    let mut exclude = Vec::new();
    let mut rest = words.iter();
    loop {
        match rest.next()?.as_str() {
            "--exclude" => exclude.push(rest.next()?.clone()),
            "--" => break,
            _ => return None,
        }
    }
    declare(rest.cloned().collect(), exclude)
}

/// The environment a row's `tools` declare: its first entry spelled
/// `batten step env ...` ([`ENV`], [`env_ask`]); `None` when it has none or
/// that entry does not parse.
#[must_use]
pub fn declared_env(tools: &[Vec<String>]) -> Option<DeclaredEnv> {
    tools
        .iter()
        .find_map(|tool| {
            tool.get(..ENV.len())
                .filter(|head| head.iter().map(String::as_str).eq(ENV))
                .and_then(|_| tool.get(ENV.len()..))
        })
        .and_then(env_ask)
}

/// The environment a journaled case is keyed on in the checkout at `root`:
/// what the committed `[[step]]` row with `journal = "nextest"` declares in
/// its `tools` ([`declared_env`]), or [`DeclaredEnv::fallback`] where no row
/// is journaled, the authority will not load, or the row declares nothing
/// readable.
#[must_use]
pub fn journal_env(root: &Path) -> DeclaredEnv {
    crate::resolve::committed(root, &crate::resolve::Overrides::default())
        .ok()
        .and_then(|config| {
            config
                .steps
                .into_iter()
                .find(|row| row.journal == Some(crate::step_table::Journal::Nextest))
        })
        .and_then(|row| declared_env(row.tools()))
        .unwrap_or_else(DeclaredEnv::fallback)
}

/// The digest of every variable of `vars` that `declared` keys.
#[must_use]
pub fn env_digest(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    declared: &DeclaredEnv,
) -> String {
    let kept: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> = vars
        .filter(|(key, _)| key.to_str().is_some_and(|key| declared.keys(key)))
        .collect();
    let mut hasher = blake3::Hasher::new();
    for (key, value) in kept {
        hasher.update(key.as_encoded_bytes());
        hasher.update(b"=");
        hasher.update(value.as_encoded_bytes());
        hasher.update(b"\x1e");
    }
    hasher.finalize().to_hex().to_string()
}

/// Remove every pass under `pass` unread for longer than `lifetime`.
///
/// # Errors
///
/// The directory cannot be read.
fn collect_passes(pass: &Path, lifetime: std::time::Duration) -> Result<()> {
    collect_passes_at(pass, lifetime, std::time::SystemTime::now())
}

/// [`collect_passes`] as of `now`: a pass is stale only once its age EXCEEDS
/// `lifetime`.
///
/// # Errors
///
/// The directory cannot be read.
fn collect_passes_at(
    pass: &Path,
    lifetime: std::time::Duration,
    now: std::time::SystemTime,
) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(pass) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry?.path();
        let stale = std::fs::metadata(&path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|at| now.duration_since(at).ok())
            .is_some_and(|age| age > lifetime);
        if stale {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Remove what an earlier layout left directly under `state`: a binary
/// journal named by its input state, which [`prune_others`] no longer sees.
///
/// # Errors
///
/// A directory cannot be removed.
fn retire_legacy(state: &Path) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(state) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry?.path();
        let ours = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| [BIN, EXPECT, PASS, PENDING, RAN].contains(&name));
        if path.is_dir() && !ours {
            std::fs::remove_dir_all(&path).with_context(|| format!("prune {}", path.display()))?;
        }
    }
    Ok(())
}

/// End a journaled run in the checkout at `root`: move every dependency pass
/// it left pending into [`PASS`] if the tree it started on still stands, and
/// drop them otherwise. A pass over a tree that moved mid-run may be a pass
/// of a binary built from neither tree, so it never outlives its run.
///
/// # Errors
///
/// The state cannot be read or written.
pub fn promote(root: &Path) -> Result<usize> {
    let state = crate::state::repo_state_dir(root)?.join("test-run");
    let started = crate::fsio::read_to_string(state.join(RUN)).ok();
    let now = schema::resource_ids(root)
        .map(|ids| schema::tree_ids_digest(&ids))
        .ok();
    promote_pending(&state, stood(started.as_deref(), now.as_deref()))
}

/// Whether the tree a run `started` on is the tree there is `now`: never where
/// either is unknown, which is a pass of an unknown tree.
fn stood(started: Option<&str>, now: Option<&str>) -> bool {
    started.is_some() && started == now
}

/// [`promote`]'s move, `stood` saying whether the run's tree still stands.
///
/// # Errors
///
/// The state cannot be read or written.
pub fn promote_pending(state: &Path, stood: bool) -> Result<usize> {
    let pending = state.join(PENDING);
    let Ok(entries) = std::fs::read_dir(&pending) else {
        return Ok(0);
    };
    let pass = state.join(PASS);
    std::fs::create_dir_all(&pass)?;
    let mut promoted = 0;
    for entry in entries {
        let path = entry?.path();
        if stood && let Some(name) = path.file_name() {
            std::fs::rename(&path, pass.join(name))?;
            promoted += 1;
        }
    }
    std::fs::remove_dir_all(&pending)?;
    Ok(promoted)
}

/// Under the run state: how many cases this run's selection held ([`select`]).
const HELD: &str = "held";

/// Under the run state: a reach seed is owed and waits for the lap that holds
/// the land singleton to end ([`lap_ended`]).
const SEED_PENDING: &str = "seed-pending";

/// The variable that makes `batten mutate cargo` the reach seed: the reach
/// phase over every workspace package, not a change's (CLOUD-2842).
pub const SEED_ENV: &str = "BATTEN_REACH_SEED";

/// The singleton and registry name a running seed holds, so two never stack
/// and a lap can find the one to preempt.
pub const SEED_TASK: &str = "reach-seed";

/// The singleton a landing lap holds (`batten land lap`).
const LAND_TASK: &str = "land";

/// What [`seed`] did after a passing journaled run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seeded {
    /// On CI: no reader restores the store there, so a seed spends metered
    /// minutes for nothing.
    NotOnCi,
    /// Inside a reach or sweep run, or a seed itself: a nested seed would
    /// sweep a fixture and stack under the running one.
    Nested,
    /// The selection held every case that passed: nothing to seed.
    Covered,
    /// A lap holds the land singleton: the seed waits for it to end.
    Deferred,
    /// The seed was spawned detached, or one already runs.
    Spawned,
}

/// After a passing journaled run in the checkout at `root`: seed the reach
/// store when the selection held fewer cases than the run passed, so the next
/// head selects what this one could not (CLOUD-2842).
///
/// AN ECONOMY, NEVER A VERDICT: whatever it decides, the step's exit stands,
/// and a seed that fails leaves the selection as it was, which re-runs.
#[must_use]
pub fn seed(root: &Path) -> Seeded {
    if on_ci() {
        return Seeded::NotOnCi;
    }
    if nested() {
        return Seeded::Nested;
    }
    let Ok(state) = crate::state::repo_state_dir(root).map(|dir| dir.join("test-run")) else {
        return Seeded::Covered;
    };
    let held = crate::fsio::read_to_string(state.join(HELD))
        .ok()
        .and_then(|held| held.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let passed = report_path(root)
        .and_then(|report| crate::fsio::read_to_string(report).ok())
        .and_then(|xml| passed_cases(&xml))
        .unwrap_or(0);
    if held >= passed {
        return Seeded::Covered;
    }
    request_seed(root)
}

/// Whether this process runs on CI: `CI` set to anything but empty.
fn on_ci() -> bool {
    std::env::var_os("CI").is_some_and(|ci| !ci.is_empty())
}

/// Whether this process runs inside a reach or sweep run, or is a seed.
fn nested() -> bool {
    [SEED_ENV, schema::REACH, schema::RECORD, schema::ACTIVE]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
}

/// Spawn the seed, or leave it owed while a lap holds the land singleton.
fn request_seed(root: &Path) -> Seeded {
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return Seeded::Covered;
    };
    if lap_live(root) {
        return Seeded::Deferred;
    }
    if batten_base::task::singleton_holder(&git_dir, SEED_TASK).is_some() {
        return Seeded::Spawned;
    }
    let Ok(exe) = std::env::current_exe() else {
        return Seeded::Covered;
    };
    crate::exec::detached(
        &exe,
        &[String::from("mutate"), String::from("cargo")],
        &[(SEED_ENV, "1"), (schema::PHASE, "reach")],
    );
    Seeded::Spawned
}

/// Whether a lap holds the land singleton in the checkout at `root`; when one
/// does, the seed is left owed ([`lap_ended`] spawns it).
#[must_use]
pub fn lap_live(root: &Path) -> bool {
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return false;
    };
    if batten_base::task::singleton_holder(&git_dir, LAND_TASK).is_none() {
        return false;
    }
    if let Ok(state) = crate::state::repo_state_dir(root).map(|dir| dir.join("test-run")) {
        let _ = std::fs::create_dir_all(&state);
        let _ = crate::durable::replace(state.join(SEED_PENDING), "");
    }
    true
}

/// A landing lap in the checkout at `root` released the land singleton: spawn
/// the seed a run during it left owed. `None` when none was owed.
#[must_use]
pub fn lap_ended(root: &Path) -> Option<Seeded> {
    let state = crate::state::repo_state_dir(root).ok()?.join("test-run");
    std::fs::remove_file(state.join(SEED_PENDING)).ok()?;
    if on_ci() {
        return Some(Seeded::NotOnCi);
    }
    Some(request_seed(root))
}

/// A landing lap in the checkout at `root` took the land singleton: end a
/// running seed's process group and leave the seed owed, so it starts over
/// once the lap ends. Whether a seed was ended.
///
/// THE LAP COMES FIRST: a first seed is a schema build and a whole reach run,
/// minutes of every core, and the lap's own gates must not queue behind it.
/// `carry_forward` keeps what the ended seed finished.
#[must_use]
pub fn preempt(root: &Path) -> bool {
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return false;
    };
    let Some(holder) = batten_base::task::singleton_holder(&git_dir, SEED_TASK) else {
        return false;
    };
    // A DETACHED SEED LEADS ITS OWN GROUP (`exec::detached`), so its pid is
    // the group's id and every build and case it spawned goes with it.
    let ended = crate::exec::terminate_group(&holder);
    batten_base::task::unregister(&git_dir, &holder);
    batten_base::task::singleton_release(&git_dir, SEED_TASK);
    if let Ok(state) = crate::state::repo_state_dir(root).map(|dir| dir.join("test-run")) {
        let _ = std::fs::create_dir_all(&state);
        let _ = crate::durable::replace(state.join(SEED_PENDING), "");
    }
    ended
}

/// How many cases a nextest `JUnit` report names as passed: no `<failure>`,
/// `<error>` or `<skipped>` child. `None` when it is not XML.
fn passed_cases(xml: &str) -> Option<usize> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    Some(
        doc.descendants()
            .filter(|node| node.has_tag_name("testcase"))
            .filter(|case| {
                !case.children().any(|child| {
                    child.has_tag_name("failure")
                        || child.has_tag_name("error")
                        || child.has_tag_name("skipped")
                })
            })
            .count(),
    )
}

/// Remove every journal under `state` but `keep`.
fn prune_others(state: &Path, keep: &Path) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(state) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() && path != keep {
            std::fs::remove_dir_all(&path).with_context(|| format!("prune {}", path.display()))?;
        }
    }
    Ok(())
}

/// The repository's nextest config with the journaling wrapper on every case of
/// the default profile, so each keeps its setup scripts, report and settings.
///
/// # Errors
///
/// The repository's nextest config does not parse.
pub fn config_text(root: &Path, wrapper: &Path, journal: &Path) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = super::cover::wrapper_experimental(root)?
        .parse()
        .context("parse nextest.toml")?;
    // A `JUnit` REPORT ON EVERY JOURNALED RUN (CLOUD-2786): a failing run's
    // cases are read from it ([`flaky_suspects`]). One the profile already
    // writes is kept where it is, so no other reader of it moves.
    // A STANZA APPENDED AS TEXT where the profile has no `junit` table: an
    // index into a missing table makes an inline one, which the
    // `[[profile.default.scripts]]` appended below may not extend.
    let profile = journal_profile();
    let mut stanza = String::new();
    if report_name(&doc).is_none() {
        let has_junit = doc
            .get("profile")
            .and_then(|profiles| profiles.get(&profile))
            .and_then(|table| table.get("junit"))
            .is_some();
        if has_junit {
            doc["profile"][&profile]["junit"]["path"] = toml_edit::value(REPORT);
        } else {
            stanza = format!(
                "\n[profile.{}.junit]\npath = \"{REPORT}\"\n",
                toml_edit::Key::new(profile.as_str())
            );
        }
    }
    let mut config = doc.to_string();
    config.push_str(&stanza);
    let wrapper = toml_edit::Value::from(wrapper.to_string_lossy().into_owned());
    let journal = toml_edit::Value::from(journal.to_string_lossy().into_owned());
    let _ = write!(
        config,
        "\n[scripts.wrapper.{WRAPPER}]\ncommand = [{wrapper}, \"{CASE_ARG}\", {journal}]\n\n\
         [[profile.default.scripts]]\nfilter = \"all()\"\nrun-wrapper = \"{WRAPPER}\"\n"
    );
    Ok(config)
}

/// The `JUnit` report a journaled run writes where its profile names none.
const REPORT: &str = "junit.xml";

/// The nextest profile a journaled run uses: `NEXTEST_PROFILE`, or `default`.
fn journal_profile() -> String {
    profile_or_default(std::env::var("NEXTEST_PROFILE").ok())
}

/// `named`, or `default` where it is unset or empty: [`journal_profile`]'s
/// decision, apart from the environment it reads.
fn profile_or_default(named: Option<String>) -> String {
    named
        .filter(|profile| !profile.is_empty())
        .unwrap_or_else(|| String::from("default"))
}

/// The `JUnit` report name `doc` gives the journal's profile, or `default`'s,
/// which every profile inherits.
fn report_name(doc: &toml_edit::DocumentMut) -> Option<String> {
    let profiles = doc.get("profile")?;
    [journal_profile(), String::from("default")]
        .iter()
        .find_map(|profile| {
            profiles
                .get(profile)?
                .get("junit")?
                .get("path")?
                .as_str()
                .filter(|path| !path.is_empty())
                .map(str::to_owned)
        })
}

/// Where a journaled run in the checkout at `root` leaves its `JUnit` report:
/// nextest's store (the config's `store.dir`, else `<target>/nextest`), the
/// profile, then the report's name ([`config_text`]).
fn report_path(root: &Path) -> Option<PathBuf> {
    let text = super::cover::wrapper_experimental(root).ok()?;
    let doc: toml_edit::DocumentMut = text.parse().ok()?;
    let store = doc
        .get("store")
        .and_then(|store| store.get("dir"))
        .and_then(toml_edit::Item::as_str)
        .map_or_else(
            || default_store(root, std::env::var_os("CARGO_TARGET_DIR")),
            |dir| root.join(dir),
        );
    let name = report_name(&doc).unwrap_or_else(|| REPORT.to_owned());
    Some(store.join(journal_profile()).join(name))
}

/// Nextest's store where the config names none: `<target>/nextest`, where
/// `<target>` is the caller's `target` (`$CARGO_TARGET_DIR`) when set and
/// non-empty, else `target`.
fn default_store(root: &Path, target: Option<std::ffi::OsString>) -> PathBuf {
    let target = target
        .filter(|dir| !dir.is_empty())
        .unwrap_or_else(|| "target".into());
    root.join(target).join("nextest")
}

/// Remove the last journaled run's report, so a run that writes none (a build
/// that failed) is never read as the last run's verdicts.
pub fn clear_report(root: &Path) {
    if let Some(report) = report_path(root) {
        let _ = std::fs::remove_file(report);
    }
}

/// Every case a nextest `JUnit` report names as failed (a `<failure>` or
/// `<error>` child), by name and binary id; `None` when it is not XML.
fn failed_cases(xml: &str) -> Option<std::collections::BTreeSet<(String, String)>> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    Some(
        doc.descendants()
            .filter(|node| node.has_tag_name("testcase"))
            .filter(|case| {
                case.children()
                    .any(|child| child.has_tag_name("failure") || child.has_tag_name("error"))
            })
            .filter_map(|case| {
                Some((
                    case.attribute("name")?.to_owned(),
                    case.attribute("classname")?.to_owned(),
                ))
            })
            .collect(),
    )
}

/// After a failing journaled run in the checkout at `root`: every failed case
/// by name and binary id, in order. `None` where the report cannot be read.
#[must_use]
pub fn failed(root: &Path) -> Option<Vec<(String, String)>> {
    let report = crate::fsio::read_to_string(report_path(root)?).ok()?;
    Some(failed_cases(&report)?.into_iter().collect())
}

/// After a failing journaled run in the checkout at `root`: the failed cases
/// whose sealed reach record still holds on this tree — nothing any of them
/// ran or read moved since it was recorded, so no change here can have caused
/// the failure (`DeFlaker`, Bell et al. ICSE 2018) — and how many cases failed.
/// `None` where the run's report cannot be read.
///
/// A LABEL, NEVER A VERDICT: the step's exit stands. It decides only whether
/// the failure receipt the step records re-runs (CLOUD-2253): a failure whose
/// every failing case is a suspect does, any other is red until its inputs move.
#[must_use]
pub fn flaky_suspects(root: &Path) -> Option<(Vec<(String, String)>, usize)> {
    let report = crate::fsio::read_to_string(report_path(root)?).ok()?;
    let failed = failed_cases(&report)?;
    let held = schema::resource_ids(root)
        .ok()
        .and_then(|resources| held_cases(root, &resources, "").ok())
        .unwrap_or_default();
    let suspects = failed
        .iter()
        .filter(|case| held.contains_key(*case))
        .cloned()
        .collect();
    Some((suspects, failed.len()))
}

/// Run one case as the wrapper, or report its journaled pass: under its
/// target in the run's journal, or under its dependency key where the run
/// selected it.
fn case(args: &[String]) -> Result<u8> {
    let (journal, test) = args.split_first().context("no journal named")?;
    let journal = PathBuf::from(journal);
    let (program, rest) = test.split_first().context("no case to run")?;
    let target = case_target(program, &std::env::current_dir()?)?;
    let marker = journal.join(case_key(Key::Target(&target), test));
    let state = journal.parent().and_then(Path::parent);
    if marker.is_file() {
        if let Some(state) = state {
            note_ran(state, program, test);
        }
        return Ok(0);
    }
    let dependency = state.and_then(|state| dependency_key(state, program, test));
    if let (Some(state), Some(key)) = (state, dependency.as_deref()) {
        let pass = state.join(PASS).join(key);
        if pass.is_file() {
            // RENEWED ON EVERY HIT, so a pass still in use outlives the
            // collection of passes nothing reads.
            let _ = std::fs::File::options()
                .write(true)
                .open(&pass)
                .and_then(|file| file.set_modified(std::time::SystemTime::now()));
            return Ok(0);
        }
    }
    let code = spawn_case(program, rest)?;
    if code == 0 {
        crate::durable::replace(&marker, "")?;
        // An economy: a pending pass that cannot be written costs the next head
        // a rerun, never this case its pass.
        if let (Some(state), Some(key)) = (state, dependency.as_deref()) {
            let _ = crate::durable::replace(state.join(PENDING).join(key), "");
        }
        if let Some(state) = state {
            note_ran(state, program, test);
        }
    }
    Ok(code)
}

/// Under the run state: each case this run passed, by [`expect_name`], with
/// the tree the run started on and its argv past the binary ([`note_ran`]).
const RAN: &str = "ran";

/// Under the run state: the environment digest the run's selection keyed on.
const RUN_ENV: &str = "env";

/// Note that the case `test` of `program` passed over the run's tree, so a
/// seed sealing that tree can key its pass ([`seed_passes`]). An economy: a
/// note that cannot be written costs the next head a rerun.
fn note_ran(state: &Path, program: &str, test: &[String]) {
    let (Some(name), Ok(cwd), Ok(over)) = (
        super::cover::test_name(test),
        std::env::current_dir(),
        crate::fsio::read_to_string(state.join(RUN)),
    ) else {
        return;
    };
    let binary = super::cover::binary_id(program, &cwd);
    if binary.is_empty() {
        return;
    }
    let args = test.get(1..).unwrap_or_default().join("\x1f");
    let _ = std::fs::create_dir_all(state.join(RAN));
    let _ = crate::durable::replace(
        state.join(RAN).join(expect_name(name, &binary)),
        format!("{over}\n{args}"),
    );
}

/// After a seed sealed reach over the checkout at `root`: key a dependency
/// pass for every case the store now holds whose last journaled run passed it
/// over this same tree, so the next head selects it at once rather than
/// re-running it to earn the pass (CLOUD-2842). How many it keyed.
///
/// THE PASS IS THE RUN'S, NEVER THE SEED'S: the seed's reach run is the probed
/// build, and only a pass of the suite as the step builds it is reused. It is
/// keyed as the run itself would have keyed it ([`case_key`] over
/// [`expected`], under the run's own environment digest), and only where the
/// tree the run passed it over is the tree the seed's record was sealed on.
///
/// # Errors
///
/// The tree cannot be read or a pass cannot be written.
pub fn seed_passes(root: &Path) -> Result<usize> {
    let state = crate::state::repo_state_dir(root)?.join("test-run");
    let Ok(env) = crate::fsio::read_to_string(state.join(RUN_ENV)) else {
        return Ok(0);
    };
    let resources = schema::resource_ids(root)?;
    let tree = schema::tree_ids_digest(&resources);
    let held = held_cases(root, &resources, env.trim())?;
    let pass = state.join(PASS);
    std::fs::create_dir_all(&pass)?;
    let mut keyed = 0;
    for ((name, binary), expected) in &held {
        let Ok(ran) = crate::fsio::read_to_string(state.join(RAN).join(expect_name(name, binary)))
        else {
            continue;
        };
        let Some((over, args)) = ran.split_once('\n') else {
            continue;
        };
        if over != tree {
            continue;
        }
        // `case_key` skips the binary's path, so its slot is held empty.
        let mut test = vec![String::new()];
        if !args.is_empty() {
            test.extend(args.split('\x1f').map(str::to_owned));
        }
        crate::durable::replace(pass.join(case_key(Key::Dep(expected), &test)), "")?;
        keyed += 1;
    }
    Ok(keyed)
}

/// The dependency key of the case `test` of `program`, where the run selected
/// it ([`EXPECT`]); `None` keeps it on the build key.
fn dependency_key(state: &Path, program: &str, test: &[String]) -> Option<String> {
    let name = super::cover::test_name(test)?;
    let binary = super::cover::binary_id(program, &std::env::current_dir().ok()?);
    if binary.is_empty() {
        return None;
    }
    let expected = crate::fsio::read_to_string(state.join(EXPECT).join(expect_name(name, &binary)))
        .ok()
        .filter(|held| !held.is_empty())?;
    Some(case_key(Key::Dep(&expected), test))
}

fn spawn_case(program: &str, rest: &[String]) -> Result<u8> {
    let ran = super::spawn_as(
        &std::env::current_dir()?,
        super::Program::Test(program),
        rest,
        &[],
        super::runner_bound(),
        super::Said::Streamed,
    )?;
    Ok(match ran.outcome {
        super::Outcome::Passed => 0,
        super::Outcome::Failed(Some(code)) => u8::try_from(code).unwrap_or(101),
        super::Outcome::Failed(None) | super::Outcome::TimedOut => 101,
    })
}

/// What a case's pass is keyed on besides its argv.
#[derive(Debug, Clone, Copy)]
pub enum Key<'a> {
    /// Its test target ([`case_target`]), in a journal keyed on the run's
    /// inputs ([`run_key`]).
    Target(&'a str),
    /// The dependency half the run selected it with ([`expected`]).
    Dep(&'a str),
}

/// A case's journal key: its target or its dependency half, and its whole
/// argv but the binary's path.
#[must_use]
pub fn case_key(key: Key<'_>, test: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    match key {
        Key::Target(target) => hasher.update(b"target\x1e").update(target.as_bytes()),
        Key::Dep(expected) => hasher.update(b"dep\x1e").update(expected.as_bytes()),
    };
    for arg in test.iter().skip(1) {
        hasher.update(b"\x1f");
        hasher.update(arg.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// The test target the binary at `program` builds, as nextest runs it from
/// `package_dir`: its binary id ([`super::cover::binary_id`]) and its file
/// name, whose cargo metadata suffix moves with the package, target, profile
/// and features. Never the binary's bytes, which a relink of an unchanged
/// tree moves, so a rebuilt binary over unmoved inputs keeps every pass.
///
/// # Errors
///
/// `program` names no file.
pub fn case_target(program: &str, package_dir: &Path) -> Result<String> {
    let file = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("no test binary in {program}"))?;
    Ok(format!(
        "{}\x1f{file}",
        super::cover::binary_id(program, package_dir)
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Fails by: a case carrying a `failure`, an `error` or a `skipped` child
    /// counted as passed, which reads one run's journal as more done than it
    /// is (CLOUD-2789).
    #[test]
    fn a_failed_errored_or_skipped_case_is_not_passed() {
        let xml = "<testsuites><testsuite>\
            <testcase name=\"ok\"/>\
            <testcase name=\"failed\"><failure/></testcase>\
            <testcase name=\"errored\"><error/></testcase>\
            <testcase name=\"skipped\"><skipped/></testcase>\
            </testsuite></testsuites>";
        assert_eq!(passed_cases(xml), Some(1));
        assert_eq!(passed_cases("<unclosed"), None);
    }

    /// Fails by: a named profile read as `default`, so a journaled run looks
    /// for its report under a profile it never ran; or an empty one kept.
    #[test]
    fn a_journal_profile_is_the_named_one_or_default() {
        assert_eq!(profile_or_default(Some(String::from("ci"))), "ci");
        assert_eq!(profile_or_default(Some(String::new())), "default");
        assert_eq!(profile_or_default(None), "default");
    }

    /// Fails by: a set `NEXTEST_PROFILE` ignored for `default`. Only a run
    /// under another profile (the `mutants` one) can tell the two apart.
    #[test]
    fn the_journal_profile_is_the_running_profile() {
        let running = std::env::var("NEXTEST_PROFILE").unwrap_or_default();
        let want = if running.is_empty() {
            "default"
        } else {
            running.as_str()
        };
        assert_eq!(journal_profile(), want);
    }

    /// Fails by: a declared report name dropped, or an empty one taken as the
    /// name rather than falling back to the built-in `junit.xml`.
    #[test]
    fn a_report_name_is_the_default_profiles_non_empty_path() {
        let doc = |text: &str| text.parse::<toml_edit::DocumentMut>().unwrap_or_default();
        assert_eq!(
            report_name(&doc("[profile.default.junit]\npath = \"r.xml\"\n")).as_deref(),
            Some("r.xml")
        );
        assert_eq!(
            report_name(&doc("[profile.default.junit]\npath = \"\"\n")),
            None
        );
    }

    /// Fails by: the last run's report left in place, so a run that writes
    /// none is read as the last run's verdicts.
    #[test]
    fn clearing_the_report_removes_the_last_runs_file() {
        let root = crate::scratch::scratch("test-run-clear-report");
        let config = root.join(".config");
        std::fs::create_dir_all(&config).unwrap_or_default();
        std::fs::write(
            config.join("nextest.toml"),
            "[store]\ndir = \"out\"\n\n[profile.default.junit]\npath = \"r.xml\"\n",
        )
        .unwrap_or_default();
        let report = root.join("out").join(journal_profile()).join("r.xml");
        std::fs::create_dir_all(report.parent().unwrap_or(&root)).unwrap_or_default();
        std::fs::write(&report, "<testsuites/>").unwrap_or_default();
        assert!(report.exists(), "the premise: a last run's report");
        clear_report(&root);
        assert!(!report.exists());
    }

    #[cfg(test)]
    /// Fails by: two cases sharing a key (one's pass skipping the other), or
    /// a key that holds across another target (a stale pass reused).
    #[test]
    fn a_case_key_moves_with_its_target_and_its_argv() {
        let argv = |name: &str| {
            ["bin", "--exact", name, "--nocapture"]
                .map(String::from)
                .to_vec()
        };
        let one = case_key(Key::Target("b1"), &argv("a"));
        assert_eq!(one, case_key(Key::Target("b1"), &argv("a")));
        assert_ne!(one, case_key(Key::Target("b1"), &argv("b")), "another case");
        assert_ne!(
            one,
            case_key(Key::Target("b2"), &argv("a")),
            "another target"
        );
        assert_ne!(
            one,
            case_key(Key::Dep("b1"), &argv("a")),
            "a dependency key is never a target key"
        );
        assert_eq!(
            case_key(
                Key::Target("b1"),
                &[
                    "elsewhere/bin".to_owned(),
                    "--exact".to_owned(),
                    "a".to_owned(),
                    "--nocapture".to_owned()
                ]
            ),
            one,
            "the binary's path is its target's business, not the key's"
        );
    }

    /// Fails by: a non-nextest command journaled (its argv rewritten), or a
    /// nextest run left whole.
    /// Fails by: the config named past `--` (handed to every test binary as a
    /// filter, so nextest never reads it), or not named at all.
    #[test]
    fn a_pinned_wrapper_outlives_a_rebuild_of_its_source() -> Result<()> {
        // Fails by: the config naming the build directory's binary, which a
        // concurrent build replaces mid-run (#1276: 597 cases exited 70).
        let dir = std::env::temp_dir().join(format!("pin-wrapper-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let exe = dir.join("batten");
        std::fs::write(&exe, "the build the run started with")?;
        let state = dir.join("state");
        std::fs::create_dir_all(&state)?;
        let pinned = pinned_wrapper(&state, &exe, &exe)?;
        assert!(pinned.starts_with(&state));
        // Cargo writes a new file and renames it over the old one.
        let fresh = dir.join("batten.new");
        std::fs::write(&fresh, "a rebuild")?;
        std::fs::rename(&fresh, &exe)?;
        assert_eq!(
            std::fs::read_to_string(&pinned)?,
            "the build the run started with"
        );
        // A second run pins afresh, over the first run's.
        assert_eq!(
            std::fs::read_to_string(pinned_wrapper(&state, &exe, &exe)?)?,
            "a rebuild"
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// A run pinned after a build already replaced its binary pins the image
    /// it is running, not the path that now names a deleted file (CLOUD-2886).
    ///
    /// Fails by: the copy made from `exe`, which no longer exists, so the
    /// wrapper cannot be pinned and every case of the run is lost.
    #[test]
    fn a_wrapper_pinned_after_a_rebuild_is_the_running_image() -> Result<()> {
        let dir = crate::scratch::scratch("pin-wrapper-deleted");
        let image = dir.join("image");
        std::fs::write(&image, "the build this run is running")?;
        let state = dir.join("state");
        std::fs::create_dir_all(&state)?;
        let gone = dir.join("batten (deleted)");
        let pinned = pinned_wrapper(&state, &gone, &image)?;
        assert_eq!(
            std::fs::read_to_string(pinned)?,
            "the build this run is running"
        );
        Ok(())
    }

    /// The running image is the kernel's own name for it on Linux, which reads
    /// the bytes this process runs (CLOUD-2886).
    ///
    /// Fails by: `current_exe()` answered there, the name a concurrent build
    /// turns into `… (deleted)`.
    #[test]
    fn the_running_image_is_the_kernels_name_for_it() -> Result<()> {
        let image = super::super::running_image()?;
        if cfg!(target_os = "linux") {
            assert_eq!(image, Path::new("/proc/self/exe"));
        }
        assert_eq!(
            std::fs::read(&image)?,
            std::fs::read(std::env::current_exe()?)?
        );
        Ok(())
    }

    /// Fails by: every failure to retire the last run's wrapper read as "there
    /// was none", so a wrapper path that cannot be removed is reported as a
    /// failure to pin rather than to retire.
    #[test]
    fn a_wrapper_that_will_not_retire_is_named_as_such() {
        let dir = crate::scratch::scratch("pin-wrapper-unretired");
        let exe = dir.join("batten");
        std::fs::write(&exe, "the build").unwrap();
        let state = dir.join("state");
        std::fs::create_dir_all(state.join("wrapper")).unwrap();
        let err = pinned_wrapper(&state, &exe, &exe).unwrap_err();
        assert!(
            format!("{err:#}").contains("retire the last run's wrapper"),
            "{err:#}"
        );
    }

    /// Fails by: the report name a profile already declares read as absent,
    /// so its `JUnit` report is looked for under the default name.
    #[test]
    fn the_declared_junit_report_name_is_read() {
        let doc: toml_edit::DocumentMut = "[profile.default.junit]\npath = \"own.xml\"\n"
            .parse()
            .unwrap();
        assert_eq!(report_name(&doc).as_deref(), Some("own.xml"));
        let empty: toml_edit::DocumentMut =
            "[profile.default.junit]\npath = \"\"\n".parse().unwrap();
        assert_eq!(report_name(&empty), None);
    }

    #[test]
    fn the_config_goes_ahead_of_the_test_binaries_arguments() {
        let argv = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            with_config(&argv(&["cargo", "nextest", "run", "--workspace"]), "c"),
            argv(&[
                "cargo",
                "nextest",
                "run",
                "--workspace",
                "--config-file",
                "c"
            ])
        );
        assert_eq!(
            with_config(&argv(&["cargo", "nextest", "run", "--", "--ignored"]), "c"),
            argv(&[
                "cargo",
                "nextest",
                "run",
                "--config-file",
                "c",
                "--",
                "--ignored"
            ])
        );
    }

    /// Fails by: a rebuilt binary over an unchanged tree missing its pass (a
    /// key over the binary's bytes, which a relink moves), or the wrapper
    /// running a case its journal holds.
    ///
    /// The binary is not executable, so a wrapper that ran it would fail.
    #[test]
    fn a_rebuilt_binary_over_an_unchanged_tree_keeps_its_pass() {
        let base = crate::scratch::scratch("test-run-rebuilt");
        let journal = base.join("journal");
        std::fs::create_dir_all(&journal).unwrap();
        let bin = base.join("fix-0123456789abcdef");
        std::fs::write(&bin, "one build").unwrap();
        let program = bin.to_string_lossy().into_owned();
        let test = [program.as_str(), "--exact", "tests::a", "--nocapture"].map(String::from);
        let target = case_target(&program, &std::env::current_dir().unwrap()).unwrap();
        std::fs::write(journal.join(case_key(Key::Target(&target), &test)), "").unwrap();
        std::fs::write(&bin, "a relinked build, other bytes").unwrap();
        let mut args = vec![journal.to_string_lossy().into_owned()];
        args.extend(test.iter().cloned());
        assert_eq!(case(&args).unwrap(), 0, "the pass holds across the relink");
        assert_ne!(
            target,
            case_target(
                &base.join("fix-fedcba9876543210").to_string_lossy(),
                &std::env::current_dir().unwrap()
            )
            .unwrap(),
            "another profile or feature set builds another target"
        );
    }

    /// Fails by: a `.rs` edit that leaves the run's journal key standing (a
    /// pass of the old code read back), a non-Rust content id moving it (the
    /// non-Rust half is `resource_digest`'s), or an unchanged tree moving it.
    #[test]
    fn a_rust_edit_moves_the_run_key_and_nothing_else_of_the_tree_does() {
        let ids = |lib: &str, notes: &str| -> std::collections::BTreeMap<String, String> {
            [("src/lib.rs", lib), ("notes.txt", notes)]
                .map(|(path, id)| (path.to_owned(), id.to_owned()))
                .into()
        };
        let held = run_key("n", &ids("1", "1"), "b", "f");
        assert_eq!(held, run_key("n", &ids("1", "1"), "b", "f"));
        assert_ne!(held, run_key("n", &ids("2", "1"), "b", "f"), "a .rs edit");
        assert_eq!(held, run_key("n", &ids("1", "2"), "b", "f"));
        for moved in [
            run_key("n2", &ids("1", "1"), "b", "f"),
            run_key("n", &ids("1", "1"), "b2", "f"),
            run_key("n", &ids("1", "1"), "b", "f2"),
        ] {
            assert_ne!(held, moved);
        }
    }

    /// Fails by: a pass promoted after the tree moved under its run (a pass of
    /// a binary built from neither tree kept), one dropped over a tree that
    /// stood, or a pending pass outliving its run either way.
    #[test]
    fn a_pending_pass_is_promoted_only_over_a_tree_that_stood() {
        let state = crate::scratch::scratch("test-run-promote");
        for (stood, kept) in [(false, false), (true, true)] {
            std::fs::create_dir_all(state.join(PENDING)).unwrap();
            std::fs::write(state.join(PENDING).join("k"), "").unwrap();
            let promoted = promote_pending(&state, stood).unwrap();
            assert_eq!(
                (promoted == 1, state.join(PASS).join("k").is_file()),
                (kept, kept)
            );
            assert!(!state.join(PENDING).exists(), "pending outlives its run");
        }
    }

    /// Fails by: a pass older than its lifetime kept (the store grows a head
    /// at a time), or a fresh one collected.
    #[test]
    fn a_pass_nothing_reads_is_collected() {
        let pass = crate::scratch::scratch("test-run-collect");
        std::fs::write(pass.join("old"), "").unwrap();
        std::fs::write(pass.join("new"), "").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(pass.join("old"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        collect_passes(&pass, std::time::Duration::from_secs(60)).unwrap();
        assert!(!pass.join("old").exists());
        assert!(pass.join("new").is_file());
    }

    /// Fails by: a pass exactly its lifetime old collected (the bound is
    /// "older than"), or one a second past it kept.
    #[test]
    fn a_pass_is_collected_only_past_its_lifetime() {
        let pass = crate::scratch::scratch("test-run-collect-edge");
        let at = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
        for name in ["edge", "past"] {
            std::fs::write(pass.join(name), "").unwrap();
        }
        let stamp = |name: &str, when: std::time::SystemTime| {
            std::fs::File::options()
                .write(true)
                .open(pass.join(name))
                .unwrap()
                .set_modified(when)
                .unwrap();
        };
        stamp("edge", at);
        stamp("past", at - std::time::Duration::from_secs(1));
        collect_passes_at(
            &pass,
            std::time::Duration::from_secs(60),
            at + std::time::Duration::from_secs(60),
        )
        .unwrap();
        assert!(pass.join("edge").is_file(), "exactly the lifetime is kept");
        assert!(
            !pass.join("past").exists(),
            "past the lifetime is collected"
        );
    }

    /// Fails by: an unknown tree read as one that stood, or two different
    /// trees read as the same.
    #[test]
    fn only_the_same_known_tree_stood() {
        assert!(stood(Some("t"), Some("t")));
        assert!(!stood(Some("t"), Some("u")));
        assert!(!stood(Some("t"), None));
        assert!(!stood(None, None), "two unknowns are not one tree");
    }

    /// Fails by: an earlier layout's journal kept beside the live one, or one
    /// of this layout's own directories, or a file, removed.
    #[test]
    fn an_earlier_layouts_journal_is_retired() {
        let state = crate::scratch::scratch("test-run-legacy");
        for name in ["0123abcd", BIN, EXPECT, PASS, PENDING] {
            std::fs::create_dir_all(state.join(name)).unwrap();
        }
        std::fs::write(state.join("loose"), "").unwrap();
        retire_legacy(&state).unwrap();
        assert!(!state.join("0123abcd").exists(), "the legacy journal goes");
        for name in [BIN, EXPECT, PASS, PENDING, "loose"] {
            assert!(state.join(name).exists(), "{name} stays");
        }
    }

    /// Fails by: two flag sets digesting alike (a build under other flags
    /// selecting on this one's record), or one set digesting two ways.
    #[test]
    fn the_flags_digest_is_the_flags() {
        let flags = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let held = flags_digest(&flags(&[("RUSTFLAGS", "-Cx")]));
        assert_eq!(held, flags_digest(&flags(&[("RUSTFLAGS", "-Cx")])));
        assert_ne!(held, flags_digest(&flags(&[("RUSTFLAGS", "-Cy")])));
        assert_ne!(held, flags_digest(&flags(&[])));
    }

    /// Fails by: a cargo config, the nextest config or a file a build script
    /// includes by `#[path]` left out of the build's key, an unrelated file
    /// moving it, or the compiler's own release left out.
    #[test]
    fn the_build_key_reads_its_configs_and_what_a_build_script_includes() {
        let root = crate::scratch::scratch("test-run-build-key");
        std::fs::create_dir_all(root.join("crates/a")).unwrap();
        std::fs::write(
            root.join("crates/a/build.rs"),
            "#[path = \"src/markers.rs\"]\nmod markers;\n",
        )
        .unwrap();
        let ids = |cargo: &str, nextest: &str, included: &str, other: &str| {
            [
                ("crates/a/build.rs", "b"),
                (".cargo/config.toml", cargo),
                (".config/nextest.toml", nextest),
                ("crates/a/src/markers.rs", included),
                ("notes.txt", other),
            ]
            .map(|(path, id)| (path.to_owned(), id.to_owned()))
            .into()
        };
        let held = build_digest(&root, &ids("1", "1", "1", "1")).expect("rustc answers");
        assert_eq!(held, build_digest(&root, &ids("1", "1", "1", "2")).unwrap());
        for moved in [
            ids("2", "1", "1", "1"),
            ids("1", "2", "1", "1"),
            ids("1", "1", "2", "1"),
        ] {
            assert_ne!(held, build_digest(&root, &moved).unwrap());
        }
        let release = compiler_version(&root).expect("rustc answers");
        assert!(
            String::from_utf8_lossy(&release).starts_with("rustc "),
            "the key reads the compiler's own release"
        );
    }

    /// Fails by: a run that picks its own features, profile or target selecting
    /// on a record of another build, or a plain run selecting nothing.
    #[test]
    fn only_a_run_built_as_the_sweep_built_selects() {
        let argv = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        assert!(builds_as_swept(&argv(&[
            "cargo",
            "nextest",
            "run",
            "--workspace"
        ])));
        assert!(builds_as_swept(&argv(&[
            "cargo",
            "nextest",
            "run",
            "--",
            "--features"
        ])));
        for flag in [
            "--features=x",
            "-F",
            "-Fx",
            "--all-features",
            "--release",
            "--target",
        ] {
            assert!(
                !builds_as_swept(&argv(&["cargo", "nextest", "run", flag])),
                "{flag}"
            );
        }
    }

    /// Fails by: an undeclared variable moving the key (every shell's noise
    /// rerunning the suite), a declared name or pattern not moving it, an
    /// excluded per-run variable moving it, or the fallback reading anything
    /// but the list the journal read before a step could declare one.
    #[test]
    fn a_declared_pattern_keys_and_an_undeclared_name_does_not() {
        let vars = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)))
                .collect::<Vec<_>>()
                .into_iter()
        };
        let owned = |words: &[&str]| -> Vec<String> {
            words.iter().map(|word| (*word).to_owned()).collect()
        };
        let declared = env_ask(&owned(&[
            "--exclude",
            "APP_PID",
            "--",
            "DATABASE_URL",
            "APP_*",
        ]))
        .unwrap();
        let digest = |pairs: &[(&str, &str)]| env_digest(vars(pairs), &declared);
        let base = digest(&[("DATABASE_URL", "a"), ("TERM", "x")]);
        assert_eq!(base, digest(&[("DATABASE_URL", "a"), ("TERM", "y")]));
        assert_eq!(base, digest(&[("DATABASE_URL", "a"), ("APP_PID", "9")]));
        assert_ne!(base, digest(&[("DATABASE_URL", "b"), ("TERM", "x")]));
        assert_ne!(base, digest(&[("DATABASE_URL", "a"), ("APP_MODE", "1")]));
        assert_eq!(
            base,
            digest(&[("DATABASE_URL", "a"), ("PATH", "/bin")]),
            "PATH is undeclared here"
        );
        // TODAY'S LIST, BYTE FOR BYTE, where nothing is declared: a journal's
        // passes keyed before declarations existed stay keyed the same.
        let fallback = DeclaredEnv::fallback();
        let today = env_digest(
            vars(&[("PATH", "/bin"), ("BATTEN_X", "1"), ("TERM", "a")]),
            &fallback,
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"BATTEN_X=1\x1ePATH=/bin\x1e");
        assert_eq!(today, hasher.finalize().to_hex().to_string());
        for refused in ["lower", "A-B", "1X", "*"] {
            assert_eq!(env_ask(&owned(&["--", refused])), None, "{refused}");
        }
        assert_eq!(
            env_ask(&owned(&["--exclude", "B*", "--", "A"])),
            None,
            "no * in an exclusion"
        );
        assert_eq!(
            env_ask(&owned(&["--exclude", "B", "--"])),
            None,
            "an exclusion alone keys nothing"
        );
        assert_eq!(env_ask(&owned(&["A"])), None, "the `--` is mandatory");
        assert_eq!(
            env_ask(&owned(&["--exclude", "--", "A"])),
            None,
            "an `--exclude` with no name before the `--` is no declaration"
        );
    }

    /// Fails by: a row's `step env` entry not found among its other tools, a
    /// row without one read as declaring something (so the journal never falls
    /// back to [`DEFAULT_ENV`]), or a malformed entry read as a declaration.
    #[test]
    fn the_declaration_is_the_rows_step_env_tool_line() {
        let line = |words: &[&str]| -> Vec<String> {
            ENV.iter()
                .chain(words)
                .map(|word| (*word).to_owned())
                .collect()
        };
        let version = vec![String::from("rustc"), String::from("--version")];
        let tools = vec![
            version.clone(),
            line(&["--exclude", "CI_PID", "--", "CI*", "HOME"]),
        ];
        assert_eq!(
            declared_env(&tools),
            Some(DeclaredEnv {
                env: vec![String::from("CI*"), String::from("HOME")],
                exclude: vec![String::from("CI_PID")],
            })
        );
        assert_eq!(declared_env(std::slice::from_ref(&version)), None);
        assert_eq!(declared_env(&[version, line(&["--", "lower"])]), None);
    }

    /// Fails by: the journal keyed on a row that is not the journaled one
    /// (the first other row's declaration read in its place).
    #[test]
    fn the_journal_reads_only_the_journaled_rows_declaration() {
        let root = crate::scratch::scratch("test-run-journal-env");
        crate::gitwrite::init_on_main(&root).unwrap();
        std::fs::write(
            root.join(crate::config_model::CONFIG_FILE),
            "version = 1\n\n\
             [[step]]\nid = \"plain\"\ninputs = [\".\"]\n\
             tools = [[\"batten\", \"step\", \"env\", \"--\", \"PLAIN_X\"]]\n\n\
             [[step]]\nid = \"journaled\"\ninputs = [\".\"]\n\
             tools = [[\"batten\", \"step\", \"env\", \"--\", \"JOURNAL_Y\"]]\n\
             journal = \"nextest\"\n",
        )
        .unwrap();
        assert_eq!(journal_env(&root).env, [String::from("JOURNAL_Y")]);
    }

    /// Fails by: a set `$CARGO_TARGET_DIR` ignored, or an empty one taken as
    /// the target.
    #[test]
    fn the_default_store_is_under_a_non_empty_target_dir() {
        let root = Path::new("/r");
        assert_eq!(
            default_store(root, Some("elsewhere".into())),
            Path::new("/r/elsewhere/nextest")
        );
        assert_eq!(
            default_store(root, Some(std::ffi::OsString::new())),
            Path::new("/r/target/nextest")
        );
        assert_eq!(default_store(root, None), Path::new("/r/target/nextest"));
    }

    /// Fails by: an edit to a package the sweep never probed left out of the
    /// key (a case that ran its code skipped), or an edit to a probed
    /// package's source or to an unprobed package's own tests moving it.
    #[test]
    fn an_unprobed_packages_source_moves_every_key() {
        let root = crate::scratch::scratch("test-run-unprobed");
        for (path, text) in [
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n"),
            ("crates/app/Cargo.toml", "[package]\nname = \"app\"\n"),
            ("crates/helper/Cargo.toml", "[package]\nname = \"helper\"\n"),
        ] {
            std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            std::fs::write(root.join(path), text).unwrap();
        }
        let format = schema::Format {
            probed: [String::from("crates/app/src/lib.rs")].into(),
            ..schema::Format::default()
        };
        let ids = |app: &str, helper: &str, helper_test: &str| {
            [
                ("Cargo.toml", "w"),
                ("crates/app/Cargo.toml", "a"),
                ("crates/helper/Cargo.toml", "h"),
                ("crates/app/src/lib.rs", app),
                ("crates/helper/src/lib.rs", helper),
                ("crates/helper/tests/it.rs", helper_test),
            ]
            .map(|(path, id)| (path.to_owned(), id.to_owned()))
            .into()
        };
        let held = unprobed_packages_digest(&root, &ids("1", "1", "1"), &format);
        assert_ne!(
            held,
            unprobed_packages_digest(&root, &ids("1", "2", "1"), &format)
        );
        assert_eq!(
            held,
            unprobed_packages_digest(&root, &ids("2", "1", "1"), &format)
        );
        assert_eq!(
            held,
            unprobed_packages_digest(&root, &ids("1", "1", "2"), &format)
        );
    }

    /// Fails by: a stale input state's journal kept (the store grows a run per
    /// head), or the live one removed (every pass lost).
    #[test]
    fn only_the_live_input_states_journal_is_kept() {
        let state = crate::scratch::scratch("test-run-prune");
        for name in ["live", "stale"] {
            std::fs::create_dir_all(state.join(name)).unwrap();
        }
        std::fs::write(state.join("nextest.toml"), "").unwrap();
        prune_others(&state, &state.join("live")).unwrap();
        assert!(state.join("live").is_dir());
        assert!(!state.join("stale").exists());
        assert!(
            state.join("nextest.toml").is_file(),
            "a file is not a journal"
        );
    }

    /// Fails by: the committed nextest row's declared environment replaced by
    /// nothing, so a journaled case is keyed on no variable at all.
    #[test]
    fn this_checkouts_journal_env_is_its_nextest_rows_declaration() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let declared = journal_env(&root);
        assert_ne!(declared, DeclaredEnv::default());
        assert!(!declared.env.is_empty(), "{declared:?}");
    }

    /// Fails by: `lap_live` answering `false` under a held land singleton, so
    /// a run during a lap seeds beside it; or `lap_ended` answering `None`
    /// for an owed seed, so the seed a lap deferred is never started
    /// (CLOUD-2789). The singleton stays held throughout, so the owed seed is
    /// deferred again rather than spawned from the test binary.
    #[test]
    fn a_held_lap_owes_the_seed_and_its_end_answers_for_it() {
        let scratch = crate::scratch::scratch("resume-lap-live");
        crate::testing::contain_state(&scratch.join("state"));
        let root = scratch.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        crate::gitwrite::init_on_main(&root).unwrap();
        let git_dir = crate::git::git_dir(&root).unwrap();
        assert!(!lap_live(&root), "anti-vacuity: no lap holds the singleton");
        assert_eq!(lap_ended(&root), None, "nothing was owed");
        let pid = std::process::id().to_string();
        assert_eq!(
            batten_base::task::singleton_acquire(
                &git_dir,
                LAND_TASK,
                &pid,
                std::time::Duration::ZERO
            ),
            batten_base::task::Claim::Taken
        );
        assert!(lap_live(&root), "a held land singleton is a live lap");
        let owed = crate::state::repo_state_dir(&root)
            .unwrap()
            .join("test-run")
            .join(SEED_PENDING);
        assert!(owed.is_file(), "a live lap leaves the seed owed");
        let ended = lap_ended(&root);
        assert!(
            matches!(ended, Some(Seeded::NotOnCi | Seeded::Deferred)),
            "{ended:?}"
        );
        batten_base::task::singleton_release(&git_dir, LAND_TASK);
    }
}
