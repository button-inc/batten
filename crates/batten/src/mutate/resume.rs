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
//! step here is (`cargo run -p batten`). CI's legs call `cargo nextest run`
//! directly, start from no journal, and so run every case.

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
    // THE SELECTION IS AN ECONOMY: a store that cannot be read or a digest
    // that cannot be taken leaves every case on the build key, never a skip.
    let _ = select(root, &state, &resources, command);
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
    crate::durable::replace(
        &config,
        config_text(config_root, &std::env::current_exe()?, &journal)?,
    )?;
    Ok(with_config(command, &config.to_string_lossy()))
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
    std::fs::create_dir_all(&expect)?;
    std::fs::create_dir_all(state.join(PENDING))?;
    collect_passes(&state.join(PASS), PASS_LIFETIME)?;
    crate::durable::replace(state.join(RUN), schema::tree_ids_digest(resources))?;
    if !builds_as_swept(command) {
        return Ok(0);
    }
    let held = held_cases(root, resources, &env_digest(std::env::vars_os()))?;
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
                | "-F"
                | "--all-features"
                | "--no-default-features"
                | "--release"
                | "-r"
                | "--cargo-profile"
                | "--target"
                | "--config"
        ) || (flag.starts_with("-F") && flag.len() > 2)
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
    hasher.update(&compiler_version(root)?);
    Some(hasher.finalize().to_hex().to_string())
}

/// `rustc -vV` as the toolchain ladder resolves the compiler, through the
/// placed adapter.
fn compiler_version(root: &Path) -> Option<Vec<u8>> {
    let argv = ["rustc", "-vV"].map(str::to_owned);
    let (code, said) =
        crate::exec::piped_argv(root, &argv, "", crate::exec::Diagnostics::Drop, &[])?;
    (code == 0 && !said.is_empty()).then(|| said.into_bytes())
}

/// Whether the variable `key` may change what a case does, as the key reads
/// it: Batten's own, Rust's and cargo's, CI, home and path. A fixed list:
/// a case reading anything else outside it is the selection's known limit.
#[must_use]
pub fn keyed_variable(key: &str) -> bool {
    key.starts_with("BATTEN_")
        || key.starts_with("RUST")
        || key.starts_with("CARGO_")
        || matches!(key, "CI" | "HOME" | "PATH")
}

/// The digest of every variable of `vars` [`keyed_variable`] keeps.
#[must_use]
pub fn env_digest(vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>) -> String {
    let kept: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> = vars
        .filter(|(key, _)| key.to_str().is_some_and(keyed_variable))
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
    let Ok(entries) = std::fs::read_dir(pass) else {
        return Ok(());
    };
    let now = std::time::SystemTime::now();
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
            .is_some_and(|name| [BIN, EXPECT, PASS, PENDING].contains(&name));
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
    promote_pending(&state, started.is_some() && started == now)
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
    let mut config = super::cover::wrapper_experimental(root)?;
    let wrapper = toml_edit::Value::from(wrapper.to_string_lossy().into_owned());
    let journal = toml_edit::Value::from(journal.to_string_lossy().into_owned());
    let _ = write!(
        config,
        "\n[scripts.wrapper.{WRAPPER}]\ncommand = [{wrapper}, \"{CASE_ARG}\", {journal}]\n\n\
         [[profile.default.scripts]]\nfilter = \"all()\"\nrun-wrapper = \"{WRAPPER}\"\n"
    );
    Ok(config)
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
    if marker.is_file() {
        return Ok(0);
    }
    let state = journal.parent().and_then(Path::parent);
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
    }
    Ok(code)
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

    /// Fails by: a variable outside the list moving the key (every shell's
    /// noise rerunning the suite), or one inside it not moving it.
    #[test]
    fn the_environment_key_reads_only_its_list() {
        let vars = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)))
                .collect::<Vec<_>>()
                .into_iter()
        };
        let base = env_digest(vars(&[("PATH", "/bin"), ("TERM", "a")]));
        assert_eq!(base, env_digest(vars(&[("PATH", "/bin"), ("TERM", "b")])));
        assert_ne!(
            base,
            env_digest(vars(&[("PATH", "/usr/bin"), ("TERM", "a")]))
        );
        assert_ne!(
            base,
            env_digest(vars(&[("PATH", "/bin"), ("BATTEN_X", "1")]))
        );
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
}
