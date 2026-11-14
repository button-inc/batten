//! A step's `cargo nextest run` kept case by case, so no case that passed is ever
//! run twice over the same inputs (CLOUD-2772).
//!
//! CRASH-ONLY, CASE BY CASE. `test:cargo` was one all-or-nothing step: a run
//! stopped partway kept nothing, so a stopped landing lap re-ran every case it
//! had already passed. Here the suite runs under a nextest run-wrapper that is
//! this binary: each case's pass is written durably the moment it passes, keyed
//! on what decides it — the test binary's bytes, the case's argv, and every
//! non-Rust file a case may read — and a case whose key holds reports a pass
//! without running. A stopped run resumes; a head that moves nothing a binary
//! holds, and no non-Rust input, re-runs nothing in it.
//!
//! The wrapper is the running binary itself (`current_exe`), so the path is right
//! on every platform and the mechanism is the one under test, as every verify
//! step here is (`cargo run -p batten`). CI's legs call `cargo nextest run`
//! directly, start from no journal, and so run every case.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The first argument of the run-wrapper the suite runs each case under; the
/// journal directory follows it, then the case's argv.
pub const CASE_ARG: &str = "__test-case";

/// The run-wrapper's name in the generated nextest config.
const WRAPPER: &str = "batten-resume";

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
/// ONE JOURNAL PER INPUT STATE: the non-Rust files every case may read are
/// digested once here, not by each of ~10,000 wrappers, and a journal for any
/// other state is stale by construction and goes, so the store stays one run's
/// worth.
///
/// # Errors
///
/// The state directory, the input digest, or the config cannot be made.
pub fn journaled(root: &Path, command: &[String]) -> Result<Vec<String>> {
    let state = crate::state::repo_state_dir(root)?.join("test-run");
    let inputs = super::schema::resource_digest(root)?;
    let journal = state.join(&inputs[..16]);
    prune_others(&state, &journal)?;
    std::fs::create_dir_all(&journal)?;
    let config = state.join("nextest.toml");
    crate::durable::replace(
        &config,
        config_text(root, &std::env::current_exe()?, &journal)?,
    )?;
    Ok(with_config(command, &config.to_string_lossy()))
}

/// Whether `command` is a `cargo nextest run`: the one shape a step's miss runs
/// under the journal.
#[must_use]
pub fn is_nextest_run(command: &[String]) -> bool {
    matches!(
        command,
        [cargo, nextest, run, ..] if cargo == "cargo" && nextest == "nextest" && run == "run"
    )
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

/// Run one case as the wrapper, or report its journaled pass.
fn case(args: &[String]) -> Result<u8> {
    let (journal, test) = args.split_first().context("no journal named")?;
    let journal = PathBuf::from(journal);
    let (program, rest) = test.split_first().context("no case to run")?;
    let marker = journal.join(case_key(&binary_digest(&journal, program)?, test));
    if marker.is_file() {
        return Ok(0);
    }
    let code = spawn_case(program, rest)?;
    if code == 0 {
        crate::durable::replace(&marker, "")?;
    }
    Ok(code)
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

/// A case's journal key: its binary's digest and its whole argv.
#[must_use]
pub fn case_key(binary: &str, test: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(binary.as_bytes());
    for arg in test.iter().skip(1) {
        hasher.update(b"\x1f");
        hasher.update(arg.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// The digest of the test binary at `program`, read once per build: cached
/// under `journal` by its path, size and modification time, so ~10,000 cases
/// sharing a few binaries hash each once.
///
/// # Errors
///
/// The binary cannot be read.
pub fn binary_digest(journal: &Path, program: &str) -> Result<String> {
    let meta = std::fs::metadata(program).with_context(|| format!("stat {program}"))?;
    let modified = meta
        .modified()
        .ok()
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |at| at.as_nanos());
    let stamp = format!("{} {modified}", meta.len());
    let cache = journal
        .join("binaries")
        .join(blake3::hash(program.as_bytes()).to_hex().as_str());
    if let Ok(held) = crate::fsio::read_to_string(&cache)
        && let Some(digest) = held.strip_prefix(&format!("{stamp} "))
    {
        return Ok(digest.to_owned());
    }
    let digest = blake3::hash(&crate::fsio::read(program)?)
        .to_hex()
        .to_string();
    if let Some(parent) = cache.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(&cache, format!("{stamp} {digest}"))?;
    Ok(digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Fails by: two cases sharing a key (one's pass skipping the other), or
    /// a key that holds when the binary changed (a stale pass reused).
    #[test]
    fn a_case_key_moves_with_its_binary_and_its_argv() {
        let argv = |name: &str| {
            ["bin", "--exact", name, "--nocapture"]
                .map(String::from)
                .to_vec()
        };
        let one = case_key("b1", &argv("a"));
        assert_eq!(one, case_key("b1", &argv("a")));
        assert_ne!(one, case_key("b1", &argv("b")), "another case");
        assert_ne!(one, case_key("b2", &argv("a")), "another build");
        assert_eq!(
            case_key(
                "b1",
                &[
                    "elsewhere/bin".to_owned(),
                    "--exact".to_owned(),
                    "a".to_owned(),
                    "--nocapture".to_owned()
                ]
            ),
            one,
            "the binary's path is its digest's business, not the key's"
        );
    }

    /// Fails by: a non-nextest command journaled (its argv rewritten), or a
    /// nextest run left whole.
    #[test]
    fn only_a_nextest_run_is_journaled() {
        let argv = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        assert!(is_nextest_run(&argv(&[
            "cargo",
            "nextest",
            "run",
            "--workspace"
        ])));
        assert!(!is_nextest_run(&argv(&["cargo", "nextest", "list"])));
        assert!(!is_nextest_run(&argv(&["cargo", "test"])));
        assert!(!is_nextest_run(&argv(&["cargo"])));
    }

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

    /// Fails by: a rebuilt binary read from the cache (its old digest keeping
    /// every stale pass), or an unchanged one hashed again for every case.
    #[test]
    fn a_binary_is_hashed_once_per_build() {
        let base = crate::scratch::scratch("test-run-binary");
        let bin = base.join("bin");
        std::fs::write(&bin, "one").unwrap();
        let bin = bin.to_string_lossy().into_owned();
        let first = binary_digest(&base, &bin).unwrap();
        assert_eq!(first, binary_digest(&base, &bin).unwrap());
        std::fs::write(&bin, "a rebuilt binary").unwrap();
        assert_ne!(first, binary_digest(&base, &bin).unwrap(), "a new build");
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
