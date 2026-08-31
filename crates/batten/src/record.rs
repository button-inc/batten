//! The write half of the two out-of-tree verdict stores (CLOUD-1265).
//!
//! # Two landed readers had no writer, so two `deny` rows decided nothing
//!
//! [`crate::tools`] resolves `.git/batten-tools/<tool>@<version>@<digest>` and
//! [`crate::forge`] resolves `.git/batten-forge/<sha>`. Both shipped correct, and
//! both shipped with the only writer in the tree being a test — so
//! `validator-verdict-clean` and `forge-verdict-required`, two registered
//! `severity = "deny"` rows, resolved `null` on every real checkout and were
//! byte-identical to a clean tree on the decision surface. That is CLOUD-845's
//! dead gate, twice. Each row says so in `batten.toml` in its own words: *SILENT
//! UNTIL A PRODUCER WRITES.* This is that producer.
//!
//! # The run stays outside, and this module is why that costs nothing
//!
//! House style §5 makes `check` `read` and structurally incapable of spawning, so
//! the validator stays a command on PATH — §9's prior-art disposition. What moves
//! in here is not the run but the RECORDING of what it said: a `mise` task or a CI
//! step runs the tool, reduces its answer to `<name> <token>` lines, and pipes
//! them here. Nothing in this module spawns anything, and
//! `evaluator-io-check` stays the gate on that.
//!
//! # The caller cannot supply a digest, because there is no argument for one
//!
//! [`crate::tools::verdicts`] digests the subject itself, "because the digest is
//! what makes the record stale-by-construction and a caller that supplied one
//! could supply the wrong one". A producer taking `--digest` would hand that
//! guarantee straight back.
//!
//! So [`run_tool`] takes ONE argument — the row id — and reads the tool, its
//! pinned version and the input path out of the committed config. It then composes
//! the key with [`crate::tools::record_key`] over [`crate::tools::digest`] of the
//! bytes it read itself: the same two functions the reader calls, so writer and
//! reader compose one string in one place.
//!
//! The negative half falls out of the same shape for free: **a record for a tool
//! nobody declared is unspellable**, because the only way to name a key is to name
//! a row that already exists in `batten.toml`.
//!
//! # Stricter than the reader, in exactly one place and deliberately
//!
//! [`crate::forge::parse`] skips a line carrying no second field, because one torn
//! record is not evidence about the others and a family refused for one bad line
//! would go offline for a producer's transient failure. This refuses that line
//! instead: a producer emitting one has a bug, and the moment to say so is while
//! its author is watching rather than silently at read time.
//!
//! # Pointer-only
//!
//! Silent on success (§6). A failure names the row id, the path it could not read,
//! or the offending line's NUMBER — never a line's content, and never a byte of
//! the validator's report. [`crate::tools`]'s own header records why that boundary
//! is here rather than at the report: a validator's output is the likeliest place
//! in this family for a secret to appear.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result};

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::facts::ToolQuery;
use crate::resolve::Overrides;
use crate::{forge, git, resolve, tools};

/// Read the verdict lines a producer piped in.
///
/// The whole of stdin, because a record is small by construction — a status token
/// and a finding name per line — and a producer that streams one is a producer
/// that has already decided to write a payload here.
fn verdict_lines() -> Result<String> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("read the verdict from stdin")?;
    Ok(raw)
}

/// Refuse a line the reader would silently skip.
///
/// The one place this half is stricter than [`crate::forge::parse`], and the
/// reason is in this module's header: the reader's tolerance protects a gate from
/// one torn record, and the writer's strictness tells a producer's author that
/// they emitted one.
///
/// The NUMBER, never the line — a validator's own output is what is being reduced
/// here, so echoing the offender back would put it in a diagnostic (rule 4).
fn validated(text: &str) -> Result<&str> {
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if line.split_whitespace().count() < 2 {
            return Err(UsageError::raise(format!(
                "the verdict's line {} carries a name with no token; a record line is `<name> <token>`",
                index + 1
            )));
        }
    }
    Ok(text)
}

/// Write one record, creating the store the reader never creates.
///
/// [`crate::tools::verdicts`] and [`crate::forge::verdicts`] only ever read, so
/// the directory is the producer's to make — which is also why an unwritable store
/// is an internal error here rather than a usage one: the caller named a row
/// correctly and the filesystem refused.
fn store(path: &Path, body: &str) -> Result<()> {
    let directory = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)
        .with_context(|| format!("create the record store {}", directory.display()))?;
    std::fs::write(path, body).with_context(|| format!("write the record {}", path.display()))?;
    Ok(())
}

/// Every `[[rule.tools]]` row the resolved config declares.
///
/// Flattened across rules rather than read from one, matching
/// [`crate::rules`]'s own acquisition: which rule a tool row hangs under is the
/// config author's business, and an id is unique across the whole table because
/// `validate_tool_rows` already refuses a duplicate at load.
fn declared(overrides: &Overrides) -> Result<Vec<ToolQuery>> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    Ok(config
        .rules
        .iter()
        .flat_map(|rule| rule.tools.iter().cloned())
        .collect())
}

/// Record a declared tool row's verdict.
///
/// # Errors
///
/// A [`UsageError`] when no `[[rule.tools]]` row carries `id`, when that row's
/// `input` cannot be read — so no key is composable, which is precisely the
/// could-not-look the reader keeps apart from a clean verdict — or when a piped
/// line carries no token. An internal error when the store cannot be written.
pub fn run_tool(id: &str, overrides: &Overrides) -> Result<ExitCode> {
    let text = verdict_lines()?;
    let rows = declared(overrides)?;
    let Some(row) = rows.into_iter().find(|row| row.id == id) else {
        return Err(UsageError::raise(format!(
            "no `[[rule.tools]]` row declares the id `{id}`, so there is no key to record under"
        )));
    };

    let root = git::repo_root(Path::new("."))?;
    let subject = Path::new(&root).join(&row.input);
    // COULD NOT LOOK, and it refuses rather than recording. A record composed
    // over bytes this producer never read would be a verdict about a file nobody
    // can identify, which is the one thing the digest in the key exists to make
    // impossible.
    let Ok(bytes) = std::fs::read(&subject) else {
        return Err(UsageError::raise(format!(
            "cannot read `{}`, the input row `{id}` names, so no verdict can be keyed to it",
            row.input
        )));
    };

    let key = tools::record_key(&row, &tools::digest(&bytes));
    let git_dir = git::git_dir(Path::new("."))?;
    store(&tools::record_path(&git_dir, &key), validated(&text)?)?;
    Ok(ExitCode::Success)
}

/// Record the forge's verdicts for one commit.
///
/// # Errors
///
/// A [`UsageError`] when `reference` resolves to no commit, or when a piped line
/// carries no token. An internal error when the store cannot be written.
pub fn run_forge(reference: &str, _overrides: &Overrides) -> Result<ExitCode> {
    let text = verdict_lines()?;
    // RESOLVED, never taken literally, because the reader keys on a sha and a
    // producer naturally holds a ref. Recording under the ref's own spelling would
    // put the record beside the key every reader composes rather than under it.
    let Some(sha) = git::resolve_ref(Path::new("."), reference)? else {
        return Err(UsageError::raise(format!(
            "`{reference}` resolves to no commit, so there is no sha to key this verdict to"
        )));
    };

    let git_dir = git::git_dir(Path::new("."))?;
    store(&forge::record_path(&git_dir, &sha), validated(&text)?)?;
    Ok(ExitCode::Success)
}

/// Dispatch the `record` verbs.
///
/// # Errors
///
/// Whatever the chosen sub-verb returns: a [`UsageError`] for an id or ref that
/// resolves to nothing, an unreadable subject, or a malformed verdict line, and
/// an internal error when the store cannot be written.
pub fn run(command: crate::cli::RecordCommand, overrides: &Overrides) -> Result<ExitCode> {
    match command {
        crate::cli::RecordCommand::Tool { id } => run_tool(&id, overrides),
        crate::cli::RecordCommand::Forge { reference } => run_forge(&reference, overrides),
    }
}
