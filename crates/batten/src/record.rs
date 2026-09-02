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
        crate::cli::RecordCommand::Plan => run_plan(),
        crate::cli::RecordCommand::Closes => run_closes(overrides),
    }
}

/// Record which rows this branch's pull request body closes.
///
/// # Errors
///
/// A [`UsageError`] when the body is empty — an unread body is could-not-look and
/// must not be recorded as "closes nothing" — when the pattern registry declares
/// no key grammar, or when there is no branch to key on. An internal error when
/// the store cannot be written.
pub fn run_closes(overrides: &Overrides) -> Result<ExitCode> {
    let body = verdict_lines()?;
    if body.trim().is_empty() {
        return Err(UsageError::raise(
            "record closes: the body is empty, and an unread body is not a body that closes nothing"
                .to_owned(),
        ));
    }

    let config = resolve::resolve(Path::new("."), overrides)?;
    let grammar = crate::ready::Grammar::resolve(&config.patterns)?;
    let keys: Vec<String> = grammar
        .keys_closed_in(&body)
        .into_iter()
        .map(|key| key.to_string())
        .collect();

    // ZERO IS A COUNT, and rendering it that way is the whole three-valued read
    // this record exists to preserve: `closes 0` says the body was READ and closes
    // nothing, where an absent record says nobody looked. The reader distinguishes
    // them, so the producer must not collapse them.
    let body = if keys.is_empty() {
        "closes 0\n".to_owned()
    } else {
        format!("closes {}:{}\n", keys.len(), keys.join(","))
    };

    let root = Path::new(".");
    let git_dir = git::git_dir(root).map_err(|_| {
        UsageError::raise(
            "record closes: not a git repository, so there is nothing to key on".to_owned(),
        )
    })?;
    let Ok(Some(branch)) = git::current_branch(root) else {
        return Err(UsageError::raise(
            "record closes: a detached HEAD has no branch to key the body on".to_owned(),
        ));
    };
    // PARTITIONED BY THE CLAIM, exactly as the reader partitions (CLOUD-1300),
    // and `pr-closes` is the record that defect was MEASURED on: after #810
    // merged and its branch was reset onto the new trunk, this file still named
    // that PR's keys and `filed-over-own-diff`'s exemption was evaluated against
    // them. A writer that skipped the partition while the reader applied it
    // would be the same staleness with an extra step — the reader would look
    // under the partitioned name, find nothing, and refuse where it used to
    // wrongly exempt.
    let claim = claim_of(&git_dir, &branch);
    store(
        &crate::recorder::record_path(&git_dir, "pr-closes", &branch, claim.as_deref()),
        &body,
    )?;
    Ok(ExitCode::Success)
}

/// This branch's claim token, for keying a verb-written record.
///
/// **The same resolution the reader makes** (`rules::recorder_records`), and a
/// free function rather than an inline call at each site because two writers
/// spelling one partition differently is the drift the partition exists to
/// close.
///
/// `None` is could-not-look — no receipt, or one naming no key — and the caller
/// keeps the unpartitioned path for it, so a branch with no claim writes exactly
/// where it always did.
fn claim_of(git_dir: &Path, branch: &str) -> Option<String> {
    crate::claim::claimed_token(&git_dir.join("batten-receipts"), branch)
}

/// The record names this crate's own VERBS write, as opposed to the ones a
/// `[[recorder]]` row mints from a tool envelope (CLOUD-472).
///
/// # Why a verb writes this at all, which is the whole design decision
///
/// A hook mediates a call the agent makes to somebody ELSE's tool, so it is
/// per-harness by nature: `TaskCreate`/`TaskUpdate` here, `write_todos` on
/// Gemini CLI, `todowrite` on `OpenCode`, `update_plan` on Codex. Recording from
/// those envelopes needs a spelling per host, and its failure mode is the one
/// this whole module exists to name — an unsurveyed harness, a tool a setting
/// switched off, and an agent that did as it was told all produce NOTHING, so the gate reads
/// clean. `OpenCode` makes that concrete: `todowrite` is denied to subagents at
/// session creation regardless of configuration.
///
/// A verb inverts the direction. The agent TELLS the engine, so a missing record
/// refuses on every harness identically — no survey, no per-host spelling, and no
/// setting that can quietly disarm it. Discovery still has a job (reporting which
/// native surface exists, so a mirror can be kept for the human's benefit), but
/// the gate reads this store and only this store.
/// `claim` is here for a second reason worth stating: `claim check` writes it and
/// nothing read it from a module before, but it is the honest signal for "this
/// branch is doing tracked work". A gate that demands a plan from EVERY tree with
/// a diff refuses every scratch fixture and every consumer checkout — measured,
/// it reddened four `cli.rs` cases that only wanted to exercise other rules.
/// Keyed to a claim, it asks the question exactly where the answer is owed.
/// `lap` joins them for the same reason and with one difference worth stating:
/// it is the only one of the three that is a HISTORY rather than a current
/// state. `land::replay` appends a line per lap, and
/// `rebase-conflict-stops-the-lap` reads the last one — so a conflict resolved by
/// a later lap stops refusing, which a store keeping only the newest line could
/// not express.
pub const VERB_WRITTEN: &[&str] = &["claim", "plan", crate::land::LAP_RECORD];

/// The statuses a plan entry may carry.
///
/// The vocabulary four harnesses already converged on, which is what makes a
/// mirror possible in either direction — but the tokens are the ENGINE's, not any
/// host's, so a harness that spells them differently is translated at the mirror
/// rather than teaching this store a dialect.
const PLAN_STATUSES: [&str; 4] = ["pending", "in_progress", "completed", "deleted"];

/// Record this branch's plan: one `<id> <status>` line per entry.
///
/// # Errors
///
/// A [`UsageError`] when a line is not `<id> <status>`, when a status is not one
/// of [`PLAN_STATUSES`], or when there is no branch to key on — a detached HEAD
/// has nothing to record against, exactly as the claim receipt has nothing to key
/// on there. An internal error when the store cannot be written.
pub fn run_plan() -> Result<ExitCode> {
    let raw = verdict_lines()?;
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(_id), Some(status)) = (words.next(), words.next()) else {
            return Err(UsageError::raise(format!(
                "plan line {} is not `<id> <status>`",
                index + 1
            )));
        };
        // THE TOKEN, NEVER THE LINE (rule 4). An entry's id is the agent's own
        // text and a status is a closed vocabulary, so the closed half is what a
        // diagnostic may echo.
        if !PLAN_STATUSES.contains(&status) {
            return Err(UsageError::raise(format!(
                "plan line {} carries an unknown status; one of {}",
                index + 1,
                PLAN_STATUSES.join(", ")
            )));
        }
    }

    let root = Path::new(".");
    let git_dir = git::git_dir(root).map_err(|_| {
        UsageError::raise(
            "record plan: not a git repository, so there is nothing to key on".to_owned(),
        )
    })?;
    let Ok(Some(branch)) = git::current_branch(root) else {
        return Err(UsageError::raise(
            "record plan: a detached HEAD has no branch to key the plan on".to_owned(),
        ));
    };
    let claim = claim_of(&git_dir, &branch);
    store(
        &crate::recorder::record_path(&git_dir, "plan", &branch, claim.as_deref()),
        &raw,
    )?;
    Ok(ExitCode::Success)
}
