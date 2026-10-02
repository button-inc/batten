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
//! them here. Nothing in this module spawns a VALIDATOR, and
//! `evaluator-io-check` stays the gate on that. The one child it can start is
//! `cargo metadata`, for a graph-reading family asked to `resolve` its own graph
//! (CLOUD-1991), and that goes through the placed `exec` adapter.
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

use std::collections::BTreeMap;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};

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
    crate::durable::replace(path, body)
        .with_context(|| format!("write the record {}", path.display()))?;
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
    store_tool(id, &text, overrides)?;
    Ok(ExitCode::Success)
}

/// Record a declared tool row's verdict out of `key=value` measurement lines
/// (CLOUD-1991, retiring `[tasks.record-perf]`'s `awk` reduction).
///
/// `pick` is `<name-key>=<token-key>`: every stdin line that OPENS with
/// `<name-key>=` and carries both fields becomes the record line
/// `<name> <token>`, and every other line is skipped — a measurement's own
/// output shape, reduced by the writer rather than by a pipeline in front of
/// it. The keys are the caller's, so no producer's field names reach the core.
///
/// # Errors
///
/// A [`UsageError`] for a `pick` that is not two non-empty keys, and every
/// refusal [`run_tool`] makes. An internal error (could-not-look, exit `3`) when
/// no line reduces: an empty record would be a PRESENT record carrying no name,
/// which a module reads as a finding whose cause is the producer.
pub fn run_tool_picked(id: &str, pick: &str, overrides: &Overrides) -> Result<ExitCode> {
    let Some((name, token)) = pick
        .split_once('=')
        .filter(|(name, token)| !name.is_empty() && !token.is_empty())
    else {
        return Err(UsageError::raise(format!(
            "record tool {id}: `--pick {pick}` is not `<name-key>=<token-key>`"
        )));
    };
    let text = picked(&verdict_lines()?, name, token);
    if text.is_empty() {
        return Err(anyhow::anyhow!(
            "record tool {id}: could not look: no line on stdin opens with `{name}=` and carries `{token}=`; nothing recorded"
        ));
    }
    store_tool(id, &text, overrides)?;
    Ok(ExitCode::Success)
}

/// The `<name> <token>` lines `pick` reduces `raw` to, in order.
///
/// A line counts only when it OPENS with `<name>=` — so a paired record
/// (`arm=… path=…`) is not taken for an absolute one — and carries a non-empty
/// value for both keys. A key given twice on one line reads its LAST value, the
/// reading the retired `awk` program made.
fn picked(raw: &str, name: &str, token: &str) -> String {
    let opener = format!("{name}=");
    let mut reduced = String::new();
    for line in raw.lines().filter(|line| line.starts_with(&opener)) {
        let mut named = None;
        let mut value = None;
        for (key, field) in line
            .split_whitespace()
            .filter_map(|field| field.split_once('='))
        {
            if key == name {
                named = Some(field);
            }
            if key == token {
                value = Some(field);
            }
        }
        if let (Some(named), Some(value)) = (named, value)
            && !named.is_empty()
            && !value.is_empty()
        {
            reduced.push_str(named);
            reduced.push(' ');
            reduced.push_str(value);
            reduced.push('\n');
        }
    }
    reduced
}

// The reduction's mutation rows, each caught by the compiled case it names in
// the perf tier, which drives the real writer and reads the record back.
//MUTANT-SUITE crates/batten/tests/it/perf_assert.rs
//MUTANT pick-any-line|s@^    for line in raw.lines().filter(|line| line.starts_with(&opener)) {$@    for line in raw.lines() {@|a_picked_measurement_skips_a_line_that_does_not_open_with_the_name
//MUTANT pick-empty-recorded|s@^    if text.is_empty() {$@    if false {@|a_picked_measurement_with_no_record_line_is_could_not_look

/// Record `text` under the declared tool row `id`: [`run_tool`]'s tail, shared with
/// [`run_tool_picked`] and with an in-process producer, so a verb that reduced a
/// tool's output itself (CLOUD-843's `sbom --record`) keys the record the same way
/// the piped doors do — one composition of the key, in one place.
///
/// # Errors
///
/// As [`run_tool`].
pub(crate) fn store_tool(id: &str, text: &str, overrides: &Overrides) -> Result<()> {
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
    store(&tools::record_path(&git_dir, &key), validated(text)?)
}

/// Run a declared tool row's `run` argv and record the exit code it answered
/// under the row's key (CLOUD-843, retiring `[tasks.record-verdicts]`' validator
/// arms).
///
/// **The exit code is the whole reduction**, `exit <n>`, and what it MEANS is the
/// consumer's module: the engine does not know which validator treats `1` as a
/// finding and which as a crash, and a vocabulary of `clean`/`error` spelled here
/// would be one consumer's reading built into every consumer's binary. The
/// tool's own report goes to the terminal through [`crate::exec::run_in`] and
/// never into the record (rule 4).
///
/// The key is composed over the bytes of the row's `input` as they stood when
/// the tool was started, with the same two functions [`run_tool`] and the reader
/// use.
///
/// **A question already answered `0` is not asked again** — see
/// [`already_clean`] — which is the step receipt the retired body kept, so a
/// `verify` that follows the hk steps over the same bytes pays nothing twice.
///
/// # Errors
///
/// A [`UsageError`] when no row declares `id`, when it declares no `run`, or when
/// its `input` will not read. Could-not-look — the argv would not start, or ended
/// without an exit code — records NOTHING and answers [`ExitCode::Internal`]: a
/// validator that never ran has no verdict, and recording one would be the
/// could-not-look-as-a-finding shape this family exists to keep apart.
pub fn run_validate(id: &str, overrides: &Overrides, err: &mut dyn Write) -> Result<ExitCode> {
    let rows = declared(overrides)?;
    let Some(row) = rows.into_iter().find(|row| row.id == id) else {
        return Err(UsageError::raise(format!(
            "no `[[rule.tools]]` row declares the id `{id}`, so there is no key to record under"
        )));
    };
    if row.run.is_empty() {
        return Err(UsageError::raise(format!(
            "the `[[rule.tools]]` row `{id}` declares no `run` argv, so there is nothing to validate with"
        )));
    }
    let root = git::repo_root(Path::new("."))?;
    let Ok(bytes) = std::fs::read(root.join(&row.input)) else {
        return Err(UsageError::raise(format!(
            "cannot read `{}`, the input row `{id}` names, so no verdict can be keyed to it",
            row.input
        )));
    };
    let key = tools::record_key(&row, &tools::digest(&bytes));
    let git_dir = git::git_dir(Path::new("."))?;
    let record = tools::record_path(&git_dir, &key);
    let receipt = git_dir.join(RECEIPTS).join(&key);
    let asked = tools::digest(row.run.join("\0").as_bytes());
    if already_clean(&record, &receipt, &asked) {
        writeln!(
            err,
            "record validate {id}: these bytes already answered 0 to this argv; not asked again"
        )?;
        return Ok(ExitCode::Success);
    }
    let code = match crate::exec::run_in(&root, &row.run) {
        Ok(ExitCode::Success) => Some(0),
        Ok(_) => None,
        Err(error) => error
            .downcast_ref::<crate::error::Passthrough>()
            .map(|passthrough| passthrough.0),
    };
    let Some(code) = code else {
        writeln!(
            err,
            "batten: record validate {id}: could not look: the declared `run` did not start or gave no exit code"
        )?;
        return Ok(ExitCode::Internal);
    };
    // THE RECEIPT GOES FIRST AND COMES BACK LAST, `forge::conditional_get`'s
    // commit-point order: an interruption between the two writes leaves no
    // receipt, which costs one re-run and never replays a stale answer.
    if let Err(error) = std::fs::remove_file(&receipt)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).context("remove a stale validate receipt");
    }
    store(&record, &format!("exit {code}\n"))?;
    if code == 0 {
        store(&receipt, &asked)?;
    }
    Ok(ExitCode::Success)
}

/// Where `record validate` keeps the argv each clean record was answered to,
/// under the git directory and beside — never inside — the tool store, so the
/// reader's keyed lookup can never mistake one for a verdict.
const RECEIPTS: &str = "batten-tools-asked";

/// Whether this exact question — these bytes, this tool at this version, this
/// argv — was already answered `0` (CLOUD-843, carrying CLOUD-1891's step
/// receipt out of `[tasks.record-verdicts]`).
///
/// **The retired receipt's two rules, kept.** It skipped a validator only when
/// the inputs it read were unchanged, and it wrote a receipt only over a CLEAN
/// store, because "a network flake reads the same as a bad config" and an error
/// held under a receipt "replays forever until an input moves". So a record
/// that is anything but `exit 0` is always asked again, and so is one whose
/// argv moved: the key carries the tool, its pinned version and the input's
/// digest, and the receipt carries the argv the key does not.
///
/// `0` here is not a verdict. What a code MEANS is the consumer's module; this
/// only declines to re-ask a question whose last answer was the process
/// convention for success, which is the one answer a flake cannot forge.
//
// THE RECEIPT'S DISCRIMINATION, over the compiled binary: skipping the check
// re-runs a validator whose inputs did not move, and an unkeyed argv replays an
// answer to a question nobody is asking.
//MUTANT receipt-never-read|s@^    if already_clean(.record, .receipt, .asked) {$@    if false {@|a_clean_answer_over_the_same_bytes_and_argv_is_not_asked_again
//MUTANT receipt-ignores-argv|s@^    let same_argv = .*$@    let same_argv = std::fs::metadata(receipt).is_ok();@|a_moved_argv_is_asked_again_over_the_same_bytes
fn already_clean(record: &Path, receipt: &Path, asked: &str) -> bool {
    let answered_zero = std::fs::read_to_string(record).is_ok_and(|body| body == "exit 0\n");
    let same_argv = std::fs::read_to_string(receipt).is_ok_and(|held| held == asked);
    answered_zero && same_argv
}

/// The forge's latest ANSWERED conclusion per check name, as `forge-verdict`
/// records spell them (CLOUD-1707, CLOUD-1965).
///
/// **Latest per name, by `checks green`'s own choice of it**: a re-run adds a
/// second run under the same name, and the reader folds a record into a map, so
/// the line that wins must be chosen here by recency rather than by listing
/// order. The choice is [`crate::checks_green::winner`] itself — `completed_at`
/// first, then `started_at`, then `id`, with a completed-but-unanswered twin
/// never burying a verdict it raced — rather than a second ordering beside it: a
/// key led by `started_at` picks the other run of an overlapping pair
/// (CLOUD-1662), and the record and `checks green` would then speak for one name
/// with two conclusions.
///
/// **Answered only, and membership is the caller's declared set**: a `skipped`
/// draft-era check, a `cancelled` fan-in and a pending run all judged nothing,
/// and recording any of them as a conclusion is how this producer twice wrote a
/// could-not-look as a verdict. The set is the one `checks green` reads, so the
/// two agree on what counts as an answer AND on which run is the latest.
//
// THE FORGE ARM'S DISCRIMINATION (CLOUD-843), each over the compiled binary and
// the fixture forge: an unanswered conclusion recorded as a grading
// (CLOUD-1965), a run other than `checks green`'s latest winning, a record
// written before the fan-in answers, and a spaced name mangled into the record.
//MUTANT-SUITE crates/batten/tests/it/record_verdicts.rs
//MUTANT unanswered-recorded|s@^    answered.contains(.conclusion)$@    true@|an_unanswered_conclusion_is_not_recorded_as_a_grading
//MUTANT listing-order-wins|s@^        if let Some(run) = crate::checks_green::winner(.group, .owned) {$@        if let Some(run) = group.last().copied() {@|the_latest_run_per_name_wins_by_completion_then_start
//MUTANT fanin-ungated|s@^        && !graded.contains_key(fanin)$@        \&\& false@|nothing_is_written_until_the_fan_in_has_answered
//MUTANT spaced-name-kept|s@^        if name.chars().any(char::is_whitespace) {$@        if false {@|a_name_with_whitespace_is_dropped_and_counted_never_mangled
//MUTANT unknown-commit-could-not-look|s@^    if answer.status == UNKNOWN_COMMIT {$@    if false {@|a_commit_the_forge_has_never_seen_records_nothing_and_passes
#[must_use]
pub fn graded(runs: &[crate::checks_green::Run], answered: &[&str]) -> BTreeMap<String, String> {
    let owned: Vec<String> = answered.iter().map(|word| (*word).to_owned()).collect();
    let mut grouped: BTreeMap<&str, Vec<&crate::checks_green::Run>> = BTreeMap::new();
    for run in runs {
        grouped.entry(run.name.as_str()).or_default().push(run);
    }
    let mut latest: BTreeMap<&str, &crate::checks_green::Run> = BTreeMap::new();
    for (name, group) in grouped {
        if let Some(run) = crate::checks_green::winner(&group, &owned) {
            latest.insert(name, run);
        }
    }
    latest
        .into_iter()
        .filter(|(_, run)| answers(answered, &run.conclusion))
        .map(|(name, run)| (name.to_owned(), run.conclusion.clone()))
        .collect()
}

/// Whether `conclusion` is one of the declared answers.
fn answers(answered: &[&str], conclusion: &str) -> bool {
    answered.contains(&conclusion)
}

/// The record body [`graded`] conclusions spell, or `None` while the fan-in has
/// not answered — and how many names could not be spelled.
///
/// **The fan-in gates writing AT ALL.** It is the check every other required job
/// feeds, so until it has an answered conclusion the forge has not finished
/// judging the commit, and a partial record would be a record PRESENT without a
/// passing fan-in — which `forge-verdict-required` refuses, on local `verify` and
/// inside CI's own run alike. Absent is could-not-look, the correct reading for
/// both.
///
/// **A name with whitespace has no spelling here** and is dropped rather than
/// mangled: the record splits `<name> <token>` on the first whitespace run, so
/// `action (ubuntu-latest) success` would record the name `action`.
#[must_use]
pub fn forge_body(
    graded: &BTreeMap<String, String>,
    fanin: Option<&str>,
) -> Option<(String, usize)> {
    if let Some(fanin) = fanin
        && !graded.contains_key(fanin)
    {
        return None;
    }
    let mut body = String::new();
    let mut dropped = 0_usize;
    for (name, conclusion) in graded {
        if name.chars().any(char::is_whitespace) {
            dropped += 1;
            continue;
        }
        body.push_str(name);
        body.push(' ');
        body.push_str(conclusion);
        body.push('\n');
    }
    Some((body, dropped))
}

/// Record the forge's verdicts for one commit.
///
/// Piped `<check> <conclusion>` lines by default. With `fetch`, the check-runs
/// are read from the forge in process through [`crate::pr_watch::read`] — the
/// same paginated client `pr watch` and `land` read — reduced by [`graded`] over
/// `answered`, and gated on `fanin` by [`forge_body`] (CLOUD-843, retiring the
/// forge arm of `[tasks.record-verdicts]`).
///
/// # Errors
///
/// A [`UsageError`] when `reference` resolves to no commit, when a piped line
/// carries no token, or when `--fanin`/`--answered` are given without `--fetch`
/// or `--fetch` without `--answered`. An internal error when the store cannot be
/// written. A forge that could not be read is could-not-look: nothing is
/// recorded and the answer is [`ExitCode::Internal`].
pub fn run_forge(
    reference: &str,
    fetch: Option<&Fetch>,
    _overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    if let Some(fetch) = fetch {
        return run_forge_fetch(reference, fetch, err);
    }
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

/// What `record forge --fetch` reads the forge with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The check whose answered conclusion gates writing at all, if any.
    pub fanin: Option<String>,
    /// The conclusions that constitute an answer.
    pub answered: Vec<String>,
}

/// Hold `record forge`'s three flags to one of its two shapes.
///
/// # Errors
///
/// A [`UsageError`] for a qualifier without `--fetch`, a `--fetch` with no
/// `--answered` set — every conclusion would then be a non-answer and the record
/// could never be written — or an empty `--fanin`, which names no check.
fn forge_fetch(
    fetch: bool,
    fanin: Option<String>,
    answered: Option<&str>,
) -> Result<Option<Fetch>> {
    if !fetch {
        if fanin.is_some() || answered.is_some() {
            return Err(UsageError::raise(String::from(
                "record forge: `--fanin` and `--answered` qualify a `--fetch` reading; a piped verdict was already reduced",
            )));
        }
        return Ok(None);
    }
    let answered: Vec<String> = answered
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    if answered.is_empty() {
        return Err(UsageError::raise(String::from(
            "record forge --fetch: `--answered` names no conclusion, so no check-run could ever count as graded",
        )));
    }
    if fanin.as_deref().is_some_and(|name| name.trim().is_empty()) {
        return Err(UsageError::raise(String::from(
            "record forge --fetch: `--fanin` is empty, so it names no check to gate on",
        )));
    }
    Ok(Some(Fetch { fanin, answered }))
}

/// The check-runs endpoint's status for a sha it holds no commit for.
const UNKNOWN_COMMIT: u16 = 422;

/// `record forge --fetch`: read the commit's check-runs from the forge and
/// record their answered conclusions, gated on the fan-in.
fn run_forge_fetch(reference: &str, fetch: &Fetch, err: &mut dyn Write) -> Result<ExitCode> {
    let root = Path::new(".");
    let Some(sha) = git::resolve_ref(root, reference)? else {
        return Err(UsageError::raise(format!(
            "`{reference}` resolves to no commit, so there is no sha to key this verdict to"
        )));
    };
    let Some(repo) = crate::repo_slug(root) else {
        writeln!(
            err,
            "batten: record forge: could not look: no forge remote names the repository"
        )?;
        return Ok(ExitCode::Internal);
    };
    let config = crate::pr_watch::Config {
        sha: sha.clone(),
        repo,
        interval: crate::pr_watch::DEFAULT_INTERVAL,
        progress: None,
    };
    let Some(answer) = crate::pr_watch::read(&config, None) else {
        writeln!(
            err,
            "batten: record forge: could not look: the forge did not answer for the check-runs"
        )?;
        return Ok(ExitCode::Internal);
    };
    // A COMMIT THE FORGE HAS NEVER SEEN HAS NO CHECK-RUNS, which is an answer:
    // the endpoint's 422 is "no commit found for SHA". It is the ordinary state
    // of a head `land` has just replayed onto a moved trunk and not yet pushed,
    // and the retired body read it as nothing graded. Calling it could-not-look
    // made every replayed lap's `verify` die of the environment (measured
    // 2026-10-01). Every other refusal still is could-not-look.
    if answer.status == UNKNOWN_COMMIT {
        writeln!(
            err,
            "record forge: the forge has no such commit yet, so nothing is graded; nothing recorded"
        )?;
        return Ok(ExitCode::Success);
    }
    if !answer.is_reading() {
        writeln!(
            err,
            "batten: record forge: could not look: the forge answered status {} for the check-runs",
            answer.status
        )?;
        return Ok(ExitCode::Internal);
    }
    let runs = crate::pr_watch::runs_from_body(&answer.body);
    let answered: Vec<&str> = fetch.answered.iter().map(String::as_str).collect();
    let conclusions = graded(&runs, &answered);
    let Some((body, dropped)) = forge_body(&conclusions, fetch.fanin.as_deref()) else {
        writeln!(
            err,
            "record forge: the fan-in has no answered conclusion yet; nothing recorded"
        )?;
        return Ok(ExitCode::Success);
    };
    // A COUNT, never the names (rule 4), so the limit stays visible.
    if dropped > 0 {
        writeln!(
            err,
            "record forge: {dropped} check-run name(s) carry whitespace and have no spelling in a forge record; dropped"
        )?;
    }
    let git_dir = git::git_dir(root)?;
    store(&forge::record_path(&git_dir, &sha), &body)?;
    Ok(ExitCode::Success)
}

/// Derive the per-suite cost corpus and print it, or write it (CLOUD-352).
///
/// The one `record` leaf whose store is a COMMITTED file rather than the
/// out-of-tree record tree, and the reason is the reader: the others are read by
/// a gate, this one by a person deciding whether the suite they are about to add
/// a case to is expensive. A record nobody opens answers nothing.
///
/// # Errors
///
/// A [`UsageError`] when the report is absent, unreadable, carries no suite, or
/// names a suite this tree does not track — see [`crate::suites::derive`], where
/// all four are could-not-look and none is an empty corpus. An internal error
/// when the corpus cannot be written.
pub fn run_suites(write: bool, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let root = git::repo_root(Path::new("."))?;
    let root = Path::new(&root);
    // TWO RUNNERS, ONE VERB (CLOUD-2059). The bats report is read where it
    // exists — a consumer with a bats lane keeps exactly what it had — and
    // nextest's own JUnit report otherwise, for the profile the run used. The
    // per-module table is printed, never written: it is a measurement an author
    // reads on the row it is posted to, and `--write`'s committed corpus is the
    // bats lane's contract alone.
    if !root.join(crate::suites::REPORT).is_file() {
        let profile = std::env::var("NEXTEST_PROFILE")
            .ok()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "default".to_owned());
        let (rows, text) = crate::suites::derive_nextest(root, &profile)?;
        write!(out, "{text}")?;
        if write {
            writeln!(
                err,
                "record suites: {} module(s) printed; a nextest table is not written to the tree",
                rows.len()
            )?;
        }
        return Ok(ExitCode::Success);
    }
    // THE TRACKED SET FROM GIT, never a directory walk: an untracked scratch file
    // beside the suites is not something the corpus should have to carry, and a
    // walk would put it there.
    let tracked = crate::git::tracked_paths(root)?
        .into_iter()
        // `extension`, not `ends_with(".bats")`: the string comparison is
        // case-sensitive where a file name is not everywhere, and a `FOO.BATS`
        // the runner would run is one this corpus would then never carry.
        .filter(|path| {
            path.starts_with("tests/")
                && Path::new(path)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("bats"))
        })
        .collect();
    let (rows, text) = crate::suites::derive(root, &tracked)?;
    if !write {
        write!(out, "{text}")?;
        return Ok(ExitCode::Success);
    }
    // `store` rather than a second write path, and it is the same helper the
    // other three leaves use: one place that creates the directory and reports
    // which write failed. The corpus lives in the tree rather than under
    // `$GIT_DIR`, and that is the only thing this leaf does differently.
    store(&crate::suites::corpus_path(root), &text)?;
    writeln!(
        err,
        "record suites: {} suite(s), written to {}",
        rows.len(),
        crate::suites::CORPUS
    )?;
    Ok(ExitCode::Success)
}

/// Dispatch the `record` verbs.
///
/// # Errors
///
/// Whatever the chosen sub-verb returns: a [`UsageError`] for an id or ref that
/// resolves to nothing, an unreadable subject, or a malformed verdict line, and
/// an internal error when the store cannot be written.
pub fn run(
    command: crate::cli::RecordCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        crate::cli::RecordCommand::Suites { write } => run_suites(write, out, err),
        crate::cli::RecordCommand::Tool { id } => run_tool(&id, overrides),
        crate::cli::RecordCommand::ToolPicked { id, pick } => {
            run_tool_picked(&id, &pick, overrides)
        }
        crate::cli::RecordCommand::Validate { id } => run_validate(&id, overrides, err),
        crate::cli::RecordCommand::Forge {
            reference,
            fetch,
            fanin,
            answered,
        } => {
            let fetch = forge_fetch(fetch, fanin, answered.as_deref())?;
            run_forge(&reference, fetch.as_ref(), overrides, err)
        }
        crate::cli::RecordCommand::Plan => run_plan(),
        crate::cli::RecordCommand::Closes => run_closes(overrides),
        crate::cli::RecordCommand::Named { family } => run_named(&family),
        crate::cli::RecordCommand::Derive { family, inputs } => {
            run_derive(&family, &inputs, overrides, out)
        }
        crate::cli::RecordCommand::Keyed { family, key } => run_keyed(&family, &key),
        crate::cli::RecordCommand::Journal { family } => run_journal(&family),
        crate::cli::RecordCommand::Show { family, key } => run_keyed_show(&family, &key, out),
        crate::cli::RecordCommand::Fold { family } => run_journal_show(&family, out),
        crate::cli::RecordCommand::Query { id, inputs } => {
            crate::forge_query::run(&id, &inputs, overrides, err)
        }
        crate::cli::RecordCommand::Probe {
            family,
            inputs,
            command,
        } => run_probe(&family, &inputs, &command, overrides, out),
        // `record decide` writes here and then DECIDES, which needs the check
        // runner and the output mode this dispatcher is not handed; the binary's
        // own dispatch takes the arm before it reaches this one.
        crate::cli::RecordCommand::Decide { .. } => Err(UsageError::raise(
            "record decide: reached without its decision; it is dispatched by the binary",
        )),
        crate::cli::RecordCommand::Divergence {
            ci_workflow,
            land_workflow,
            since,
            max_pages,
        } => crate::ci_signal::run_divergence(
            ci_workflow.as_deref(),
            land_workflow.as_deref(),
            since.as_deref(),
            max_pages.as_deref(),
            out,
            err,
        ),
        crate::cli::RecordCommand::Nonverdict {
            window,
            required_checks,
            exclude_jobs,
            verdict_steps,
        } => crate::ci_signal::run_nonverdict(
            window.as_deref(),
            &required_checks,
            &exclude_jobs,
            &verdict_steps,
            out,
            err,
        ),
        crate::cli::RecordCommand::Census { command } => crate::reclaim::run(command, out, err),
        crate::cli::RecordCommand::Release { tag, manifest } => {
            crate::release::run_record(tag.as_deref(), &manifest, err)
        }
        crate::cli::RecordCommand::Attestation {
            tag,
            binary,
            verifier,
        } => crate::attestation::run(tag.as_deref(), &binary, verifier.as_deref(), err),
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
    // that PR's keys and `issue file same`'s exemption was evaluated against
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
/// `replay halt conflict` reads the last one — so a conflict resolved by
/// a later lap stops refusing, which a store keeping only the newest line could
/// not express.
pub const VERB_WRITTEN: &[&str] = &["claim", "plan", crate::land::LAP_RECORD];

/// One family a producer writes through [`run_named`], declared by the consumer
/// (CLOUD-1810).
///
/// # The gap this closes, and why neither existing surface could
///
/// [`run_named`] writes a branch-keyed store, and until this existed nothing
/// could read one. [`crate::rules`]' projection builds the set of families it
/// hands a module as the declared [`crate::recorder::Declared`] rows unioned with
/// [`VERB_WRITTEN`], and a caller-named family is in neither:
///
/// - [`VERB_WRITTEN`] is a fixed list because the ENGINE owns both halves of
///   those three stores. A consumer's family cannot join it without this crate
///   knowing a consumer's name, which non-negotiable rule 1 forbids outright.
/// - A `[[recorder]]` cannot express one either: [`crate::recorder::Declared`]
///   requires `tool`, because that table selects on a mediated tool call. A
///   family a `mise` task writes answers to no tool call at all.
///
/// So the store was written, the row was registered, the module read
/// `input.tree.records["<family>"]` — and the key was absent, every rule beneath
/// it undefined, and the gate green. Measured over `branch-age`: a record naming
/// a 36-day branch against a two-day threshold, `batten check` exit `0`. That is
/// CLOUD-1707's dead gate one surface over.
///
/// # Declared rather than swept, which is the whole design
///
/// The projection could have read whatever files happen to sit in the store
/// directory. It must not, for the reason [`crate::rules`] already gives about a
/// sibling fact: a family set cannot become an ambient sweep of whatever records
/// happen to be on disk, because then a leftover file from a retired producer
/// answers as a live measurement and nothing names what SHOULD be there.
///
/// A declaration is also what makes could-not-look readable. An absent record
/// under a DECLARED family is "the producer did not run"; the same absence under
/// no declaration is not a reading at all, and collapsing the two is the error in
/// the fact model this whole store exists to avoid.
///
/// # Config rather than a column on the rule that reads it
///
/// [`crate::rules`] settles this at its own call site: the fact is what THIS
/// repository's producers accumulated, so a per-rule declaration would be a
/// second place for the same answer to live. Two rules reading one family is
/// ordinary; two rules disagreeing about what writes it is not expressible.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Declared {
    /// The family name, which is also its file name under the store.
    ///
    /// Held to [`safe_component`]'s grammar at validation rather than at write
    /// time alone, so a family that could never be written is refused while its
    /// author is watching instead of on the first producer run.
    pub record: String,
    /// What writes it, as a runnable command.
    ///
    /// **Never executed, and that is not a gap.** House style §5 keeps the spawn
    /// outside `check`, so this is a pointer — the job `[[verdict.route]]`'s
    /// `target` already does. What it buys is that a declared family always says
    /// who fills it: a store with no producer is a row that can only ever read
    /// could-not-look, and the moment to catch that is at config load rather than
    /// after a green run nobody questions.
    pub writer: String,
}

/// Prove every declared family well formed (CLOUD-253's obligation).
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a family whose name is not a single path
/// component, for an empty `writer`, and for two rows naming one family — the
/// last because a second row is a second answer to "who writes this", which is
/// the one question the table exists to settle.
pub fn validate(declared: &[Declared], recorders: &[crate::recorder::Declared]) -> Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for family in declared {
        // ONE NAME, ONE SOURCE. The projection resolves a `[[recorder]]` row's
        // record, then a `[[record]]` family, then a verb-written store, and
        // keeps the first — so a family sharing a name with either was silently
        // shadowed, its producer writing a store no module reads as its own.
        if VERB_WRITTEN.contains(&family.record.as_str()) {
            return Err(UsageError::raise(format!(
                "record `{}` is a store the engine writes itself; a declared family \
                 of that name would be a second writer for it",
                family.record
            )));
        }
        if recorders
            .iter()
            .any(|recorder| recorder.record == family.record)
        {
            return Err(UsageError::raise(format!(
                "record `{}` is already a `[[recorder]]` row's record; a declared family \
                 of that name would be shadowed by it",
                family.record
            )));
        }
        // The same grammar the writer enforces, checked here so the refusal lands
        // at load. A name that escapes its store is why `safe_component` exists;
        // reaching it only from `run_named` would let a config sit green until a
        // producer ran.
        safe_component("record", &family.record)?;
        if family.writer.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "record `{}`: `writer` names what fills this store and is empty, so the \
                 family could only ever read could-not-look",
                family.record
            )));
        }
        if !seen.insert(family.record.as_str()) {
            return Err(UsageError::raise(format!(
                "record `{}` is declared twice; one family has one writer",
                family.record
            )));
        }
    }
    Ok(())
}

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

// --- the two store families a task can reach (CLOUD-1713) --------------------
//
// Three programs (841 lines) each hand-rolled a durable keyed store under
// `.git/` while the engine shipped both shapes with no door to either. These are
// the doors: `keyed` is put/hit, `journal` is append-and-fold.
//
// THE COST CLASS IS NOT WIDENED, and this is the answer §2 asks for in one
// sentence: `check` is `Cost::Read` and structurally cannot spawn or write, so a
// record reaches a read-classed surface exactly as `validator-verdict-clean`'s
// already does — a SEPARATE PRODUCER VERB writes it, and `verify` runs that verb
// before the gates. The producer here is `record keyed` / `record journal`
// (`Effect::Write`); the consumer is `show record` / `show journal`
// (`Effect::Read`) or a fact. Nothing on the read path writes.

/// Where the keyed put/hit family stores its records.
const KEYED_STORE: &str = "batten-records";

/// Where the append-and-fold family stores its shards.
const JOURNAL_STORE: &str = "batten-journals";

/// A journal family's store directory under `git_dir` — the one spelling of
/// where `record journal` / `record fold` keep a family, so an in-process
/// writer (the reclaim census) lands where `record fold` reads.
pub(crate) fn journal_store(git_dir: &Path, family: &str) -> PathBuf {
    git_dir.join(JOURNAL_STORE).join(family)
}

/// A family name that cannot escape its store.
///
/// **A path component, checked rather than trusted.** The family and the key both
/// reach this from a caller's argv, and a `..` or a `/` in either would put a
/// record outside the store the reader looks in — which is not a security
/// boundary here so much as a silent miss: the write succeeds, the read finds
/// nothing, and the gate reads clean.
pub(crate) fn safe_component(what: &str, value: &str) -> Result<String> {
    let clean = value.trim();
    if clean.is_empty()
        || clean == "."
        || clean == ".."
        || clean.contains('/')
        || clean.contains('\\')
        || clean.contains('\0')
    {
        return Err(UsageError::raise(format!(
            "the {what} must be one path component and must not be `.`, `..`, or contain a separator"
        )));
    }
    Ok(clean.to_owned())
}

/// The `--input <key>=<value>` tokens a `record` leaf was handed, as a map.
///
/// Shared by `record derive` and `record query` (CLOUD-843) rather than parsed
/// twice: both take the same flag spelling, and two parsers of one token shape
/// are two answers to whether `a=b=c` binds `a` — `verb` only names the leaf in
/// the refusal.
///
/// # Errors
///
/// A [`UsageError`] for a token carrying no `=`, for an empty key, and for a
/// key given twice — a repeated key is a caller who believes both values are in
/// effect, and silently keeping one would run the reading on an input nobody
/// asked for.
pub(crate) fn inputs_of(verb: &str, inputs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for token in inputs {
        let Some((key, value)) = token.split_once('=') else {
            return Err(UsageError::raise(format!(
                "{verb}: `--input {token}` is not `<key>=<value>`"
            )));
        };
        if key.is_empty() {
            return Err(UsageError::raise(format!(
                "{verb}: an input with no key names nothing"
            )));
        }
        if parsed.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(UsageError::raise(format!(
                "{verb}: input `{key}` was given twice"
            )));
        }
    }
    Ok(parsed)
}

/// One required input, or a usage error naming what is missing.
fn required_input<'a>(
    inputs: &'a BTreeMap<String, String>,
    family: &str,
    key: &str,
) -> Result<&'a str> {
    inputs.get(key).map(String::as_str).ok_or_else(|| {
        UsageError::raise(format!(
            "record derive {family}: needs `--input {key}=<value>`"
        ))
    })
}

/// Refuse an input key the family does not read.
///
/// **A KEY NOBODY READS IS A USAGE ERROR, NEVER A SILENT DEFAULT**, and that is
/// the same property `--rule` has one verb over: a caller who misspells an input
/// would otherwise get a clean exit from a reading that ran on something else.
/// The failure would be invisible precisely because the record still got written.
fn only_these_inputs(
    inputs: &BTreeMap<String, String>,
    family: &str,
    accepted: &[&str],
) -> Result<()> {
    for key in inputs.keys() {
        if !accepted.contains(&key.as_str()) {
            return Err(UsageError::raise(format!(
                "record derive {family}: reads no input `{key}`"
            )));
        }
    }
    Ok(())
}

/// One declared `[[pattern]]` row, compiled.
///
/// NON-NEGOTIABLE RULE 1 IS WHY THIS EXISTS. Which package is the evaluator,
/// which crates bear IO, which need a platform SDK and which vendor what they
/// link are all CONSUMER facts, and a `const` here would put a consumer
/// identifier in the repo-agnostic core. They live in the one committed
/// authority instead, exactly as `run_closes` resolves its key grammar — with
/// the side benefit that the lists become reviewable data rather than constants
/// compiled into a binary (rule 3).
fn declared_pattern(
    patterns: &[crate::pattern::NamedPattern],
    family: &str,
    id: &str,
) -> Result<regex::Regex> {
    let row = patterns.iter().find(|row| row.id == id).ok_or_else(|| {
        UsageError::raise(format!(
            "record derive {family}: no `[[pattern]]` row declares `{id}`"
        ))
    })?;
    regex::Regex::new(&row.regex).map_err(|_| {
        UsageError::raise(format!(
            "record derive {family}: `[[pattern]]` row `{id}` will not compile"
        ))
    })
}

/// The `cargo metadata` document a graph-reading family takes on stdin.
///
/// COULD-NOT-LOOK IS A REFUSAL, NEVER AN EMPTY GRAPH. The producer writes
/// nothing when the document will not parse, because an absent record means
/// "the producer did not run" and must not be spelled the same way as a graph
/// that resolved and found nothing.
fn graph_on_stdin(family: &str, document: Option<&str>) -> Result<crate::cargo_graph::Graph> {
    let raw = document_or_stdin(document)?;
    let meta: serde_json::Value = serde_json::from_str(&raw).map_err(|_| {
        UsageError::raise(format!(
            "record derive {family}: stdin is not a `cargo metadata` document"
        ))
    })?;
    Ok(crate::cargo_graph::Graph::from_metadata(&meta))
}

/// The `cargo metadata` document a graph-reading family reads: on stdin, or
/// resolved here when the caller names `resolve` (CLOUD-1991).
///
/// # Why the resolution moved in
///
/// The two producer tasks were a `cargo metadata` spawn piped into this verb,
/// behind a fixture switch — shell whose only job was to connect one argv's
/// stdout to another's stdin. `resolve=<triple>` resolves the graph for that
/// platform (`--filter-platform`), and `resolve=any` for every platform, which
/// are the two questions the two families ask. Omitting it keeps the stdin
/// route, which is how a recorded graph still reaches the walk.
///
/// ALWAYS `--locked`: the question is about the COMMITTED resolution, and a
/// producer allowed to update the lockfile answers "what would upstream give me
/// today". The spawn is `crate::exec::piped_argv`'s, the placed adapter, so
/// the inventory does not grow; `cargo` is the toolchain's own name and names no
/// consumer.
///
/// COULD-NOT-LOOK IS AN INTERNAL ERROR (exit `3`), never an empty graph: a
/// resolution that failed or answered something unparseable writes nothing, so
/// the module reads an absent record as "the producer did not run".
fn graph_for(
    inputs: &BTreeMap<String, String>,
    family: &str,
    document: Option<&str>,
) -> Result<crate::cargo_graph::Graph> {
    let Some(platform) = inputs.get("resolve") else {
        return graph_on_stdin(family, document);
    };
    if platform.trim().is_empty() {
        return Err(UsageError::raise(format!(
            "record derive {family}: `--input resolve=` names no platform; a target triple, or `any`"
        )));
    }
    let mut argv: Vec<String> = ["cargo", "metadata", "--locked", "--format-version", "1"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    if platform != "any" {
        argv.push("--filter-platform".to_owned());
        argv.push(platform.clone());
    }
    let Some((0, raw)) = crate::exec::piped_argv(
        Path::new("."),
        &argv,
        "",
        crate::exec::Diagnostics::Drop,
        &[],
    ) else {
        return Err(anyhow::anyhow!(
            "record derive {family}: could not look: `cargo metadata` did not resolve the graph; nothing recorded"
        ));
    };
    let meta: serde_json::Value = serde_json::from_str(&raw).map_err(|_| {
        anyhow::anyhow!(
            "record derive {family}: could not look: `cargo metadata` answered no document; nothing recorded"
        )
    })?;
    Ok(crate::cargo_graph::Graph::from_metadata(&meta))
}

// The resolution's mutation rows. Each is caught by the compiled case it names,
// which drives a scratch crate through the real `cargo`.
//MUTANT-SUITE crates/batten/tests/it/evaluator_closure.rs
//MUTANT resolve-unlocked|s@\["cargo", "metadata", "--locked", "--format-version", "1"\]@["cargo", "metadata", "--format-version", "1"]@|a_resolution_that_would_rewrite_the_lockfile_is_could_not_look
//MUTANT resolve-ignored|s@^    let Some(platform) = inputs.get("resolve") else {$@    let Some(platform) = inputs.get("no-such-input") else {@|the_engine_resolves_a_locked_crate_itself

/// Derive one family's record from its input and write it.
///
/// The engine applies the READING; the effects that produced the input stay in
/// the producer task (house-style §5), with one exception a family opts into:
/// `--input resolve=` asks a graph-reading family to resolve its own
/// `cargo metadata` document (CLOUD-1991).
///
/// # Errors
///
/// A [`UsageError`] for an unknown family, a malformed or missing input, a
/// family that is not a single path component, a repository with no branch to
/// key on, or a tree that is not a repository; an internal error when the store
/// cannot be written, or when a requested resolution could not look.
pub fn run_derive(
    family: &str,
    inputs: &[String],
    overrides: &Overrides,
    out: &mut dyn std::io::Write,
) -> Result<ExitCode> {
    let inputs = inputs_of("record derive", inputs)?;
    // THE TRACKER FAMILIES ARE CLEARED BEFORE ANY OF THEM IS READ (CLOUD-843).
    // One preset row decides over all five, so a record another tracker question
    // left on this branch would otherwise answer beside this one — and a reading
    // that refuses would leave its own previous record answering as current.
    // Clearing first makes both absences true: the store holds this answer or
    // nothing.
    // `released` is the preset's sixth family and is cleared with the five, for
    // the same reason: one row decides over all of them.
    if crate::tracker_reading::is_family(family) || family == crate::released::FAMILY {
        for sibling in crate::tracker_reading::FAMILIES
            .iter()
            .chain(&[crate::released::FAMILY])
        {
            clear_named("record derive", sibling)?;
        }
    }
    let derived = derive_reading(family, &inputs, overrides, None)?;
    let family = safe_component("family", family)?;
    store_derived(&family, &derived)?;
    emit_derived(&derived, out)
}

/// The input a reading consumes: the document a caller already holds, or stdin.
///
/// `record derive` reads its document from stdin because the producer that
/// wrote it ran in a task. `record probe` runs the producer itself and hands its
/// output here instead, so the reading is one function over either source.
fn document_or_stdin(document: Option<&str>) -> Result<String> {
    match document {
        Some(given) => Ok(given.to_owned()),
        None => verdict_lines(),
    }
}

/// The input key a probe's exit status is supplied under.
const PROBE_STATUS: &str = "status";

/// Run a probe command and derive a family's reading from what it answered
/// (CLOUD-843, retiring `[tasks.evaluator-io-record]`).
///
/// [`run_derive`] with the producer moved IN: the command's exit status is the
/// `status` input and its combined output is the document, so a caller needs no
/// temporary file, no captured status and no pipe. The reading, the store and
/// the emitted tokens are `record derive`'s own.
///
/// # Errors
///
/// A [`UsageError`] for a `status` the caller tried to supply (it is the
/// command's to answer), an empty command, an unknown family or a malformed
/// input; an internal error for a command that will not start or a store that
/// cannot be written. NOTHING is written on any error, so a stale record is
/// never refreshed by a probe that did not run.
pub fn run_probe(
    family: &str,
    inputs: &[String],
    command: &[String],
    overrides: &Overrides,
    out: &mut dyn std::io::Write,
) -> Result<ExitCode> {
    let mut inputs = inputs_of("record probe", inputs)?;
    if inputs.contains_key(PROBE_STATUS) {
        return Err(UsageError::raise(
            "record probe: `status` is the command's own exit, never an input",
        ));
    }
    let family = safe_component("family", family)?;
    let ran = crate::probe::run(command)?;
    inputs.insert(PROBE_STATUS.to_owned(), ran.status.to_string());
    let derived = derive_reading(&family, &inputs, overrides, Some(&ran.log))?;
    store_derived(&family, &derived)?;
    emit_derived(&derived, out)
}

/// The family whose reading is a session's judged turn (CLOUD-843, retiring
/// `[tasks.finding-sink-check]`).
///
/// Its own name here for the reason every family arm below carries one: the
/// reading is this engine's, and the consumer names the rule that decides.
const TURN_FAMILY: &str = "turn-writes";

/// What `record decide` wrote before the caller decides over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The reading is recorded.
    Recorded,
    /// The reading is recorded and holds no turn, so there is nothing to judge.
    Empty,
    /// Nothing could be read, and any stale record is removed, so the module is
    /// silent. The reason is a fixed pointer, never a byte of the input.
    Abstained(&'static str),
}

/// Derive one family's reading and write it WITHOUT emitting it, for a caller
/// that decides over it next (`record decide`).
///
/// **Silent on stdout, unlike `record derive`, and that is the point.** A
/// `stop` handler's stdout on a passing exit is advisory text the host shows,
/// so a reading echoed there would be said on every turn. The decision's own
/// output is the only thing this verb says.
///
/// **Transient**: the dispatcher removes the record once the decision is made
/// ([`clear_named`]), so a reading never answers a later `check` or `enforce`.
///
/// # Errors
///
/// As [`run_derive`]: a [`UsageError`] for an unknown family, a malformed input
/// or a tree with no branch to key on; an internal error for an unwritable store.
pub fn decide_record(family: &str, inputs: &[String], overrides: &Overrides) -> Result<Decision> {
    let inputs = inputs_of("record decide", inputs)?;
    let family = safe_component("family", family)?;
    if family != TURN_FAMILY {
        let derived = derive_reading(&family, &inputs, overrides, None)?;
        store_named("record decide", &family, &derived)?;
        return Ok(Decision::Recorded);
    }
    // OUTSIDE A CHECKOUT THERE IS NO STORE TO DECIDE OVER, and a `stop` handler
    // runs wherever the session stands: could-not-look, which the handler door
    // reads as a pass, never a usage error said on every turn.
    if git::git_dir(Path::new(".")).is_err() {
        return Ok(Decision::Abstained(
            "not a git repository, so no record store",
        ));
    }
    // NOR IS A DIRECTORY WITH NO AUTHORITY OF ITS OWN, one level in. The store
    // check above discovers upward and configuration never does (house style
    // §8), so a session standing in a subdirectory of a checkout resolves the
    // defaults, which declare none of this reading's rows — and the reading
    // below then fails as a usage error on every turn. Measured on this
    // repository's own `finding-sink` handler once the session's working
    // directory moved into `crates/batten/tests/it` (CLOUD-2059).
    //MUTANT-SUITE crates/batten/tests/it/finding_sink.rs
    //MUTANT subdirectory-decides|s@^        \&\& !Path::new(crate::config::CONFIG_FILE).is_file()$@        \&\& false@|a_session_in_a_subdirectory_abstains_rather_than_failing
    if overrides.config_from.is_none()
        && overrides.config_in.is_none()
        && !Path::new(crate::config::CONFIG_FILE).is_file()
    {
        return Ok(Decision::Abstained(
            "no committed authority in this directory",
        ));
    }
    match turn_reading(&family, &inputs, overrides)? {
        None => {
            clear_named("record decide", &family)?;
            Ok(Decision::Abstained("no readable transcript"))
        }
        Some((body, turns)) => {
            store_named("record decide", &family, &body)?;
            Ok(if turns == 0 {
                Decision::Empty
            } else {
                Decision::Recorded
            })
        }
    }
}

/// The judged turn's reading, or `None` where the transcript could not be read.
///
/// Every input names a consumer fact (non-negotiable rule 1): `citation` and
/// `key` are `[[pattern]]` row ids — the second must carry a `key` group —
/// `fields` the comma-separated input fields a direct call names its row by,
/// `receipt` the read-receipt family, and `field` the 1-indexed field of it that
/// holds the row's column.
///
/// # Errors
///
/// A [`UsageError`] for a missing, unaccepted or malformed input, or an
/// undeclared pattern row.
fn turn_reading(
    family: &str,
    inputs: &BTreeMap<String, String>,
    overrides: &Overrides,
) -> Result<Option<(String, usize)>> {
    only_these_inputs(
        inputs,
        family,
        &["citation", "key", "fields", "receipt", "field"],
    )?;
    let config = resolve::resolve(Path::new("."), overrides)?;
    let citation = declared_pattern(
        &config.patterns,
        family,
        required_input(inputs, family, "citation")?,
    )?;
    let key_row = required_input(inputs, family, "key")?;
    let key = declared_pattern(&config.patterns, family, key_row)?;
    if !key.capture_names().any(|name| name == Some("key")) {
        return Err(UsageError::raise(format!(
            "record derive {family}: `[[pattern]]` row `{key_row}` has no `key` group"
        )));
    }
    let fields: Vec<String> = required_input(inputs, family, "fields")?
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
        .collect();
    let receipt = safe_component("receipt", required_input(inputs, family, "receipt")?)?;
    let raw = required_input(inputs, family, "field")?;
    let field: usize = raw.parse().ok().filter(|field| *field > 0).ok_or_else(|| {
        UsageError::raise(format!(
            "record derive {family}: field `{raw}` is not a 1-indexed field number"
        ))
    })?;
    let stdin = verdict_lines()?;
    let Some(path) = crate::turn::transcript_of(&stdin) else {
        return Ok(None);
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    let vocabulary = crate::turn::Vocabulary {
        citation: &citation,
        key: &key,
        fields: &fields,
    };
    let crate::turn::Reading::Read(turn) = crate::turn::read(&body, &vocabulary) else {
        return Ok(None);
    };
    let git_dir = git::git_dir(Path::new(".")).ok();
    let rendered = crate::turn::render(&turn, &|row: &str| {
        crate::turn::column(git_dir.as_deref(), &receipt, field, row)
    });
    Ok(Some((rendered, turn.turns)))
}

/// The READING for one family, from its declared inputs and whatever is on stdin.
///
/// Split out of [`run_derive`] because the two halves grow at different rates:
/// this one gains an arm per producer, and the store-and-emit tail below it is
/// fixed. Nothing here spawns except the one resolution `graph_for` owns —
/// house-style §5 keeps a producer's effects in the task, and what arrives is
/// otherwise already a reading's worth of input.
///
/// # Errors
///
/// A [`UsageError`] for an unknown family, or a malformed, missing or
/// unaccepted input.
///
/// `document` is the input a family reads from stdin when the caller already
/// holds it — `record probe`'s captured output — and `None` reads stdin.
fn derive_reading(
    family: &str,
    inputs: &BTreeMap<String, String>,
    overrides: &Overrides,
    document: Option<&str>,
) -> Result<String> {
    let derived = match family {
        "evaluator-io-probe" => {
            only_these_inputs(inputs, family, &["status", "test"])?;
            let raw = required_input(inputs, family, "status")?;
            let status: i32 = raw.parse().map_err(|_| {
                UsageError::raise(format!(
                    "record derive {family}: status `{raw}` is not a whole number"
                ))
            })?;
            let test = required_input(inputs, family, "test")?;
            let log = document_or_stdin(document)?;
            format!(
                "{}\n",
                crate::probe_verdict::verdict(status, &log, test).token()
            )
        }
        "signing-posture" => {
            // NO INPUTS SINCE CLOUD-843. The task body that ran `git config` and
            // handed the two values over retired; the engine reads them through
            // gix itself, which is a read of this checkout rather than a spawn, so
            // house-style §5's reason for keeping the gathering outside is gone.
            // An input here is a caller still speaking the retired contract, and
            // it is refused rather than silently ignored.
            only_these_inputs(inputs, family, &[])?;
            let posture = crate::signer_posture::read(Path::new(".")).map_err(|_| {
                UsageError::raise(format!(
                    "record derive {family}: not a git repository, so the signer posture could \
                     not be read. Nothing recorded."
                ))
            })?;
            crate::signer_posture::record(&posture)
        }
        "transcript-corpus" => {
            only_these_inputs(inputs, family, &["root", "threshold", "exclude"])?;
            let root = required_input(inputs, family, "root")?;
            let raw = required_input(inputs, family, "threshold")?;
            let threshold: usize = raw.parse().map_err(|_| {
                UsageError::raise(format!(
                    "record derive {family}: threshold `{raw}` is not a whole number"
                ))
            })?;
            let root = Path::new(root);
            if !root.is_dir() {
                // THE QUESTION COULD NOT BE ASKED. Write NOTHING — an absent
                // record is "the producer did not run", which must never be
                // spelled the same way as a root that was walked and held no
                // transcripts.
                return Err(UsageError::raise(format!(
                    "record derive {family}: no transcript root to walk"
                )));
            }
            // ABSENT AND PRESENT-BUT-EMPTY ARE DIFFERENT CLAIMS, which is the
            // whole reason this is an `Option` rather than a defaulted string: a
            // caller naming no exclusion is saying nothing, and a caller naming
            // the empty string is saying "exclude nothing". `--input exclude=`
            // is the second, and omitting the flag is the first.
            let exclude = inputs.get("exclude").map(String::as_str);
            let sessions = crate::transcript::census(root, exclude);
            format!("sessions {sessions}\nthreshold {threshold}\n")
        }
        "evaluator-closure" => evaluator_closure_reading(inputs, family, overrides, document)?,
        "macos-link" => macos_link_reading(inputs, family, overrides, document)?,
        // The `tracker-hygiene` preset's five readings (CLOUD-843). The module
        // owns the reading; this arm hands it the consumer's pattern table, the
        // checkout it walks, and stdin — nothing here spawns.
        // CLOUD-843's retirement of `[tasks.released]`: the tag's range and the
        // composed board gate, read in process. A terminal on stdin is the
        // retired body's `[[ -t 0 ]]`: no payloads, so the tag's refs alone.
        crate::released::FAMILY => {
            let config = resolve::resolve(Path::new("."), overrides)?;
            let stdin = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                String::new()
            } else {
                verdict_lines()?
            };
            crate::released::reading(
                inputs,
                config.board.as_ref(),
                &config.patterns,
                Path::new("."),
                &stdin,
            )?
        }
        tracker if crate::tracker_reading::is_family(tracker) => {
            let config = resolve::resolve(Path::new("."), overrides)?;
            let stdin = verdict_lines()?;
            crate::tracker_reading::reading(
                tracker,
                inputs,
                &config.patterns,
                Path::new("."),
                &stdin,
            )?
        }
        // AN UNKNOWN FAMILY IS A USAGE ERROR, never a record written under a name
        // nothing reads. A producer whose family was renamed would otherwise go on
        // writing happily into a key no module has looked at since.
        _ => {
            return Err(UsageError::raise(format!(
                "record derive: no reading is declared for family `{family}`"
            )));
        }
    };
    Ok(derived)
}

/// The evaluator's own sub-closure, and which crates in it bear IO (CLOUD-831).
///
/// THE ROW IDS ARE THE PRODUCER'S, NOT THIS MODULE'S (non-negotiable rule 1).
/// `roots` and `bears` name `[[pattern]]` rows, and which rows a repository
/// declares is a consumer fact — a literal here would be this consumer's config
/// key compiled into the repo-agnostic core, which is the thing
/// [`declared_pattern`]'s own doc comment says must not happen. The caller names
/// them, exactly as `DERIVE_INPUT` describes: the keys a family accepts are that
/// family's own contract.
///
/// # Errors
///
/// A [`UsageError`] for a missing or unaccepted input, an undeclared
/// `[[pattern]]` row, or stdin that is not a `cargo metadata` document; an
/// internal error when a `resolve` the engine ran could not look.
fn evaluator_closure_reading(
    inputs: &BTreeMap<String, String>,
    family: &str,
    overrides: &Overrides,
    document: Option<&str>,
) -> Result<String> {
    only_these_inputs(inputs, family, &["roots", "bears", "resolve"])?;
    let config = resolve::resolve(Path::new("."), overrides)?;
    let evaluator = declared_pattern(
        &config.patterns,
        family,
        required_input(inputs, family, "roots")?,
    )?;
    let bears_io = declared_pattern(
        &config.patterns,
        family,
        required_input(inputs, family, "bears")?,
    )?;
    let graph = graph_for(inputs, family, document)?;

    // THE SCOPE IS THE EVALUATOR'S SUB-CLOSURE, NOT THE WORKSPACE'S, and
    // that was measured before it was written because the obvious
    // spelling is wrong: walking from the workspace members instead
    // reached 281 packages, including two direct dependencies of the
    // consumer itself entering by paths with nothing to do with the
    // evaluator. The wider spelling fired on all five lockfile-touching
    // commits reachable from HEAD and every firing was a false positive.
    let roots = graph.roots_matching(|name| evaluator.is_match(name));
    let reading = if roots.is_empty() {
        // NOT A PASS. The evaluator vanishing from the graph means the
        // question could not be asked, and reporting "nothing found"
        // there is the vacuous pass this repository names CLOUD-251.
        "absent\n".to_owned()
    } else {
        let reached = graph.reachable(roots);
        let mut lines = format!("closure {}\n", reached.len());
        let mut found: Vec<&str> = graph
            .named_in_order(&reached)
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| bears_io.is_match(name))
            .collect();
        found.dedup();
        for name in found {
            lines.push_str("crate ");
            lines.push_str(name);
            lines.push('\n');
        }
        lines
    };
    Ok(reading)
}

/// What this tree BUILDS, and which of it needs a platform SDK to link.
///
/// [`evaluator_closure_reading`]'s sibling, and the two differ only in their
/// ROOTS and in what they look for once there — which is the whole reason
/// [`crate::cargo_graph`] exists rather than a walk per caller. Its `framework`
/// and `vendored` row ids are the producer's for that function's reason.
///
/// # Errors
///
/// A [`UsageError`] for an unaccepted input, an undeclared `[[pattern]]` row, or
/// stdin that is not a `cargo metadata` document; an internal error when a
/// `resolve` the engine ran could not look.
fn macos_link_reading(
    inputs: &BTreeMap<String, String>,
    family: &str,
    overrides: &Overrides,
    document: Option<&str>,
) -> Result<String> {
    only_these_inputs(inputs, family, &["framework", "vendored", "resolve"])?;
    let config = resolve::resolve(Path::new("."), overrides)?;
    let framework = declared_pattern(
        &config.patterns,
        family,
        required_input(inputs, family, "framework")?,
    )?;
    let vendored = declared_pattern(
        &config.patterns,
        family,
        required_input(inputs, family, "vendored")?,
    )?;
    let graph = graph_for(inputs, family, document)?;

    // THE WALK STARTS AT THE WORKSPACE MEMBERS, because the question is
    // about everything this tree builds — unlike `evaluator-closure`,
    // whose question is about one package's sub-closure. That is the
    // only difference between the two callers of this graph.
    let built = graph.reachable(graph.member_roots());
    let mut lines = format!("scanned {}\n", built.len());
    for (name, id) in graph.named_in_order(&built) {
        match graph.links_of(id) {
            // RULE 1's PROXY, minus the crates it is wrong about. A crate
            // that VENDORS AND COMPILES the library it names reaches no
            // platform framework — measured, after this gate refused a
            // tree the linker then built with no SDK present. An UNKNOWN
            // `links` crate is still a finding, so this narrows the gate
            // rather than opening it.
            Some(library) if !vendored.is_match(name) => {
                lines.push_str("links ");
                lines.push_str(name);
                lines.push(' ');
                lines.push_str(library);
                lines.push('\n');
            }
            _ if framework.is_match(name) => {
                lines.push_str("framework ");
                lines.push_str(name);
                lines.push('\n');
            }
            _ => {}
        }
    }
    Ok(lines)
}

/// Write a derived reading into the policy-readable store for this branch.
///
/// # Errors
///
/// A [`UsageError`] for a tree that is not a repository or a detached HEAD with
/// no branch to key on; an internal error when the store cannot be written.
fn store_derived(family: &str, derived: &str) -> Result<()> {
    let root = Path::new(".");
    let git_dir = git::git_dir(root).map_err(|_| {
        UsageError::raise(
            "record derive: not a git repository, so there is nothing to key on".to_owned(),
        )
    })?;
    let Ok(branch) = git::record_key(root) else {
        return Err(UsageError::raise(
            "record derive: HEAD resolves to no commit, so there is nothing to key the record on"
                .to_owned(),
        ));
    };
    let claim = claim_of(&git_dir, &branch);
    store(
        &crate::recorder::record_path(&git_dir, family, &branch, claim.as_deref()),
        derived,
    )
}

/// Emit the derived reading on the data channel.
///
/// # Errors
///
/// An internal error when the output channel cannot be written.
fn emit_derived(derived: &str, out: &mut dyn std::io::Write) -> Result<ExitCode> {
    // THE DERIVED RECORD GOES TO STDOUT TOO, and it stays pointer-only doing it:
    // what is emitted is the READING — a bounded set of tokens this verb
    // computed — never a byte of the input it read. That distinction is why
    // `record named` prints nothing and this does: `named` cannot tell a verdict
    // from a payload, because it never looked at one.
    //
    // It matters beyond symmetry. A producer task composes: a caller that
    // branches on the reading it just derived reads it here, and a verb that
    // swallowed its own answer would force the caller to read the record store
    // back — a second reader of a path `recorder::record_path` is the one
    // authority on.
    out.write_all(derived.as_bytes())?;
    Ok(ExitCode::Success)
}

/// Record one named family under this branch, read from stdin.
///
/// **The POLICY-readable store, which is a different store from the two below.**
/// `record keyed`/`record journal` write task stores that `record show`/`record
/// fold` read back; this writes through [`crate::recorder::record_path`], which
/// is the store [`crate::facts::Fact::Records`] projects onto
/// `input.tree.records.<family>`. A module reads what this writes; nothing reads
/// what those write except the task that wrote it. Keeping them apart is why
/// this is a third verb rather than a flag on one of them: the two stores have
/// different keys, different readers and different lifetimes.
///
/// **One verb, not one per measurement** (CLOUD-1717). Nine programs in that wave
/// are measurements rather than gates — the `gh` call stays outside per
/// house-style §5 and only the adjudication moves in — so each needs a producer
/// that writes a record a module can read. Nine bespoke verbs would be nine
/// spellings of `run_plan` with the validation removed, which is the duplication
/// the retirement campaign exists to delete rather than to relocate.
///
/// **NO VALIDATION OF THE LINES, deliberately.** [`run_plan`] refuses an unknown
/// status because a plan entry has a closed vocabulary this binary owns. A
/// measurement's shape is the module's business, and a second reading here would
/// be the two-authorities-over-one-fact defect: the module already has to decide
/// what a malformed line means, and a writer that pre-judged it would make the
/// module's own arm unreachable.
///
/// # Errors
///
/// A [`UsageError`] when the family is not a single path component, when the
/// repository has no branch to key on, or when this is not a git repository; an
/// internal error when the store cannot be written.
pub fn run_named(family: &str) -> Result<ExitCode> {
    let family = safe_component("family", family)?;
    let raw = verdict_lines()?;
    store_named("record named", &family, &raw)?;
    Ok(ExitCode::Success)
}

/// The path one named family's record lives at for this branch.
///
/// **The one composition of that path for every verb that writes the policy
/// store** (CLOUD-843). `record named` read its body from stdin and composed the
/// path inline; `record query` computes its body in process, and a second inline
/// composition would be a second spelling of the key the projection reads — the
/// drift CLOUD-1300's claim partition exists to close.
///
/// # Errors
///
/// A [`UsageError`] naming `verb` when this is not a git repository or HEAD
/// resolves to no commit, so there is nothing to key on.
fn named_path(verb: &str, family: &str) -> Result<PathBuf> {
    let root = Path::new(".");
    let git_dir = git::git_dir(root).map_err(|_| {
        UsageError::raise(format!(
            "{verb}: not a git repository, so there is nothing to key on"
        ))
    })?;
    let Ok(branch) = git::record_key(root) else {
        return Err(UsageError::raise(format!(
            "{verb}: HEAD resolves to no commit, so there is nothing to key the record on"
        )));
    };
    let claim = claim_of(&git_dir, &branch);
    Ok(crate::recorder::record_path(
        &git_dir,
        family,
        &branch,
        claim.as_deref(),
    ))
}

/// Write one named family's record for this branch, whole.
///
/// `family` must already be a single path component; the callers hold it to
/// [`safe_component`] first, which is where a bad name is a usage error.
///
/// # Errors
///
/// As [`named_path`], and an internal error when the store cannot be written.
pub(crate) fn store_named(verb: &str, family: &str, body: &str) -> Result<()> {
    store(&named_path(verb, family)?, body)
}

/// Read one named family's record for this branch back, or `None` where none
/// was written (CLOUD-843).
///
/// **The same path [`store_named`] writes**, so a producer that fans out over an
/// earlier producer's rows reads exactly what the projection hands a module —
/// never a second composition of the key.
///
/// # Errors
///
/// As [`named_path`], and an internal error when a record exists and will not
/// read — which is not the same answer as one that is absent.
pub(crate) fn load_named(verb: &str, family: &str) -> Result<Option<String>> {
    let path = named_path(verb, family)?;
    match std::fs::read_to_string(&path) {
        Ok(body) => Ok(Some(body)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read the record {}", path.display())),
    }
}

/// Remove one named family's record for this branch, where one exists.
///
/// **For a producer that could not look** (CLOUD-843). An absent record is how
/// could-not-look reads on the policy surface, and a producer that failed while
/// a previous run's record still sat in the store would leave that record
/// answering as the current reading — a module cannot tell a stale window from
/// a fresh one, because the clock is not on its surface. Removing it makes the
/// absence true. A record that was never there is already absent, so that is not
/// an error.
///
/// # Errors
///
/// As [`named_path`], and an internal error when an existing record cannot be
/// removed.
pub(crate) fn clear_named(verb: &str, family: &str) -> Result<()> {
    let path = named_path(verb, family)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove the stale record {}", path.display()))
        }
    }
}

/// The record path for one (family, key) pair.
///
/// Keyed by a digest of the key rather than by the key itself, on
/// [`crate::review::record_path`]'s reason one store over: the key is a caller's
/// string and may be any length or hold any byte, and a digest is a filename on
/// every platform. The key is not recoverable from the path, which is the
/// pointer-only posture rule 4 asks for anyway.
fn keyed_path(git_dir: &Path, family: &str, key: &str) -> PathBuf {
    git_dir
        .join(KEYED_STORE)
        .join(family)
        .join(crate::tools::digest(key.as_bytes()))
}

/// One keyed record's value, or `None` where it is absent or unreadable.
///
/// **The in-process door onto the store `record keyed`/`record show` spell on
/// argv** (CLOUD-843). `batten step` keys its receipts here, and composing the
/// path a second time beside [`keyed_path`] would be a second spelling of the key
/// the two verbs share. `family` must already be a single path component.
pub(crate) fn keyed_read(git_dir: &Path, family: &str, key: &str) -> Option<String> {
    std::fs::read_to_string(keyed_path(git_dir, family, key)).ok()
}

/// Write one keyed record's value whole, through the same store as
/// [`run_keyed`]. `family` must already be a single path component.
///
/// # Errors
///
/// An internal error when the store cannot be written.
pub(crate) fn keyed_write(git_dir: &Path, family: &str, key: &str, value: &str) -> Result<()> {
    store(&keyed_path(git_dir, family, key), value)
}

/// Put one value into the keyed family, read from stdin.
///
/// # Errors
///
/// A [`UsageError`] when the family or key is not a single path component; an
/// internal error when the store cannot be written.
pub fn run_keyed(family: &str, key: &str) -> Result<ExitCode> {
    let family = safe_component("family", family)?;
    let value = verdict_lines()?;
    let git_dir = git::git_dir(Path::new("."))?;
    store(&keyed_path(&git_dir, &family, key), &value)?;
    Ok(ExitCode::Success)
}

/// Append one record to the journal family, read from stdin.
///
/// **Reuses [`crate::journal::append_line`] rather than opening a file here**,
/// which is CLOUD-1713's §2 in one call: the durability barrier, the one-writer
/// shard rule and the persist-before-emit order all live in that function, and a
/// second append path beside it is precisely the defect this row removes.
///
/// The shard is per worktree, via [`crate::journal::shard_id`] — `reclaim-census`
/// keyed its single shard by boot id instead, which is a caller's choice of key
/// rather than a different mechanism.
///
/// # Errors
///
/// A [`UsageError`] when the family is not a single path component or the record
/// is blank — an empty append is a caller with nothing to say, and recording it
/// would put a record in the log that no fold can distinguish from a torn one.
/// An internal error when the shard cannot be written or synced.
pub fn run_journal(family: &str) -> Result<ExitCode> {
    let family = safe_component("family", family)?;
    let record = verdict_lines()?;
    let record = record.trim();
    if record.is_empty() {
        return Err(UsageError::raise(String::from(
            "the record is empty; an empty append is not a record",
        )));
    }
    if record.contains('\n') {
        return Err(UsageError::raise(String::from(
            "a record is one line; a multi-line append would fold back as several records",
        )));
    }
    let git_dir = git::git_dir(Path::new("."))?;
    let store_dir = journal_store(&git_dir, &family);
    let shard = crate::journal::shard_id(Path::new("."));
    crate::journal::append_line(&store_dir, &shard, record)?;
    Ok(ExitCode::Success)
}

/// Read one keyed record back: `hit` and the value, or `miss`.
///
/// **A miss is exit 0 and the discrimination comes off STDOUT**, which is
/// `checks-green`'s shape and is deliberate. The engine's contract makes exit 2 a
/// VIOLATION, and a cache miss is not a violation — it is the ordinary answer that
/// says *run the step*. A caller reading only the code holds either way; the one
/// caller that needs the difference reads the line.
///
/// # Errors
///
/// A [`UsageError`] when the family or key is not a single path component; an
/// internal error when the git directory cannot be resolved.
pub fn run_keyed_show(family: &str, key: &str, out: &mut dyn std::io::Write) -> Result<ExitCode> {
    let family = safe_component("family", family)?;
    let git_dir = git::git_dir(Path::new("."))?;
    match std::fs::read_to_string(keyed_path(&git_dir, &family, key)) {
        Ok(value) => {
            writeln!(out, "hit")?;
            write!(out, "{value}")?;
        }
        // ABSENT IS A MISS, and it is the only reading here: a record that exists
        // and holds nothing is a hit carrying an empty value, because the producer
        // chose to record that.
        Err(_) => writeln!(out, "miss")?,
    }
    Ok(ExitCode::Success)
}

/// Fold a journal family: `nothing`, the records, or `unreadable <path>`.
///
/// # Errors
///
/// A [`UsageError`] when the family is not a single path component; an internal
/// error when the git directory cannot be resolved.
pub fn run_journal_show(family: &str, out: &mut dyn std::io::Write) -> Result<ExitCode> {
    let family = safe_component("family", family)?;
    let git_dir = git::git_dir(Path::new("."))?;
    let store_dir = journal_store(&git_dir, &family);
    match crate::journal::fold_lines(&store_dir) {
        crate::journal::Fold::Nothing => writeln!(out, "nothing")?,
        crate::journal::Fold::Records(records) => {
            for record in records {
                writeln!(out, "{record}")?;
            }
        }
        // A PATH IS A POINTER (§6 names `path:line` outright), so naming the
        // store a reader could not open is rule 4 satisfied rather than breached.
        crate::journal::Fold::Unreadable(path) => writeln!(out, "unreadable {}", path.display())?,
    }
    Ok(ExitCode::Success)
}
