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

use std::collections::BTreeMap;
use std::io::Read as _;
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
pub fn run(
    command: crate::cli::RecordCommand,
    overrides: &Overrides,
    out: &mut dyn std::io::Write,
) -> Result<ExitCode> {
    match command {
        crate::cli::RecordCommand::Tool { id } => run_tool(&id, overrides),
        crate::cli::RecordCommand::Forge { reference } => run_forge(&reference, overrides),
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
pub fn validate(declared: &[Declared]) -> Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for family in declared {
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

/// A family name that cannot escape its store.
///
/// **A path component, checked rather than trusted.** The family and the key both
/// reach this from a caller's argv, and a `..` or a `/` in either would put a
/// record outside the store the reader looks in — which is not a security
/// boundary here so much as a silent miss: the write succeeds, the read finds
/// nothing, and the gate reads clean.
fn safe_component(what: &str, value: &str) -> Result<String> {
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

/// The non-document inputs a family was handed, as a key/value map.
///
/// # Errors
///
/// A [`UsageError`] for a token carrying no `=`, for an empty key, and for a
/// key given twice — a repeated key is a caller who believes both values are in
/// effect, and silently keeping one would run the reading on an input nobody
/// asked for.
fn derive_inputs(inputs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    for token in inputs {
        let Some((key, value)) = token.split_once('=') else {
            return Err(UsageError::raise(format!(
                "record derive: `--input {token}` is not `<key>=<value>`"
            )));
        };
        if key.is_empty() {
            return Err(UsageError::raise(
                "record derive: an input with no key names nothing".to_owned(),
            ));
        }
        if parsed.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(UsageError::raise(format!(
                "record derive: input `{key}` was given twice"
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
fn graph_on_stdin(family: &str) -> Result<crate::cargo_graph::Graph> {
    let raw = verdict_lines()?;
    let meta: serde_json::Value = serde_json::from_str(&raw).map_err(|_| {
        UsageError::raise(format!(
            "record derive {family}: stdin is not a `cargo metadata` document"
        ))
    })?;
    Ok(crate::cargo_graph::Graph::from_metadata(&meta))
}

/// Derive one family's record from its input and write it.
///
/// The engine applies the READING; the effects that produced the input stay in
/// the producer task (house-style §5), so nothing here spawns.
///
/// # Errors
///
/// A [`UsageError`] for an unknown family, a malformed or missing input, a
/// family that is not a single path component, a repository with no branch to
/// key on, or a tree that is not a repository; an internal error when the store
/// cannot be written.
pub fn run_derive(
    family: &str,
    inputs: &[String],
    overrides: &Overrides,
    out: &mut dyn std::io::Write,
) -> Result<ExitCode> {
    let inputs = derive_inputs(inputs)?;
    let derived = derive_reading(family, &inputs, overrides)?;
    let family = safe_component("family", family)?;
    store_derived(&family, &derived)?;
    emit_derived(&derived, out)
}

/// The READING for one family, from its declared inputs and whatever is on stdin.
///
/// Split out of [`run_derive`] because the two halves grow at different rates:
/// this one gains an arm per producer, and the store-and-emit tail below it is
/// fixed. Nothing here spawns — house-style §5 keeps a producer's effects in the
/// task, and what arrives is already a reading's worth of input.
///
/// # Errors
///
/// A [`UsageError`] for an unknown family, or a malformed, missing or
/// unaccepted input.
fn derive_reading(
    family: &str,
    inputs: &BTreeMap<String, String>,
    overrides: &Overrides,
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
            let log = verdict_lines()?;
            format!(
                "{}\n",
                crate::probe_verdict::verdict(status, &log, test).token()
            )
        }
        "signing-posture" => {
            only_these_inputs(
                inputs,
                family,
                &["signingkey", "ssh-program", "gpgsign", "signed"],
            )?;
            let signingkey = required_input(inputs, family, "signingkey")?;
            let program = required_input(inputs, family, "ssh-program")?;
            // THE TWO ABSENT-MEANS-NOTHING INPUTS. A producer that found no
            // conflict and no signed commit still sends both, empty; treating an
            // omitted input as "no" here would make "the producer did not look"
            // and "the producer looked and found none" the same record.
            let conflict = required_input(inputs, family, "gpgsign")? == "conflict";
            let signed = required_input(inputs, family, "signed")?;
            crate::signer_posture::record(signingkey, program, conflict, signed)
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
        "evaluator-closure" => evaluator_closure_reading(inputs, family, overrides)?,
        "macos-link" => macos_link_reading(inputs, family, overrides)?,
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
/// # Errors
///
/// A [`UsageError`] for an unaccepted input, an undeclared `[[pattern]]` row, or
/// stdin that is not a `cargo metadata` document.
fn evaluator_closure_reading(
    inputs: &BTreeMap<String, String>,
    family: &str,
    overrides: &Overrides,
) -> Result<String> {
    only_these_inputs(inputs, family, &[])?;
    let config = resolve::resolve(Path::new("."), overrides)?;
    let evaluator = declared_pattern(&config.patterns, family, "evaluator-package")?;
    let bears_io = declared_pattern(&config.patterns, family, "evaluator-io-crate")?;
    let graph = graph_on_stdin(family)?;

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
/// [`crate::cargo_graph`] exists rather than a walk per caller.
///
/// # Errors
///
/// A [`UsageError`] for an unaccepted input, an undeclared `[[pattern]]` row, or
/// stdin that is not a `cargo metadata` document.
fn macos_link_reading(
    inputs: &BTreeMap<String, String>,
    family: &str,
    overrides: &Overrides,
) -> Result<String> {
    only_these_inputs(inputs, family, &[])?;
    let config = resolve::resolve(Path::new("."), overrides)?;
    let framework = declared_pattern(&config.patterns, family, "sdk-framework-crate")?;
    let vendored = declared_pattern(&config.patterns, family, "vendored-links-crate")?;
    let graph = graph_on_stdin(family)?;

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
    let Ok(Some(branch)) = git::current_branch(root) else {
        return Err(UsageError::raise(
            "record derive: a detached HEAD has no branch to key the record on".to_owned(),
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
    // It matters beyond symmetry. A producer task composes: `evaluator-io-record`
    // branches on `probe failed` to mint its step receipt, and a verb that
    // swallowed its own answer would force the task to read the record store back
    // — a second reader of a path `recorder::record_path` is the one authority on.
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
    let root = Path::new(".");
    let git_dir = git::git_dir(root).map_err(|_| {
        UsageError::raise(
            "record named: not a git repository, so there is nothing to key on".to_owned(),
        )
    })?;
    let Ok(Some(branch)) = git::current_branch(root) else {
        return Err(UsageError::raise(
            "record named: a detached HEAD has no branch to key the record on".to_owned(),
        ));
    };
    let claim = claim_of(&git_dir, &branch);
    store(
        &crate::recorder::record_path(&git_dir, &family, &branch, claim.as_deref()),
        &raw,
    )?;
    Ok(ExitCode::Success)
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
    let store_dir = git_dir.join(JOURNAL_STORE).join(&family);
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
    let store_dir = git_dir.join(JOURNAL_STORE).join(&family);
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
