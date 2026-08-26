//! Batten is a repo-agnostic policy engine.
//!
//! It gates what gets written, proves what was verified, and refuses to let
//! unlanded work appear finished — enforcing one repository's policy consistently
//! at the pre-commit layer, in CI, and at an agent's tool call.
//!
//! This crate exposes the library surface ([`run`]) that the `batten` binary is a
//! thin wrapper around. Keeping the logic in the library keeps it testable and
//! keeps the binary's `main` trivial.

pub mod action;
pub mod admission;
pub mod attribution;
pub mod baseline;
pub mod brief;
pub mod budget;
pub mod bypass;
pub mod capture;
pub mod ci;
pub mod cli;
pub mod commit;
pub mod completion;
pub mod config;
pub mod contract;
pub mod decision;
pub mod defects;
pub mod design;
pub mod doctor;
pub mod drain;
pub mod effect;
pub mod emission;
pub mod epoch;
pub mod error;
pub mod exec;
pub mod exit;
pub mod facts;
pub mod findings;
pub mod git;
pub mod handler;
pub mod hook;
pub mod identity;
pub mod init;
/// Rust call sites, parsed — where a token sits, not merely that it appears.
pub mod invocation;
pub mod journal;
pub mod judge;
pub mod lint;
pub mod markers;
pub mod mint;
pub mod output;
pub mod outputs;
/// The in-process patch identity: what a change IS, independent of the commit
/// carrying it and of the host's git configuration.
mod patch;
pub mod pattern;
pub mod policy;
pub mod provision;
pub mod receipt;
pub mod recorder;
pub mod redirect;
pub mod refusal;
pub mod render;
pub mod resolve;
pub mod rules;
pub mod secrets;
pub mod selfwrite;
pub mod session;
pub mod severity;
pub mod sink;
pub mod spec;
/// Resolved-symbol facts, from a delegated analyser's structured output
/// (CLOUD-760). The first occupant of `Cost::Effect`: resolving it runs a
/// program, which is the classification rather than an accident of it.
pub mod symbols;

pub mod state;
pub mod stop;
pub mod store;
pub mod surface;
pub mod transcript;
pub mod trust;
/// The `use` graph: which module reaches which, resolved through the root's own
/// re-export table.
pub mod uses;
pub mod verbs;
pub mod verdict;
pub mod waiver;
pub mod worktree;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

pub use cli::{
    AttributionCommand, Cli, Command, CommitCommand, ConfigCommand, DefectsCommand, DesignCommand,
    GenerateCommand, LintCommand, OverrideCommand, PolicyCommand, ProvisionCommand, ReceiptCommand,
    SpecFormat, StateCommand, WorktreeCommand,
};
pub use config::Config;
pub use effect::Effect;
pub use error::{Denial, Passthrough, UsageError};
pub use exit::ExitCode;
pub use output::{Mode, Presentation, Verbosity};
pub use refusal::{Fix, Refusal};
pub use resolve::{Overrides, Resolved, Source};
pub use severity::{AdvisoryTier, Mapping, ReportLevel, RuleSeverity};

/// Execute a parsed [`Cli`], writing any data output to `out`, and return the
/// [`ExitCode`] to hand back to the OS.
///
/// Data output goes to `out` (the binary passes stdout) rather than through a
/// `print!`, so the library stays byte-stable and testable and the
/// stdout-is-the-answer split of the output contract is honoured.
///
/// `err` is the **other** channel, and the split is the whole point: nothing a
/// verb writes there can reach the data channel, so a ladder-gated message
/// (CLOUD-42) is structurally incapable of corrupting a `-J` document. `mode`
/// carries the resolved rung, so what gets written there is a decision the
/// binary already made rather than one each verb re-derives.
///
/// # Errors
///
/// Returns an error when a command cannot complete because of an underlying
/// failure (I/O, a missing external tool, or an internal invariant violation).
/// Such errors map to [`ExitCode::Internal`] at the boundary; a *policy
/// violation*, by contrast, is a normal return of [`ExitCode::Violation`].
pub fn run(cli: Cli, mode: Mode, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let Cli {
        strictness,
        fail_on_warning,
        config_from,
        command,
    } = cli;
    // The flag layer of the §8 precedence chain; every config read in this run
    // resolves through it, so a flag can never apply to one verb and not another.
    let overrides = Overrides {
        strictness,
        fail_on_warning,
        config_from,
    };
    match command {
        // Unreachable in practice: `arg_required_else_help` has clap offer the
        // subcommand listing (a usage error, exit 1) before parse returns. Kept
        // total — the workspace lints forbid panicking on a reachable path.
        None => Ok(ExitCode::Success),
        Some(Command::Check { json, rule }) => run_rules(
            out,
            err,
            mode,
            &overrides,
            rules::run_static_over,
            RunRequest::read_only(json, rule.as_deref()),
        ),
        Some(Command::Enforce { json }) => run_rules(
            out,
            err,
            mode,
            &overrides,
            rules::run_all_over,
            RunRequest::spawning(json),
        ),
        Some(Command::Config { command }) => run_config(&command, &overrides, out),
        Some(Command::Spec { format }) => run_spec(format, out),
        Some(Command::Doctor { command }) => run_doctor(&command, out),
        // `init` reads no config — it is the verb that exists because there is
        // none — so the §8 chain is deliberately not threaded through it.
        Some(Command::Init { dry_run }) => run_init(dry_run, mode, out, err),
        // `baseline` reads config — it evaluates the same rules `check` does, and
        // its minting predicate consults `must_land_on` — so the §8 chain is
        // threaded through it like any other rule-running verb.
        Some(Command::Baseline { prune, dry_run }) => {
            run_baseline(prune, dry_run, mode, &overrides, out, err)
        }
        Some(Command::Generate { command }) => run_generate(&command, out),
        // `exec` reads no config and renders no verdict: it runs what the caller
        // named and reports what that returned. The §8 chain is deliberately not
        // threaded through it — there is nothing here for policy to decide.
        // `exec` resolves config for exactly one reason — the output predicates
        // (CLOUD-117) — and renders no verdict of its own beyond them. An
        // unreadable authority is still a usage error here: a pattern table nobody
        // could read is a gate that silently did not run.
        Some(Command::Exec(request)) => run_exec(&request, &overrides, err),
        Some(Command::Capture { command }) => run_capture(&command, mode, out, err),
        Some(Command::Hook { harness }) => run_hook(harness, mode, &overrides, out, err),
        // CLOUD-479. Touches NO config — this is the per-turn hot path, and the
        // whole point is that it costs less than the `jq` process it replaces.
        // `run_hook` loads policy only past its cheap refusals for the same
        // reason; this has no policy to load at all.
        Some(Command::HookField { harness, field }) => run_hook_field(harness, field, out),
        // The receipt verbs read their own git facts; the §8 config chain does
        // not apply — a receipt records policy (as a digest), it never resolves it.
        Some(Command::Receipt { command }) => match command {
            ReceiptCommand::Record { check } => receipt::run_record(&check, mode, err),
            ReceiptCommand::Status { check, key, json } => {
                receipt::run_status(&check, key, json, out)
            }
        },
        Some(Command::Policy { command }) => run_policy(command, &overrides, out),
        // `lint <kind>` reads text the caller names and answers about its shape.
        // The §8 config chain is deliberately not threaded through it: the schema
        // is engine structure, not repo policy, so there is no key for a config to
        // layer and nothing a `batten.local.toml` could weaken.
        Some(Command::Lint { command }) => match command {
            LintCommand::Brief { path, json } => run_lint_brief(path.as_deref(), json, out),
        },
        // Commit metadata is neither tree content nor a mediated call, so the §8
        // config chain supplies the patterns and git supplies the object. The
        // range is the caller's: `verify` and CI already agree on which commits a
        // branch produced, and deriving it again here would be a second authority
        // for that fact.
        Some(Command::Attribution { command }) => run_attribution(command, &overrides, out, err),
        // Same object as `attribution`, different question: the subject's shape
        // rather than the metadata's provenance (CLOUD-701).
        Some(Command::Commit { command }) => match command {
            CommitCommand::Check {
                json,
                range,
                message,
            } => run_commit_check(json, range.as_deref(), message.as_deref(), &overrides, out),
        },
        Some(Command::Worktree { command }) => match command {
            WorktreeCommand::Status { json } => run_worktree_status(json, &overrides, out),
        },
        Some(Command::Override { command }) => run_override(command, &overrides, out, err),
        // The ledger is a committed file the consumer declares; the §8 config
        // chain supplies its path and taxonomy and nothing else layers.
        Some(Command::Defects { command }) => match command {
            DefectsCommand::Query {
                json,
                class,
                id,
                ungated,
            } => run_defects_query(
                json,
                class.as_deref(),
                id.as_deref(),
                ungated,
                &overrides,
                out,
            ),
            DefectsCommand::Add { dry_run } => run_defects_add(dry_run, mode, &overrides, err),
        },
        // The corpus is stdin's and nothing else (CLOUD-324); the §8 chain
        // supplies one ceiling and no second source of records.
        Some(Command::Design { command }) => match command {
            DesignCommand::Audit { json } => run_design_audit(json, &overrides, out),
        },
        Some(Command::Provision { command }) => match command {
            ProvisionCommand::Status { json } => run_provision_status(json, &overrides, out),
            ProvisionCommand::Apply { dry_run } => run_provision_apply(dry_run, &overrides, err),
        },
        // The store resolves itself from git facts and the OS state dir; the §8
        // config chain does not apply, because which store a checkout owns is
        // not a policy question and no `batten.toml` may answer it.
        Some(Command::State { command }) => match command {
            StateCommand::Adopt { store } => store::run_adopt(store.as_deref(), err),
            StateCommand::Record => run_state_record(&overrides, mode, err),
            StateCommand::Migrate => run_state_migrate(err),
            StateCommand::List { json } => run_state_list(json, mode, out, err),
        },
    }
}

/// Audit a design-evidence claim stream read on stdin (CLOUD-53).
///
/// The whole input is stdin: no config path, no filesystem walk, no second
/// source and therefore no precedence question (CLOUD-324). Config supplies
/// exactly one value — the per-capture ceiling — so this verb resolves the §8
/// chain for a number and reads its records from nowhere else.
///
/// The two channels answer differently on a clean corpus, and both are the
/// contract: plain prints **nothing** (§6, and the acceptance's own wording),
/// while `-J` emits its document unconditionally, because JSON that is sometimes
/// absent is unparseable.
fn run_design_audit(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    // `[design]` is authority-only, so there is no local layer to clamp against
    // today; the tighten-only call is the semantics, stated where it applies.
    let cap = design::effective_cap(
        config.design.and_then(|design| design.max_capture_bytes),
        None,
    );

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    // A malformed corpus is exit 1, never 2: the policy verdict is reserved for
    // a claim about the evidence, and "this is not the format" is a claim about
    // the invocation.
    let claims = design::parse(&raw)?;
    let problems = design::audit(&claims, cap);

    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&design::Report::new(&problems))?
        )?;
    } else {
        for problem in &problems {
            writeln!(out, "{}", problem.line_text())?;
        }
    }

    let findings: Vec<rules::Finding> = problems.iter().map(design::Problem::finding).collect();
    Ok(ExitCode::verdict(design::blocks(
        &findings,
        config.strictness,
        config.fail_on_warning,
    )))
}

/// Report which provisioned tools do not match the manifest (CLOUD-90).
///
/// A manifest with **no entries is not an error**, unlike `policy budget`'s
/// absent budget: zero entries is a complete and honest answer — this repository
/// provisions nothing — where a budget verb with no budget would be claiming to
/// have measured something it did not. The two absences are different claims.
fn run_provision_status(
    json: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let repo = git::repo_root(Path::new("."))?;
    let report = provision::status(&config.provisions, &provision::cache_root(&repo)?)?;

    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // Only the stale entries: a fresh one is not news, and an all-fresh run
        // prints nothing at all.
        for line in report.stale_lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::verdict(report.any_stale()))
}

/// Fetch, verify, and install every stale manifest entry (CLOUD-90).
///
/// Reports through `err`, never `out`: this verb writes to the cache and has no
/// document to emit, so its progress belongs on the messaging channel. That also
/// keeps the one thing it could print — what it installed — off a stream a
/// caller might be parsing.
fn run_provision_apply(
    dry_run: bool,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let repo = git::repo_root(Path::new("."))?;
    let cache = provision::cache_root(&repo)?;

    for entry in &config.provisions {
        // A checksum mismatch propagates as a `Denial` (exit 2) from here, so
        // the loop stops at the first bad artifact rather than going on to
        // install the rest under a verdict that already failed.
        let applied = provision::apply(entry, &cache, dry_run)?;
        let verb = match applied {
            provision::Applied::Installed => "installed",
            provision::Applied::AlreadyFresh => continue,
            provision::Applied::Previewed => "would install",
        };
        // Pointer-only: the entry and its pinned version, never a URL response
        // and never a byte of the artifact.
        writeln!(err, "provision: {verb} {} {}", entry.name, entry.version)?;
    }
    Ok(ExitCode::Success)
}

/// Scaffold the committed authority (CLOUD-206).
///
/// The channel split is §6's: **stdout carries the pointer** — the one path this
/// invocation is about — and stderr carries the messaging. The refusal is the
/// exception, and deliberately so: §7 defines exit `2` as a verdict whose reason
/// travels on stderr, so an already-present config prints nothing on stdout and
/// the reason unprefixed on stderr. A caller reading only stdout therefore sees a
/// path exactly when a path is what it got.
///
/// The `-n` preview is **not** ladder-gated, following `defects add`: a silenced
/// preview is a `--dry-run` that did nothing. The success line is, because a
/// caller that asked for `-q` after a write it requested wants the pointer and
/// not the prose.
fn run_init(
    dry_run: bool,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match init::apply(Path::new("."), dry_run)? {
        init::Outcome::Created => {
            writeln!(out, "{}", config::CONFIG_FILE)?;
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("wrote {}; run `batten check` next", config::CONFIG_FILE),
            )?;
            Ok(ExitCode::Success)
        }
        init::Outcome::WouldCreate => {
            writeln!(out, "{}", config::CONFIG_FILE)?;
            writeln!(err, "init: would write {}", config::CONFIG_FILE)?;
            Ok(ExitCode::Success)
        }
        // Unprefixed and ungated: this is the verdict, not a message about one.
        // Built through `Refusal` rather than a `format!` of its own — this is a
        // deny site, and CLOUD-122's contract is that every deny points to a fix
        // structurally rather than because its author remembered to name one.
        init::Outcome::Exists => {
            let refusal = Refusal::declared(
                init::CONFIG_EXISTS,
                verdict::Native::InitWouldOverwrite,
                &[verdict::Subject::Path {
                    path: config::CONFIG_FILE.to_owned(),
                }],
                Fix::Run(format!(
                    "edit {file} in place, or move it aside and run `batten init` again",
                    file = config::CONFIG_FILE
                )),
            );
            output::verdict(err, &refusal.render())?;
            Ok(ExitCode::Violation)
        }
    }
}

/// Record the findings that already exist, so only new ones fail (CLOUD-67).
///
/// Two modes over one artifact. Without `--prune` this **mints**: it runs the
/// same rules `check` runs and records their identities, behind
/// [`baseline::mintable`] — only landed, committed state may be baselined, which
/// is the whole thing that keeps a bulk suppression inside the threat model.
/// With `--prune` it **subtracts**: entries nothing backs are dropped and reduced
/// anchors ratchet down, which needs no mint gate because it can only ever
/// suppress less.
///
/// `rules::run_static` deliberately, not `run_all`: the predicate this baseline
/// serves is `batten check`'s, so it must cover exactly that surface — and it
/// keeps a `write` verb from reaching user-supplied code on the way.
///
/// Output is pointer-only (rule 4): a count and `rule <digest>` pointers, never a
/// baselined line.
///
/// # Errors
///
/// Propagates config resolution, the rule scan, and the store write. Raises a
/// [`UsageError`] (exit `1`) when no findings store is bound to this checkout.
fn run_baseline(
    prune: bool,
    dry_run: bool,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = anchor();
    let config = resolve::resolve(&root, overrides)?;
    let scan = rules::run_static(
        &config.rules,
        &config.provisions,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        &root,
    )?;

    if prune {
        let Some(existing) = baseline::load(&root)? else {
            output::verdict(
                err,
                "baseline --prune: no baseline is recorded for this checkout",
            )?;
            return Ok(ExitCode::Violation);
        };
        let (pruned, drifted) = baseline::prune(&existing, &scan);
        let dropped = existing.entries.len() - pruned.entries.len();
        for item in &drifted {
            writeln!(out, "{}", item.entry.pointer())?;
        }
        if dry_run {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("baseline: would drop {dropped} entr{}", plural(dropped)),
            )?;
            return Ok(ExitCode::Success);
        }
        let file = baseline::save(&root, &pruned)?;
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "baseline: dropped {dropped} entr{}, {} remain ({})",
                plural(dropped),
                pruned.entries.len(),
                file.display()
            ),
        )?;
        return Ok(ExitCode::Success);
    }

    // The minting gate. A refusal is the verdict, not an error: exit 2, on the
    // one table, unprefixed — a host reads that as a policy answer rather than
    // as Batten falling over (§7).
    if let Some(refusal) = baseline::mintable(&root, config.must_land_on.as_deref())? {
        for line in refusal.lines() {
            output::verdict(err, &line)?;
        }
        return Ok(ExitCode::Violation);
    }

    let target = worktree::land_target(&root, config.must_land_on.as_deref())?;
    let sha = match target.as_deref() {
        Some(reference) => git::resolve_ref(&root, reference)?,
        None => None,
    };
    let commit = git::head_commit(&root)?;
    let minted = baseline::mint(&scan, target, sha, commit, waiver::today()?);

    for entry in &minted.entries {
        writeln!(out, "{}", entry.pointer())?;
    }
    let count = minted.entries.len();
    if dry_run {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("baseline: would record {count} identit{}", plural(count)),
        )?;
        return Ok(ExitCode::Success);
    }
    let file = baseline::save(&root, &minted)?;
    // The audit line every mint owes, unconditional at `Normal` for the same
    // reason a waiver's is: a suppression this size must not be a detail a
    // default run has to ask for. Pointer-only — a ref, a sha and a count.
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!(
            "baseline: recorded {count} identit{} against {} {} ({})",
            plural(count),
            minted.minted.reference.as_deref().unwrap_or("-"),
            minted
                .minted
                .sha
                .as_deref()
                .map_or("-", |sha| &sha[..12.min(sha.len())]),
            file.display()
        ),
    )?;
    Ok(ExitCode::Success)
}

/// The `y`/`ies` suffix for `entr…` and `identit…`, which share one.
const fn plural(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

/// Report work that is uncommitted, unpushed, or not landed (CLOUD-51).
///
/// An absent `must_land_on` **falls back to the remote's recorded default
/// branch**, and where no target resolves at all the verb still reports every
/// other fact, with the unlanded component rendered `not-computable`.
///
/// This was a usage error until CLOUD-51's `DoD` audit: refusing the whole
/// invocation looked like the safe reading and is the opposite of one. A repo
/// with no `must_land_on` got *nothing* — not the dirty tree, not the branch
/// tracking nothing — so the one configuration most likely to be a fresh,
/// at-risk checkout was also the one the gate stayed silent about. Not-computable
/// must never read as clean, and it must never suppress the facts beside it. A
/// configured target that resolves to no commit is still exit 1, raised by
/// `git::landing`: a target the author named and got wrong is a config error,
/// which is a different thing from naming none.
fn run_worktree_status(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let target = config.must_land_on.as_deref();
    // The repo root, not the process directory: the three categories are
    // properties of the repository, and answering from a subdirectory would
    // report a clean tree for a dirty one one level up.
    let repo = git::repo_root(Path::new("."))?;
    let at_risk = worktree::status(&repo, target)?;

    if json {
        // Unconditional, including the clean run: JSON that is sometimes absent
        // is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&at_risk)?)?;
    } else {
        // Clean prints nothing — `lines()` is empty exactly then, so silence is
        // structural here rather than a branch that could disagree with `any()`.
        for line in at_risk.lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::verdict(at_risk.any()))
}

/// The declared ledger, or a usage error naming what is missing (CLOUD-52).
///
/// A verb over a ledger nobody declared measured nothing, and answering "no
/// records" there would be the false green the engine exists to catch — the same
/// reading `policy budget` gives an absent budget.
fn declared_ledger(overrides: &Overrides) -> Result<(defects::Defects, PathBuf)> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let declared = config.defects.ok_or_else(|| {
        UsageError::raise(format!(
            "no [defects] in {}; there is no ledger to read",
            config::CONFIG_FILE
        ))
    })?;
    let repo = git::repo_root(Path::new("."))?;
    let path = repo.join(&declared.path);
    Ok((declared, path))
}

/// Read and parse the declared ledger. An absent file is an empty ledger — the
/// ordinary state before the first record.
fn read_ledger(path: &Path) -> Result<Vec<defects::Record>> {
    defects::parse(&std::fs::read_to_string(path).unwrap_or_default())
}

/// List recorded defects, as pointers (CLOUD-52).
fn run_defects_query(
    json: bool,
    class: Option<&str>,
    id: Option<&str>,
    ungated: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let (declared, path) = declared_ledger(overrides)?;
    let records = read_ledger(&path)?;

    // One filter, not a conjunction: the flags are alternative ways to name a
    // subset, and combining them would need a precedence nobody asked for.
    // Refusing the combination is clearer than picking a winner silently.
    let named = [class.is_some(), id.is_some(), ungated]
        .iter()
        .filter(|set| **set)
        .count();
    if named > 1 {
        return Err(UsageError::raise(
            "defects query: --class, --id and --ungated are alternative filters; name one",
        ));
    }
    let filter = match (class, id, ungated) {
        (Some(class), _, _) => defects::Filter::Class(class),
        (_, Some(id), _) => defects::Filter::Id(id),
        (_, _, true) => defects::Filter::Ungated,
        _ => defects::Filter::All,
    };

    if json {
        // Sorted by id, and emitted unconditionally including the empty answer:
        // JSON that is sometimes absent is unparseable.
        let mut matched: Vec<&defects::Record> = records
            .iter()
            .filter(|record| filter.admits(record))
            .collect();
        matched.sort_by(|a, b| a.id.cmp(&b.id));
        writeln!(out, "{}", serde_json::to_string_pretty(&matched)?)?;
    } else {
        // Pointers, then the count the DoD asks for on its own trailing line.
        // Unconditional, including `0`: the count is the answer to "how many",
        // and an empty listing that says nothing cannot be told from a filter
        // the caller misspelled.
        let lines = defects::query_lines(&records, &declared.path, filter);
        for line in &lines {
            writeln!(out, "{line}")?;
        }
        writeln!(out, "{} record(s)", lines.len())?;
    }
    Ok(ExitCode::Success)
}

/// Append records read as JSONL on stdin (CLOUD-52).
///
/// Idempotent on a byte-identical row, which is what makes a half-finished
/// import safe to re-run; the same id with different content is refused, because
/// that is a revision and revisions append with `supersedes`.
fn run_defects_add(
    dry_run: bool,
    mode: Mode,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (declared, path) = declared_ledger(overrides)?;

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let incoming = defects::parse(&raw)?;
    if incoming.is_empty() {
        return Err(UsageError::raise(
            "defects add: stdin carried no record; an add that adds nothing is a mistake, not a no-op",
        ));
    }
    // The taxonomy is config's, so an unknown class is refused here rather than
    // written and caught later by the gate — a ledger is append-only, so a bad
    // row admitted once cannot be taken back.
    let problems = defects::validate_records(&incoming, &declared.classes);
    if let Some(problem) = problems.first() {
        return Err(UsageError::raise(format!(
            "defects add: stdin line {} is {}; `classes` in {} declares the taxonomy",
            problem.line,
            problem.id,
            config::CONFIG_FILE
        )));
    }

    let existing = read_ledger(&path)?;
    let (summary, fresh) = defects::plan(&existing, &incoming)?;

    if dry_run {
        // The one line this verb prints unconditionally: `-n` exists to be read,
        // and the would-append count IS the migration acceptance (§5). It is a
        // *preview*, not a report of what happened, so the ladder does not gate
        // it — a silenced preview is a `-n` that did nothing.
        writeln!(
            err,
            "defects add: would append {} record(s), {} already present",
            summary.appended, summary.already
        )?;
        return Ok(ExitCode::Success);
    }
    if !fresh.is_empty() {
        let mut body = String::new();
        for record in &fresh {
            body.push_str(&record.line()?);
            body.push('\n');
        }
        // Append, never rewrite: the file is opened in append mode, so this verb
        // is structurally incapable of the edit the gate refuses.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(body.as_bytes())?;
    }
    // Silence on the ordinary path (§5: `add` prints nothing on success). The
    // counts ride the ladder at `Verbose`, where a caller who asked for them
    // gets them and a script that did not is not made to parse them.
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!(
            "defects add: appended {}, already present {}",
            summary.appended, summary.already
        ),
    )?;
    Ok(ExitCode::Success)
}

/// Bind the store, scan this ref, and fold the findings in as its instances.
///
/// **The scan is `rules::run_static`** — the read-effect surface, no process
/// spawn. A recording verb that could execute a configured command would put
/// user-supplied code behind a store write, which is a different and much larger
/// promise than "remember what the read-only gates found".
///
/// A detached `HEAD` records **nothing**, loudly. An observation is keyed by ref,
/// and a detached head has none; inventing a synthetic one would mint an
/// instance that ref-death GC could never collect, because the ref it names
/// never existed to die.
///
/// When a session is declared ([`session::SESSION_ENV`]) this also records the
/// lineage edge and advances **its own** fold position
/// ([`session::HOLDER_RECORD`]) — never a drain's, since this verb folds shards
/// whether or not anything reached an agent (CLOUD-83).
fn run_state_record(overrides: &Overrides, mode: Mode, err: &mut dyn Write) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    // **The ref comes from HERE, not from `repo`.** `repo_root` answers with the
    // MAIN worktree's root — which is exactly what makes every linked worktree
    // share one store — so asking it for the branch would report the main
    // checkout's ref no matter which worktree the scan ran in, and every
    // worktree's observations would pile onto one context. Measured: the
    // worktree-pair fixture recorded both scans as `refs/heads/main`.
    let Some(branch) = git::current_branch(Path::new("."))? else {
        return Err(UsageError::raise(
            "HEAD is detached, so this scan belongs to no ref; check out a branch to record it",
        ));
    };
    let context = findings::Context::new(format!("refs/heads/{branch}"));
    let commit = git::head_commit(Path::new("."))?;

    let config = resolve::resolve(Path::new("."), overrides)?;
    // `run_recorded`, not `run_static`: a spawning kind is WITHHELD here rather
    // than refused. The refusal is right for `check`, whose silence reaches a
    // human as an exit code and nothing else, and wrong for this verb — it
    // returns before any work, so one `command` or `secrets` rule in the config
    // cost the repository its whole store write, the transcript detectors
    // included (CLOUD-97 never once evaluated in this repository for exactly
    // that reason). Withholding is honest here because `record` below folds
    // `not_evaluated` into the store, where a withheld rule's findings HOLD.
    let scan = rules::run_recorded(
        &config.rules,
        &config.provisions,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        Path::new("."),
    )?;
    if !scan.not_evaluated.is_empty() {
        // Never silent: a rule that did not look must say so, or a clean-looking
        // record is the false green. The COUNT carries that on the default rung
        // and the ids ride `Verbose` — this fires at every turn end, and sixteen
        // rule ids on every one is how a line stops being read (`stop-guard`'s
        // own lesson about spending a channel). Ids are the config author's own
        // tokens rather than content, so the higher rung is a noise decision,
        // not a rule-4 one.
        let withheld: Vec<&str> = scan.not_evaluated.keys().map(String::as_str).collect();
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "state record: {} rule(s) not evaluated, their findings held",
                withheld.len()
            ),
        )?;
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            &format!("state record: not evaluated: {}", withheld.join(", ")),
        )?;
    }

    let bound = store::commit(store::resolve(&repo)?)?;
    if let Some(note) = &bound.note {
        writeln!(err, "batten: {note}")?;
    }

    // The store's own version decides what gets written, never this binary's
    // (CLOUD-78's write-old rule). A store newer than this binary is read-only:
    // it still dedupes, it just does not persist, and it says so rather than
    // reporting a record that did not happen.
    let access = journal::open(&bound.dir)?;
    if let journal::Access::DegradedReadOnly { reason, .. } = &access {
        writeln!(err, "batten: degraded read-only: {reason}")?;
        writeln!(err, "batten: state record {context}: persisted:false")?;
        return Ok(ExitCode::Success);
    }
    let schema = access.format().findings_schema;

    // The worktree actually scanned, not the main root — this is metadata for a
    // human reading a report, and naming the wrong directory would misdirect it.
    let here = std::env::current_dir().ok();
    let recorded = findings::record(
        &bound.dir,
        &context,
        &commit,
        here.as_deref().and_then(Path::to_str),
        &scan.findings,
        schema,
        // The rules that never looked. Without this the pass below reads their
        // silence as "clean" and resolves every finding they cover (CLOUD-81).
        &scan.not_evaluated,
    )?;

    // The transcript-substrate detectors (CLOUD-97, CLOUD-98), folded in beside
    // the rule scan rather than through it: their identities are sequences over
    // the session's event order, which `rules::run_static` has no input for and
    // no vocabulary to express. They run AFTER `record` on purpose — that pass
    // resolves what this context no longer sees, and a raise written before it
    // would be reasoning about a store mid-update.
    register_transcript_detectors(
        &repo,
        &Recording {
            context: &context,
            commit: &commit,
            store_dir: &bound.dir,
            schema,
        },
        &config,
        mode,
        err,
    )?;

    // Fold any dispositions this worktree journalled since the last record. A
    // lost lock race is not a failure — the entries stay in the shard and the
    // next record folds them — so it reports and carries on.
    let merged = journal::merge(&bound.dir)?;
    if merged == journal::Merge::Busy {
        writeln!(
            err,
            "batten: shard-merge busy; dispositions stay queued in this worktree's shard"
        )?;
    }

    // Ref-death GC rides the same verb: the live set is what exists now, so a
    // branch deleted since the last record loses its instances here.
    let live = git::refs(&repo)?
        .into_iter()
        .map(findings::Context::new)
        .collect();
    let dropped = findings::gc(&bound.dir, &live)?;
    if dropped > 0 {
        // GC's half of the cursor handshake: a new generation, so every
        // outstanding drain cursor resyncs instead of computing a delta against
        // records that are gone.
        journal::new_generation(&bound.dir)?;
    }

    // The session's durable resume point (CLOUD-83), recorded LAST so the stored
    // cursor names the generation this run finished in — a GC above may have
    // rotated it, and a cursor saved before that would name a dead one and force
    // a resync this process already knows the answer to.
    record_session_position(&bound.dir, mode, err)?;

    // Pointer-only counts on stderr; `record` emits no data document, so the
    // stdout channel stays empty for it.
    writeln!(
        err,
        "batten: state record {context}: {} minted, {} updated, {} resolved, {} held, \
         {dropped} instances GC'd",
        recorded.minted, recorded.updated, recorded.resolved, recorded.held
    )?;
    Ok(ExitCode::Success)
}

/// Record this session's lineage edge and fold position, when one is declared.
///
/// Split out because it is a different question from "what did this scan find",
/// and because the whole of it is skipped when no session is declared: a host
/// that supplies none is a repository not using this, and an absent session must
/// leave the store and this verb's output byte-identical to before
/// ([`transcript`]'s absent-is-not-empty law).
///
/// The note rides the `Verbose` rung rather than the default line. `state
/// record`'s one-line report is a byte-stable contract, and a resume position is
/// detail for a caller who asked — not a second sentence every consumer must now
/// parse.
///
/// **Not reachable on the degraded read-only path**: [`run_state_record`] returns
/// before the merge there, so a binary that may not write the store does not
/// write a session record either.
fn record_session_position(store_dir: &Path, mode: Mode, err: &mut dyn Write) -> Result<()> {
    let Some(declared) = session::declared() else {
        return Ok(());
    };
    let observed = session::observe(store_dir, &declared)?;
    let root = session::root(store_dir, &declared.key)?;
    let held = session::load_cursor(store_dir, &root, session::HOLDER_RECORD)?;
    // The same `since` every reader uses, so a rotated generation forces the
    // resync here exactly as it would anywhere else — this verb gets no private
    // reading of a cursor's validity.
    let drained = journal::since(store_dir, held.as_ref())?;
    let resumed = match &drained {
        journal::Drain::Delta { entries, .. } => format!("resumed, {} new", entries.len()),
        journal::Drain::FullResync { reason, .. } => format!("full resync ({reason})"),
    };
    session::save_cursor(store_dir, &root, session::HOLDER_RECORD, drained.cursor())?;

    // Pointer-only (rule 4): the lineage root as a fingerprint prefix and the
    // walk's depth, never the host's session id and never an entry.
    let lineage = if root.truncated {
        format!("lineage {} (truncated at {})", root.short(), root.depth)
    } else if root.depth > 0 {
        format!("lineage {} (+{})", root.short(), root.depth)
    } else {
        format!("lineage {}", root.short())
    };
    let conflict = if observed == session::Observed::ParentConflict {
        "; declared parent differs from the recorded one, which stands"
    } else {
        ""
    };
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!("state record: session {lineage}: {resumed}{conflict}"),
    )?;
    Ok(())
}

/// Upgrade the store's record version. The one explicit upgrade path.
///
/// A `write` verb by declaration and in fact: it rewrites every record. No read
/// path may do this, which is what keeps a routine `check` in one worktree from
/// rewriting a store an older binary is using in another.
fn run_state_migrate(err: &mut dyn Write) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        return Err(UsageError::raise(
            "no store is bound to this repository; run `batten state adopt` first",
        ));
    };
    let migrated = journal::migrate(&dir)?;
    if migrated.from == migrated.to {
        writeln!(
            err,
            "batten: state migrate: already at record version {}",
            migrated.to
        )?;
    } else {
        writeln!(
            err,
            "batten: state migrate: {} record(s) {} -> {}",
            migrated.records, migrated.from, migrated.to
        )?;
    }
    Ok(ExitCode::Success)
}

/// Navigate a frozen capture (CLOUD-121).
///
/// A dispatcher only. The three sub-verbs are separate functions rather than
/// three arms of one match, because a single body carrying all of them crossed
/// the workspace's own function-length lint — and the lint was right: `show`
/// resolves a selection, `list` filters a directory, and `prune` removes, which
/// are three jobs sharing nothing but a repository root.
fn run_capture(
    command: &cli::CaptureCommand,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    match command {
        cli::CaptureCommand::Show {
            handle,
            lines,
            grep,
            raw,
            bytes,
            json,
        } => run_capture_show(
            &repo,
            handle,
            &ShowRequest {
                lines: lines.as_deref(),
                grep: grep.as_deref(),
                raw: *raw,
                byte_range: bytes.as_deref(),
                json: *json,
            },
            out,
        ),
        cli::CaptureCommand::List {
            stream,
            calls,
            json,
        } => run_capture_list(&repo, stream.as_deref(), *calls, *json, out),
        cli::CaptureCommand::Prune { yes, dry_run } => {
            run_capture_prune(&repo, *yes, *dry_run, mode, err)
        }
    }
}

/// What one `capture show` asked for: which window, and in which encoding.
///
/// Grouped rather than passed as five parameters, and the workspace's own
/// argument-count lint is what asked for it — correctly, because these are one
/// thing: a caller's request. Two selectors (`lines`, `grep`), one byte window
/// (`byte_range`), and two encodings (`raw`, `json`), whose legal combinations
/// [`run_capture_show`] decides in one place.
#[derive(Debug, Clone, Copy)]
struct ShowRequest<'a> {
    /// A 1-indexed inclusive line range.
    lines: Option<&'a str>,
    /// A literal substring.
    grep: Option<&'a str>,
    /// Write the selected bytes verbatim.
    raw: bool,
    /// A 0-indexed half-open byte range.
    byte_range: Option<&'a str>,
    /// Emit a byte-stable document.
    json: bool,
}

/// Read a frozen capture, with no second run of the command that made it.
///
/// **Always [`ExitCode::Success`]**, for the same reason [`run_state_list`] is:
/// this reports what a past run produced, and a verdict here would put a record
/// on the deny channel. A handle that names nothing is still a [`UsageError`] —
/// the caller asked about a capture that is not there, which is a statement about
/// the invocation, not a finding about the repository.
///
/// `--lines` and `--grep` together is refused rather than composed. Two selectors
/// have two readings — the intersection or the union — and picking one silently
/// would make the answer depend on a choice the caller never saw. A caller who
/// wants both greps first and then widens around what it found, which is the
/// navigation loop this verb exists to make possible.
fn run_capture_show(
    repo: &Path,
    handle: &str,
    asked: &ShowRequest<'_>,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let ShowRequest {
        lines,
        grep,
        raw,
        byte_range,
        json,
    } = *asked;
    let parsed = capture::Handle::parse(handle)?;
    // REFUSED BEFORE ANYTHING IS READ, and refused rather than resolved
    // (CLOUD-918). `--raw` and `--json` are two encodings of one selection, and a
    // combination that had to pick between them silently is how a caller ends up
    // with base64 where it wanted bytes. `--lines` and `--grep` are line views,
    // which a byte stream is not — pairing either with `--raw` asks for two
    // different products at once.
    if raw && json {
        return Err(UsageError::raise(
            "capture show: --raw and --json are two encodings of the same selection; pass one. \
             --raw writes bytes, --json writes a byte-stable document",
        ));
    }
    if raw && (lines.is_some() || grep.is_some()) {
        return Err(UsageError::raise(
            "capture show: --raw writes bytes and --lines/--grep select decoded lines; pass \
             --bytes to narrow a raw read",
        ));
    }
    if byte_range.is_some() && (lines.is_some() || grep.is_some()) {
        return Err(UsageError::raise(
            "capture show: --bytes and --lines/--grep select differently; a byte range is not a \
             line range",
        ));
    }
    // A byte range is its own selection, so it is resolved ahead of the line
    // selectors rather than folded into their match — the two are not alternatives
    // over one axis.
    if raw || byte_range.is_some() {
        let (from, to) = match byte_range {
            Some(range) => parse_bytes(range)?,
            None => (None, None),
        };
        return run_capture_raw(repo, &parsed, from, to, raw, json, out);
    }
    let selection = match (lines, grep) {
        (Some(_), Some(_)) => {
            return Err(UsageError::raise(
                "capture show: --lines and --grep select differently; grep first, then widen \
                 around the line it names",
            ));
        }
        (Some(range), None) => capture::Selection::Lines {
            from: parse_line(range, 0)?,
            to: parse_line(range, 1)?,
        },
        (None, Some(needle)) => capture::Selection::Grep {
            needle: needle.to_owned(),
        },
        (None, None) => capture::Selection::Summary,
    };
    // The byte count is the store's to know, not the caller's: this record exists
    // only to name the file, and `select` reports the real length off the bytes.
    let record = capture::Capture {
        stream: parsed.stream.as_str(),
        bytes: 0,
        digest: parsed.digest.clone(),
    };
    let bytes = capture::read(repo, &record).map_err(|_| {
        UsageError::raise(format!(
            "capture show: no capture at {parsed} — `batten capture list` names the ones this \
             repository holds"
        ))
    })?;
    let answer = capture::select(&parsed, &bytes, &selection);
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&answer)?)?;
    } else if matches!(selection, capture::Selection::Summary) {
        // The pointer, in the `<pointer> <fact>` shape every other verb here
        // emits, so a caller needs no second parser.
        writeln!(
            out,
            "{} {} bytes {} lines",
            answer.handle, answer.bytes, answer.lines
        )?;
    } else {
        for line in &answer.selected {
            writeln!(
                out,
                "{}:{} {}",
                parsed.stream.as_str(),
                line.number,
                line.text
            )?;
        }
    }
    Ok(ExitCode::Success)
}

/// Read a byte range of a capture — verbatim, or as a base64 document.
///
/// Split out of [`run_capture_show`] because the two produce different things: a
/// line view is text this binary formats, and this is the child's own bytes
/// leaving the process untouched. Keeping them in one function would put a decoded
/// value in scope beside the raw path, which is exactly what `select_raw` exists
/// to avoid.
///
/// **What the raw write bypasses**, stated because each omission is deliberate:
/// `writeln!` (so no trailing newline is added — the one thing every other arm of
/// this verb does), `serde_json::to_string_pretty`, and the whole `output::`
/// ladder. `out` is already a byte sink, so `write_all` is the whole mechanism.
///
/// Rust's `std::io` performs no newline translation on any platform, so there is
/// no `\n` → `\r\n` hazard to guard. The platform claim worth stating is narrower:
/// on Windows a `Stdout` bound to a *console* goes through `WriteConsoleW`, which
/// requires valid UTF-8, and obtaining a true byte handle needs `unsafe` — which
/// the workspace lints forbid. So the verbatim guarantee is a guarantee about a
/// REDIRECTED stdout, which is the only way a program consumes these bytes.
fn run_capture_raw(
    repo: &Path,
    parsed: &capture::Handle,
    from: Option<u64>,
    to: Option<u64>,
    raw: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let record = capture::Capture {
        stream: parsed.stream.as_str(),
        bytes: 0,
        digest: parsed.digest.clone(),
    };
    let bytes = capture::read(repo, &record).map_err(|_| {
        UsageError::raise(format!(
            "capture show: no capture at {parsed} — `batten capture list` names the ones this \
             repository holds"
        ))
    })?;
    let answer = capture::select_raw(parsed, &bytes, from, to);
    if raw {
        // The one write in this binary that is not text.
        out.write_all(&answer.data)?;
    } else if json {
        // Base64 rather than an escaped string, because §6 requires the document
        // to be a function of the bytes and a lossy decode is not one; and rather
        // than the bytes themselves, because a `-J` document is parsed by
        // consumers that assume UTF-8.
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "handle": answer.handle,
                "bytes": answer.bytes,
                "from": answer.from,
                "to": answer.to,
                "encoding": "base64",
                "data": base64(&answer.data),
            }))?
        )?;
    } else {
        // Pointer-only by default here too (rule 4): a byte range with neither
        // encoding named reports what it would return, never the payload.
        writeln!(
            out,
            "{} {}..{} {} selected",
            answer.handle,
            answer.from,
            answer.to,
            answer.data.len()
        )?;
    }
    Ok(ExitCode::Success)
}

/// Standard base64, unpadded-free (RFC 4648 with `=` padding).
///
/// ~20 lines rather than a dependency: `deny.toml` and
/// `tests/ambient_authority.rs` both price a new crate in the supply chain as a
/// decision to be argued, and this is the only base64 in the tool.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let indices = [
            (triple >> 18) & 0x3F,
            (triple >> 12) & 0x3F,
            (triple >> 6) & 0x3F,
            triple & 0x3F,
        ];
        for (position, index) in indices.iter().enumerate() {
            // The last chunk pads: two source bytes drop the final character and
            // one source byte drops the final two.
            if position > chunk.len() {
                encoded.push('=');
            } else {
                encoded.push(char::from(ALPHABET[*index as usize]));
            }
        }
    }
    encoded
}

/// List this repository's captures as handles, or its recorded calls.
///
/// Two views over one store, on the two axes CLOUD-917 keeps separate: the blob
/// listing answers "which bytes does this repository hold", and `--calls` answers
/// "which calls happened". Dedup collapses the first and never the second, so
/// forty calls that printed the same thing are one line in the blob view and
/// forty in this one — which is the whole reason provenance is a second record.
///
/// Both orderings are byte-stable (§6) and neither reads an mtime. The call view
/// never renders `seen_at`, because a listing that printed a timestamp would stop
/// agreeing with itself across runs.
fn run_capture_list(
    repo: &Path,
    stream: Option<&str>,
    calls: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    if calls {
        let recorded = capture::calls(repo)?;
        if json {
            writeln!(out, "{}", serde_json::to_string_pretty(&recorded)?)?;
        } else {
            for row in &recorded {
                // Pointer-only: a handle or a reason id, the host, the event and
                // the ordinal. Never bytes, never a path, never the timestamp.
                let names = match (&row.digest, &row.absent) {
                    (Some(digest), _) => format!("response:{digest}"),
                    (None, Some(reason)) => format!("absent:{reason}"),
                    (None, None) => "absent:unrecorded".to_owned(),
                };
                writeln!(
                    out,
                    "{names} {} {} {} #{}",
                    row.source, row.host, row.event, row.order
                )?;
            }
        }
        return Ok(ExitCode::Success);
    }
    if let Some(stream) = stream {
        // Validated through the handle parser rather than a second list of stream
        // names, so the filter cannot come to disagree with the store about what a
        // stream is. The `00` is a throwaway digest: only the stream is judged.
        capture::Handle::parse(&format!("{stream}:00"))?;
    }
    let held: Vec<capture::Capture> = capture::list(repo)?
        .into_iter()
        .filter(|record| stream.is_none_or(|want| record.stream == want))
        .collect();
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&held)?)?;
    } else {
        for record in &held {
            writeln!(out, "{} {} bytes", record.handle(), record.bytes)?;
        }
    }
    Ok(ExitCode::Success)
}

/// Remove this repository's captures — the one removal path.
fn run_capture_prune(
    repo: &Path,
    yes: bool,
    dry_run: bool,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    if dry_run {
        let held = capture::list(repo)?.len();
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            &format!("capture prune: would remove {held} capture(s)"),
        )?;
        return Ok(ExitCode::Success);
    }
    if !yes {
        // §4's refusal, and unconditional rather than only-when-unattended on
        // purpose: the same section says a policy engine that blocks a loop
        // waiting for a Y/N is a dead gate, and the primary caller here is a
        // program. Naming the flag is the whole remedy, which is what makes the
        // refusal one hop from done rather than a wall.
        return Err(UsageError::raise(
            "capture prune: removing captures is destructive and this never prompts — pass -y, \
             or -n to see what would go",
        ));
    }
    let removed = capture::prune(repo)?;
    output::message(
        mode,
        output::Verbosity::Normal,
        err,
        &format!("capture prune: removed {removed} capture(s)"),
    )?;
    Ok(ExitCode::Success)
}

/// One half of a `FROM:TO` range, as a 1-indexed line number.
///
/// Strict on both halves: a range with a missing or unparseable side is a
/// [`UsageError`] naming the shape, never a silent default. Defaulting the end to
/// the capture's length would make `--lines 5:` mean "the rest" without anyone
/// declaring it, and defaulting the start to 1 would turn a typo into a full dump
/// — the exact cost this verb exists to avoid.
fn parse_line(range: &str, half: usize) -> Result<usize> {
    let bad = || {
        UsageError::raise(format!(
            "capture show: {range:?} is not a line range — write `FROM:TO`, both 1-indexed"
        ))
    };
    let (from, to) = range.split_once(':').ok_or_else(bad)?;
    let chosen = if half == 0 { from } else { to };
    let value: usize = chosen.trim().parse().map_err(|_| bad())?;
    if value == 0 {
        return Err(UsageError::raise(format!(
            "capture show: line numbers are 1-indexed, so {range:?} has no line 0"
        )));
    }
    Ok(value)
}

/// A `FROM:TO` byte range: 0-indexed, half-open, either half omittable.
///
/// **Deliberately laxer than [`parse_line`] about an EMPTY half and exactly as
/// strict about a malformed one**, and the divergence is declared rather than
/// inherited. `parse_line` refuses `5:` because defaulting the end would make it
/// mean "the rest" without anyone saying so — the range is inclusive, so there is
/// no notation for an open end and a caller could not have meant one. A byte range
/// is half-open, so an absent bound is the *only* way to say "to the end" without
/// first learning the length, and reading it as such invents nothing.
///
/// Three refusals, worded apart so a caller can tell them from each other: no
/// separator, a non-numeric half, and a half that overflows `u64`. The last is
/// separate because "too big" and "not a number" have different fixes.
///
/// **It never compares against a length**, because it has none — an out-of-range
/// but well-formed bound is clamped, and the clamp lives in
/// [`capture::select_raw`] and only there.
fn parse_bytes(range: &str) -> Result<(Option<u64>, Option<u64>)> {
    let shape = || {
        UsageError::raise(format!(
            "capture show: {range:?} is not a byte range — write `FROM:TO`, 0-indexed, `FROM` \
             inclusive and `TO` exclusive; either side may be omitted"
        ))
    };
    let (from, to) = range.split_once(':').ok_or_else(shape)?;
    let half = |text: &str, side: &str| -> Result<Option<u64>> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(UsageError::raise(format!(
                "capture show: the {side} bound {text:?} is not a number — a byte offset is \
                 decimal digits"
            )));
        }
        text.parse::<u64>().map(Some).map_err(|_| {
            UsageError::raise(format!(
                "capture show: the {side} bound {text:?} is larger than {} — no capture is that \
                 long",
                u64::MAX
            ))
        })
    };
    Ok((half(from, "start")?, half(to, "end")?))
}

/// List what the store holds.
///
/// **Always [`ExitCode::Success`].** A stored finding is a record, not a fresh
/// verdict — `check` already spent the `2` when it found the thing. Emitting a
/// violation here would put the store on the deny channel and let a stale record
/// block a call, which is exactly the interaction law the identity module
/// states: identity governs advisory reporting and never touches an exit path.
fn run_state_list(
    json: bool,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        // Nothing bound yet: an empty listing, not an error. The note rides the
        // §3 ladder above `normal` rather than being written directly — an
        // unbound store is an ordinary first-run state, and a read verb's clean
        // piped run prints nothing unless the caller asked for detail.
        output::message(
            mode,
            output::Verbosity::Verbose,
            err,
            "no store is bound to this repository yet",
        )?;
        if json {
            writeln!(out, "{}", serde_json::to_string_pretty(&Vec::<u8>::new())?)?;
        }
        return Ok(ExitCode::Success);
    };
    let records = findings::load_all(&dir)?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&records)?)?;
    } else {
        for line in findings::pointer_lines(&records) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Report every declared file-set budget (CLOUD-50).
///
/// The **introspection** surface, not the enforcement one — enforcement is a
/// finding on `check`, so a budget bites without anybody choosing to look.
///
/// A config declaring no budget at all is a **usage error**, not a silent pass.
/// A budget verb run against a config that declares no budget measured nothing,
/// and reporting that as `0` would be the false green this engine exists to
/// catch — the same reading `rules::run_static` gives a rule it cannot honestly
/// run. (`check` reads the same absence the other way, and both are right: see
/// [`budget::measure_all`].)
fn run_budget(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let declared = config.budget.as_ref().ok_or_else(|| {
        UsageError::raise(format!(
            "no [budget.<name>] in {}; there is no budget to judge",
            config::CONFIG_FILE
        ))
    })?;
    let reports = budget::measure_all(Path::new("."), Some(declared))?;
    let over = reports.iter().any(budget::Report::over_budget);

    if json {
        // Emitted unconditionally, including for a run within budget: JSON that
        // is sometimes absent is unparseable. An array because there are N sets;
        // one set is an array of one, not a bare object, so the shape does not
        // change under the consumer as they add a second budget.
        writeln!(out, "{}", serde_json::to_string_pretty(&reports)?)?;
    } else {
        // Silence is the success signal on the human channel (§6), so a set's
        // per-file breakdown is written only when it explains a verdict.
        for report in reports.iter().filter(|report| report.over_budget()) {
            for file in &report.files {
                writeln!(out, "{}", file.line())?;
            }
            writeln!(out, "{}", report.summary())?;
        }
    }
    Ok(ExitCode::verdict(over))
}

/// The reason tokens `policy test` reports with.
///
/// Named constants rather than literals at the call site, because these are the
/// verb's stable vocabulary: a caller greps for them and `tests/policy_test.rs`
/// asserts on them, so a reworded string is a broken contract rather than a
/// cosmetic change. Same shape `doctor::WiringReport` uses for its findings.
const FIXTURE_MISSING: &str = "fixture-missing";
const TEST_FAILED: &str = "test-failed";
const PREDICATE_UNEXERCISED: &str = "predicate-unexercised";
const MODULE_UNTESTED: &str = "module-untested";
const SUITE_NOT_RUN: &str = "suite-not-run";

/// One bundle's suite, as the `-J` document renders it (CLOUD-835).
///
/// **One shape, always.** Every key is present on every run, including a clean
/// one and one whose suite never ran — a document whose keys come and go is
/// unparseable. Degrade the VALUE, never the shape, the same rule
/// `AttributionDocument` keeps.
///
/// Field order is struct order rather than a map's, so the emission is
/// byte-stable (§6). Pointer-only (rule 4): module paths, rule names, predicate
/// ids and counts — never a fixture's contents and never a byte of policy body.
#[derive(serde::Serialize)]
struct SuiteReport {
    /// The row that registered this bundle.
    bundle: String,
    /// Whether the suite ran at all. `false` makes every list below vacuous
    /// rather than clean, which is the distinction CLOUD-251 exists for.
    looked: bool,
    /// Declared documents the tree does not carry.
    missing: Vec<String>,
    /// Tests that evaluated to `true`.
    passed: Vec<policy::TestId>,
    /// Tests that did not — `false` and undefined alike.
    failed: Vec<policy::TestId>,
    /// Published predicate ids no test caused to be entered.
    unexercised: Vec<String>,
    /// Module paths carrying no `test_` rule at all.
    untested_modules: Vec<String>,
}

impl SuiteReport {
    /// A suite that could not run at all, for the row named.
    ///
    /// Constructed rather than defaulted so the `looked: false` is written once:
    /// a report assembled field-by-field at three call sites is how one of them
    /// eventually says `true` about a run that did not happen.
    fn not_run(bundle: &str, missing: Vec<String>) -> Self {
        Self {
            bundle: bundle.to_owned(),
            looked: false,
            missing,
            passed: Vec::new(),
            failed: Vec::new(),
            unexercised: Vec::new(),
            untested_modules: Vec::new(),
        }
    }
}

/// Run each registered module's own `test_` rules (CLOUD-835).
///
/// **The gap this closes.** `crates/batten/tests/policy_modules.rs` exercises
/// the *evaluator*; nothing exercises a *module*. That is a blocker rather than
/// a nicety because the retirement campaign has to move 1,570 of 2,485 bats
/// cases onto policy rows, and CLOUD-202 measured the trap that makes an
/// untested port worse than none — the shell tasks spell `1 = violation,
/// 2 = could not read` and this contract is the exact inverse.
///
/// **The fixture is the row's own `documents`.** No new config key: CLOUD-833
/// already gave a tree-scoped policy row the documents it hands its bundle, and
/// `rules::tree_document` already parses them and returns the ones the tree does
/// not carry rather than guessing. Non-negotiable 6 keeps configuration narrow,
/// and this is the reuse that honours it.
///
/// # Exit codes, and the two faults kept apart
///
/// `2` when a test failed or a published predicate went unexercised — the row's
/// §7(b) is explicit that the latter is *"reported, not green"*. `1` when the
/// suite could not run: a declared fixture the tree does not carry, or a sweep
/// that did not happen. Separating them is CLOUD-202's whole lesson, and
/// `tests/policy_test.rs` asserts each independently so the port cannot
/// reintroduce the inversion it exists to avoid.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when the config will not resolve or a registered
/// module will not load — both refused by [`policy::load`] with their own
/// message, at the boundary where a config fault belongs.
/// The tree input one policy suite runs against.
///
/// Split out of [`run_policy_test`] so that function reads as a loop over rows;
/// what it holds is the pair of deliberate omissions, which are easier to see
/// stated together than buried in an argument list.
///
/// **A SUITE RUNS AGAINST NO PRODUCED RECORD** (CLOUD-851). A module's tests must
/// decide the same way on every machine, and the sink store is per-checkout state
/// that differs between them — so a test that wants a baseline supplies it with
/// `with input as`, the same way a mediated-call suite supplies its call.
///
/// **AND AGAINST NO GIT FACT**, for exactly the same reason (CLOUD-907). HEAD, the
/// branch, the remotes and whether a ref resolves are all per-checkout state: a
/// suite that read them would pass on the author's machine and fail in CI's
/// detached, remote-less clone, which is a test asserting its environment rather
/// than its module.
fn suite_input(
    rule: &rules::Rule,
    documents: &std::collections::BTreeMap<(String, rules::Wanted), rules::Acquired>,
    tracked: &[String],
) -> Result<(String, Vec<(String, rules::NotAcquired)>)> {
    // A mediated-call row declares no documents, so its tests run against `{}`
    // and supply their own input with `with input as` — OPA and Conftest's own
    // shape, and the reason neither surface needs a fixture key.
    Ok(rules::tree_document(
        documents,
        &rules::Declared {
            documents: &rules::declared_documents(rule, tracked)?,
            lines: &rules::declared_lines(rule, tracked)?,
            invocations: &rules::declared_invocations(rule, tracked)?,
            uses: &rules::declared_uses(rule, tracked)?,
        },
        tracked,
        &std::collections::BTreeMap::new(),
        // A module's own `test_` rules supply their input with `with input as`,
        // so the record projection is empty here for the same reason the two
        // beside it are: this builds the shape, and the case chooses the values.
        &std::collections::BTreeMap::new(),
        &git::GitFacts::default(),
        &facts::Look::IsNot,
    ))
}

/// Print the tool names the `mediated_call` rows decide (CLOUD-312 row 4).
///
/// # Why the engine publishes this
///
/// A consumer's permission file may deny a tool on a host-supplied connector, and
/// the host chooses that connector's exposed name per registration episode — so a
/// deny naming one spelling enforces nothing the moment it comes back under
/// another (CLOUD-178). What rescues such a rule is something matching the tool by
/// SUFFIX, which is exactly what a `tool`-keyed row does.
///
/// A consumer gate therefore has to know which names the table decides. That fact
/// used to be a flag on the guard that decided them; retiring the guard into rows
/// would have left the gate grepping `batten.toml`, which is a second authority
/// for a fact the loader already holds. So the engine answers it.
///
/// # Output
///
/// One name per line, sorted and deduplicated, or a byte-stable JSON array under
/// `-J`. A name is a selector out of the committed config — the consumer's own
/// vocabulary, echoed back — and never a payload, so this is pointer-shaped by
/// construction (non-negotiable rule 4).
fn run_policy_tools(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let root = Path::new(".");
    let config = resolve::resolve(root, overrides)?;
    // A `BTreeSet` rather than a sort at the end: the dedupe and the order are one
    // decision, and §6's byte-stability is what both are for.
    let names: std::collections::BTreeSet<&str> = config
        .rules
        .iter()
        .filter(|rule| rule.scope == rules::RuleScope::MediatedCall)
        .filter_map(|rule| rule.tool.as_deref())
        .collect();
    if json {
        let document = serde_json::json!({ "tools": names.iter().collect::<Vec<_>>() });
        writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
    } else {
        for name in &names {
            writeln!(out, "{name}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Resolve a verdict token to its class definition and routes (CLOUD-1053).
///
/// # The hot path got shorter and this is where the rest went
///
/// A refusal now prints a token, a one-line gloss and a pointer. That is the
/// common case, and it is the case that has to be cheap: an agent refused
/// eighteen times in a session reads eighteen lines, not eighteen paragraphs.
/// The paragraph is still worth having exactly once, when a reader meets a class
/// for the first time — so it lives in the registry and this is what fetches it.
///
/// # Its payload is a deliberate, stated exception to pointer-only output
///
/// House style §6 and non-negotiable rule 4 say a check emits a count, a
/// `path:line` or a boolean, never the content. This prints a paragraph, and
/// that is inside the rule rather than an exception to it in one respect and an
/// exception in another. Inside: the text is the **config author's own
/// declaration**, the class `config show` exists to echo, never content read out
/// of a subject file. Exception: it is a payload, and carrying it is the whole
/// point — a documentation verb that emitted a pointer to its own documentation
/// would be a redirect with extra steps.
///
/// # Local, deterministic, and never a verdict
///
/// No network, no spawn, no tree walk: the committed registry is resolved and a
/// token is looked up in it. Exit `0` for a token the registry declares, `1` for
/// one it does not or for a registry that will not load, `3` for an internal
/// fault — and never `2`, because this decides nothing about the repository.
///
/// # Errors
///
/// Propagates a config-resolution failure, which is the usage class (exit `1`).
fn run_policy_explain(
    token: &str,
    json: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    // The same union the engine decides against, so `explain` cannot resolve a
    // token differently from the gate that raised it — which is the drift a
    // second reader of one table always produces.
    let registry = policy::registry_for(&config.verdicts)?;
    let Some((resolved, retired)) = verdict::resolve(&registry, token) else {
        // Named, and the token is the caller's own argument rather than
        // anything read out of the tree. A list of what IS declared would be the
        // whole registry on stderr; the count plus the verb to run is the
        // pointer-shaped answer.
        return Err(error::UsageError::raise(format!(
            "no `[[verdict]]` row declares `{token}`; this registry declares {} class(es)",
            registry.len()
        )));
    };
    if json {
        writeln!(out, "{}", explain_json(token, resolved, retired)?)?;
        return Ok(ExitCode::Success);
    }
    writeln!(out, "{} {}", resolved.id, resolved.gloss)?;
    if retired {
        // The token the reader ASKED for was a tombstone. Said outright rather
        // than silently swapped: a reader who greps their own logs for the old
        // token has to learn that it moved, and an answer that just showed the
        // new class would leave them believing the old one is live.
        writeln!(out, "retired  {token} -> {}", resolved.id)?;
    }
    writeln!(out)?;
    writeln!(out, "{}", resolved.class.trim())?;
    writeln!(out)?;
    for route in &resolved.routes {
        let target = match route.precondition.as_deref() {
            Some(precondition) => precondition,
            None => route.target.as_str(),
        };
        writeln!(out, "{}  {}  {target}", route.id, route.kind.as_str())?;
    }
    Ok(ExitCode::Success)
}

/// Dispatch the `policy` subtree.
///
/// Lifted out of [`run`]'s table alongside [`run_override`] and for the same
/// reason: that body is one line per verb, and a three-verb nested match is not
/// one line.
fn run_policy(
    command: PolicyCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        PolicyCommand::Budget { json } => run_budget(json, overrides, out),
        PolicyCommand::Test { json } => run_policy_test(json, overrides, out),
        PolicyCommand::Tools { json } => run_policy_tools(json, overrides, out),
        PolicyCommand::Explain { token, json } => run_policy_explain(&token, json, overrides, out),
    }
}

/// Dispatch the `override` subtree.
///
/// One arm today, and a function rather than an inline match for the reason
/// every other multi-verb noun here has one: [`run`]'s body is a table of one
/// line per verb, and a verb whose arm is a nested destructure stops it being
/// readable as a table.
fn run_override(
    command: OverrideCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        OverrideCommand::Request {
            rule,
            verdict,
            subject,
        } => run_override_request(&rule, &verdict, &subject, overrides, out, err),
        OverrideCommand::Spend {
            admission,
            rule,
            verdict,
            subject,
        } => run_override_spend(&admission, &rule, &verdict, &subject, overrides, out, err),
    }
}

/// `batten override spend` — consume an admission for the situation it names
/// (CLOUD-1051).
///
/// # Why this is a verb and not a flag on the gate
///
/// `check` is declared `read`, and [`perform_requested_sinks`] states the rule
/// that keeps it honest: a read-effect verb that left a record behind would be a
/// verb that changes what it is judging. Spending moves a record from issued to
/// spent, which is a write — so the gate's task calls this AFTER the refusal
/// rather than the gate consuming its own override mid-decision.
///
/// # The situation is re-stated rather than remembered
///
/// The caller passes the rule, the class and the subject again instead of having
/// them read out of the record. Reading them from the record would make every
/// spend self-consistent by construction and the binding decorative: the whole
/// content of an admission is that it is valid for ONE situation, so the
/// situation has to come from the caller and be COMPARED.
///
/// HEAD and the epoch are resolved here for [`run_override_request`]'s reason,
/// inverted: a caller who could choose them could present a stale admission
/// against a moved tree or a changed policy.
///
/// # Exit codes
///
/// `0` spent. `2` refused — every [`admission::Refused`] arm, because a refusal
/// to release is a policy verdict and §7 gives that one code on every verb. `3`
/// when the store itself cannot be read or written, which is an internal fault
/// rather than a statement about the admission.
///
/// # Errors
///
/// Returns an internal error when the store cannot be reached.
fn run_override_spend(
    admission: &str,
    rule: &str,
    token: &str,
    subject: &str,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    // Resolved rather than taken, exactly as `request` resolves them.
    let head = git::head_commit(root)?;
    let (epoch, _) = epoch::describe(root, overrides.config_from.as_deref())?;
    let situation = admission::Situation {
        rule,
        verdict: token,
        subject,
        head: &head,
        epoch: &epoch,
    };
    match admission::consume(root, admission, &situation)? {
        Ok(record) => {
            // POINTER, NEVER THE ANSWERS (rule 4). The address and the class,
            // which is what a reader needs to find the record; the reasoning the
            // author typed stays in the store where it was written.
            writeln!(out, "{} {} spent", record.binding.verdict, admission)?;
            Ok(ExitCode::Success)
        }
        Err(refused) => {
            writeln!(
                err,
                "::error:: admission {admission} is {} for {rule}/{token}",
                refused.as_str()
            )?;
            Ok(ExitCode::Violation)
        }
    }
}

/// `batten override request` — issue an admission for one situation
/// (CLOUD-1051).
///
/// # What the caller supplies and what this resolves
///
/// The caller names the rule, the class and the gate's canonical subject; the
/// other two binding terms — HEAD and the config epoch — are resolved HERE. That
/// asymmetry is the point: an admission whose HEAD the caller could choose would
/// bind nothing, and one whose epoch the caller could choose would survive the
/// policy change that made it unnecessary.
///
/// # The questions, and the two-step this produces
///
/// They are generated from the class's own declared `override.precondition`, so
/// a class that declares no override route cannot be overridden at all — the
/// right default, and the one `verdict::validate` already composes with by
/// refusing a class whose ONLY route is an override.
///
/// Run with nothing on stdin, this PRINTS the questions and exits `1`. That is
/// the "an unanswered question yields no admission" clause and the
/// re-presentation of the declined routes in one step, at the last cheap moment
/// — which is what catches the reader who never received route 1 (CLOUD-1050
/// defect B, measured).
///
/// # It never grades an answer
///
/// Non-negotiable rule 3. The predicate is presence and non-emptiness; anything
/// stronger is a model verdict inside a gate, which would be worse than today's
/// password.
///
/// # Errors
///
/// Returns a [`error::UsageError`] for an unknown class or a class that declares
/// no override route, and an internal error when the store cannot be written.
fn run_override_request(
    rule: &str,
    token: &str,
    subject: &str,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    let config = resolve::resolve(root, overrides)?;
    let registry = policy::registry_for(&config.verdicts)?;
    let Some((resolved, _)) = verdict::resolve(&registry, token) else {
        return Err(error::UsageError::raise(format!(
            "no `[[verdict]]` row declares `{token}`; this registry declares {} class(es)",
            registry.len()
        )));
    };
    let Some(questions) = admission::questions_for(resolved) else {
        // Not a failure of the request — a statement about the class. A class
        // that declares no override route is one this repository decided cannot
        // be overridden, and saying so is more useful than issuing something the
        // gate would then refuse.
        return Err(error::UsageError::raise(format!(
            "{} declares no `override` route, so it cannot be overridden",
            resolved.id
        )));
    };

    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        raw.clear();
    }
    let answers = parse_answers(&raw);
    let missing = admission::unanswered(&questions, &answers);
    if !missing.is_empty() {
        for question in &questions {
            writeln!(err, "{}  {}", question.id, question.prompt)?;
        }
        writeln!(
            err,
            "::error:: {} question(s) unanswered. Answer each as `<id>=<text>` on stdin.",
            missing.len()
        )?;
        return Ok(ExitCode::Usage);
    }

    let head = git::head_commit(root)?;
    // The SAME epoch `config epoch` reports, resolved through the same function,
    // so an admission cannot bind a generation the caller could not look up.
    let (epoch, _) = epoch::describe(root, None)?;
    // `user.email` rather than a name: it is the accountable identity
    // `[attribution]` already decides over, and it is never a model identity
    // (`.claude/rules/commits.md`). An unset one is the empty string rather than
    // a failure — the author is a field of the record, not a precondition of it,
    // and refusing an override because git has no email configured would put a
    // gate in front of the break-glass for a reason unrelated to the situation.
    let author = git::config_value(root, "user.email")
        .ok()
        .flatten()
        .unwrap_or_default();
    let prev = admission::chain_head(root, rule, subject)?;
    let binding = admission::Binding {
        rule: rule.to_owned(),
        verdict: resolved.id.clone(),
        subject: subject.to_owned(),
        head,
        epoch,
        answers,
        prev,
        author,
    };
    let issued = admission::issue(root, binding)?;
    // The admission alone on stdout. It authorizes nothing on its own — the
    // record's existence and state do — which is exactly what makes it safe to
    // print, log, and quote in a commit.
    writeln!(out, "{issued}")?;
    Ok(ExitCode::Success)
}

/// Read `<question-id>=<answer>` lines into an answer map.
///
/// Everything after the FIRST `=` is the answer, so an answer may contain one;
/// a line with no `=` is not an answer and is dropped rather than guessed at.
/// Blank lines are skipped so a caller can lay the block out readably.
fn parse_answers(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let (id, answer) = line.split_once('=')?;
            let id = id.trim();
            (!id.is_empty()).then(|| (id.to_owned(), answer.trim().to_owned()))
        })
        .collect()
}

/// The `-J` shape of [`run_policy_explain`], byte-stable.
///
/// `token` and `resolved` are both carried, and they differ exactly when the
/// asked-for token was a tombstone — which is the one fact a caller reading this
/// programmatically cannot reconstruct from either alone.
fn explain_json(token: &str, resolved: &verdict::DeclaredVerdict, retired: bool) -> Result<String> {
    let routes: Vec<serde_json::Value> = resolved
        .routes
        .iter()
        .map(|route| {
            serde_json::json!({
                "id": route.id,
                "kind": route.kind.as_str(),
                "target": route.target,
                "precondition": route.precondition,
            })
        })
        .collect();
    Ok(serde_json::to_string(&serde_json::json!({
        "token": token,
        "resolved": resolved.id,
        "retired": retired,
        "gloss": resolved.gloss,
        "class": resolved.class.trim(),
        "routes": routes,
    }))?)
}

fn run_policy_test(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let root = Path::new(".");
    let config = resolve::resolve(root, overrides)?;
    let bundles = policy::load(
        root,
        &config.rules,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        policy::ModuleChecks::Run,
        overrides.config_from.as_deref(),
    )?;
    // The same walk the tree engine hoists, so a suite's input carries the same
    // `tracked` a real `check` would hand the bundle (CLOUD-845). Resolved once
    // here rather than per row, for the reason `rules::run` gives.
    // §4's "cheap when irrelevant": a config declaring no policy row pays no
    // walk. `tree_files` walks the whole repository, and this verb reported
    // `0 bundle(s)` after paying for it.
    let tracked = if config
        .rules
        .iter()
        .any(|rule| rule.kind == rules::RuleKind::Policy)
    {
        rules::tree_files(root)?
    } else {
        Vec::new()
    };
    // The same shared acquisition a real `check` does, so a suite's input is the
    // one the engine would build — including the one-read-per-path property
    // (CLOUD-850).
    let documents = rules::acquire_declared(&config.rules, root, &tracked)?;

    let mut reports = Vec::new();
    for rule in config
        .rules
        .iter()
        .filter(|rule| rule.kind == rules::RuleKind::Policy)
    {
        let Some(bundle) = bundles.iter().find(|bundle| bundle.id() == rule.id) else {
            // A row whose bundle never loaded. Not a pass: this verb has nothing
            // to decide with, and reporting clean would be a suite that never
            // ran reading as one that found nothing.
            reports.push(SuiteReport::not_run(&rule.id, Vec::new()));
            continue;
        };
        // The same input a tree-scoped row would hand this bundle. A
        // mediated-call row declares no documents, so its tests run against `{}`
        // and supply their own input with `with input as` — OPA and Conftest's
        // own shape, and the reason neither surface needs a fixture key.
        let (input, not_acquired) = suite_input(rule, &documents, &tracked)?;
        if !not_acquired.is_empty() {
            // Pointer-only (rule 4): the PATH and its stated cause, never a byte
            // of the document. The cause is CLOUD-849's — before it, all four
            // ways a declared document can fail to arrive looked identical here.
            let missing = not_acquired
                .into_iter()
                .map(|(path, why)| format!("{path} ({})", why.as_str()))
                .collect();
            reports.push(SuiteReport::not_run(&rule.id, missing));
            continue;
        }
        match policy::test(bundle, &input)? {
            facts::Look::Is(suite) => reports.push(SuiteReport {
                bundle: rule.id.clone(),
                looked: true,
                missing: Vec::new(),
                passed: suite.passed,
                failed: suite.failed,
                unexercised: suite.unexercised,
                untested_modules: suite.untested_modules,
            }),
            facts::Look::IsNot | facts::Look::CouldNotLook => {
                reports.push(SuiteReport::not_run(&rule.id, Vec::new()));
            }
        }
    }

    if json {
        // Emitted unconditionally, including for a clean run: JSON that is
        // sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&reports)?)?;
    } else {
        for report in &reports {
            for path in &report.missing {
                writeln!(out, "{} {FIXTURE_MISSING} {path}", report.bundle)?;
            }
            if !report.looked && report.missing.is_empty() {
                writeln!(out, "{} {SUITE_NOT_RUN}", report.bundle)?;
            }
            for id in &report.failed {
                writeln!(
                    out,
                    "{} {TEST_FAILED} {} {}",
                    report.bundle, id.module, id.name
                )?;
            }
            for id in &report.unexercised {
                writeln!(out, "{} {PREDICATE_UNEXERCISED} {id}", report.bundle)?;
            }
            for path in &report.untested_modules {
                writeln!(out, "{} {MODULE_UNTESTED} {path}", report.bundle)?;
            }
        }
        let passed: usize = reports.iter().map(|report| report.passed.len()).sum();
        let failed: usize = reports.iter().map(|report| report.failed.len()).sum();
        writeln!(
            out,
            "policy test: {} bundle(s), {passed} passed, {failed} failed",
            reports.len()
        )?;
    }

    // A suite that could not run is exit `1` — the config class — and it wins
    // over a verdict, because a run that did not happen must never be reported
    // as one that found nothing.
    if reports.iter().any(|report| !report.looked) {
        return Ok(ExitCode::Usage);
    }
    Ok(ExitCode::verdict(reports.iter().any(|report| {
        !report.failed.is_empty() || !report.unexercised.is_empty()
    })))
}

/// Resolve the `[attribution]` table, or say why the gate cannot decide.
///
/// An absent table is exit `1`, never a clean pass: "this repository declares no
/// attribution policy" and "these commits are clean" are different answers, and
/// collapsing them would report green over a gate that never ran.
fn attribution_policy(overrides: &Overrides) -> Result<attribution::Attribution> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    config.attribution.clone().ok_or_else(|| {
        UsageError::raise(format!(
            "no [attribution] in {}; there is no attribution policy to judge by",
            config::CONFIG_FILE
        ))
    })
}

/// The `attribution check -J` document (CLOUD-274, CLOUD-276).
///
/// **One shape, always.** Every key is present on every run, including a clean
/// one and one that named no host — a document whose keys come and go is
/// unparseable, and this is the same rule `decision::Caller` keeps for its own
/// three fields: degrade the VALUE, never the shape.
///
/// Field order is struct order rather than a map's, so the emission is
/// byte-stable (§6).
///
/// Pointer-only (rule 4): `findings` carries a label and a field name,
/// `expects` two vocabulary tokens, and `caller` a harness token plus whatever
/// the declared fidelity allowed — never a line of commit content.
#[derive(serde::Serialize)]
struct AttributionDocument<'a> {
    /// Who made the call, captured at the fidelity the named host declares.
    caller: decision::Caller,
    /// What that host is declared to do to a produced commit.
    expects: Vec<Expectation>,
    /// The verdict half, and the only half that reaches the exit code.
    findings: &'a [attribution::Finding],
}

/// One declared attribution row, as the document renders it.
#[derive(serde::Serialize)]
struct Expectation {
    /// The capability's stable token.
    capability: &'static str,
    /// What this host declares for it: `yes`, `no`, `partial` or `unknown`.
    declares: &'static str,
}

/// Resolve the `[commit]` table, or say why the gate cannot decide.
///
/// An absent table is exit `1`, never a clean pass: "this repository declares no
/// commit convention" and "these subjects are conventional" are different
/// answers, and collapsing them would report green over a gate that never ran.
fn commit_policy(overrides: &Overrides) -> Result<commit::Commit> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    config.commit.clone().ok_or_else(|| {
        UsageError::raise(format!(
            "no [commit] in {}; there is no subject convention to judge by",
            config::CONFIG_FILE
        ))
    })
}

fn run_commit_check(
    json: bool,
    range: Option<&str>,
    message: Option<&str>,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    // Exactly one mode. Both is ambiguous, and neither is a run over nothing that
    // would exit 0 — the vacuous pass a gate must never produce.
    let subjects = match (range, message) {
        (Some(_), Some(_)) => {
            return Err(UsageError::raise(
                "commit check: a range and --message name two different objects; pass one"
                    .to_owned(),
            ));
        }
        (None, None) => {
            return Err(UsageError::raise(
                "commit check: pass <base>..<head> or --message <file>; with neither there is \
                 nothing to judge"
                    .to_owned(),
            ));
        }
        (Some(range), None) => {
            let (base, head) = range.split_once("..").ok_or_else(|| {
                UsageError::raise(format!(
                    "commit check: `{range}` is not a <base>..<head> range"
                ))
            })?;
            commit::read_range(Path::new("."), base, head)?
        }
        (None, Some(message)) => vec![commit::read_message(Path::new(message))?],
    };

    let findings = commit_policy(overrides)?.judge(&subjects)?;

    if json {
        // Emitted unconditionally, including for a clean run: JSON that is
        // sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&findings)?)?;
    } else {
        // Silence is the success signal on the human channel (§6).
        write!(out, "{}", commit::report(&findings))?;
    }
    Ok(ExitCode::verdict(!findings.is_empty()))
}

/// Dispatch the `attribution` subtree.
///
/// Split out of [`run`] rather than matched inline: the gate half now threads a
/// harness through (CLOUD-276), and `run` is at its line ceiling — a dispatcher
/// that grows every time one verb gains an argument is the shape that ceiling
/// exists to catch.
fn run_attribution(
    command: AttributionCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        AttributionCommand::Check {
            json,
            range,
            message,
            harness,
        } => run_attribution_check(
            json,
            range.as_deref(),
            message.as_deref(),
            harness,
            overrides,
            out,
        ),
        AttributionCommand::Identity => run_attribution_identity(overrides, err),
    }
}

fn run_attribution_check(
    json: bool,
    range: Option<&str>,
    message: Option<&str>,
    harness: Option<hook::Harness>,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    // Exactly one mode. Both is ambiguous and neither is a run over nothing that
    // would exit 0 — the vacuous pass a gate must never produce.
    let commits = match (range, message) {
        (Some(_), Some(_)) => {
            return Err(UsageError::raise(
                "attribution check: --range and --message name two different objects; pass one"
                    .to_owned(),
            ));
        }
        (None, None) => {
            return Err(UsageError::raise(
                "attribution check: pass --range <base>..<head> or --message <file>; with neither \
                 there is nothing to judge"
                    .to_owned(),
            ));
        }
        (Some(range), None) => {
            let (base, head) = range.split_once("..").ok_or_else(|| {
                UsageError::raise(format!(
                    "attribution check: `{range}` is not a <base>..<head> range"
                ))
            })?;
            attribution::read_range(Path::new("."), base, head)?
        }
        (None, Some(message)) => {
            vec![attribution::read_message(
                Path::new("."),
                Path::new(message),
            )?]
        }
    };

    let policy = attribution_policy(overrides)?;
    let mut findings = Vec::new();
    for commit in &commits {
        findings.extend(policy.judge(commit)?);
    }

    if json {
        // Emitted unconditionally, including for a clean run: JSON that is
        // sometimes absent is unparseable.
        //
        // `None` for both candidate values, and stated rather than left to be
        // inferred: this verb's input is a commit range or a message file, and
        // neither carries a model identity or a session. The offered-value arms of
        // `attribution::capture` — where a declaration REFUSES a value the host
        // did supply — belong to a surface that reads a host payload, which is the
        // provenance record CLOUD-275 owns. They are pinned at the library surface
        // instead, not left unpinned.
        let document = AttributionDocument {
            caller: match harness {
                Some(harness) => attribution::capture(harness, None, None),
                // No host named: three degraded values, which is a different
                // claim from any host's row and must not read as one.
                None => decision::Caller::undeclared(),
            },
            expects: harness
                .map(|harness| {
                    attribution::expectations(harness)
                        .into_iter()
                        .map(|(capability, declares)| Expectation {
                            capability,
                            declares,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            findings: &findings,
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
    } else {
        // Silence is the success signal on the human channel (§6).
        write!(out, "{}", attribution::report(&findings))?;
    }
    Ok(ExitCode::verdict(!findings.is_empty()))
}

fn run_attribution_identity(overrides: &Overrides, err: &mut dyn Write) -> Result<ExitCode> {
    let policy = attribution_policy(overrides)?;
    let outcome = attribution::set_identity(Path::new("."), &policy)?;
    // The report goes to stderr: this is a statement about what Batten did to the
    // clone, not a verdict about the repository, and §6 keeps those channels
    // apart.
    writeln!(err, "{}", outcome.line(&policy.identity))?;
    Ok(ExitCode::Success)
}

/// What a fail-open boundary says on its way out.
///
/// Loud, not silent (CLOUD-43). A guard that cannot read its input is a gate
/// that did not run, and the silent version of that is byte-identical to a clean
/// allow — the false green this engine exists to catch, in the one place nobody
/// would think to look. They go through [`output::message`], so they are
/// `batten: `-prefixed and ladder-gated: this is a statement about Batten, not a
/// verdict, which is exactly the distinction [`output::verdict`]'s unprefixed,
/// ungated shape draws in the other direction.
const UNREADABLE_STDIN: &str =
    "hook: stdin could not be read, so nothing was adjudicated — allowing";
const UNDECODABLE_PAYLOAD: &str =
    "hook: the payload on stdin did not decode, so nothing was adjudicated — allowing";

/// Adjudicate one mediated call read from stdin (CLOUD-202).
///
/// Fail open at every boundary — unreadable stdin, an undecodable payload, an
/// envelope with no command all allow: a guard must never be the reason a
/// session cannot proceed. The bypass env var is the same hatch the shell
/// guards honour, resolved here at the boundary so the core stays pure.
///
/// The deny channel is per-harness — the number is not. The Claude Code adapter
/// answers in the host's JSON decision object (exit 0), where the document *is*
/// the deny; the neutral exit-code adapter denies with [`ExitCode::Violation`],
/// the same code a `check` violation returns, carrying its reason to stderr
/// through [`Denial`] so the write stays at the binary boundary.
/// Print one allowlisted payload field, or nothing (CLOUD-479).
///
/// SILENT ON EVERY FAILURE, and that is the contract rather than an oversight:
/// the callers are shell hooks whose next line is `[ -n "$x" ] || exit 0`, so an
/// unreadable stdin, an undecodable payload and an absent field must all arrive
/// as the same empty answer they get from `jq -r '.x // empty'` today. Anything
/// louder would turn a fail-open guard into one that reports on payloads it was
/// never meant to judge.
///
/// The failure a caller genuinely must NOT miss — the binary being absent
/// entirely — cannot reach this function, and since CLOUD-824 there is no
/// launcher to report it either. `mise-tasks/stop-guard.sh` and
/// `mise-tasks/contract-drift.sh` still carry that half themselves, which is the
/// shape they always had; what is gone is the shell copy they inherited it from.
///
/// Exit is always `Success`: this renders no verdict, so it has none to signal.
fn run_hook_field(
    harness: hook::Harness,
    field: hook::Field,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return Ok(ExitCode::Success);
    }
    if let Some(value) = hook::field(harness, &raw, field) {
        writeln!(out, "{value}")?;
    }
    Ok(ExitCode::Success)
}

/// The receipt verdicts this call's required checks resolve to, read at the
/// boundary.
///
/// Lifted out of [`run_hook`] rather than left inline because that function is
/// held to clippy's 100-line ceiling and this is a self-contained question: what
/// do the receipt store and the agent's own records say about the checks this
/// call's rows require. Everything here LOOKS; `adjudicate` decides — the split
/// the whole boundary keeps, so nothing in this function judges anything.
///
/// `None` throughout means "could not look", which allows.
fn receipt_facts(
    policy: &hook::Policy,
    envelope: &hook::Envelope,
    sourced: &[(&String, &rules::ReceiptKey)],
    store: Option<&receipt::SourcedStore>,
    receipted: &std::collections::BTreeMap<String, rules::ReceiptKey>,
    max_ages: &std::collections::BTreeMap<String, u64>,
    judgeable: bool,
) -> hook::ReceiptFacts {
    // The two non-answers are DIFFERENT answers, and CLOUD-787 is where they
    // stopped being one. `IsNot` is the boundary having looked: no required
    // check selected this call, or the write lands somewhere policy does not
    // judge. `CouldNotLook` is further down, where the receipt store itself
    // could not be read. Both allow, and they are not the same fact.
    //
    // `sourced` and `receipted` are the partition of the required set, so their
    // both being empty IS "no required check selected this call" — read from the
    // two halves rather than from a third parameter carrying the union, which
    // clippy's argument ceiling is right to refuse and which was a second
    // spelling of one fact besides.
    if (sourced.is_empty() && receipted.is_empty()) || !judgeable {
        return facts::Look::IsNot;
    }
    let mut verdicts = if receipted.is_empty() {
        // Nothing to ask the receipt store, having looked: there simply were no
        // receipt-keyed checks among the ones required. An EMPTY map, not a
        // non-answer — the agent-sourced loop below fills it in.
        Some(std::collections::BTreeMap::new())
    } else {
        // The subject a `named`-keyed row files under, resolved HERE because
        // `receipt::verdicts` has no envelope and `adjudicate` may not open a
        // file (CLOUD-987). One value per call: a mediated call names one
        // subject, so the declaring rows cannot disagree about which.
        // The clock is handed in, never taken inside (CLOUD-988), and it is read
        // only when a row declared a bound — an empty `max_ages` means no
        // `SystemTime::now()` and no `stat` on the hottest path in the binary.
        receipt::verdicts(
            receipted,
            policy.named_receipt_subject(envelope).as_deref(),
            max_ages,
            std::time::SystemTime::now(),
        )
    };
    // Each agent-sourced check, decided by the pure predicate over the record
    // the boundary just read. `Look::Is` is the only answer that satisfies a
    // check; never-ran and command-mismatch both arrive as `Missing`, which
    // is the deny that carries the `Fix::Run` asking for the command.
    //
    // A store the boundary could not build takes the WHOLE call to
    // could-not-look (CLOUD-859), rather than leaving these checks out of the
    // map. Leaving them out is not a softer answer: `receipt_rules` reads an
    // absent verdict as `Missing` — deliberately, since a boundary that answered
    // for fewer checks than a row requires has not proved the precondition — so
    // an omission is the strictest answer available, and it would make a
    // checkout with no resolvable HEAD refuse every `gh pr ready` for a property
    // of the environment. This is `receipt::verdicts`'s own posture, where an
    // unresolvable branch takes the call to could-not-look for the same reason.
    if !sourced.is_empty() && store.is_none() {
        return facts::Look::CouldNotLook;
    }
    if let (Some(verdicts), Some(store)) = (verdicts.as_mut(), store) {
        for (check, _) in sourced {
            let Some(declared) = policy.agent_fact(check) else {
                continue;
            };
            let record = store.record(check);
            let verdict = match facts::sourced(record.as_ref(), &declared.command) {
                facts::Look::Is(_) => receipt::Validity::Valid,
                facts::Look::IsNot | facts::Look::CouldNotLook => receipt::Validity::Missing,
            };
            // THE AGE IS READ LAST AND ONLY OVER A VALID RECORD, exactly as
            // `receipt::verdicts` reads it (CLOUD-988): a record already Missing
            // has a more specific answer and a different remedy — *run it*,
            // where this one says *run it again* — and a repository declaring no
            // bound pays no `stat`.
            let verdict = match (verdict, max_ages.get(*check)) {
                (receipt::Validity::Valid, Some(&max_age))
                    if store.expired(check, max_age, std::time::SystemTime::now()) =>
                {
                    receipt::Validity::Expired
                }
                (verdict, _) => verdict,
            };
            verdicts.insert((*check).clone(), verdict);
        }
    }
    // A store the boundary could not read is the could-not-look arm — the one
    // case here that is genuinely "the question could not be asked".
    verdicts.map_or(facts::Look::CouldNotLook, facts::Look::Is)
}

/// Drop every row whose declared `bypass_env` is set in this process's
/// environment (CLOUD-437).
///
/// The environment read lives here rather than in [`hook`] for the reason every
/// other fact does: `adjudicate` is contractually pure, so the boundary looks and
/// the core decides. [`hook::Policy::declared_hatches`] hands back the names and
/// this answers which of them are set.
///
/// **Cheap when irrelevant** (house-style §4). A ruleset declaring no
/// `bypass_env` — every ruleset until one opts in — collects an empty set, reads
/// no environment variable, and clones no policy. This runs on the hottest path
/// in the binary, so that is a requirement rather than a nicety.
fn without_set_hatches(policy: hook::Policy) -> hook::Policy {
    let set: std::collections::BTreeSet<String> = policy
        .declared_hatches()
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .map(std::borrow::ToOwned::to_owned)
        .collect();
    if set.is_empty() {
        return policy;
    }
    // The row is REMOVED rather than its refusal suppressed, so the rows behind
    // it still fire. See `hook::Policy::without_hatched`.
    policy.without_hatched(&set)
}

fn run_hook(
    harness: hook::Harness,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        output::message(mode, Verbosity::Normal, err, UNREADABLE_STDIN)?;
        return Ok(ExitCode::Success);
    }
    let bypass = std::env::var_os(hook::BYPASS_ENV).is_some_and(|value| !value.is_empty());
    let Some(envelope) = hook::decode(harness, &raw) else {
        output::message(mode, Verbosity::Normal, err, UNDECODABLE_PAYLOAD)?;
        return Ok(ExitCode::Success);
    };
    // The capability table, consulted before anything keys on the event
    // (CLOUD-45). A host that does not declare this event fires nothing and
    // allows — never an error, never a deny: an absent capability is a statement
    // about the host, and refusing the call would make Batten the reason a
    // session cannot proceed on a host that simply offers less.
    //
    // The note rides the ladder above `normal`, because on the hosts where this
    // is reachable it is the ordinary state rather than news.
    let capabilities = harness.capabilities();
    if !capabilities.emits(envelope.event) && envelope.event != hook::Event::Unrecognized {
        let note = match capabilities.degrade(envelope.event) {
            Some(fallback) => format!(
                "{} does not emit {}; a policy keyed on it watches {} here",
                harness.as_str(),
                envelope.event.as_str(),
                fallback.as_str()
            ),
            None => format!(
                "{} does not emit {}; nothing keyed on it fires here",
                harness.as_str(),
                envelope.event.as_str()
            ),
        };
        output::message(mode, Verbosity::Verbose, err, &note)?;
        return Ok(ExitCode::Success);
    }
    // The advisory drain rides the BATCH boundary (CLOUD-79), and which event
    // that is on this host is the capability table's answer rather than a literal
    // here (CLOUD-389). `degrade` hands back `PostToolBatch` where the host emits
    // it and `PostTool` where it does not, so the exact boundary is used wherever
    // it exists and the coalescing window stays the fallback for the four
    // surveyed hosts that offer none.
    //
    // Asking through `degrade` rather than testing two events is what keeps the
    // rule in one place: a second `||` here would be a copy of the table that
    // could disagree with it, and the drain would then own a fact about hosts.
    //
    // It is not part of adjudication and cannot become part of it: `adjudicate`
    // stays a pure function of config plus argv, this is a side effect at the
    // boundary, and it returns nothing the decision reads. This boundary is where
    // it belongs precisely because no host offers a deny channel at either event
    // — an advisory surface at an event that cannot refuse anything is
    // structurally unable to block (house-style §0.3).
    //
    // Both advisory producers WRITE INTO one buffer rather than each emitting:
    // the channel is one document per call on every host that has one, so two
    // emits on the same batch would put two JSON documents on stdout and the
    // host would read the first and discard the rest. Coalescing here is also
    // the honest shape — they are two findings of one advisory, not two
    // channels.
    let mut advice: Vec<String> = Vec::new();
    collect_batch_advice(harness, &envelope, overrides, mode, err, &mut advice)?;
    // NOT EMITTED HERE ANY MORE (CLOUD-898). A third producer arrived — a
    // dispatched handler — and its answer does not exist until config is
    // resolved, which happens below. Emitting here would put a second JSON
    // document on stdout for any event where a handler also speaks, which is the
    // exact defect the coalescing above was added to fix. So the buffer is
    // filled here and drained at ONE site further down. Safe because nothing
    // between the two points returns early: the only escapes are `?` on a config
    // failure, which is exit 3, and losing an advisory on a run that could not
    // read its own authority is the correct trade.
    // Only now is config touched. Ordering the cheap refusals first is §4's
    // "cheap when irrelevant" applied to the hottest path in the binary — this
    // runs on every mediated tool call — and it is also what keeps a bypassed or
    // command-less call from being able to fail on an unrelated config error.
    //
    // "Command-less" is no longer the same claim as "nothing to judge": a write
    // tool carries a path and no command, and skipping the config load for it
    // is what made the write matcher unjudgeable even once `adjudicate` grew
    // the gate (CLOUD-312). The cheap-refusals-first ordering is intact — a
    // bypassed call, and a payload that is neither a command nor a write, still
    // never touch config.
    // THE OTHER HALF OF THE LOOP (CLOUD-776). A gate denied with `Fix::Run`; the
    // agent ran that command with its own binary; the harness is handing the
    // result back right now. Record what it said, so the retry has a fact.
    //
    // Before the config load below and deliberately cheap when irrelevant: the
    // recorder asks whether this call carries a result at all before it asks
    // policy anything, so a post-tool event for any other command — which is
    // nearly all of them, now that batten is registered on every surface — does
    // no config work here.
    //
    // Failure is silent by design. A hook that cannot write a fact must not
    // become the reason work stops; the retry will simply deny again with the
    // same `Fix::Run`, which is the safe direction and a visible one.
    if envelope.event == hook::Event::PostTool {
        record_post_tool(overrides, &envelope, harness, &mut advice);
    }
    // THE SAME CORRECTION AGAIN, ONE SELECTOR LATER (CLOUD-924). The paragraph
    // above records CLOUD-312 finding that "command-less" had stopped meaning
    // "nothing to judge" once a write could be judged, and widening this
    // condition is what made the write matcher reachable. A tool selector does
    // it a second time: a `mediated_call` row may now be keyed on the TOOL a
    // call names, and an MCP call, a `Read` and a `Task` spawn carry neither a
    // command nor a write — so a repository declaring such a row had its rows
    // loaded for no call that could match them, and `adjudicate` was handed
    // `Policy::declaring_nothing` however carefully its gate was written.
    //
    // **THE COST IS REAL AND IS PAID HERE RATHER THAN HIDDEN.** `perf`'s
    // `passthrough` arm is exactly this shape — a `Read` with a `file_path`,
    // no command, no write — and its below-`noop` reading came from taking the
    // skip. That reading is load-bearing (`.claude/rules/rust.md`), so it is
    // re-measured with `perf-pair` against the merge base rather than argued
    // about, and the number travels with the change.
    //
    // The cheap refusals stay first and stay cheap: a bypassed call still never
    // touches config, and so does every event that is not the adjudicated one.
    // What is no longer free is a PreToolUse call with a tool name, which is the
    // one shape a tool-keyed row exists to judge — buying that back would mean
    // knowing whether any such row is declared, which is a question only the
    // config can answer.
    // Named `adjudicable` rather than `judgeable`: the latter is taken a few
    // lines below for a different question — whether a WRITTEN PATH is one
    // policy judges at all — and two bindings one letter apart deciding
    // different things is how a later edit reads the wrong one.
    //
    // THE SAME CORRECTION A THIRD TIME, AND IT WAS A DEAD GATE (CLOUD-1051). A
    // `Stop` payload carries no command, no write and no tool name, so this
    // predicate was false for every end of turn and the config was never loaded
    // there — which meant `Policy::declaring_nothing`, no bundles, and a
    // `mediated_call` module registered for the one moment that projects
    // `final-message` could not run at all. `policy/stop-posture.rego` shipped
    // in exactly that state and its own suite stayed green throughout, because a
    // `with input as` case fabricates the shape the boundary never built.
    //
    // The cost is one config load per TURN, not per call, and it buys the whole
    // end-of-turn surface. The retired shell hook this replaces paid ~330-440ms
    // at the same boundary; `perf`'s `passthrough` and `noop` arms are pre-tool
    // shapes and are untouched by this clause.
    let adjudicable = !envelope.command.is_empty()
        || envelope.writes.is_some()
        || envelope.event == hook::Event::Stop
        || (envelope.event == hook::Event::PreTool && !envelope.raw_tool.is_empty());
    let (policy, waivers) = if bypass || !adjudicable {
        (hook::Policy::declaring_nothing(harness), Vec::new())
    } else {
        load_policy(overrides, harness)?
    };
    // THE PER-ROW HATCHES (CLOUD-437), resolved here and nowhere earlier.
    //
    // `BYPASS_ENV` is read before the config load above, because a bypassed call
    // must never pay for one. These cannot be: which hatches exist is a property
    // of the loaded rows, so the read has to follow the load. That ordering is
    // the whole reason the general hatch survives as a separate switch rather
    // than becoming just another row's name.
    //
    // Cheap when irrelevant (§4): a ruleset declaring no `bypass_env` — every
    // ruleset until one opts in — collects an empty set, reads no environment,
    // and clones no policy.
    let policy = without_set_hatches(policy);
    // The receipt facts, resolved HERE because `adjudicate` is contractually
    // pure — no I/O, no environment, no clock — and a receipt predicate reads a
    // file and two git refs. Same split the bypass hatch already uses: the
    // boundary looks, the core decides.
    //
    // Resolved only for the names the policy actually requires, so a repository
    // declaring no receipt row does no git work at all on the hottest path in
    // the binary. `None` throughout means "could not look", which allows.
    //
    // A write-triggered row (CLOUD-444) adds one more boundary question before
    // the store is consulted: is the written path one policy judges at all? The
    // exclusions — git-ignored, outside the repository, inside `.git` — are
    // properties of a checkout, so they resolve here and reach `adjudicate` as
    // the same "nothing to answer" absence a failed lookup produces. The
    // `check-ignore` behind it runs only when a write-triggered row actually
    // selected, so a repository declaring none pays nothing for it.
    let required = policy.required_checks_for(&envelope);
    let judgeable = envelope.writes.as_deref().is_none_or(receipt::judgeable);
    // CLOUD-988's declared bounds, resolved beside the checks they qualify.
    let max_ages = policy.max_age_for(&envelope);
    // An AGENT-SOURCED check is resolved from its own record rather than from the
    // receipt store (CLOUD-776), so the two are split before either is read: a
    // repository whose required checks are all agent-sourced must not pay
    // `receipt::verdicts`'s git work for questions it is not asking.
    let (sourced, receipted): (Vec<_>, Vec<_>) = required
        .iter()
        .partition(|(check, _)| policy.agent_fact(check).is_some());
    let receipted: std::collections::BTreeMap<_, _> = receipted
        .into_iter()
        .map(|(check, key)| (check.clone(), *key))
        .collect();
    // Where each agent-sourced record lives on THIS call, resolved once for both
    // readers (CLOUD-859). A record is filed under the subject its receipt row's
    // `key` names, so the boundary resolves that subject here — `adjudicate` may
    // not look, and resolving it per reader would let the two disagree.
    let sourced_store =
        receipt::sourced_store(&sourced, policy.named_receipt_subject(&envelope).as_deref());
    let receipts: hook::ReceiptFacts = receipt_facts(
        &policy,
        &envelope,
        &sourced,
        sourced_store.as_ref(),
        &receipted,
        &max_ages,
        judgeable,
    );
    let agent_sourced = agent_records(&sourced, sourced_store.as_ref());
    // The key evidence (CLOUD-446), resolved on the same terms and for the same
    // reason: two git queries a pure `adjudicate` cannot make, spent only when a
    // `requires_key` row has already selected this command. A repository
    // declaring none — and a call matching none, which is nearly every call —
    // does no git work here at all.
    // `IsNot` where no `requires_key` row selected this command: the boundary
    // looked and there is no key question. `key_facts` answers the other two.
    let keys: hook::KeyFacts = policy
        .key_base_for(&envelope)
        .map_or(facts::Look::IsNot, key_facts);
    // The waiver facts (CLOUD-610), resolved HERE for exactly the reason above:
    // a waiver lapses on a date, `adjudicate` is contractually pure, and reading
    // the clock inside it would dissolve the contract rather than satisfy it.
    // The boundary already reads a clock for `check`'s tree filter, so this is
    // the one edge where the environment is legible, not a new one.
    //
    // Cheap when irrelevant, the same narrowing `required_checks_for` applies:
    // an empty waiver table skips `today()` entirely, so a repository declaring
    // no waiver pays no clock read on the hottest path in the binary. `today()`
    // can fail — a clock before the epoch — and that propagates rather than
    // defaulting, because a date nobody could read must not silently become a
    // table where every waiver is live.
    let waived = if waivers.is_empty() {
        waiver::Live::new()
    } else {
        waiver::live(&waivers, waiver::today()?)
    };
    // The declared side effects (CLOUD-91), fired BEFORE the decision is written
    // and structurally unable to reach it: `action::fire` returns nothing, so
    // there is no value here to branch on even by mistake.
    //
    // Ordering matters twice. Before `decide`, because `decide` owns stdout and
    // an action's report must not interleave with a decision document a host is
    // parsing. And after the capability check above, which is what makes "a host
    // lacking the capability fires nothing" structural rather than a second
    // check this call site could get wrong.
    fire_actions(&envelope, bypass, overrides, err)?;
    // The end-of-turn facts (CLOUD-85) are NOT resolved, because nothing reads
    // them (CLOUD-906). They used to be, on the stop event only, for `receipts`'
    // reason: `adjudicate` is contractually pure and this reads git and the
    // findings store. That reasoning was right and is now moot.
    //
    // Their one consumer is the policy-input projection's `Fact::Stop` arm — and
    // since CLOUD-889 `adjudicate` returns `Allow` at `Event::Stop` before any
    // rule or module is evaluated, so at Stop the early return precedes the
    // projection, and on every other event this was already the default. The
    // resolved value could not be observed on any path, so every turn paid a git
    // read plus a findings-store read for it.
    //
    // Removed rather than commented as kept-for-later: paying two reads per turn
    // against a consumer that does not exist is speculative, and "kept for a
    // future consumer" is the deferral this repository names a punt. CLOUD-892
    // moves the Stop surface into Rego and gives `Fact::Stop` a reachable
    // consumer; it resolves what it reads, where it reads it. `stop_facts` and
    // its module stay — this drops the call, not the capability.
    let stop = stop::StopFacts::default();
    let prospective = prospective_for(&policy, &envelope);
    // The reading manifest (CLOUD-925), resolved here because the tracked set is
    // a property of a checkout and `adjudicate` is contractually pure.
    //
    // Behind the CLOUD-460 narrowing, and the narrowing is the whole cost story:
    // `manifest_for` asks the row table first, so a repository declaring no
    // `tracked-artifacts` ceiling — which is every repository today — spawns no
    // git and opens nothing. `None` is could-not-look and allows.
    let manifest = manifest_for(&policy, &envelope);
    let facts = hook::Facts {
        bypass,
        receipts: &receipts,
        keys: &keys,
        stop: &stop,
        waived: &waived,
        sourced: &agent_sourced,
        prospective: &prospective,
        manifest,
    };
    // THE DOOR (CLOUD-898). Declared handlers run here, under the contract in
    // `crate::handler`: bounded by the parent, fail-open on anything they break,
    // and read rather than forwarded. Their advice joins the one buffer above;
    // their violations join it too, because a handler that broke the contract is
    // something its author must see and nothing else will tell them.
    //
    // AFTER `fire_actions` and BEFORE `decide`, and both halves matter. After,
    // because an action is a side effect that cannot change the answer and a
    // handler can — running the ones that cannot first keeps the ordering a
    // reader would guess. Before, because `decide` owns stdout and a handler's
    // refusal has to reach the same rendering the engine's own does.
    let handled = dispatch_handlers(&envelope, &raw, bypass, overrides, &mut advice)?;
    // THE END-OF-TURN NUDGE (CLOUD-1051), and it is a SEPARATE call from
    // `adjudicate` rather than a widening of it. `adjudicate` returns `Allow` at
    // `Stop` before any rule is read — CLOUD-889's runaway removed by
    // construction — which also meant a `mediated_call` module never ran there,
    // so `stop-posture` was a dead gate for its whole life. `hook::stop_advice`
    // evaluates the modules and answers with TEXT, so there is no value it can
    // return that refuses anything.
    //
    // AT MOST ONE NUDGE PER TURN, and that is the retired shell hook's measured
    // rule rather than a new one: two nudges on one turn is how a channel stops
    // being read. A turn already handed a handler's advice has been told
    // something more specific, so the module's line is appended only to a silent
    // buffer.
    if advice.is_empty()
        && let Some(nudge) = hook::stop_advice(&policy, &envelope, &facts)
            .or_else(|| stop_nudges(overrides, &envelope))
    {
        advice.push(nudge);
    }
    if !advice.is_empty() {
        emit_advisory(harness, &envelope, out, err, &advice.join("\n\n"))?;
    }
    let decision = handled.unwrap_or_else(|| hook::adjudicate(&policy, &envelope, &facts));
    // Resolved HERE rather than inside `render`, because `render` deliberately
    // cannot see the policy (CLOUD-898) and that property is worth more than the
    // convenience: a renderer that cannot see the inputs cannot re-decide by
    // accident. A hatch NAME is not such an input — it is a string the renderer
    // prints and never branches on — so handing it over costs nothing.
    let hatch = match &decision {
        hook::Decision::Deny(refusal) | hook::Decision::Ask(refusal) => {
            policy.bypass_env_for(refusal.rule()).to_owned()
        }
        // Nothing is being refused, so nothing advertises a hatch. The general
        // name stands in rather than an empty string: the value is unread on
        // these arms, and a blank one would render as `Bypass with =1.` if a
        // later arm ever did read it.
        _ => hook::BYPASS_ENV.to_owned(),
    };
    render(harness, &envelope, decision, &hatch, mode, out, err)
}

/// Fill the advisory buffer from the two producers that ride a batch boundary.
///
/// Split out of `run_hook` so the batch-boundary question lives in one place —
/// and because `run_hook` is the hottest function in the binary and every line
/// in it is read by somebody diagnosing a mediated call.
///
/// Which event IS the boundary is the capability table's answer rather than a
/// literal here (CLOUD-389): `degrade` hands back `PostToolBatch` where the host
/// emits it and `PostTool` where it does not, so asking through the table is
/// what keeps the rule in one place. A second `||` here would be a copy of that
/// table that could disagree with it.
fn collect_batch_advice(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
    advice: &mut Vec<String>,
) -> Result<()> {
    if Some(envelope.event) == harness.capabilities().degrade(hook::Event::PostToolBatch) {
        drain_advisories(envelope, overrides, mode, err, advice)?;
    }
    report_contract_drift(envelope, overrides, advice);
    Ok(())
}

/// Run the declared handlers for this envelope's event (CLOUD-898).
///
/// Returns the decision a handler forced, if any, and appends its advice and its
/// contract violations to `advice`. A handler that refuses becomes a
/// [`hook::Decision::Deny`] rendered by `decide`, so a handler's refusal and the
/// engine's own travel the identical per-host channel — the point of the door
/// being that a dispatched program cannot invent a second one.
fn dispatch_handlers(
    envelope: &hook::Envelope,
    raw: &str,
    bypass: bool,
    overrides: &Overrides,
    advice: &mut Vec<String>,
) -> Result<Option<hook::Decision>> {
    if bypass {
        return Ok(None);
    }
    // `fire_actions`' reading, for `fire_actions`' reason: a handler table is a
    // per-repository declaration, so it comes from the REPOSITORY's authority
    // rather than the cwd's (CLOUD-824).
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(None);
    }
    let Some(hook_config) = resolve::resolve(here, overrides)?.hook else {
        return Ok(None);
    };
    // CLOUD-460's narrowing, and the reason `pre-tool` is affordable at all: a
    // repository declaring no handler for this event pays one slice scan and
    // never reaches a spawn.
    if !handler::selects(&hook_config.handlers, envelope.event, &envelope.raw_tool) {
        return Ok(None);
    }
    let dispatched = handler::dispatch(
        &hook_config.handlers,
        envelope.event,
        &envelope.raw_tool,
        raw,
    );
    advice.extend(dispatched.advice());
    advice.extend(dispatched.violations());
    // A REFUSAL IS DEMOTED TO ADVICE ON A MOMENT THAT CANNOT CARRY ONE, and this
    // is the door's own loophole rather than a hypothetical. CLOUD-889 made
    // `adjudicate` structurally unable to refuse at `Stop` — that is what ended
    // the runaway this branch is named after — and `run_hook` reads
    // `handled.unwrap_or_else(|| adjudicate(..))`, so a handler's `Deny` REPLACES
    // that decision instead of being reconciled with it. A `[[hook.handler]]
    // on = "stop"` exiting 2 would therefore refuse every turn, unbounded by
    // `stop_active`, through the exact path the branch opened. The same hole runs
    // one event wider: `session-start`, `config-change` and `task-completed` all
    // return `Allow` before any rule is read, for their own stated reasons.
    //
    // So the handler still RUNS on those events and still speaks — its reason
    // becomes advice, which is the channel those moments do have — and what it
    // cannot do is convert that into a verdict the engine itself declines to
    // reach. `Event::carries_a_verdict` is the one authority both producers ask,
    // so this cannot drift from `adjudicate`'s arms.
    let Some((id, reason)) = dispatched.refusal() else {
        return Ok(None);
    };
    if !envelope.event.carries_a_verdict() {
        advice.push(format!("hook.handler.{id}: {reason}"));
        return Ok(None);
    }
    Ok(Some(hook::Decision::Deny(
        crate::refusal::Refusal::declared(
            format!("hook.handler.{id}"),
            verdict::Native::HandlerDenied,
            // THE HANDLER'S OWN WORDS TRAVEL AS A SUBJECT, not as the reason
            // (CLOUD-1050). The class is Batten's — "a configured hook handler denied
            // the call" — and the handler's text is what it denied over, which is a
            // subject of that class rather than a competing statement of it. Keeping
            // it in the `reason` slot would have made a class Batten declares
            // indistinguishable from free text a third party wrote.
            &[verdict::Subject::Artifact {
                artifact: reason.to_owned(),
            }],
            // A handler's reason may or may not name a remedy, so the fix falls back
            // to the class's declared route rather than being invented here. §5's
            // "every refusal names something to run" is now the REGISTRY's obligation
            // and `verdict::validate` refuses a class that fails it.
            crate::refusal::Fix::None,
        ),
    )))
}

/// Assemble a `requires_key` row's checkout evidence (CLOUD-446).
///
/// Two queries, and every failure among them reads as **could not look** — which
/// allows. That is the fail-open posture the bash guard it ports had at each of
/// the same points (`|| exit 0`), and it is the right one for a hook: refusing
/// because there is no checkout would make Batten the reason a call cannot run,
/// in exactly the directories it governs nothing.
///
/// A detached HEAD is not a failure, only a missing *source*: the commit
/// messages still answer, so the evidence is the shorter list rather than
/// `None`. `base` failing to resolve is a failure, because with no range there
/// is no commit evidence at all and the branch name alone would be a narrowing
/// nobody wrote.
///
/// **A shallow clone is the same failure, and it is the one that was measured.**
/// Truncated history means the range holds a suffix of the work rather than the
/// work, so "no commit names a key" is a statement about what was fetched. CI
/// takes its base with `git fetch --depth=1` and its head at the same depth, and
/// the first version of this refused every PR there — a gate that fired on the
/// one checkout its predicate cannot be evaluated in. It is checked before the
/// range is read rather than after, because a truncated range answers
/// confidently and wrongly.
/// What the agent reported for each agent-sourced check (CLOUD-776, CLOUD-834).
///
/// **The records themselves, kept rather than discarded once the receipt-side
/// verdict is derived.** A `Validity` answers "is this check satisfied"; the
/// record answers "what did the agent run, and what did it find". `facts.rs`
/// gives those two questions two variants, so the policy input carries them
/// under two keys — folding one into the other would leave
/// [`facts::Fact::AgentSourced`] with no spelling of its own, which is the
/// "exactly one key" property CLOUD-834 asserts.
///
/// Same narrowing as every other fact on this path: `checks` is empty unless a
/// required check is agent-sourced, so a repository declaring none pays nothing
/// and the answer is `None` rather than an empty map.
fn agent_records(
    checks: &[(&String, &rules::ReceiptKey)],
    store: Option<&receipt::SourcedStore>,
) -> hook::AgentFacts {
    if checks.is_empty() {
        return None;
    }
    // A store that could not be built answers `None` for the same reason an
    // empty `checks` does: there is nothing this boundary looked at, so the
    // policy input carries no records rather than an empty map asserting there
    // are none.
    let store = store?;
    let mut records = std::collections::BTreeMap::new();
    for (check, _) in checks {
        if let Some(record) = store.record(check) {
            records.insert((*check).clone(), record);
        }
    }
    Some(records)
}

/// The checkout evidence behind a `requires_key` row, or the reason there is none.
///
/// Every early return here is [`facts::Look::CouldNotLook`] and each is the same
/// kind of failure: no checkout, a shallow clone whose history is not there to
/// read, or a `base` git cannot resolve. None of them is "looked and found no
/// key" — that answer belongs to the caller, which knows whether any row asked
/// (CLOUD-787).
fn key_facts(base: &str) -> hook::KeyFacts {
    let inner = || -> Option<Vec<String>> {
        let repo = git::repo_root(Path::new(".")).ok()?;
        if git::is_shallow(&repo).ok()? {
            return None;
        }
        let messages = git::log_messages(&repo, base).ok()??;
        let mut evidence = vec![messages];
        evidence.extend(git::current_branch(&repo).ok().flatten());
        Some(evidence)
    };
    inner().map_or(facts::Look::CouldNotLook, facts::Look::Is)
}

/// Assemble the end-of-turn gate's inputs (CLOUD-85).
///
/// **Outside a repository, both inputs are absent rather than clean.** `batten
/// hook` is registered once and then mediates every turn in whatever directory
/// the agent is in; answering "nothing is at risk" for a directory Batten does
/// not govern would be a claim nobody made, and answering "deny" would make the
/// guard the reason a turn cannot end.
///
/// **Uncalled today, and kept rather than deleted** (CLOUD-906). `run_hook`
/// stopped resolving these because nothing could observe the result; what stays
/// here is the semantics above, which is the part worth keeping and the part a
/// rewrite would get wrong. CLOUD-892 gives `Fact::Stop` a reachable consumer
/// and is where the call comes back.
///
/// `#[expect]` rather than `#[allow]` for the spawn census's reason: the day a
/// caller returns, this annotation is unfulfilled and goes red, so the licence
/// is deleted by whoever restores the call instead of outliving it.
#[expect(
    dead_code,
    reason = "CLOUD-906: the only consumer is unreachable until CLOUD-892 moves the Stop surface into Rego; the semantics are what is being kept"
)]
fn stop_facts(overrides: &Overrides) -> Result<stop::StopFacts> {
    let here = Path::new(".");
    let Ok(repo) = git::repo_root(here) else {
        return Ok(stop::StopFacts::default());
    };
    // Config is optional here, unlike for the mediated-call policy: the at-risk
    // half is a property of the checkout and answers with or without a
    // `batten.toml`, and the config-supplied target simply goes unset.
    let target = if here.join(config::CONFIG_FILE).exists() {
        resolve::resolve(here, overrides)?.must_land_on.clone()
    } else {
        None
    };
    // A store this checkout is not bound to yields no denials — an answer, not a
    // gap. `resolve` reads and never writes, which is what keeps the stop gate's
    // `read` effect honest.
    let store_dir = store::bound_dir(&store::resolve(&repo)?);
    stop::facts(Some(&repo), target.as_deref(), store_dir.as_deref())
}

/// Spawn the `[[hook.action]]` rows declared for this envelope's event.
///
/// Reads config on its **own** path rather than reusing [`load_policy`]'s
/// result, because the two answer different questions: the policy is the
/// mediated-call rule set and is deliberately not loaded for a bypassed or
/// nothing-to-judge call, while the action table is keyed on the event alone.
///
/// The hot path is preserved all the same, and structurally: `action::validate`
/// refuses an action on `pre-tool`, so this returns before touching config for
/// the one event that runs on every mediated tool call.
///
/// A bypassed run fires nothing. `BATTEN_HOOK_BYPASS` means "do not mediate this
/// call", and spawning the operator's cleanup command while claiming not to be
/// mediating would be the surprising reading.
fn fire_actions(
    envelope: &hook::Envelope,
    bypass: bool,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<()> {
    if bypass || envelope.event == hook::Event::PreTool {
        return Ok(());
    }
    // The REPOSITORY's authority, not the cwd's (CLOUD-824). Same reading as
    // `load_policy` below and for the same reason: an action table is a
    // per-repository declaration, and reading it from a linked worktree's
    // checkout would fire a different set depending on which ref that worktree
    // sits on. Resolved after the two refusals above, so a bypassed or pre-tool
    // call still pays nothing.
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(());
    }
    let Some(hook_config) = resolve::resolve(here, overrides)?.hook else {
        return Ok(());
    };
    action::fire(
        &hook_config.actions,
        envelope.event,
        action::Facts {
            event: envelope.event.as_str(),
            tool: &envelope.raw_tool,
            path: envelope.writes.as_deref().unwrap_or_default(),
            session: envelope.session.as_deref().unwrap_or_default(),
        },
        err,
    );
    Ok(())
}

/// Wake the advisory drain for this batch boundary (CLOUD-79).
///
/// **Every early return here is a decision, not an omission.** This runs on every
/// post-tool event of every session on every host, most of them in directories
/// that are not Batten repositories, so the ladder of refusals below is ordered
/// cheapest-first (§4) and each one is the honest reading of its condition:
///
/// * not a repository, or no committed authority → the drain has no policy to
///   pace itself from and no store to read;
/// * no bound store → nothing has ever been recorded here, so there is nothing
///   to drain. An unbound store is an ordinary first-run state, not an error;
/// * no session id → the host reported none, so there is no key under which a
///   window could be remembered. CLOUD-43's contract is that a missing session
///   degrades to **per-invocation** handling, and per-invocation is precisely
///   the once-per-verifier behaviour a coalescing window exists to prevent — so
///   the honest degradation is to hold the wake rather than to drain on each
///   one. It is reported on the verbose rung, because on a host that never sends
///   a session this is the ordinary state rather than news.
///
/// A drain failure is **fail-loud and never a deny**: the error propagates to the
/// binary boundary as an ordinary failure, where §7 spends `1`/`3`, neither of
/// which any host reads as a refusal.
/// Put one advisory in front of the model, on whichever channel this host
/// actually delivers (CLOUD-461).
///
/// **The choice is the capability table's, asked about this event's host
/// spelling**, so no caller reconstructs it from a harness name. `Some` body
/// means the host reads an in-band document on exit 0 and the advisory goes to
/// **stdout**; `None` means it declares no such channel and the text stays on
/// stderr, where it is the operator's rather than the model's.
///
/// **Never a verdict, on either branch.** [`hook::encode_advice`] emits an
/// object with no `permissionDecision` field, the exit code is untouched, and
/// this runs only at a boundary where `adjudicate` has already returned
/// `Allow` — so stdout carries at most one document per invocation and none of
/// them can refuse a call. An advisory surface that could block would be a gate
/// (house-style §0.3), and `drain.rs` states that as its own contract.
fn emit_advisory(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    out: &mut dyn Write,
    err: &mut dyn Write,
    text: &str,
) -> Result<()> {
    match hook::encode_advice(harness, &envelope.raw_event, text)? {
        Some(body) => {
            writeln!(out, "{body}")?;
        }
        // No reachable channel: silence toward the model, and the text stays on
        // the operator's stream. Not a deny and not an error — an advisory that
        // degraded to either would invent a verdict nobody wrote, which is the
        // mirror of the inversion `encode_ask` refuses.
        None => output::verdict(err, text)?,
    }
    Ok(())
}

/// Tell this session what moved under it, once per change-set (CLOUD-461).
///
/// Fails **open** on everything it cannot establish — not a repository, no
/// committed authority, no `[contract]` table, an unreadable snapshot — because
/// the cost of a missed notice is one reminder and the cost of a refusing
/// reporter is a blocked call at a moment nothing is meant to be blocked at.
///
/// The write happens **before** the emit and is the rate limit itself, the same
/// shape `Decision::Waived`'s audit line has: `adjudicate` is pure and owns no
/// channel, so the boundary both speaks and records, and the two cannot disagree
/// about whether a notice was spent. Recording first is the direction that fails
/// safe — a snapshot written for a notice nobody read costs one missed reminder,
/// where a notice read but unrecorded costs an unbounded repeat of it.
fn report_contract_drift(
    envelope: &hook::Envelope,
    overrides: &Overrides,
    advice: &mut Vec<String>,
) {
    // The two events that carry the predicate, tested HERE rather than at the
    // call site so the function owns which moments it serves.
    //
    // `SessionStart` is load-bearing rather than merely convenient: an
    // autonomous session's first batch is routinely fetch-and-rebase, so a
    // snapshot seeded at the END of that batch would record post-rebase state
    // and the session would never learn what moved under it.
    //
    // Both are events no host offers a deny channel for, which is what makes
    // this structurally unable to become part of adjudication.
    if !matches!(
        envelope.event,
        hook::Event::PostToolBatch | hook::Event::SessionStart
    ) {
        return;
    }
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return;
    }
    let Ok(repo) = git::repo_root(here) else {
        return;
    };
    let Ok(git_dir) = git::git_dir(&repo) else {
        return;
    };
    // Fail open, per the contract above: an authority this reporter cannot read
    // and a surface it cannot hash are both "could not establish", and neither
    // may become an error out of `run_hook` on an event nothing is meant to be
    // blocked at.
    let Ok(resolved) = resolve::resolve(here, overrides) else {
        return;
    };
    let Some(declared) = resolved.contract else {
        return;
    };
    let Ok(facts::Look::Is(current)) = contract::surface(&repo, &declared.tracked) else {
        return;
    };
    let session = envelope.session.as_deref();

    // No snapshot is the FIRST batch of this session, seeded silently. A session
    // that started after a change has already read the new files at start, and
    // nudging it about them is the noise that gets an advisory channel ignored.
    let facts::Look::Is(previous) = contract::previous(&git_dir, session) else {
        drop(contract::record(&git_dir, session, &current));
        return;
    };

    let change = contract::compare(&previous, &current);
    if change.is_empty() {
        return;
    }
    // Recorded BEFORE the emit: a notice the agent saw and the snapshot did not
    // record is a notice the next batch repeats, which is precisely the nagging
    // this bound exists to stop. Erring toward one missed reminder beats erring
    // toward an unbounded stream of the same one.
    // An unwritable snapshot costs a repeated notice, never a refused call.
    drop(contract::record(&git_dir, session, &current));
    advice.push(contract::render(&change, &declared.wiring));
}

/// What this call's write would land, resolved only if a row asks (CLOUD-758).
///
/// The narrowing IS the cost argument. `facts::PROSPECTIVE` is `read` rather
/// than `free` because the edit shape needs the file off disk, and that price is
/// only acceptable because a repository declaring no content-keyed row — and any
/// call that is not a write — never pays it. Same discipline as
/// `Policy::required_checks_for` and `Policy::key_base_for`, which is CLOUD-460's
/// lesson: a call no row selects for does less work than `--help`.
///
/// The un-asked answer is `CouldNotLook` rather than an empty string, because
/// "nobody looked" and "the write is empty" are different claims and a content
/// predicate must never confuse them.
/// How many tracked artifacts this call's measured projection names (CLOUD-925).
///
/// **The column test comes before any work**, so a repository declaring no
/// `tracked-artifacts` ceiling pays one pass over rows it has already loaded and
/// touches neither git nor the filesystem — CLOUD-460's shape, applied to the one
/// unit of this feature that acquires anything.
///
/// `None` throughout means could-not-look, which allows: a ceiling that could not
/// count must not refuse. That is deliberately distinct from `Some(0)`, which is
/// "counted, and it names nothing".
///
/// The candidate set is derived from the projection exactly as the shell guard
/// derived it — path-shaped tokens, then the intersection with the tracked set —
/// and the consumer's own shorthand is applied first through the row's `resolves`
/// table, so no reference convention reaches this crate (non-negotiable rule 1).
fn manifest_for(policy: &hook::Policy, envelope: &hook::Envelope) -> hook::ManifestFacts {
    let rule = policy.manifest_ceiling_for(envelope)?;
    let value = rule.measures?.read(envelope)?;
    let root = git::repo_root(&std::env::current_dir().ok()?).ok()?;
    let tracked = git::tracked_paths(&root).ok()?;
    Some(hook::count_named_artifacts(
        &value,
        &rule.resolves,
        &tracked,
    ))
}

fn prospective_for(policy: &hook::Policy, envelope: &hook::Envelope) -> hook::ProspectiveFacts {
    if policy.reads_prospective(envelope) {
        hook::prospective_facts(hook_authority_root(), envelope)
    } else {
        facts::Look::CouldNotLook
    }
}

fn drain_advisories(
    envelope: &hook::Envelope,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
    advice: &mut Vec<String>,
) -> Result<()> {
    // The repository, resolved through the one finder (CLOUD-824). This read
    // asked TWO different questions before: whether an authority sits in the cwd,
    // and where the repository is — so in a linked worktree with no committed
    // authority of its own the drain returned early while the store it wanted was
    // bound perfectly well one directory up.
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(());
    }
    let Ok(repo) = git::repo_root(here) else {
        return Ok(());
    };
    let Some(dir) = store::bound_dir(&store::resolve(&repo)?) else {
        return Ok(());
    };
    let Some(session) = envelope.session.as_deref() else {
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            "hook: the host reported no session, so the advisory drain has no \
             boundary to coalesce against; nothing drained",
        )?;
        return Ok(());
    };

    let config = resolve::resolve(here, overrides)?.drain.unwrap_or_default();
    let access = journal::open(&dir)?;
    let seqno = access.format().seqno;
    let mut state = drain::load_wake(&dir, session);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });

    match drain::decide_wake(&state, &config, now_ms, seqno) {
        drain::Wake::Coalesced => {
            state.coalesce();
            drain::save_wake(&dir, session, &state)?;
            return Ok(());
        }
        // Nothing is read, which is the whole saving: the give-up is measured
        // against a one-file format read that has already happened above.
        drain::Wake::GaveUp => return Ok(()),
        drain::Wake::Drain => {}
    }

    // The ref this checkout is on, so the count shown is the one for the tree in
    // front of the agent. A detached `HEAD` has none, and the cycle falls back to
    // a deterministic instance rather than to silence.
    let context = git::current_branch(here)?
        .map(|branch| findings::Context::new(format!("refs/heads/{branch}")));
    let records = findings::load_all(&dir)?;
    let drained = drain::cycle(
        &records,
        &git::changed_paths(here)?,
        context.as_ref(),
        &config,
        &state.counts,
        // The emission policy's whole input (CLOUD-165). Read with `all` rather
        // than `since`, because a ratio is computed over a window of the history
        // and a cursor read would hand back a delta and take a position this
        // process has no business holding — the drain's cursor is the lineage's.
        &journal::all(&dir),
    );

    // Persist before emit. A degraded store cannot record the suppression, and
    // must not: writing a record version it cannot represent would drop fields.
    // The emission still happens — dedupe and reporting work read-only — so the
    // agent is not silenced by an out-of-date binary.
    if access.is_writable()
        && drain::journal_suppressions(&dir, &journal::shard_id(here), &drained)? > 0
    {
        // Fold the entries into their records now rather than leaving them for
        // whenever `state record` next runs. Two reasons, and the second is the
        // load-bearing one: the false-positive rate reads the *records*, so an
        // unfolded suppression is invisible to the measurement it exists for;
        // and `record_suppressions` skips a record that already carries the
        // disposition, which only stops the per-drain re-append once the fold
        // has happened. A lost lock race is not a failure — the entries are
        // already durable in this worktree's shard and the next fold picks them
        // up — so it is silent here rather than reported, since a hook that
        // narrated its own bookkeeping to an agent would be spending context on
        // a non-event.
        let _ = journal::merge(&dir)?;
    }

    // The `resultId` cheap path (CLOUD-166), measured against the LINEAGE's
    // watermark rather than this session's own bookkeeping, so a warm fork does
    // not re-list the set its parent had just shown.
    let root = session::root(&dir, session)?;
    let previous = session::load_watermark(&dir, &root)?;
    let repeat = previous
        .as_ref()
        .is_some_and(|mark| mark.result_id == drained.result_id);

    // **Persistence is never skipped, which is the half the short-circuit must
    // not take with it.** The ordinal advances on every cycle including this one,
    // so a reader can tell a repeated cycle from a cycle that never ran — and the
    // flap rate that divides by it stays honest. Written before the emit, for the
    // same reason the suppressions above are.
    session::save_watermark(
        &dir,
        &root,
        &session::Watermark::next(previous.as_ref(), drained.result_id.clone()),
    )?;

    // Three outcomes, and the middle one is what CLOUD-166 adds: say the payload,
    // say `unchanged`, or say nothing. A repeat answers with the fixed marker
    // rather than silence, because silence is indistinguishable from a drain that
    // never ran. Nothing found still says nothing — that is a different claim.
    let emitted = !drained.lines.is_empty() && !repeat;
    // Persist before emit, on the emitting side too (CLOUD-165): an emission the
    // agent saw and the log did not record is an emission the re-emit cap cannot
    // count, so the flood the cap exists to stop would be invisible to it. Written
    // only when the payload actually reaches the agent — an `unchanged` boundary
    // showed nothing and must not spend the cap.
    if emitted
        && access.is_writable()
        && drain::record_emissions(&dir, &journal::shard_id(here), &records, &drained.counts)? > 0
    {
        let _ = journal::merge(&dir)?;
    }
    // The channel, chosen by the capability table rather than by this module
    // (CLOUD-461). Until it existed the drain wrote to **stderr**, which on
    // Claude Code is not shown to the model on exit 0 — so the one thing in the
    // engine whose entire purpose is to report findings back to the agent was
    // reporting them where the agent could not read them. `emit_advisory` puts
    // both outcomes on the surface the host actually delivers, and keeps stderr
    // for the hosts that declare no channel, where it is still the operator's.
    if emitted {
        advice.push(drain::render(&drained));
    } else if repeat && !drained.lines.is_empty() {
        advice.push(drain::UNCHANGED.to_owned());
    }

    // Volume and suppression counts are the operator's, not the agent's: they
    // say how the drain is behaving, which is a diagnostic about Batten rather
    // than a finding about the repository. They travel on the `batten: ` channel
    // at the verbose rung, so the default path — the one an agent reads — spends
    // nothing on them (§5). Routing them into `systemMessage` proper rides
    // CLOUD-44's per-host emitter shims.
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!(
            "hook: drained {} line(s); withheld {} out of scope, {} over the cardinality cap, {} \
             over the token budget, {} flapping; {} rule(s) with a flapping identity",
            drained.lines.len(),
            drained.scope_filtered.len(),
            drained.capped.len(),
            drained.over_budget.len(),
            drained.flap_suppressed.len(),
            drained.flapping.len(),
        ),
    )?;

    state.drained(now_ms, seqno, &drained, emitted);
    drain::save_wake(&dir, session, &state)?;
    Ok(())
}

/// Resolve the mediated-call policy for this run.
///
/// **Absent authority is the empty policy, not an error.** `batten hook` is
/// registered once and then mediates every call in whatever directory the agent
/// happens to be in, most of which are not Batten repositories; refusing there
/// would make the guard the reason ordinary work stops.
///
/// An authority that exists and **cannot be read** is the opposite case, and it
/// propagates: a policy file that does not parse means the rules the operator
/// wrote are not being applied, and silently allowing would be the false green
/// this engine exists to catch. It surfaces as a [`UsageError`] — exit `1`, loud
/// on stderr, and structurally not a deny, because §7 spends `2` on the verdict
/// alone.
/// Record an agent-sourced fact, if this post-tool call is one a declared fact
/// asked for (CLOUD-776).
///
/// The command comparison is byte equality against the DECLARED command, the same
/// value [`facts::sourced`] later verifies the record against — so a call that
/// merely resembles the request records nothing, rather than recording something
/// the reader would then have to reject.
///
/// Rule 4 is satisfied here rather than downstream: [`facts::rows_declared`]
/// reduces the buffer to a count at this boundary, and the count is what is
/// written. No byte of a tool's stdout — the likeliest place in the envelope for
/// a secret — reaches disk.
///
/// # The declaration is resolved BEFORE the buffer is read, and the order is the
/// contract
///
/// [`facts::rows_declared`] needs the row's `returns`, so the policy load and the
/// command match come first and the count second. The reverse order is what
/// CLOUD-993 shipped and it made the field dead config: `rows_in` was still the
/// reader, so a row could declare `json-array` and a command emitting prose would
/// still record one opaque row — a `rows == 0` gate silently unsatisfiable, over a
/// declaration nobody read. Naming a contract and then not checking it is worse
/// than never offering the field.
///
/// Every failure is silent. A hook that cannot record a fact must not become the
/// reason work stops: the next attempt denies again with the same `Fix::Run`,
/// which is the safe direction and one the agent can see.
fn record_agent_fact(overrides: &Overrides, envelope: &hook::Envelope) {
    let Ok((policy, _)) = load_policy(overrides, hook::Harness::ExitCode) else {
        return;
    };
    let Some(declared) = policy
        .declared_facts()
        .iter()
        .find(|declared| declared.command == envelope.command)
    else {
        return;
    };
    // A buffer that said nothing at all — absent, or empty — is `CouldNotLook`
    // and records NOTHING. Writing a zero here would turn "the tool printed
    // nothing" into the fact "there are none", which is the guessed-envelope
    // failure the whole capability table exists to prevent.
    //
    // CHECKED against the row's declaration rather than inferred from the bytes
    // (CLOUD-993): a buffer that does not match what the row said it returns is
    // `CouldNotLook` and records nothing, so a command that quietly stops
    // emitting JSON denies loudly instead of recording a plausible number.
    // `opaque` is where the inferring reader stays available, and it has to be
    // said.
    let facts::Look::Is(rows) = facts::rows_declared(&envelope.result, declared.returns) else {
        return;
    };
    let record = facts::Sourced {
        command: declared.command.clone(),
        // The clock is read HERE, at the boundary, for the reason every other
        // clock read in this crate is: a predicate that read one would stop being
        // a pure function of its inputs. The stamp is provenance beside the
        // answer — `facts::sourced` never consults it.
        seen_at: receipt::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since_epoch| since_epoch.as_secs()),
        ),
        rows,
    };
    // FILED UNDER THE KEY THE DECLARING ROW STATES (CLOUD-859), resolved
    // policy-wide because this envelope is the fact's own command and not the
    // call the receipt row selects — a call-scoped lookup finds nothing here.
    // A fact no receipt row requires is unreadable by anything, so recording it
    // would leave a file nobody consults; that is silent like every other
    // failure on this path.
    let Some(key) = policy.receipt_key_for_check(&declared.name) else {
        return;
    };
    let _ = receipt::record_sourced(
        &declared.name,
        key,
        policy.named_receipt_subject(envelope).as_deref(),
        &record,
    );
}

/// Everything the post-tool event records, in the order it must happen.
///
/// Extracted from [`run_hook`] because the workspace's function-length lint asked
/// for it, and the lint was right: this is one decision — what a completed call
/// leaves behind — and `run_hook`'s body is a sequence of stages, not a place to
/// spell one out.
///
/// **The capture is first, and textually first is the point.** CLOUD-917 makes it
/// the authoritative record and the row count a derived view of it, so projecting
/// first would permit a build where the count survived and the bytes did not.
fn record_post_tool(
    overrides: &Overrides,
    envelope: &hook::Envelope,
    harness: hook::Harness,
    advice: &mut Vec<String>,
) {
    // GATED ONLY ON THE RESPONSE MEMBER, never on the command. The
    // `!command.is_empty()` conjunct below is correct for a FACT — a fact is
    // keyed to a command that ran — and wrong for a capture, because the
    // response of a structured tool is still a response. That conjunct is why
    // every MCP call, every `Read` and every `Write` is missed today.
    //
    // A host that literally sends `"tool_response": null` is indistinguishable
    // from one that sends no member at all, because `decode`'s alias walk
    // produces `Value::Null` for both. Accepted rather than papered over:
    // telling them apart is `decode`'s work and buys nothing any surveyed host
    // produces.
    if envelope.result.is_null() {
        // ABSENT IS A RECORD, not silence (CLOUD-917). Without this row a host
        // that sends no response is indistinguishable from a call nobody made,
        // which is the two-outcomes-into-one collapse the empty case is careful
        // about at the other end. Only on `PostTool`, so the pre-tool path — which
        // is nearly every call — still does no work here.
        record_absent_response(envelope, harness, advice);
    } else {
        capture_response(envelope, harness, advice);
    }
    // CLOUD-776's gate, byte-for-byte what it was: a fact is keyed to a command
    // that ran, so a call carrying no command has no fact to record.
    if !envelope.command.is_empty() {
        record_agent_fact(overrides, envelope);
    }
    // CLOUD-1024's, on the other selector. Keyed to the TOOL rather than to a
    // command, so it fires on exactly the calls the conjunct above excludes: an
    // MCP call carries no command and is the whole point here.
    record_mints(overrides, envelope);
    // CLOUD-1051's, on the same selector and after it. A mint renders a closed
    // template; a recorder may additionally run a declared program and record
    // what it decided, which is what a board write's refinement column IS.
    // Ordered after so a recorder can never be the reason a receipt goes
    // unwritten — the two are independent, and the cheaper one goes first.
    write_records(overrides, envelope);
}

/// The end-of-turn rules that are not a module, ranked (CLOUD-1051).
///
/// # What this replaces, and why the ranking is here rather than in config
///
/// `mise-tasks/stop-guard.sh` ran five rules in a fixed order and emitted **at
/// most one**, because two nudges on one turn is how a channel stops being read.
/// Four of them cannot be a `mediated_call` module: three spawn a sibling
/// program and one reads the tree, and `RuleKind::scopes` pairs every spawning
/// kind with `RuleScope::Tree` alone. So they live here, in the order the shell
/// ranked them — by MEASURED precision, `stop-posture` at 3/3 leading
/// `finding-sink` at 1/1, with the three unmeasured below — and the caller emits
/// the first that speaks.
///
/// # The siblings are spawned unchanged, which is a deliberate bound
///
/// `finding-sink-check.sh` and `unlanded-check.sh` are invoked exactly as the
/// bash invoked them, with the same stdin. Neither enters this change's
/// changed-file set, so `shell-retirement` never fires on them and the cascade
/// stops at the program actually being retired. A `[[hook.handler]]` row cannot
/// serve here: that door pipes the host's own payload, and the first of those
/// two reads a transcript PATH on stdin — it would answer "no readable
/// transcript path" every turn, which is a broken gate wearing a nudge's shape.
///
/// # Everything fails open, and every failure is silent
///
/// This runs at `Stop`. A routine that errored, blocked or printed would put the
/// end-of-turn check on the path that must stay free — committing and pushing to
/// a draft is what survives a container reclaim. So every unreadable path,
/// missing program and unresolvable branch yields `None`.
fn stop_nudges(overrides: &Overrides, envelope: &hook::Envelope) -> Option<String> {
    if envelope.event != hook::Event::Stop || envelope.stop_active == Some(true) {
        return None;
    }
    if std::env::var_os(STOP_GUARD_BYPASS).is_some() {
        return None;
    }
    let root = &hook_authority_root();
    // THE TRANSCRIPT SEAM, and it is a WRITE this routine owes rather than a rule
    // (CLOUD-990). `[transcript].path` names one fixed repo-relative path because
    // the key is the committed authority and is deliberately unlayerable — a
    // local file redirecting it would be CHOOSING THE EVIDENCE. The host's
    // transcript is a per-session absolute path no committed value can name, so
    // the indirection lives at the boundary: the authority names the file
    // forever, and this points it at the session the host just named.
    //
    // NOTHING IS READ HERE. The symlink is a pointer; the engine is the only
    // thing that opens it. The retired shell hook was the ONLY writer, so
    // dropping this would have left `batten check`'s transcript capability
    // reading a dangling path on every fresh container — the CLOUD-990 condition,
    // reintroduced by the retirement that was supposed to preserve it.
    refresh_transcript_link(root, envelope);
    // RULE 2 — a finding stated in prose with nothing durable written. It reads
    // the transcript, so it reaches prose the module above cannot see: the final
    // text block is under half a turn's assistant prose.
    if let Some(path) = envelope.transcript.as_deref()
        && let Some(pointer) = spawn_reading(root, "mise-tasks/finding-sink-check.sh", path)
    {
        return Some(format!(
            "{pointer}\nA finding was stated here and nothing durable was written. Go re-derive \
             it and file it, or confirm it is already tracked."
        ));
    }
    // RULE 3 — a row this branch filed names a file this branch is changing. The
    // same predicate `land` decides on, run here so the punt surfaces at the end
    // of the turn that created it rather than when a runner is about to be spent.
    //
    // ONCE PER ROW PER BRANCH. A Stop hook sees no PR body, so repeating one
    // pointer every turn for the rest of a session is exactly how this channel
    // dies. The turn the overlap first appears is the one that can still act
    // cheaply, which is the whole reason for running it ahead of `land`.
    if let Some(fresh) = filed_here_pointers(overrides, root, Suppression::PerRow) {
        return Some(format!(
            "{fresh}\nA row this branch filed names a file this branch is changing. Finish it \
             now while the file is open, or make sure the PR body closes it when you land."
        ));
    }
    // RULE 4 — a completion signal with no patch-id-equivalent commit on the
    // landing target. `state record` mints that verdict and this reads what it
    // wrote; both ride `unlanded-check`'s own hatch rather than one of their own,
    // because a caller who switched the rule off must not still pay a tree walk
    // and a store write per turn for an answer nobody reads.
    if std::env::var_os(UNLANDED_BYPASS).is_none() {
        record_state(overrides);
        if let Some(pointer) = spawn_reading(root, "mise-tasks/unlanded-check.sh", "") {
            return Some(format!(
                "{pointer}\nThis turn declared a stopping point and the work is not on the \
                 landing target. Land it, or say what blocks it."
            ));
        }
    }
    // RULE 5 — every row this branch spun off, enumerated for re-evaluation.
    // Rule 3 asks a narrow measured question and answers it once per row; this
    // asks the broad one no predicate scores (non-negotiable rule 3): here is the
    // whole set, say for each that it is genuinely independent work.
    //
    // SUPPRESSED ON THE SET, NOT PER ROW, and that is the whole difference. A
    // per-row receipt would show a partial list, and a checklist with rows hidden
    // is not a checklist. File another row and the whole list is asked again,
    // because the question is about the set.
    let rows = filed_here_pointers(overrides, root, Suppression::PerSet)?;
    Some(format!(
        "{rows}\nEvery row above was spun off while this branch was open. For each, by number: \
         is it genuinely independent work, or a punt you could close here? Close the punts; \
         leave a reason for the rest."
    ))
}

/// Point the committed transcript path at the session the host just named.
///
/// The declared path is the consumer's `[transcript].path` — read from config
/// rather than assumed, because the authority names the file and this only
/// refreshes what it points at. A repository declaring none has nothing to link.
///
/// Silent on every failure, like everything else at this boundary: no config, no
/// declared path, an unreadable source, an unwritable link. A transcript that
/// cannot be pointed at resolves to `Capability::Absent` downstream, which is
/// silence rather than a verdict.
fn refresh_transcript_link(root: &Path, envelope: &hook::Envelope) {
    let Some(source) = envelope.transcript.as_deref() else {
        return;
    };
    if !Path::new(source).is_file() {
        return;
    }
    let Ok(config) = resolve::resolve(root, &Overrides::default()) else {
        return;
    };
    let Some(declared) = config
        .transcript
        .as_ref()
        .and_then(|transcript| transcript.path.as_deref())
    else {
        return;
    };
    let link = root.join(declared);
    if let Some(parent) = link.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Replaced rather than updated in place: `symlink` refuses an existing path,
    // and the old target is a session that has ended.
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(source, &link);
}

/// The hatch that silences the whole end-of-turn surface.
///
/// One hatch for the set rather than one per rule, exactly as the retired shell
/// hook had it: these are five readings of one question — *is this turn actually
/// finished* — and a per-rule switch would let the surface be dismantled a rule
/// at a time with nothing reporting that it had been.
const STOP_GUARD_BYPASS: &str = "BATTEN_STOP_GUARD_BYPASS";

/// The hatch `unlanded-check` declares, ridden by the recorder that feeds it.
const UNLANDED_BYPASS: &str = "BATTEN_UNLANDED_CHECK_BYPASS";

/// Evaluate the completion detectors so rule 4 has something to read.
///
/// [`run_state_record`]'s own work, with its streams and its verdict discarded:
/// this is an EVALUATION, not a decision. A recorder that failed simply leaves
/// nothing to read, which is silence — the correct answer for a hook that may
/// never be the reason a turn stalls.
fn record_state(overrides: &Overrides) {
    let mut sink = std::io::sink();
    let _ = run_state_record(overrides, Mode::default(), &mut sink);
}

/// What the `filed-here` row says about this branch, suppressed and rendered.
///
/// # Two questions over one predicate, which is what keeps them from drifting
///
/// [`Suppression::PerRow`] answers the narrow one — which filed row names a file
/// this branch is holding open — from the row's own findings.
/// [`Suppression::PerSet`] answers the broad one no predicate scores: here is
/// EVERY row you spun off. Its ids come from the recorder's record directly,
/// because a finding is emitted only for a refusal and the checklist is about
/// the whole set.
///
/// # The pointer is the PATH, and that is a stated difference
///
/// The retired shell emitted `<id> filed-over-own-diff <path>` and suppressed on
/// the id. A `Finding` carries its first path-bearing subject as its pointer and
/// the row's id travels as an ordered subject the engine does not project onto
/// the struct, so the nudge names the path and the suppression key is the path.
/// That is the half an agent must act on — *finish it now while the file is
/// open* — and the id is one board read away. Recorded rather than glossed,
/// because it is a real narrowing of what the nudge says.
fn filed_here_pointers(
    overrides: &Overrides,
    root: &Path,
    suppression: Suppression,
) -> Option<String> {
    let config = resolve::resolve(root, overrides).ok()?;
    let (selected, _checks) = select_rules(&config.rules, Some(FILED_HERE_ROW)).ok()?;
    let vocabulary = policy::Vocabulary {
        patterns: &config.patterns,
        verdicts: &config.verdicts,
        recorders: &config.recorders,
    };
    let scan = rules::run_static(&selected, &config.provisions, vocabulary, root).ok()?;
    let flagged: std::collections::BTreeSet<String> = scan
        .findings
        .iter()
        .filter(|finding| finding.rule == FILED_OVER_OWN_DIFF)
        .map(|finding| finding.path.clone())
        .collect();
    let git_dir = git::git_dir(root).ok()?;
    let branch = git::current_branch(root).ok()??;
    let lines: Vec<String> = match suppression {
        Suppression::PerRow => flagged.into_iter().collect(),
        Suppression::PerSet => {
            // EVERY ROW, MARKED — the checklist's whole question. A row whose
            // named paths intersect the diff is marked so the reader can see
            // which ones rule 3 already asked about; the rest are `filed`, and
            // the judgement about all of them is the agent's.
            let record = recorder::record_path(&git_dir, BOARD_RECORD, &branch);
            let text = std::fs::read_to_string(record).ok()?;
            let mut seen = std::collections::BTreeSet::new();
            text.lines()
                .filter_map(|line| {
                    let mut columns = line.split(' ');
                    (columns.next()? == "issue").then(|| columns.next())?
                })
                .filter(|id| seen.insert((*id).to_owned()))
                .map(|id| format!("{id} filed"))
                .collect()
        }
    };
    if lines.is_empty() {
        return None;
    }
    // THE SUPPRESSION, and its unit is what the two modes disagree about. Rule 3
    // stores one line per row, so a second row is asked about and the first is
    // not; rule 5 stores the whole set as one key, so the list is asked again in
    // full the moment it changes and never partially.
    let (store, keys) = match suppression {
        Suppression::PerRow => (
            git_dir
                .join("batten-receipts")
                .join(format!("filed-here-nudged.{}", branch.replace('/', "-"))),
            lines.clone(),
        ),
        Suppression::PerSet => (
            git_dir
                .join("batten-receipts")
                .join(format!("filed-set-nudged.{}", branch.replace('/', "-"))),
            vec![lines.join(" ")],
        ),
    };
    let already: std::collections::BTreeSet<String> = std::fs::read_to_string(&store)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default();
    let fresh: Vec<String> = keys
        .iter()
        .filter(|key| !already.contains(*key))
        .cloned()
        .collect();
    if fresh.is_empty() {
        return None;
    }
    // Written before the nudge is returned, so a turn that is interrupted after
    // being told still counts as told. Silent on failure, like everything here.
    if let Some(parent) = store.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&store)
    {
        for key in &fresh {
            let _ = writeln!(file, "{key}");
        }
    }
    Some(match suppression {
        Suppression::PerRow => fresh.join("\n"),
        Suppression::PerSet => lines.join("\n"),
    })
}

/// The row the two nudge modes read, and the predicate whose findings rule 3 uses.
const FILED_HERE_ROW: &str = "filed-here";
const FILED_OVER_OWN_DIFF: &str = "filed-over-own-diff";
/// The record the checklist enumerates.
const BOARD_RECORD: &str = "board-writes";

/// Whether a filed-row pointer is suppressed per row or per set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suppression {
    /// Rule 3: one nudge per row per branch.
    PerRow,
    /// Rule 5: one nudge per SET per branch.
    PerSet,
}

/// Run one sibling program and return its pointer, or `None` for silence.
///
/// The contract is the retired hook's, unchanged: a fired predicate is a
/// non-zero exit with the pointer on stdout, and anything else — clean,
/// unreadable, absent, unrunnable — is silence.
#[expect(
    clippy::disallowed_types,
    reason = "stays: CLOUD-1051 retires `stop-guard.sh` and invokes the siblings it invoked, unchanged and by path, so the cascade stops at the program being retired rather than reaching four more"
)]
fn spawn_reading(root: &Path, program: &str, stdin: &str) -> Option<String> {
    use std::process::{Command, Stdio};

    let path = root.join(program);
    if !path.is_file() {
        return None;
    }
    let mut child = Command::new(&path)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(stdin.as_bytes()).ok()?;
    let output = child.wait_with_output().ok()?;
    if output.status.success() {
        return None;
    }
    let pointer = String::from_utf8(output.stdout).ok()?;
    let pointer = pointer.trim_end();
    (!pointer.is_empty()).then(|| pointer.to_owned())
}

/// Append every declared record this result earns (CLOUD-1051).
///
/// [`record_mints`]'s shape deliberately: the same cheap-question-first ordering,
/// the same anchor-not-cwd rule, and the same silence on every failure. What
/// differs is that a recorder may SPAWN — see [`crate::recorder::run_program`]'s
/// inventory row — so the tool match is load-bearing rather than an economy, and
/// it is checked inside `append_all` before any program is reached.
fn write_records(overrides: &Overrides, envelope: &hook::Envelope) {
    // The cheap question first, for `record_mints`' reason: a post-tool event for
    // a tool no row names is nearly every call, and `perf-gate` holds the
    // mediated path to a ratio.
    if envelope.result.is_null() {
        return;
    }
    let Some(result) = facts::payload_in(&envelope.result) else {
        return;
    };
    let Ok((policy, _)) = load_policy(overrides, hook::Harness::ExitCode) else {
        return;
    };
    let recorders = policy.declared_recorders();
    if recorders.is_empty() {
        return;
    }
    // THE ANCHOR, NEVER THE CWD (CLOUD-1024's measured defect, restated here
    // because this is a second writer and would have repeated it): `batten hook`
    // is registered once and then mediates calls from wherever the agent happens
    // to be standing.
    let root = hook_authority_root();
    let Ok(git_dir) = git::git_dir(root) else {
        return;
    };
    let Ok(Some(branch)) = git::current_branch(root) else {
        return;
    };
    let patterns = policy.compiled_patterns();
    let context = crate::recorder::Context {
        result: &result,
        input: &envelope.input,
        programs: policy.declared_programs(),
        patterns: &patterns,
        root,
    };
    crate::recorder::append_all(
        recorders,
        &git_dir,
        &branch,
        &context,
        rules::selects_tool_name,
        &envelope.raw_tool,
    );
}

/// Mint every receipt this result earns (CLOUD-1024).
///
/// **The forgery this removes and the one it must not add are the same
/// question.** A receipt minted from the result is one the agent cannot author;
/// a receipt minted from a result that did not succeed would be a read receipt
/// for a read that never happened, which is worse than the hand-piped path it
/// replaces. [`crate::mint::satisfied`] is what separates them, and it is checked
/// before anything reaches disk rather than after.
///
/// The clock and the ref resolver are read HERE, at the boundary, for the reason
/// every other clock read in this crate is: `render` stays a pure function of its
/// inputs and so stays testable without a world.
///
/// Every failure is silent, which is [`record_agent_fact`]'s posture verbatim: a
/// hook that cannot record a fact must not become the reason work stops. The gate
/// that reads the receipt simply denies again with the same remedy, which is the
/// safe direction and one the agent can see.
fn record_mints(overrides: &Overrides, envelope: &hook::Envelope) {
    // Before the config load, the cheap question first: a post-tool event for a
    // tool no row names — which is nearly all of them, now that batten is
    // registered on every surface — must do no config work here. `perf-gate`
    // holds the mediated path to a ratio, and this is the call that would move it.
    if envelope.result.is_null() {
        return;
    }
    // THE ENVELOPE IS THE SHAPE. A connector wraps every response in content
    // blocks, so reading fields off `envelope.result` directly matches nothing in
    // production while passing every fixture, which hands the engine a bare
    // object. `facts::payload_in` is the one authority on that unwrap.
    let Some(result) = facts::payload_in(&envelope.result) else {
        return;
    };
    let Ok((policy, _)) = load_policy(overrides, hook::Harness::ExitCode) else {
        return;
    };
    let declared = policy.declared_mints();
    if declared.is_empty() {
        return;
    }
    // THE ANCHOR, NEVER THE CWD, and this is a measured defect rather than a
    // style choice. The first version resolved every git question against `.`,
    // which passed each fixture — a test harness runs the engine IN the repo —
    // and minted nothing at all against the live host, because `batten hook` is
    // registered once and then mediates calls from wherever the agent happens to
    // be standing. `capture_response` states the same rule one function over and
    // is why the capture store kept working while this wrote nothing.
    let root = hook_authority_root();
    let Ok(git_dir) = git::git_dir(root) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs());
    let resolve = |reference: &str| git::resolve_ref(root, reference).ok().flatten();
    for mint in declared {
        if !rules::selects_tool_name(&mint.tool, &envelope.raw_tool) {
            continue;
        }
        // The branch is resolved only for a row that asked, which is the same
        // economy `receipt::verdicts` states one channel over: a caller must not
        // pay a git invocation for a question it never asks.
        let filename = match mint.key {
            crate::mint::MintKey::Named => {
                let Some(subject) = crate::mint::subject(mint, &result) else {
                    continue;
                };
                format!("{}.{subject}", mint.name)
            }
            crate::mint::MintKey::Branch => {
                let Ok(Some(branch)) = git::current_branch(root) else {
                    continue;
                };
                format!("{}.{}", mint.name, branch.replace('/', "-"))
            }
        };
        let Some(record) = crate::mint::render(mint, &result, now, &resolve) else {
            continue;
        };
        let path = git_dir.join("batten-receipts").join(filename);
        if let Some(parent) = path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            continue;
        }
        let written = match mint.mode {
            crate::mint::MintMode::Replace => std::fs::write(&path, &record),
            crate::mint::MintMode::Append => {
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .and_then(|mut file| file.write_all(record.as_bytes()))
            }
        };
        let _ = written;
    }
}

/// Persist this post-tool response as a local capture (CLOUD-919).
///
/// **Returns nothing, and that is the failure posture rather than laziness.**
/// CLOUD-917's decision, applied: hook execution continues, the exit code is
/// unchanged and never `2` — a storage failure is not a policy verdict — and the
/// outcome is *recorded and reported* instead of raised. It takes `&mut advice`
/// rather than returning a `Result` for the same reason: a `?` here would cross
/// the fill-and-drain span the advisory buffer lives in, and the one escape that
/// span tolerates is a config failure at exit 3.
///
/// This is deliberately the OPPOSITE posture from [`capture::store`]'s own
/// "never a silent skip" doc, and the surface is the reason. `store` is called by
/// `exec`, where an unrecorded capture is a lie about a command a human asked
/// for. Here it is called on the mediated path, where the non-negotiable is that
/// no Batten failure can block a tool call.
///
/// **No repo root, no capture.** [`hook_authority_root`] falls back to the cwd,
/// so capturing unconditionally would scatter state roots across the filesystem
/// on every post-tool call made anywhere — something nothing in this binary did
/// before. A call from outside a repository records the reason and stores
/// nothing.
///
/// Three outcomes, kept distinct (CLOUD-917): an absent member never reaches
/// here, a present-but-empty one is a real record of zero bytes, and a
/// non-empty one is its bytes at the declared fidelity. The provenance row is
/// what tells the first two apart — one carries a digest, the other a reason id,
/// and they differ in which keys exist rather than in a count.
fn capture_response(envelope: &hook::Envelope, harness: hook::Harness, advice: &mut Vec<String>) {
    let mut note = |reason: &str| {
        // Pointer-only: the reason id, never a path and never a byte count that
        // could fingerprint the content. The same id reaches `doctor`.
        advice.push(format!("hook.capture.response: {reason}"));
    };
    // NO FALLBACK TO THE CWD, which is what makes the doc above true: resolving
    // to wherever the agent happens to be standing would mint a state root there
    // on every post-tool call. The anchor rather than `.` for the second half of
    // the same reason (CLOUD-824): every other repository read in `run_hook`
    // resolves through `hook_authority_root`, and a capture written under one
    // root while its budget is read from another is two authorities for one
    // call.
    let Ok(root) = git::repo_root(hook_authority_root()) else {
        note(capture::STATE_ROOT_UNRESOLVED);
        return;
    };
    let decoded = match capture::decode_response(&envelope.result) {
        Ok(decoded) => decoded,
        Err(reason) => {
            note(reason);
            record_absence(&root, envelope, harness, reason, advice);
            return;
        }
    };
    let Ok(stored) = capture::store(&root, capture::Stream::Response, &decoded.bytes) else {
        note(capture::STORE_UNWRITABLE);
        record_absence(&root, envelope, harness, capture::STORE_UNWRITABLE, advice);
        return;
    };
    let row = capture::CallRow {
        order: 0,
        // A host that names no session still gets a row, under a token that says
        // so: dropping the row would make an unnamed session look like no calls,
        // and inventing an id would make two of them look like one.
        session: envelope
            .session
            .clone()
            .unwrap_or_else(|| "unnamed".to_owned()),
        source: "post-tool-member".to_owned(),
        host: harness.as_str().to_owned(),
        tool: envelope.raw_tool.clone(),
        event: hook::Event::PostTool.as_str().to_owned(),
        fidelity: decoded.fidelity.as_str().to_owned(),
        // The clock is read at the boundary, as `record_agent_fact` reads it and
        // for the same reason. It is a fact about the CALL, which is why it may
        // live on this row while the content-addressed blob still refuses one.
        seen_at: Some(receipt::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since_epoch| since_epoch.as_secs()),
        )),
        class: None,
        digest: Some(stored.digest),
        absent: None,
    };
    if capture::record_call(&root, &row).is_err() {
        // THE ONE UNRECORDABLE FAILURE (CLOUD-917 clause 4): the provenance write
        // itself. The advisory is the only channel left, which is why it is not
        // conditional on the row.
        note(capture::STORE_UNWRITABLE);
    }
    // Write-time only, and only for responses. `exec` captures are not
    // candidates, so that consumer's behaviour is byte-identical to before.
    // An `Err` here is a store that could not be READ or REWRITTEN — the bytes
    // are already published and the row is already written, so it is never a
    // budget refusal. `BUDGET_EXHAUSTED` would send a `doctor` reader to the
    // wrong remedy, which is the whole point of a reason id.
    if capture::evict_to_budget(&root, capture_budget().as_ref()).is_err() {
        note(capture::STORE_UNWRITABLE);
    }
}

/// A post-tool call whose host sent no response member.
///
/// The row is the whole deliverable, and it is deliberately NOT an advisory: a
/// host that sends nothing is the surveyed-`Unavailable` case rather than a
/// failure, so pushing a reason id at the operator on every such call would make
/// the ordinary shape of five of six harnesses look like a fault. The record is
/// where it belongs — readable on demand, silent otherwise.
///
/// **No repo root, no row**, for `capture_response`'s reason: resolving to the
/// cwd would mint a state root wherever the agent happens to be standing.
fn record_absent_response(
    envelope: &hook::Envelope,
    harness: hook::Harness,
    advice: &mut Vec<String>,
) {
    let Ok(root) = git::repo_root(hook_authority_root()) else {
        return;
    };
    record_absence(&root, envelope, harness, capture::RESPONSE_ABSENT, advice);
    // THE BOUND APPLIES HERE TOO, and this path needs it more than the capture
    // one does: a host that sends no response appends a row per post-tool call
    // and mints no blob, so nothing else would ever bring the log inside its
    // record bound — and `next_order` scans that log on every later call.
    if capture::evict_to_budget(&root, capture_budget().as_ref()).is_err() {
        advice.push(format!(
            "hook.capture.response: {}",
            capture::STORE_UNWRITABLE
        ));
    }
}

/// Record that a capture did not happen, so "no record" cannot mean "no calls".
fn record_absence(
    root: &Path,
    envelope: &hook::Envelope,
    harness: hook::Harness,
    reason: &'static str,
    advice: &mut Vec<String>,
) {
    let row = capture::CallRow {
        order: 0,
        // A host that names no session still gets a row, under a token that says
        // so: dropping the row would make an unnamed session look like no calls,
        // and inventing an id would make two of them look like one.
        session: envelope
            .session
            .clone()
            .unwrap_or_else(|| "unnamed".to_owned()),
        source: "post-tool-member".to_owned(),
        host: harness.as_str().to_owned(),
        tool: envelope.raw_tool.clone(),
        event: hook::Event::PostTool.as_str().to_owned(),
        fidelity: capture::Fidelity::Unavailable.as_str().to_owned(),
        seen_at: None,
        class: None,
        digest: None,
        absent: Some(reason.to_owned()),
    };
    if capture::record_call(root, &row).is_err() {
        advice.push(format!(
            "hook.capture.response: {}",
            capture::STORE_UNWRITABLE
        ));
    }
}

/// The `[capture]` bound, or `None` when the authority cannot be read.
///
/// Read separately from the policy load below, and deliberately tolerant: a
/// capture must not fail because config did not parse, so an unreadable
/// authority means the engine defaults rather than an error.
fn capture_budget() -> Option<capture::CaptureConfig> {
    let text = std::fs::read_to_string(hook_authority_root().join(config::CONFIG_FILE)).ok()?;
    let parsed: config::Config = toml::from_str(&text).ok()?;
    parsed.capture
}

/// The directory `batten hook` reads its authority from (CLOUD-824).
///
/// **Never the session's cwd on its own.** `load_policy` reads `./batten.toml`
/// with no upward walk, so whichever directory this answers *is* which authority
/// governs a mediated call — and a hook fires wherever the agent happens to be
/// standing. Until this existed the answer came from a `cd` in a shell launcher
/// (`.claude/hooks/batten-hook.sh`, deleted by CLOUD-824): a second repo-root
/// resolver outside the single-implementation gate CLOUD-34 built, and one that
/// asked the *wrong git question*. It took the WORKTREE's toplevel where
/// [`git::repo_root`] answers with the repository's shared root, which in a
/// linked worktree is the **main** checkout. [`git`]'s module doc names both
/// spellings and is the one module allowed to; what matters here is that they
/// differ — measured on a constructed pair, two different directories. So from a
/// linked worktree whose checkout carries no `batten.toml` the launcher landed on
/// `Policy::declaring_nothing` and every mediated call was allowed, silently.
/// That is verbatim the state the launcher's own comment called the `cd` "the
/// whole defence" against.
///
/// **[`anchor`], not a bare [`git::repo_root`], and that is the correction the
/// suite forced.** The first attempt here answered `repo_root` unconditionally,
/// on the reading that CLOUD-34's "stable across worktrees" makes the shared root
/// the only honest answer. Ten hook cases went red and were right to: a directory
/// that carries its own `batten.toml` and happens to sit inside another
/// repository — every fixture under `target/tmp`, and a nested project in real
/// life — had its authority ignored in favour of the outer repository's. What
/// CLOUD-34's invariant governs is per-repository **state**, which lives under
/// the shared dir and is untouched by this. So the rule is the one the crate
/// already has: an authority in this directory answers for it, and otherwise the
/// repository does. Reusing it is also the point — `check` and `hook` disagreeing
/// about which directory is "here" would be a second authority on the question
/// this row exists to give one answer to.
///
/// The §2 fixture still decides correctly under it, which is what makes the reuse
/// legitimate rather than convenient: a linked worktree with no `batten.toml`
/// falls through to the repository's, and so does a subdirectory like
/// `crates/batten` — the case the launcher's `cd` was actually written for.
///
/// **Resolved once per process, and lazily.** Once, because three callers asking
/// the same question would spend three lookups on the hottest path in the binary.
/// Lazily, because a pass-through — a read tool, no command, no writes — reaches
/// no config reader at all, and CLOUD-777's acceptance is that such a call costs
/// no more than the published `noop` figure. [`anchor`] also stats before it
/// spawns, so the ordinary case (a session standing at the root) asks git
/// nothing.
///
/// **A directory this cannot resolve is the cwd, not an error.** `batten hook` is
/// registered once and then mediates every call in whatever directory the agent
/// is in, most of them outside any repository; refusing there would make Batten
/// the reason ordinary work stops (CLOUD-70) — the same fail-open posture the
/// launcher had at this exact point (`|| exit 0`), and [`anchor`]'s own fallback.
fn hook_authority_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(anchor)
}

fn load_policy(
    overrides: &Overrides,
    harness: hook::Harness,
) -> Result<(hook::Policy, Vec<waiver::Waiver>)> {
    let here = hook_authority_root();
    // THE FLAG IS CONSULTED BEFORE THE FILE (CLOUD-719). The zero-config
    // short-circuit below is correct in its own right — `batten hook` runs in
    // directories that are not Batten repositories, and refusing there would
    // make the hook the reason ordinary work stops (CLOUD-70). What it must not
    // do is answer *first*: under `--config-from` the working file's absence is
    // the MAXIMAL WEAKENING, and a policy declaring nothing is exactly the
    // verdict a branch deleting `batten.toml` was hoping for.
    //
    // This is CLOUD-243's rule on the surface where it bites hardest. There the
    // cost was a report that under-stated; here it is an un-gated write, because
    // `hook` is the pre-tool adjudicator and its verdict is the only thing that
    // stops the call. `resolve` already reads the ref and never touches the
    // working tree when one is named (`resolve::authority`), so consulting the
    // flag is all this needs.
    if overrides.config_from.is_none() && !here.join(config::CONFIG_FILE).exists() {
        return Ok((hook::Policy::declaring_nothing(harness), Vec::new()));
    }
    // The waivers travel beside the policy rather than inside it (CLOUD-610).
    // `Policy` is what `adjudicate` decides against and is resolved without a
    // clock; a waiver is only half a fact until a date is applied to it, so
    // folding the table into `Policy` would put an undecided value in the one
    // structure whose whole point is that everything in it is decided.
    let resolved = resolve::resolve(here, overrides)?;
    let policy =
        hook::Policy::from_resolved(&resolved, harness, here, overrides.config_from.as_deref())?;
    Ok((policy, resolved.waivers))
}

/// Resolve the `exec` output predicates for this run (CLOUD-117).
///
/// **Absent authority declares no patterns, and is not an error** — the same
/// reading [`load_policy`] gives the mediated-call policy, and for the same
/// reason. `batten exec` is a wrapper a caller puts in front of arbitrary
/// commands, most of them in directories that are not Batten repositories;
/// refusing there would make the wrapper the reason ordinary work stops.
///
/// An authority that exists and **cannot be read** propagates. A pattern table
/// nobody could parse is a gate that silently did not run, which is the false
/// green this predicate exists to prevent.
/// `batten exec`: layer the flags over the committed table, then dispatch.
///
/// # Errors
///
/// Returns a [`UsageError`] for an unreadable authority or a `--jobs` value that
/// is not a positive whole number, and whatever [`exec::run_with`] returns
/// otherwise — including the child's own code, as a [`error::Passthrough`].
fn run_exec(
    request: &cli::ExecRequest,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (patterns, mut settings) = load_exec_settings(overrides)?;
    // §8's precedence, flag over file. The two presentation axes are plain
    // presentation, so a flag setting them weakens nothing; `--tee` and
    // `--continue-on-error` widen, and they widen towards the caller's own
    // terminal rather than towards a gate's verdict — the same reading
    // `--verbose` gets.
    // `--capture-only` is `--tee`'s inverse spelling and loses to it when both
    // are typed, because asking for the bytes is the specific request: a caller
    // who typed both meant the one that says what they want rather than the one
    // that says what they do not.
    settings.tee = if request.tee {
        true
    } else if request.capture_only {
        false
    } else {
        settings.tee
    };
    if let Some(format) = request.format {
        settings.format = format;
    }
    if let Some(style) = request.style {
        settings.style = style;
    }
    if let Some(jobs) = request.jobs.as_ref() {
        // Parsed here rather than by clap so the refusal can say what was wrong
        // with the value. `0` is a width nobody can mean, and reading it as `1`
        // would answer a question the caller did not ask; reading it as
        // "unbounded" would be worse.
        settings.jobs = jobs
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                UsageError::raise(format!(
                    "exec: --jobs wants a positive whole number, not `{jobs}`"
                ))
            })?;
    }
    settings.continue_on_error = settings.continue_on_error || request.continue_on_error;
    // The report goes to the ERROR channel, never `out`: stdout belongs to the
    // wrapped command (CLOUD-285), so a pointer line there would corrupt a
    // document the caller may be parsing.
    exec::run_with(&request.command, &patterns, &settings, err)
}

fn load_exec_settings(
    overrides: &Overrides,
) -> Result<(Vec<outputs::OutputPattern>, exec::ExecConfig)> {
    let here = Path::new(".");
    // The flag before the file, for the reason `load_policy` states at length
    // (CLOUD-719). The failure here is quieter than the hook's and still real:
    // deleting `batten.toml` drops every `[[exec_pattern]]` row, so a wrapped
    // command that lies with exit `0` stops being promoted to a failure — the
    // one thing CLOUD-117 built this table to catch.
    if overrides.config_from.is_none() && !here.join(config::CONFIG_FILE).exists() {
        return Ok((Vec::new(), exec::ExecConfig::DEFAULT));
    }
    // One resolve for both, because they are one question — what this repository
    // declared about wrapped commands. Two calls would read the authority twice
    // and could, on a file rewritten in between, answer from two different epochs.
    let config = resolve::resolve(here, overrides)?;
    let settings = config.exec.unwrap_or(exec::ExecConfig::DEFAULT);
    Ok((config.exec_patterns, settings))
}

/// Map one decoded call onto its harness's decision channel.
///
/// Split out of [`run_hook`] so the mapping is reachable without the process's
/// own stdin: `run_hook` owns the boundary (stdin, the bypass variable, the
/// config load) and this owns the contract CLOUD-40's matrix pins — including
/// the case where writing the decision document itself fails.
fn render(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    decision: hook::Decision,
    hatch: &str,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // THE DECISION ARRIVES AS A VALUE, which is what makes this a renderer
    // rather than a second adjudicator (CLOUD-898). A handler's refusal and the
    // engine's own reach the host through the identical match below: a
    // dispatched program must not be able to reach a channel the engine does
    // not, and one rendering path is how that is structural rather than
    // reviewed. It also drops `policy` and `facts` from the signature — a
    // renderer that cannot see the inputs cannot re-decide by accident.
    match decision {
        hook::Decision::Allow => Ok(ExitCode::Success),
        // A suppressed deny (CLOUD-610) is an allow that owes a record, and this
        // is where the record is written — on the ERROR channel, at `Normal`, in
        // the shape the tree side writes at the `waiver::apply` call site. Both
        // choices are the tree side's, taken again rather than re-decided: stderr
        // because a decision document on stdout is what a host parses and an
        // audit line is not part of it, and `Normal` because a policy finding
        // that was let through is not a detail a default run should have to ask
        // for.
        //
        // Pointer-only (non-negotiable rule 4): `Suppressed` carries a rule and
        // an expiry and structurally cannot carry the command, so this call site
        // has nothing to leak even by mistake.
        hook::Decision::Waived(suppressed) => {
            output::message(mode, Verbosity::Normal, err, &suppressed.line_text())?;
            Ok(ExitCode::Success)
        }
        // One dispatch for every host, because the *shape* of the answer is the
        // adapter's business and the decision is not. A host that reads a body
        // gets one; a host whose channel is the exit code alone gets the §7 `2`
        // with the reason on stderr. Adding a host does not touch this function.
        //
        // The host's OWN event spelling goes back, not our normalized token: a
        // decision document is read by the host, which knows only its own
        // vocabulary. Normalizing inward and echoing outward are different
        // directions, which is why the envelope carries both.
        // One refusal value, projected onto whichever channel this host reads
        // (CLOUD-122). The projection happens once, here, so the in-band document
        // and the stderr line cannot disagree about what the refusal said or
        // whether it named a fix.
        hook::Decision::Deny(refusal) => {
            let reason = hook::deny_text(&refusal, hatch);
            match hook::encode_deny(harness, &envelope.raw_event, &reason)? {
                Some(body) => {
                    writeln!(out, "{body}")?;
                    Ok(ExitCode::Success)
                }
                None => Err(Denial::raise(reason)),
            }
        }
        // The escalation degradation (CLOUD-45 §7(b)), decided in exactly one
        // place. Unreachable until CLOUD-340 lands the `ask` severity that lets a
        // consumer ask for one — stated rather than left to be discovered, and
        // written now so that issue adds a config token and not a decision. Where the host can ask a human, the ask travels on its channel
        // and the call is neither allowed nor refused. Where it cannot, this
        // falls through to the deny arm's contract — the SAME refusal text, the
        // §7 `2`. What it never becomes is an allow: "check with a human"
        // degrading to "go ahead" is the one direction that inverts the policy,
        // and it is why `encode_ask`'s `None` means refuse rather than proceed.
        hook::Decision::Ask(refusal) => {
            let reason = hook::deny_text(&refusal, hatch);
            match hook::encode_ask(harness, &envelope.raw_event, &reason)? {
                Some(body) => {
                    writeln!(out, "{body}")?;
                    Ok(ExitCode::Success)
                }
                None => Err(Denial::raise(reason)),
            }
        }
    }
}

/// One finding as the `-J` data channel renders it (§6).
///
/// Borrowed from the finding rather than owning a copy, and carrying **two**
/// severity fields that are not two sources of truth: `severity` is the
/// committed rule's own rating, and `report` is that rating rendered through the
/// taxonomy table *after* the resolved `fail_on_warning` setting has been
/// applied. A promoted warning is therefore visible as `"severity": "warn"` with
/// `"report": "fail"` — the promoted disposition, derived here at the output
/// boundary and never stored (see [`severity`]'s one-stored-field rule).
///
/// `identity` is the whole [`identity::StoredIdentity`], not a bare fingerprint,
/// so this document joins `state list -J` **key for key** rather than merely
/// agreeing in value — the same `identity.fingerprint` path reads on both. The
/// version rides along because a consumer freezing a fingerprint forever (SARIF's
/// `partialFingerprints`, CLOUD-167) has to know which function minted it.
#[derive(Debug, serde::Serialize)]
struct FindingView<'a> {
    rule: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    severity: RuleSeverity,
    report: severity::ReportLevel,
    /// The finding's minted identity (CLOUD-322).
    ///
    /// Emitted unconditionally. The oracle argument that kept it off this
    /// channel was inherited from the secret class and does not transfer: a
    /// code-anchored fingerprint digests a line of **tracked source**, already
    /// readable by anyone reading the `path:line` beside it, so confirming a
    /// guess about it buys nothing. The secret class cannot leak here however
    /// this path is written, because [`identity::secret_code_fingerprint`] takes
    /// an `IdentityKey` in its signature — a secret-bearing identity cannot be
    /// minted unkeyed at all.
    ///
    /// Withholding it would not remove the need for a stable key on the wire
    /// (drain dedup, worktree hygiene, SARIF); it would move the derivation
    /// elsewhere, which is the second identity a single module exists to prevent.
    identity: &'a identity::StoredIdentity,
}

/// The `-J` payload for one `check`/`enforce` run.
///
/// The resolved setting rides alongside the findings so a consumer can tell a
/// `warn` that was promoted from one that was not without re-deriving the §8
/// chain itself.
#[derive(Debug, serde::Serialize)]
struct CheckReport<'a> {
    fail_on_warning: bool,
    /// The keys the working tree weakened relative to `--config-from`'s ref.
    /// Absent when the run did not name one, so the field's presence says
    /// "a base ref was compared" rather than "nothing was weakened".
    #[serde(skip_serializing_if = "Option::is_none")]
    config_delta: Option<Vec<DeltaView<'a>>>,
    /// The transcript capability's state, when the authority configured one
    /// (CLOUD-95). Absent when no transcript is declared, so the field's presence
    /// says "this repository uses the capability" rather than "it is available" —
    /// the same reading `config_delta` above gives its own absence.
    ///
    /// It rides the DATA channel deliberately. The stderr half is ladder-gated,
    /// so `--silent` would erase the one signal that dependent rules did not run,
    /// and a skipped gate nobody was told about is the false green this engine
    /// exists to catch. `-J` has no `Mode` to consult, so this cannot be silenced.
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript: Option<TranscriptView>,
    findings: Vec<FindingView<'a>>,
}

/// The transcript capability as the `-J` document renders it: a state token and,
/// when present, counts. Never a pointer into the file's content, and never the
/// configured path — a path is the operator's filesystem, which the data channel
/// has no business carrying.
#[derive(Debug, serde::Serialize)]
struct TranscriptView {
    capability: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    counts: Option<transcript::Counts>,
    /// Unprompted self-persistence (CLOUD-267), as counts and line pointers.
    ///
    /// Advisory and structurally unable to block: it rides the transcript view
    /// rather than the `findings` vec, so no promotion setting and no
    /// `--fail-on-warning` can route it to an exit code (house style §0.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    unprompted_memory_writes: Option<SelfWriteView>,
}

/// The self-persistence scan as the `-J` document renders it.
///
/// Counts plus bare line numbers. Never the memory key, the target path, the
/// tool arguments, or the written bytes — those are what the agent persisted,
/// and disclosing them is the leak the rule exists to avoid.
#[derive(Debug, serde::Serialize)]
struct SelfWriteView {
    #[serde(flatten)]
    counts: selfwrite::Counts,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    lines: Vec<usize>,
}

/// One weakened key in the `-J` payload, the same pointer the human channel
/// prints, split into its parts so a consumer need not parse the arrow.
#[derive(Debug, serde::Serialize)]
struct DeltaView<'a> {
    key: &'a str,
    base: &'a str,
    working: &'a str,
}

/// The transcript half of the `-J` document.
///
/// `None` for an unconfigured repository: a config that never mentions the key
/// is not missing anything, so the document carries no key either. An **absent**
/// capability does get a view, because that is the half `--silent` cannot erase
/// and the whole reason the skip is honest.
fn transcript_view(
    capability: &transcript::Capability,
    self_writes: &[selfwrite::Detection],
) -> Option<TranscriptView> {
    match capability {
        transcript::Capability::Unconfigured => None,
        // Both unreadable states render the same SHAPE — no counts, nothing to
        // count — while `as_str()` keeps them different WORDS. That split is the
        // whole point: a reader of the `-J` document must be able to tell a seam
        // that was never wired from data that was damaged, because only the
        // second names something to repair (CLOUD-819).
        transcript::Capability::Absent | transcript::Capability::Unreadable(_) => {
            Some(TranscriptView {
                capability: capability.as_str(),
                counts: None,
                unprompted_memory_writes: None,
            })
        }
        transcript::Capability::Present(stream) => Some(TranscriptView {
            capability: capability.as_str(),
            counts: Some(stream.counts()),
            // Emitted only when there is something to point at, so a clean
            // transcript adds no key rather than an empty one.
            unprompted_memory_writes: (!self_writes.is_empty()).then(|| SelfWriteView {
                counts: selfwrite::counts(self_writes),
                // The session pointer the finding anchors to: an id the host
                // minted, never transcript content.
                session: stream.session.clone(),
                lines: self_writes.iter().map(|found| found.line).collect(),
            }),
        }),
    }
}

/// Scan a resolved transcript capability for unprompted self-persistence.
///
/// Split out of [`run_rules`] to keep that function under the line ceiling, and
/// the split falls on a real seam: this is the whole of CLOUD-267's engine-side
/// entry, so a reader looking for "where does the rule run" finds one place.
///
/// An unconfigured or absent capability yields no detections rather than an
/// error — the rule simply did not run, and `ABSENT_NOTICE` is what says so.
/// Which of the two rule surfaces [`run_rules`] is serving.
///
/// The `runner` fn pointer above already encodes this — `run_static` versus
/// `run_all` — but a fn pointer is not a value you can `match` on, and the judge
/// pass needs to ask. Stated as data rather than compared by address, so the
/// question "may this run spawn a configured command?" has one readable answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// `check`: declared `read` (§5), so no configured command runs.
    ReadOnly,
    /// `enforce`: unclassified, and the only surface a judge runs on.
    Spawning,
}

/// Run every configured judge row, and register what the judges said.
///
/// **This function returns no [`rules::Finding`], and that is its contract.** A
/// judge outcome goes to the store through [`findings::record_advisory`] and
/// nowhere else, so `any_blocking` never sees one and `--fail-on-warning` has
/// nothing to promote (§0.3, CLOUD-56). The exit code of the run that called
/// this is decided entirely by the deterministic findings beside it.
///
/// The order inside each row is load-bearing and is CLOUD-135's, not this
/// issue's: match the glob, offer the spans to [`judge::assemble`], and let it
/// decide protection **before any byte is read into a payload**. A refusal here
/// is exit 1 — a statement about the invocation, never a policy verdict.
///
/// # Errors
///
/// [`UsageError`] (→ exit `1`) for a judge row with no resolvable command, a
/// program absent from `PATH`, or a payload the boundary refuses.
fn run_judges(
    err: &mut dyn Write,
    mode: Mode,
    config: &resolve::Resolved,
    root: &Path,
) -> Result<Vec<findings::Advisory>> {
    let rows: Vec<&rules::Rule> = config
        .rules
        .iter()
        .filter(|rule| rule.kind == rules::RuleKind::Judge)
        .collect();
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let protected = rules::PathSet::includes("protected", &config.protected)?;
    let cap = judge::effective_cap(
        config.judge.as_ref().and_then(|j| j.max_payload_bytes),
        None,
    );
    let files = rules::tree_files(root)?;

    let mut raised = Vec::new();
    for rule in rows {
        let argv = judge::argv(&rule.id, config.judge.as_ref())?;
        let Some(glob) = rule.glob.as_deref() else {
            continue;
        };
        let criteria = rule.criteria.clone().unwrap_or_default();
        let matched: Vec<&String> = files
            .iter()
            .filter(|path| rules::glob_match(glob, path))
            .collect();
        // No match is no question: a judge asked about nothing would spend a
        // metered model call to be told so. The glob is a gate before it is a
        // payload source, the same reading `run_rule` gives a command row.
        if matched.is_empty() {
            continue;
        }
        let mut spans = Vec::with_capacity(matched.len());
        for path in &matched {
            spans.push(judge::Span {
                rule: rule.id.clone(),
                path: Some((*path).clone()),
                line: None,
                class: judge::PayloadClass::FileText,
                bytes: std::fs::read(root.join(path)).unwrap_or_default(),
            });
        }
        let rule_text = judge::RuleText {
            id: rule.id.clone(),
            criteria,
        };
        let assembled = judge::assemble(&rule_text, &spans, &protected, config.judge.as_ref(), cap)
            .map_err(|refusal| UsageError::raise(refusal.line()))?;
        let verdict = judge::invoke(&rule.id, &argv, &assembled.serialized)?;
        // The pointer-only invocation record, on the error channel and
        // ladder-gated: it is a statement about Batten's own egress, which a
        // default run should see and a quiet one need not.
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "judge {}: {} bytes to {} over {} file(s) — {}",
                rule.id,
                assembled.record.bytes,
                argv.first().map_or("<none>", String::as_str),
                assembled.record.matched_files,
                verdict.as_str()
            ),
        )?;
        if !verdict.registers() {
            continue;
        }
        raised.push(findings::Advisory {
            rule: rule.id.clone(),
            // A judge finding is a whole-scope condition — the row and the file
            // set it named — so it takes the `scope` identity, the same one a
            // budget or a ledger finding takes. Deliberately NOT the payload
            // hash: that would re-mint the identity every time any matched file
            // changed, so a settled judge finding would reappear as a new one
            // after an unrelated edit, which is the churn CLOUD-123 exists to
            // prevent.
            identity: identity::StoredIdentity::new(
                identity::FindingKind::Scope,
                identity::scope_fingerprint(&rule.id, glob),
            ),
            tier: rule.tier.unwrap_or(severity::AdvisoryTier::Advisory),
            path: glob.to_owned(),
            line: None,
            check: findings::Check::Argv(argv.clone()),
            remediation: findings::Remediation::NoFix(
                rule.no_fix_reason.clone().unwrap_or_default(),
            ),
        });
    }
    Ok(raised)
}

/// Put judge outcomes in the findings store, or say why they are not there.
///
/// Split from [`run_judges`] so the spawn and the persistence are separable: a
/// judge's verdict is a fact about the tree whether or not a store exists to
/// hold it, and folding the two together would make an unopenable store look
/// like a judge that did not run.
///
/// **No failure path here reaches the exit code.** A store that is absent,
/// busy, or newer than this binary reports and returns — the same posture
/// `state record` takes, and a stronger obligation here, because refusing to
/// finish an `enforce` over a *bookkeeping* problem would give an advisory
/// surface the blocking power §0.3 denies it.
///
/// # Errors
///
/// Propagates a write failure on the error channel.
fn register_advisories(raised: &[findings::Advisory], err: &mut dyn Write) -> Result<()> {
    if raised.is_empty() {
        return Ok(());
    }
    let repo = git::repo_root(Path::new("."))?;
    let Some(branch) = git::current_branch(Path::new("."))? else {
        // Detached HEAD names no ref, so there is no context to key an instance
        // on. `state record` raises here; this one reports and carries on, for
        // the reason in the doc comment.
        writeln!(
            err,
            "batten: HEAD is detached, so {} judge finding(s) belong to no ref: persisted:false",
            raised.len()
        )?;
        return Ok(());
    };
    let context = findings::Context::new(format!("refs/heads/{branch}"));
    let commit = git::head_commit(Path::new("."))?;

    let bound = store::commit(store::resolve(&repo)?)?;
    if let Some(note) = &bound.note {
        writeln!(err, "batten: {note}")?;
    }
    let access = journal::open(&bound.dir)?;
    if let journal::Access::DegradedReadOnly { reason, .. } = &access {
        writeln!(err, "batten: degraded read-only: {reason}")?;
        writeln!(
            err,
            "batten: {} judge finding(s): persisted:false",
            raised.len()
        )?;
        return Ok(());
    }
    let schema = access.format().findings_schema;
    let here = std::env::current_dir().ok();
    for advisory in raised {
        findings::record_advisory(
            &bound.dir,
            &context,
            &commit,
            here.as_deref().and_then(Path::to_str),
            advisory,
            schema,
        )?;
    }
    Ok(())
}

/// Put an enforce-surface scan in the findings store, and journal each evaluation
/// it performed (CLOUD-529).
///
/// # Why the call moved and the scan did not
///
/// `batten state record` scans with [`rules::run_static`], so no finding from an
/// enforce-only kind — `command`, and the `secrets` kind — could ever reach the
/// store, and everything downstream of the store (the drain, self-clearing, key
/// custody) was blind to that whole half of the engine. The obvious repair is to
/// widen the recording verb's scan, and it is the wrong one: that verb's own
/// rustdoc refuses it, because a recording verb that could execute a configured
/// command would put user-supplied code behind a store write. So the *journaling*
/// moved to the surface that already spawns instead. `enforce` is already
/// classified `unclassified` for exactly that reason, so this adds no
/// effect-table row and re-classifies nothing, and [`run_state_record`] is
/// untouched.
///
/// # It never mints a store, and that is the drain's posture rather than a
/// recorder's
///
/// [`store::bound_dir`], not [`store::commit`]. `state record` is the declared
/// write half and may mint; a verb whose job is a verdict may not turn a
/// first-ever run into a store creation as a side effect. An unbound store is
/// "not asked", reported at [`Verbosity::Verbose`] and nothing more — the same
/// answer `drain_advisories` gives, for the same reason.
///
/// # No failure path here reaches the exit code
///
/// A detached `HEAD`, an unbound store, a busy merge, a degraded read-only store
/// and a finding the store refuses all report and return. Journaling is a side
/// record of a verdict already reached, so letting any of it move the exit code
/// would make bookkeeping into policy — §5's clause, and the same posture
/// [`register_advisories`] takes one function above.
///
/// # Errors
///
/// Propagates a write failure on the error channel, and a store or journal I/O
/// failure (exit 3, fail loud — never a deny).
fn register_enforce_findings(scan: &rules::Scan, mode: Mode, err: &mut dyn Write) -> Result<()> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            "no bound findings store, so this scan is not journalled",
        )?;
        return Ok(());
    };
    // The ref comes from the process directory, never from `repo`: `repo_root`
    // answers with the MAIN worktree's root, so asking it for the branch would
    // pile every linked worktree's observations onto one context.
    let Some(branch) = git::current_branch(Path::new("."))? else {
        writeln!(
            err,
            "batten: HEAD is detached, so this scan belongs to no ref: persisted:false"
        )?;
        return Ok(());
    };
    let context = findings::Context::new(format!("refs/heads/{branch}"));
    let commit = git::head_commit(Path::new("."))?;

    let access = journal::open(&dir)?;
    if let journal::Access::DegradedReadOnly { reason, .. } = &access {
        writeln!(err, "batten: degraded read-only: {reason}")?;
        writeln!(err, "batten: enforce {context}: persisted:false")?;
        return Ok(());
    }
    let schema = access.format().findings_schema;

    // `record` refuses a finding with no remediation as a usage error, which is
    // the right answer for a recording verb and the wrong one here: it would let
    // one unfixable rule row turn a policy verdict into exit 1. `Rule::validate`
    // already refuses such a row, so this partition should never fire — which is
    // exactly why it reports a count instead of being an `expect`.
    let (recordable, unrecordable): (Vec<_>, Vec<_>) = scan
        .findings
        .iter()
        .cloned()
        .partition(|finding| finding.remediation.is_some());
    if !unrecordable.is_empty() {
        writeln!(
            err,
            "batten: {} finding(s) carry no remediation: persisted:false",
            unrecordable.len()
        )?;
    }

    let here = std::env::current_dir().ok();
    findings::record(
        &dir,
        &context,
        &commit,
        here.as_deref().and_then(Path::to_str),
        &recordable,
        schema,
        &scan.not_evaluated,
    )?;

    // Custody acts on stored records, which is why it lands here and not in
    // `secrets.rs`: that module holds the keys and must never read the store it
    // protects, and this seam holds the store and never sees a key's bytes.
    reconcile_secret_custody(&repo, &dir, err)?;

    // The worktree actually scanned, not the repository root: `shard_id` is per
    // WORKTREE, and a relative `.` would fingerprint identically from every one of
    // them — collapsing the per-writer shards into one shared file, which is the
    // lock-free concurrency the journal is built on.
    let appended = journal_evaluations(&dir, here.as_deref().unwrap_or(&repo), &context)?;
    if appended > 0 && journal::merge(&dir)? == journal::Merge::Busy {
        writeln!(
            err,
            "batten: shard-merge busy; this scan's evaluations stay queued in this worktree's shard"
        )?;
    }
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!("enforce {context}: {appended} evaluation(s) journalled"),
    )?;
    Ok(())
}

/// Apply what the custody ledger says to the records it is about: move a rotated
/// identity onto its new key, re-open an orphaned one, and close a finished
/// rotation window (CLOUD-529).
///
/// # The split this function is one half of
///
/// `secrets.rs` owns the keys and the ledger and reads **no** store — the
/// invariant the keyed identity rests on is that the key is not reachable from the
/// digests it protects, and a module that opened the store would be one edit away
/// from breaking it. This seam owns the store and never sees a key's bytes. So the
/// span-dependent half (a dual-HMAC pair, computable only while both keys are held)
/// is written to the ledger by the scan, and the record-dependent half is applied
/// from here.
///
/// # Rotation moves a record, it does not re-mint one
///
/// A join names (old fingerprint, new fingerprint) for one span under two
/// generations. Applying it copies the record onto the new identity **carrying its
/// disposition, tier and instances**, and removes the old one. That is the whole
/// point of joining rather than re-scanning into a fresh record: a
/// `rejected-by-design` decision outlives the key it was made under, and a
/// rotation that dropped it would silently resurrect every finding a reviewer had
/// already dismissed.
///
/// # Key loss is the other branch, and it is loud
///
/// A generation the ledger names that the key file no longer holds makes every
/// identity minted under it unreproducible: the span comes back from a re-scan, the
/// old HMAC does not come back without the old key. Those findings are re-opened —
/// returned to unsettled, so the operator re-triages them — and the count is
/// reported. **Never a silent re-mint**: `secrets::read` already refuses to re-mint
/// over a malformed key file, and this is that same refusal at the store boundary,
/// which is where the consequence actually lands.
///
/// # Errors
///
/// Propagates a ledger read, a store read or a record write failure.
fn reconcile_secret_custody(repo: &Path, store_dir: &Path, err: &mut dyn Write) -> Result<()> {
    let today = waiver::today()?;
    let key_file = secrets::key_path(repo)?;
    let ledger = secrets::ledger_path(repo)?;
    // Nothing has ever scanned for a secret here, so there is no custody to
    // reconcile and — this is the load-bearing half — no key to mint either. A
    // reconciliation that minted a key would give every repository a key file for
    // running `enforce` once, and the orphan check's whole premise is that a key
    // file appearing is not the same as a generation existing.
    if !ledger.exists() {
        return Ok(());
    }

    let joined = secrets::joins(&ledger)?;
    let mut moved = 0;
    for (old, new) in &joined {
        if apply_join(store_dir, *old, *new)? {
            moved += 1;
        }
    }
    if moved > 0 {
        writeln!(
            err,
            "batten: secret-identity rotation: {moved} finding(s) re-keyed"
        )?;
    }

    let lost = secrets::orphaned_key_ids(repo, today)?;
    if !lost.is_empty() {
        // Every secret-class record EXCEPT the ones a join has already moved onto a
        // held generation. The exclusion is what keeps the event proportionate, and
        // the breadth of what remains is not a shortcut: the key id lives inside the
        // preimage, so with the key gone there is no way to ask a record which
        // generation minted it. Guessing would be the silent path, and the honest
        // answer to "cannot tell" is to re-triage.
        let reproducible: std::collections::BTreeSet<String> =
            joined.iter().map(|(_, new)| new.to_hex()).collect();
        let mut reopened = 0;
        for mut record in findings::load_all(store_dir)? {
            if !record.identity.is_secret()
                || reproducible.contains(&record.identity.fingerprint.to_hex())
            {
                continue;
            }
            if record.reopen() {
                findings::save_one(store_dir, &record)?;
                reopened += 1;
            }
        }
        for key_id in &lost {
            secrets::record_orphan(&key_file, key_id, reopened)?;
        }
        // On the error channel unconditionally, never ladder-gated: this is the
        // loud event §7(d) asks for, and a custody loss an operator has to opt in
        // to hearing about is one they will not hear about.
        writeln!(
            err,
            "batten: secret-identity key(s) {} are gone: {reopened} finding(s) re-opened for \
             re-triage. Their identities cannot be re-derived, so nothing has been re-minted.",
            lost.join(", ")
        )?;
    }

    // The window closes when nothing is keyed under the retired generation any
    // more — which only this side can see, since it is a fact about records.
    //
    // **The test is over the RECORDS, not over the joins**, and the difference is a
    // window that closes too early. A run whose secrets rule matched nothing
    // journals no pair at all, so "no outstanding joins" is true on the first
    // evaluation after a rotation — and retiring there would drop the old key while
    // records were still keyed under it, which is the orphan this whole branch
    // exists to avoid, reached by the code meant to finish the rotation cleanly.
    // So a secret-class record that is not the new half of a join holds the window
    // open. A cleared-but-still-present record holds it open too, and that is the
    // safe direction: it costs a rotation that cannot start until ref-death GC
    // collects the record, where the other way costs a key.
    if secrets::custody(repo, today)?.retired().is_some() {
        let joined_new: std::collections::BTreeSet<String> =
            joined.iter().map(|(_, new)| new.to_hex()).collect();
        let outstanding = findings::load_all(store_dir)?.into_iter().any(|record| {
            record.identity.is_secret()
                && !joined_new.contains(&record.identity.fingerprint.to_hex())
        });
        if !outstanding && let Some(key_id) = secrets::retire(&key_file)? {
            writeln!(
                err,
                "batten: secret-identity rotation complete: key {key_id} retired"
            )?;
        }
    }
    Ok(())
}

/// Move one record from its pre-rotation identity to its post-rotation one.
///
/// Returns whether anything moved: an already-applied join finds no old record and
/// is a no-op, which is what makes reading the whole ledger every run cheap and
/// safe rather than needing an "applied" marker that could itself be lost.
fn apply_join(
    store_dir: &Path,
    old: identity::Fingerprint,
    new: identity::Fingerprint,
) -> Result<bool> {
    let Some(mut record) = findings::load_one(store_dir, old)? else {
        return Ok(false);
    };
    // The new identity, with everything the old record knew. `tier` travels
    // untouched for CLOUD-80's no-escalation law, and `disposition` travels because
    // a rotation is a change of key, not a change of what a reviewer decided.
    record.identity = identity::StoredIdentity::secret(new);
    findings::save_one(store_dir, &record)?;
    findings::forget(store_dir, old)?;
    Ok(true)
}

/// Journal one evaluation entry per identity this scan spoke about.
///
/// # Read back from the store rather than folded a second time
///
/// [`findings::record`] folds identical spans into one identity with a count
/// inside itself and returns only a summary, so an entry built from the scan
/// would have to repeat that fold — two implementations of "how many
/// occurrences", drifting the moment either changes. Reading the instance back
/// means the journal reports exactly what the store holds, with the store as the
/// single authority.
///
/// # The clear side is the whole point
///
/// An evaluation journal that recorded only raises could never show an
/// oscillation, because half of every oscillation is a clear. `record`'s resolve
/// pass has just written `Observed(0)` for everything this context no longer
/// sees, so reading instances back picks up raises, clears and holds in one pass
/// — which is what makes a flap ratio computable at all (CLOUD-165).
///
/// # The growth this accepts, stated rather than discovered
///
/// One entry per evaluated identity per run is unbounded in a long session, where
/// a disposition entry is written once. That is inherent to an evaluation record:
/// the denominator of a state-change *rate* is every evaluation, including the
/// unchanged ones, so suppressing repeats would remove the denominator. What
/// bounds it is that shards die with their worktree and a generation rotation
/// truncates the log, and that every reader takes a bounded suffix.
///
/// # Errors
///
/// Returns an error when the store cannot be read or a shard cannot be appended.
fn journal_evaluations(
    store_dir: &Path,
    worktree: &Path,
    context: &findings::Context,
) -> Result<usize> {
    let shard = journal::shard_id(worktree);
    let mut appended = 0;
    for record in findings::load_all(store_dir)? {
        let Some(instance) = record.instance(context) else {
            continue;
        };
        journal::append(
            store_dir,
            &shard,
            &journal::Entry {
                identity: record.identity.fingerprint.to_hex(),
                rule: record.rule.clone(),
                origin: journal::Origin::Scan,
                context: Some(context.as_str().to_owned()),
                observation: Some(instance.occurrences),
                // A scan settles nothing and shows nothing: the disposition is the
                // agent's to give, and `presentation` belongs to the drain channel
                // (`journal::Origin::Scan`), which is why `merge` ignores this one.
                disposition: None,
                presentation: findings::Presentation::Shown,
            },
        )?;
        appended += 1;
    }
    Ok(appended)
}

/// Where one observation is being written: the ref it belongs to, the commit
/// that ref was at, and the store that will hold it.
///
/// Grouped rather than passed as four parameters because they travel together
/// and only together — an instance is keyed by context and stamped with the
/// commit, and the schema is the store's own version rather than this binary's
/// (`journal`'s write-old rule). Naming the tuple also keeps
/// [`register_completion`] inside the workspace's argument-count lint without
/// the lint being silenced, which is the honest way past it.
#[derive(Debug, Clone, Copy)]
struct Recording<'a> {
    /// The ref this observation belongs to.
    context: &'a findings::Context,
    /// The commit that ref was at when the scan ran.
    commit: &'a str,
    /// The bound store's directory.
    store_dir: &'a Path,
    /// The record schema **the store is written in**, never [`FINDINGS_SCHEMA`].
    ///
    /// [`FINDINGS_SCHEMA`]: findings::FINDINGS_SCHEMA
    schema: u32,
}

/// Run every detector that reads the completed transcript, and fold what they
/// found into the store (CLOUD-97, CLOUD-98).
///
/// Called from `state record` — the verb that already binds the store, owns the
/// ref context, and is the declared write half — so this costs **no new command
/// and no new effect-table row**. `check` is deliberately untouched: these
/// findings never enter that verb's `findings` vec, which is how "an advisory
/// surface is structurally unable to block" (§0.3) is satisfied here, exactly as
/// [`register_advisories`] satisfies it for a judge.
///
/// The transcript is resolved and parsed **once** for every detector. Not only
/// an economy: the absent notice below is a statement about a capability rather
/// than about a rule, so emitting it per detector would report one fact as
/// several, and two parses of one file are two chances to disagree about it.
///
/// Two of the three silent states are shared by every detector:
///
/// * **Unconfigured** — the repository does not use the transcript input, so
///   nothing is written and nothing is said ([`transcript`]'s absent-is-not-empty
///   law).
/// * **Absent** — configured and unreadable, so no predicate ran. The store is
///   left exactly as it was, which **holds** an open finding rather than
///   clearing it, and the notice is reported for the same reason `check` reports
///   it: a skipped gate that exits `0` in silence is the false green.
///
/// # Errors
///
/// Propagates a write failure, an undecodable transcript, and an unresolvable
/// declared `must_land_on`.
fn register_transcript_detectors(
    repo: &Path,
    recording: &Recording<'_>,
    config: &resolve::Resolved,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let declared = config
        .transcript
        .as_ref()
        .and_then(|declared| declared.path.as_deref());
    let capability = transcript::resolve(Path::new("."), declared);
    let stream = match &capability {
        transcript::Capability::Unconfigured => return Ok(()),
        transcript::Capability::Absent => {
            output::message(mode, Verbosity::Normal, err, transcript::ABSENT_NOTICE)?;
            return Ok(());
        }
        // The same could-not-look answer as absent, plus the pointer that names
        // the line to repair (CLOUD-819). This path already returned `Ok(())`
        // for absent, so recording nothing is the established reading here; what
        // changes is only that a decode failure reaches it instead of raising.
        // Reported through the shared helper, so the two callers cannot drift
        // into wording the same state differently.
        transcript::Capability::Unreadable(_) => {
            report_transcript_capability(&capability, mode, err)?;
            return Ok(());
        }
        transcript::Capability::Present(stream) => stream,
    };
    register_completion(repo, recording, config, declared, stream, mode, err)?;
    register_bypass(recording, declared, stream, mode, err)
}

/// Evaluate the done-but-not-landed predicate and fold its answer into the
/// store (CLOUD-97).
///
/// The one silent state that is this detector's own rather than the
/// capability's: **not signalled** — the session declared no stopping point, so
/// nothing is written, because resolving an open finding on that silence would
/// let a scan of a still-running session clear an incident nobody addressed.
///
/// # Errors
///
/// Propagates a write failure, and an unresolvable declared `must_land_on` —
/// which is a config error the caller owes exit `1`, the reading
/// [`worktree::status`] already gives a target its author named and got wrong.
fn register_completion(
    repo: &Path,
    recording: &Recording<'_>,
    config: &resolve::Resolved,
    declared: Option<&str>,
    stream: &transcript::Stream,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let &Recording {
        context,
        commit,
        store_dir,
        schema,
    } = recording;
    let signal = completion::signal(stream);
    // The landing question is asked only once the session has declared a
    // stopping point. Not an optimisation: an unsignalled session's outcome is
    // already decided, and asking git anyway would let a misconfigured target
    // fail a scan whose verdict never depended on it.
    let landing = match signal {
        None => None,
        Some(_) => match resolve_landing_target(repo, config)? {
            Some(target) => Some((
                git::landing(repo, &target, "HEAD", git::Window::DEFAULT)?,
                target,
            )),
            None => None,
        },
    };
    let outcome = completion::assess(signal, landing.as_ref().map(|(landing, _)| landing));

    let Some(observation) = outcome.observation() else {
        // Not signalled: nothing to write. Reported on the top rung, because a
        // detector that ran and answered "nothing" is a detail rather than news.
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            &format!("completion: {} {context}", outcome.as_str()),
        )?;
        return Ok(());
    };

    let identity = completion::identity(stream.session.as_deref());
    let fingerprint = identity.fingerprint.to_hex();
    let advisory = findings::Advisory {
        rule: completion::RULE_ID.to_owned(),
        identity,
        // The one stored severity axis: answer soon, on a bounded deadline, but
        // the session need not stop for it (CLOUD-80). Unlanded work at a
        // declared stopping point is time-sensitive — the checkout it lives in
        // is not permanent — and is still never a reason to block.
        tier: severity::AdvisoryTier::Caution,
        // A pointer pair: the transcript the operator declared, and the line the
        // marker was on. Never a line of it, and never the session id, which
        // reaches the store only inside the fingerprint above.
        path: declared.unwrap_or_default().to_owned(),
        line: outcome.signal().map(|signal| signal.line),
        // The engine's own next evaluation settles it — which *is* the
        // self-clearing mechanism, so the check names it rather than an argv a
        // caller would have to remember to run.
        check: findings::Check::Reevaluate,
        remediation: findings::Remediation::NoFix(completion::no_fix_reason(
            landing
                .as_ref()
                .map_or(completion::NO_TARGET, |(_, target)| target.as_str()),
        )),
    };
    findings::record_sequence(
        store_dir,
        context,
        commit,
        std::env::current_dir()
            .ok()
            .as_deref()
            .and_then(Path::to_str),
        &advisory,
        observation,
        schema,
    )?;

    // Pointer-only (rule 4): the outcome token, the ref, the identity, and
    // counts. Byte-stable for identical inputs — nothing here carries a clock,
    // a path outside the two the config already names, or a SHA.
    let detail = match &outcome {
        completion::Outcome::Raised {
            signal,
            unaccounted,
        } => format!(
            " {}:{} {} unaccounted, marker {}",
            advisory.path,
            signal.line,
            unaccounted,
            signal.marker.as_str()
        ),
        _ => String::new(),
    };
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!(
            "completion: {} {context} {fingerprint}{detail}",
            outcome.as_str()
        ),
    )?;
    Ok(())
}

/// Register every guardrail bypass the session recorded (CLOUD-98).
///
/// The store side is [`register_completion`]'s exactly — [`bypass::Detection`]
/// is a different predicate over the same substrate, registered through the same
/// door — and the two differences are both properties of the subject rather than
/// choices:
///
/// * **It never clears.** A bypass anchors to an immutable transcript event, so
///   the observation is always positive and never resolves to zero. A clean scan
///   writes nothing rather than a clear, because a later transcript saying
///   nothing about an earlier session's bypass is not evidence the bypass did
///   not happen. It settles by disposition instead (CLOUD-78's three-valued
///   model) — the issue's stated assumption 1, landed as written.
/// * **It carries a tier above the completion rule's.** `Warning` is CLOUD-80's
///   "answer now, before the work continues", which is what an overridden
///   guardrail is. Still structurally unable to block: an [`findings::Advisory`]
///   carries no severity the exit contract can read.
///
/// One finding per bypassed **operation**, so two different operations are two
/// findings and a repeat of one is a count.
///
/// # Errors
///
/// Propagates a write failure.
fn register_bypass(
    recording: &Recording<'_>,
    declared: Option<&str>,
    stream: &transcript::Stream,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let &Recording {
        context,
        commit,
        store_dir,
        schema,
    } = recording;
    let detections = bypass::scan(stream);
    if detections.is_empty() {
        return Ok(());
    }
    let path = declared.unwrap_or_default();
    let here = std::env::current_dir().ok();
    for detection in &detections {
        let advisory = findings::Advisory {
            rule: bypass::RULE_ID.to_owned(),
            identity: detection.identity.clone(),
            tier: severity::AdvisoryTier::Warning,
            path: path.to_owned(),
            // The refusal's line, so the pointer names where the guardrail
            // spoke; the retry's line rides the report below. Never the command,
            // never the target, never an argument.
            line: Some(detection.denied_line),
            check: findings::Check::Reevaluate,
            remediation: findings::Remediation::NoFix(bypass::no_fix_reason()),
        };
        findings::record_sequence(
            store_dir,
            context,
            commit,
            here.as_deref().and_then(Path::to_str),
            &advisory,
            findings::Observation::Observed(detection.retries),
            schema,
        )?;
        // Pointer-only (rule 4): the ref, the identity, the turn pair, the
        // refusal token and a count.
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "bypass: raised {context} {} {path}:{}->{} {} retry(ies), refusal {}",
                detection.identity.fingerprint.to_hex(),
                detection.denied_line,
                detection.retry_line,
                detection.retries,
                detection.refusal.as_str()
            ),
        )?;
    }
    Ok(())
}

/// The ref landedness is judged against: the declared key, else the remote's
/// recorded default.
///
/// The same ladder [`worktree::status`] walks, and deliberately the same one
/// rather than a second: `must_land_on` is the one key that names a landing
/// target, and a detector that resolved its own would be a second authority on
/// where work is supposed to go. `None` is "nobody could ask", which the caller
/// reads as not-computable and never as landed.
fn resolve_landing_target(repo: &Path, config: &resolve::Resolved) -> Result<Option<String>> {
    match config.must_land_on.as_deref() {
        Some(declared) => Ok(Some(declared.to_owned())),
        None => git::remote_default_branch(repo),
    }
}

/// The human half of the transcript report, for both states that could not be
/// read (CLOUD-819).
///
/// Ladder-gated, because it is a statement about Batten rather than a verdict —
/// the `-J` field is the half that cannot be silenced. Both states are reported;
/// only the unreadable one has a pointer to add, and `Capability::as_str` is what
/// keeps them different words on the data channel.
///
/// Extracted rather than inlined because `run_rules` sits against the line
/// ceiling `clippy::too_many_lines` enforces, and a reporting decision is a seam
/// worth naming in any case.
///
/// # Errors
///
/// Propagates a write failure on the message channel.
fn report_transcript_capability(
    capability: &transcript::Capability,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    match capability {
        transcript::Capability::Absent => {
            output::message(mode, Verbosity::Normal, err, transcript::ABSENT_NOTICE)?;
        }
        transcript::Capability::Unreadable(pointer) => {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("{} ({pointer})", transcript::UNREADABLE_NOTICE),
            )?;
        }
        transcript::Capability::Unconfigured | transcript::Capability::Present(_) => {}
    }
    Ok(())
}

fn scan_self_writes(
    capability: &transcript::Capability,
    declared: Option<&transcript::TranscriptConfig>,
) -> Vec<selfwrite::Detection> {
    match capability {
        transcript::Capability::Present(stream) => selfwrite::scan(
            stream,
            declared
                .and_then(|config| config.memory_root.as_deref())
                .unwrap_or(selfwrite::DEFAULT_MEMORY_ROOT),
        ),
        // An unreadable transcript joins these two rather than getting an arm of
        // its own: all three mean the stream could not be read, and this function
        // answers only "what did the rule detect". WHY it detected nothing is the
        // notice's job and the `-J` field's, which is where the three stay
        // distinguishable (CLOUD-819).
        transcript::Capability::Unconfigured
        | transcript::Capability::Absent
        | transcript::Capability::Unreadable(_) => Vec::new(),
    }
}

/// The human half of the self-persistence report.
///
/// Pointer-only: counts alone on this channel. Never the memory key, the target,
/// the arguments, or the bytes — those are what the agent persisted, and naming
/// them here would disclose exactly what the rule is watching being written.
///
/// Ladder-gated like every other statement-about-Batten, because the `-J` field
/// is the half that cannot be silenced.
///
/// # Errors
///
/// Propagates a write failure on the error channel.
fn report_self_writes(
    detections: &[selfwrite::Detection],
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    if detections.is_empty() {
        return Ok(());
    }
    let folded = selfwrite::counts(detections);
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!(
            "transcript: {} memory write(s) in a turn no user message opened, {} unresolved",
            folded.raised, folded.unresolved
        ),
    )?;
    Ok(())
}

/// Run the configured rules against the current directory and report findings.
///
/// `runner` selects which surface runs them — [`rules::run_static`] for the
/// `read`-effect `check`, [`rules::run_all`] for the unclassified `enforce`
/// (§5, CLOUD-170). Both report identically; only the admissible rule kinds
/// differ, so the two verbs can never drift in output shape.
///
/// Output is pointer-only (non-negotiable rule 4): one `path:line rule-id` per
/// finding, byte-stable and never the matched bytes. `json` swaps that for the
/// `-J` data channel, which is the same pointers plus each finding's severity
/// and its post-promotion reporting level — still never the matched bytes.
///
/// The exit code consumes each finding's severity (CLOUD-61): a clean run exits
/// [`ExitCode::Success`], any `deny` finding exits [`ExitCode::Violation`], and
/// a `warn` finding is reported without failing the run unless the resolved
/// `fail_on_warning` setting promotes it (CLOUD-49). Reporting is unaffected by
/// that promotion: a warn finding prints either way, and only the verdict moves.
/// The `config deprecations -J` document: what left the surface unannounced.
///
/// THREE-VALUED, and `baseline` is the field that makes it so. An unreadable
/// baseline and a clean comparison would otherwise both render
/// `removed_without_window: []`, so a consumer could not tell "nothing was
/// removed" from "nothing was compared" — CLOUD-251's vacuous pass, moved out of
/// the exit code and into the document a parser actually reads.
#[derive(Debug, serde::Serialize)]
struct DeprecationReport<'a> {
    against: &'a str,
    baseline: &'a str,
    removed_without_window: &'a [String],
}

/// The `config epoch -J` document: the digest and the surface it covers.
#[derive(Debug, serde::Serialize)]
struct EpochReport<'a> {
    epoch: &'a str,
    tracked: &'a [String],
}

/// One smell in the `config lint -J` payload, split into the parts the human
/// pointer line concatenates.
#[derive(Debug, serde::Serialize)]
struct SmellView<'a> {
    at: String,
    id: &'a str,
}

/// The `config lint -J` document. A struct rather than a bare array so the count
/// is a length a consumer can read without a second convention.
#[derive(Debug, serde::Serialize)]
struct LintReport<'a> {
    smells: Vec<SmellView<'a>>,
}

/// Where a rule run is anchored: the process directory when it carries the
/// authority, otherwise the repository root (CLOUD-214).
///
/// A run used to anchor at `.` unconditionally, so `batten check` from a
/// subdirectory reported "no config found at ./batten.toml" and exited on a
/// repository it was standing inside. A pre-commit hook survived that because
/// git runs it at the root; an agent part-way through a trajectory does not, and
/// being unable to run the gate from where you already are is an adoption
/// blocker rather than a nicety.
///
/// **Exactly two candidates are consulted, in this order**, and the order is the
/// whole design:
///
/// 1. **`.`, when it carries a `batten.toml`.** A directory that declares its own
///    authority *is* the subject, whatever it happens to be nested inside. This
///    is what keeps a fixture tree — materialized under `target/`, deep inside
///    this repository — answering about itself rather than about its host, and
///    it makes the common root invocation bit-for-bit what it always was.
/// 2. **The repository root**, via the one `repo_root` primitive. This is the
///    new capability and nothing else: a directory with no authority of its own,
///    inside a repository that has one.
///
/// Absent both, the answer is `.` and `resolve` raises its own "no config"
/// error, naming the file — the same diagnostic as before, from the same place.
///
/// **This is not the upward config walk §8 forbids.** That rule is about
/// *authority*: one committed `batten.toml`, no directory-by-directory probing,
/// no `conf.d` merge. Nothing here probes a chain of parents — it asks git once,
/// for one answer — and nothing merges: exactly one of the two candidates is
/// used, never both. Which is also what makes the output contract hold, since
/// pointers are relative to the anchor and every subdirectory resolves the same
/// one.
fn anchor() -> PathBuf {
    let here = PathBuf::from(".");
    if here.join(config::CONFIG_FILE).is_file() {
        return here;
    }
    git::repo_root(&here).unwrap_or(here)
}

/// Filter `findings` against this checkout's baseline, and fold what drifted
/// back in (CLOUD-67).
///
/// Called from [`run_rules`] immediately before the waiver filter, and that
/// order is load-bearing in one direction: a waiver *removes* a finding, so
/// applying waivers first would make a live baseline entry look unmatched and
/// report staleness for a finding that is still there. Baselining first asks its
/// question of the full set.
///
/// The drift it reports joins `findings` on exactly the terms `budget` and
/// `defects` join on — an unmatched entry is an ordinary [`rules::Finding`], so
/// it is waivable, appears in `-J`, reaches the store and decides the exit code
/// without any of that being re-implemented on a private verdict path.
/// [`baseline::Drifted::is_reportable`] is what keeps a *hold* out of it: an
/// entry whose rule never ran has no verdict to contribute, only a note.
///
/// A checkout with no bound store, or no baseline in it, returns `findings`
/// untouched.
fn apply_baseline(
    findings: Vec<rules::Finding>,
    scan: &rules::Scan,
    root: &Path,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<Vec<rules::Finding>> {
    let Some(recorded) = baseline::load(root)? else {
        return Ok(findings);
    };
    let (mut kept, drifted) = baseline::apply(findings, &recorded, &scan.not_evaluated);
    kept.extend(drifted.iter().filter_map(baseline::Drifted::finding));

    // The audit half, on the ERROR channel beside the waiver lines: a baseline
    // is a suppression, so the record of one is the compensating control, and it
    // must not be able to corrupt a `-J` document even in principle. Holds are
    // reported here and nowhere else — they are exactly the entries that
    // produced no finding, so silence about them would be the whole hold going
    // unobserved.
    for held in drifted.iter().filter(|item| !item.is_reportable()) {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("baseline held {}", held.entry.pointer()),
        )?;
    }
    Ok(kept)
}

/// One of the two rule-running surfaces, as [`run_rules`] takes it.
///
/// Named rather than written inline because the pattern table joined the
/// argument list (CLOUD-885) and a four-argument fn pointer is past what
/// `clippy::type_complexity` will read. The alias is also the clearer spelling:
/// the tables and the root are what a runner needs, and saying so once beats
/// repeating it at both call sites.
///
/// The pattern table and the refusal vocabulary travel as one
/// [`policy::Vocabulary`] (CLOUD-1050) rather than as two positions, which is
/// why this alias did not have to grow again.
type RuleRunner = fn(
    &[rules::Rule],
    &[provision::Provision],
    policy::Vocabulary<'_>,
    &Path,
    policy::ModuleChecks,
) -> Result<rules::Scan>;

/// Write what the decision asked for, on the surface allowed to write
/// (CLOUD-851).
///
/// ONLY THE SPAWNING SURFACE. `check` is declared `read` (§5) and computes
/// `scan.requested` exactly as `enforce` does — the decision is the same
/// decision, which is what makes the split a boundary rather than a second
/// engine — but it writes nothing, because a read-effect verb that left a record
/// behind would be a verb that changes what it is judging.
///
/// EVERY FAILURE IS COULD-NOT-RECORD, never a verdict. The run has already
/// decided by the time this is called; a store that cannot be written must not
/// become the reason work stops, which is the same posture `record_sourced`'s
/// caller takes one channel over. Nothing here reaches a stream: the records are
/// digests and counts, and even those stay on disk.
fn perform_requested_sinks(surface: Surface, root: &Path, scan: &rules::Scan) {
    if surface != Surface::Spawning || scan.requested.is_empty() {
        return;
    }
    let Ok(git_dir) = git::git_dir(root) else {
        return;
    };
    // Only when a request needs it, for the reason `rules::run`'s acquisition
    // guard states: a read nobody asked for is what `perf-compare` refused.
    let branch = if scan
        .requested
        .iter()
        .any(|request| request.key == rules::SinkKey::Branch)
    {
        git::current_branch(root).ok().flatten()
    } else {
        None
    };
    let _ = sink::perform(&git_dir, branch.as_deref(), &scan.requested);
}

/// What a rule-running verb was asked for, as one value.
///
/// A struct rather than three more positionals, for `ExecRequest`'s reason and a
/// lint that enforces it: [`run_rules`] is the funnel every rule-running verb
/// comes through, and a funnel that takes eight arguments is one a caller gets
/// wrong by transposing two of them.
#[derive(Debug, Clone, Copy)]
struct RunRequest<'a> {
    /// Which effect class the caller is on, which decides the sink pass.
    surface: Surface,
    /// Emit findings as byte-stable JSON instead of pointer lines.
    json: bool,
    /// Run only the declared row with this id (CLOUD-1051), or every applicable
    /// row.
    only: Option<&'a str>,
}

impl<'a> RunRequest<'a> {
    /// `check`'s request: the read-only surface, optionally narrowed.
    const fn read_only(json: bool, only: Option<&'a str>) -> RunRequest<'a> {
        RunRequest {
            surface: Surface::ReadOnly,
            json,
            only,
        }
    }

    /// `enforce`'s request. Deliberately NOT narrowable: `--rule` exists so a
    /// migrated gate keeps its task name on the read surface, and every caller
    /// that needs it is a `check` caller. Offering it here too would be surface
    /// nobody asked for, on the verb that spawns.
    const fn spawning(json: bool) -> RunRequest<'static> {
        RunRequest {
            surface: Surface::Spawning,
            json,
            only: None,
        }
    }
}

/// The rows a run evaluates, and which config-fault checks it may make.
///
/// # A narrowing narrows BOTH, and two wrong turns settled that
///
/// Loading a one-row subset under the ordinary checks reports every OTHER
/// module's classes as unemitted and refuses — measured the first time `--rule`
/// ran, twenty-six tokens named and none of them the caller's business — because
/// registry equality is a property of the AUTHORITY rather than of a run.
/// Loading the FULL set instead refuses too, for the opposite reason: `check`
/// declines before any work when any declared row spawns, and this repository
/// declares one, so a narrowed read of a policy row died on `no-secrets`.
///
/// So [`policy::ModuleChecks::RunOverSelection`] keeps every check that is about
/// the modules that loaded and drops the one that is about the table, which the
/// unnarrowed run every `verify` performs still answers.
///
/// **A filter matching nothing is a usage error, never a clean run.** That is the
/// vacuous pass in its purest form — the caller reads "the gate passed" from a
/// gate that was never selected, and a renamed row silently stops being
/// enforced.
///
/// # Errors
///
/// Returns a [`error::UsageError`] when `only` names no declared row.
fn select_rules(
    declared: &[rules::Rule],
    only: Option<&str>,
) -> Result<(Vec<rules::Rule>, policy::ModuleChecks)> {
    let Some(id) = only else {
        return Ok((declared.to_vec(), policy::ModuleChecks::Run));
    };
    let selected: Vec<rules::Rule> = declared
        .iter()
        .filter(|rule| rule.id == id)
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err(error::UsageError::raise(format!(
            "no `[[rule]]` row is declared with id `{id}`; this authority declares {} row(s)",
            declared.len()
        )));
    }
    Ok((selected, policy::ModuleChecks::RunOverSelection))
}

/// The gates the ENGINE owns rather than a `[[rule]]` row, as findings.
///
/// Both join the ordinary finding list, deliberately: a budget and a ledger
/// verdict are policy verdicts like any other, so they must be waivable, must
/// appear in `-J`, and must reach the store — all of which come free from being
/// an ordinary `Finding`, and all of which a private verdict path would have had
/// to re-implement. An over-budget set was previously visible only to whoever
/// thought to run `policy budget`, which is a report, not a gate (CLOUD-50).
///
/// The ledger's gate (CLOUD-52) is engine-side for a sharper reason: it records
/// the lessons that produced the other gates, and one a branch could lower by
/// editing a rule table is worth less than none.
///
/// Rooted at the repo rather than the process directory — the ledger path is
/// repo-relative and the git bases are the repository's, so answering from a
/// subdirectory would read a ledger that is not there. It takes the run's one
/// anchor (CLOUD-214) rather than resolving a second.
///
/// # Errors
///
/// Returns an error when a declared budget entry or the ledger cannot be read.
fn engine_side_findings(root: &Path, config: &resolve::Resolved) -> Result<Vec<rules::Finding>> {
    let mut found: Vec<rules::Finding> = budget::measure_all(root, config.budget.as_ref())?
        .iter()
        .filter_map(budget::Report::finding)
        .collect();
    if let Some(declared) = config.defects.as_ref() {
        found.extend(defects::gate(root, declared)?);
    }
    Ok(found)
}

/// The two stderr notices every rule-running verb opens with.
///
/// Lifted out of [`run_rules`] to keep that funnel under the line lint, and the
/// pair travels together because both are ladder-gated messages about the
/// CONFIG rather than about the tree — stdout is the findings channel and must
/// stay byte-identical to a run whose committed authority states the same
/// effective config, so neither can ever be anything but a stderr line.
///
/// The first is zero-config onboarding's one visible half (CLOUD-70), emitted
/// from this funnel because it is the surface a first contact reaches; `config
/// show` already says the same thing in its own language, by attributing every
/// key to `default`.
///
/// # Errors
///
/// Returns an error when the message channel cannot be written.
fn announce_config(mode: Mode, err: &mut dyn Write, config: &resolve::Resolved) -> Result<()> {
    if config.authority == config::Authority::Absent {
        output::message(mode, Verbosity::Normal, err, config::DEFAULTS_NOTE)?;
    }
    announce_degrade(mode, err, config.base.as_ref())
}

fn run_rules(
    out: &mut dyn Write,
    err: &mut dyn Write,
    mode: Mode,
    overrides: &Overrides,
    runner: RuleRunner,
    request: RunRequest<'_>,
) -> Result<ExitCode> {
    let RunRequest {
        surface,
        json,
        only,
    } = request;
    // The *resolved* rule set, so a local override's added rules are gates a run
    // actually applies rather than config the tool merely prints. The promotion
    // setting comes off the same resolution, so one §8 chain decides both.
    let base_ref = overrides.config_from.as_deref();
    // One anchor for the whole run, resolved once (CLOUD-214): config, the tree
    // walk, budgets, the ledger and the transcript all answer about the same
    // directory, so a subdirectory invocation cannot read policy from one place
    // and files from another.
    let root = anchor();
    let config = resolve::resolve(&root, overrides)?;
    announce_config(mode, err, &config)?;
    // The whole `Scan`, not just its findings: `not_evaluated` is what keeps the
    // store's resolve pass fail-closed (CLOUD-81), and the enforce surface now
    // journals (CLOUD-529), so dropping it here would let a rule that never
    // looked resolve every finding it covers.
    let vocabulary = policy::Vocabulary {
        patterns: &config.patterns,
        verdicts: &config.verdicts,
        recorders: &config.recorders,
    };
    let (selected, checks) = select_rules(&config.rules, only)?;
    let scan = runner(&selected, &config.provisions, vocabulary, &root, checks)?;
    perform_requested_sinks(surface, &root, &scan);
    let mut findings = scan.findings.clone();

    // Declared budgets are gates, evaluated here rather than only under `policy
    // budget` (CLOUD-50). Reading files and summing them spawns nothing, so this
    // preserves `check`'s declared `read` effect.
    //
    // They join `findings` BEFORE the waiver filter below, deliberately: a
    // budget is a policy verdict like any other, so it must be waivable, must
    // appear in `-J`, and must reach the store — all of which come free from
    // being an ordinary `Finding`, and all of which a private verdict path would
    // have had to re-implement. An over-budget set was previously visible only
    // to whoever thought to run `policy budget`, which is a report, not a gate.
    // The engine-side gates are skipped entirely under a narrowing: a caller
    // asking about one declared row is not asking about the budget or the
    // ledger, and running them would make a narrowed read fail for a reason it
    // did not ask about.
    if only.is_none() {
        findings.extend(engine_side_findings(&root, &config)?);
    }

    // The transcript capability (CLOUD-95), resolved BESIDE the runner rather than
    // through it: `runner` is a plain fn pointer over `(&[Rule], &Path)` with
    // nowhere to carry a transcript, and widening that signature to thread an
    // input no rule reads yet would be scaffolding for CLOUD-97/98 built before
    // either exists. This issue lands the substrate and reports its availability;
    // the rules that consume it widen the seam when they have findings to emit.
    //
    // A transcript this verb cannot read is REPORTED, never a veto (CLOUD-819).
    // It used to propagate as a `UsageError` — exit 1 — which stopped `check`
    // entirely, every unrelated tree rule with it, over one line written by a
    // host this repository does not control. That contradicted the invariant
    // twenty lines below: the only rule consuming this capability is declared
    // structurally unable to block (§0.3), so the surface feeding it must not
    // block either. Refusing also defended nothing — `Absent` already yields the
    // same silence at `Success`, so anyone wanting those rules quiet deletes the
    // file rather than tearing a byte of it.
    let capability = transcript::resolve(
        &root,
        config
            .transcript
            .as_ref()
            .and_then(|declared| declared.path.as_deref()),
    );
    report_transcript_capability(&capability, mode, err)?;

    // The first rule to consume the stream (CLOUD-267), which is what widens the
    // seam the comment above left open. It joins NEITHER `findings` nor
    // `any_blocking`: an advisory surface must be structurally unable to block
    // (§0.3), and routing it through `Finding` would put it behind
    // `--fail-on-warning`, which is a promotion path, not a tier.
    let self_writes = scan_self_writes(&capability, config.transcript.as_ref());
    report_self_writes(&self_writes, mode, err)?;

    // The judge (CLOUD-56), joining on exactly the terms above and for the same
    // §0.3 reason — beside `findings`, never into it. `check` never reaches
    // here: `run_static` already refused the run for carrying a spawning kind,
    // so this is not a second gate on the same question, it is the surface that
    // is allowed to answer it.
    if surface == Surface::Spawning {
        let raised = run_judges(err, mode, &config, &root)?;
        register_advisories(&raised, err)?;
        // The enforce surface's own findings, journalled from where they already
        // run (CLOUD-529). Gated on the surface and not on the kind: `check` must
        // reach no store write at all, which is what keeps its `read` effect
        // honest, and `run_state_record` stays the read surface's recorder.
        register_enforce_findings(&scan, mode, err)?;
    }

    // The baseline filter (CLOUD-67), immediately before the waiver filter.
    let findings = apply_baseline(findings, &scan, &root, mode, err)?;

    // The waiver filter (CLOUD-208), applied HERE and nowhere else. This function
    // is the single funnel `check` and `enforce` share — they differ only in the
    // `runner` above — so one insertion point covers both verbs, both channels and
    // the exit code. Inside `rules::run` it would also hide waived findings from
    // `-J`, and `run` has no access to resolved config beyond `&[Rule]`.
    //
    // Before rendering and before `any_blocking`: a waiver is a statement about
    // whether a finding is *counted*, not a fourth severity (`crate::severity`
    // says why a fourth rank would be a redesign). An expired waiver simply is not
    // found here, so the finding survives and the verdict below is the one the
    // rule always rendered — nobody had to act for the suppression to lapse.
    let (findings, waived) = waiver::apply(findings, &config.waivers, waiver::today()?);
    // The audit line every application owes, on the ERROR channel: ladder-gated
    // chatter that cannot reach a `-J` document even in principle. At `Normal`,
    // because a suppressed policy finding is not a detail a default run should
    // have to ask for.
    for applied in &waived {
        output::message(mode, Verbosity::Normal, err, &applied.line_text())?;
    }

    let delta = config_delta(config.base.as_ref());
    if json {
        // A data channel emits its document unconditionally — including the
        // empty one for a clean run. "Prints nothing when clean" (§6) is the
        // human channel's contract; JSON that is sometimes absent is unparseable.
        let report = CheckReport {
            fail_on_warning: config.fail_on_warning,
            transcript: transcript_view(&capability, &self_writes),
            config_delta: delta.as_ref().map(|weakenings| {
                weakenings
                    .iter()
                    .map(|weakening| DeltaView {
                        key: &weakening.key,
                        base: &weakening.base,
                        working: &weakening.working,
                    })
                    .collect()
            }),
            findings: findings
                .iter()
                .map(|finding| FindingView {
                    rule: &finding.rule,
                    path: &finding.path,
                    line: finding.line,
                    severity: finding.severity,
                    report: severity::promote(
                        severity::row_for_rule(finding.severity).report,
                        config.fail_on_warning,
                    ),
                    identity: &finding.identity,
                })
                .collect(),
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // The delta precedes the findings and is summarised by a line naming the
        // ref and the count, so a reader sees "judged against origin/main, 2
        // keys weakened" before the findings that judgement produced. Emitted
        // only under `--config-from`, so a run without one keeps stdout exactly
        // the findings it has always been.
        if let (Some(weakenings), Some(reference)) = (delta.as_ref(), base_ref) {
            for weakening in weakenings {
                writeln!(out, "{}", weakening.line())?;
            }
            writeln!(
                out,
                "config-from {reference}: {} weakened",
                weakenings.len()
            )?;
        }
        for finding in &findings {
            // Pointer only: location and the rule that fired, never the line
            // text. A rule-scoped finding (no line) prints its pointer without
            // one rather than inventing a line number it does not have.
            match finding.line {
                Some(line) => writeln!(out, "{}:{} {}", finding.path, line, finding.rule)?,
                None => writeln!(out, "{} {}", finding.path, finding.rule)?,
            }
        }
    }
    report_clean_run(json, mode, err, &findings, &config, &scan)?;
    // THE PIN IS MINTED HERE, and the position is the meaning (CLOUD-720):
    // "validated" is scoped to what this run already proved.
    if let Some(loaded) = config.base.as_ref() {
        trust::record_pin(&root, loaded);
    }
    // The severity axis reaches the exit contract exactly here: blocking is
    // derived through the taxonomy table, never name-matched (CLOUD-168), and
    // the two-valued outcome becomes a code in one place (§7).
    Ok(ExitCode::verdict(rules::any_blocking(
        &findings,
        config.fail_on_warning,
    )))
}

/// Announce a run served from the offline pin, on the messaging channel.
///
/// A degrade announces itself or it is not safe (CLOUD-720). Same channel and
/// rung as [`config::DEFAULTS_NOTE`], and for the same reason: stdout is the
/// findings channel and must be byte-identical to the run that reached the ref,
/// so a caller parsing it sees no new shape. No `-J` field pairs with this.
///
/// Split out of [`run_rules`] for [`report_clean_run`]'s reason — that funnel is
/// at clippy's line ceiling, and a notice is not what should push it over.
fn announce_degrade(mode: Mode, err: &mut dyn Write, base: Option<&trust::Loaded>) -> Result<()> {
    if let Some(trust::Provenance::Pin(evidence)) = base.map(|base| &base.provenance) {
        output::message(mode, Verbosity::Normal, err, &trust::pinned_note(evidence))?;
    }
    Ok(())
}

/// The working-tree-vs-base delta, or `None` when no base ref was named.
///
/// *Reporting*, not a verdict: the exit code comes from the rules as evaluated
/// against the base config, which is what makes the gate un-loweable. Turning a
/// weakening into a violation on its own is `config lint`'s job (CLOUD-87),
/// which reuses this same comparison.
///
/// The base is the one `resolve` took its policy from, never a second load of
/// the same ref (CLOUD-720): two loads could reach two answers — a resolve
/// served from a pin followed by a delta that refuses — which would be one run
/// disagreeing with itself about one ref.
///
/// A working authority that cannot be read is not a reason to abandon the
/// verdict. The rules being evaluated are the trusted ones and the exit code is
/// computable; this feeds the *report*. Letting it abort turned the maximal
/// weakening — delete `batten.toml` — into exit 1, a code every mediating
/// harness reads as "do not block", in the one mechanism whose stated purpose is
/// to be un-loweable (CLOUD-243). An unreadable authority grants no policy, so
/// it is compared as one that declares nothing: every key the base declares
/// reports as removed, each under its own key path.
fn config_delta(base: Option<&trust::Loaded>) -> Option<Vec<trust::Weakening>> {
    let base = base?;
    let working = config::load(&Path::new(".").join(config::CONFIG_FILE))
        .unwrap_or_else(|_| config::Config::declaring_nothing());
    Some(trust::weakenings(&base.config, &working))
}

/// Say what a clean run did, if anything (CLOUD-222).
///
/// The write half, split from [`clean_run_notice`]'s decision half so the branch
/// that a TTY-less test cannot reach is still decided by something a table can
/// drive. Kept out of [`run_rules`] because that funnel is already at clippy's
/// line ceiling, and a notice is not what should push it over.
fn report_clean_run(
    json: bool,
    mode: Mode,
    err: &mut dyn Write,
    findings: &[rules::Finding],
    config: &resolve::Resolved,
    scan: &rules::Scan,
) -> Result<()> {
    if let Some(note) = clean_run_notice(
        json,
        mode.machine,
        findings.is_empty(),
        config.rules.len(),
        scan.not_evaluated.len(),
    ) {
        output::message(mode, Verbosity::Normal, err, &note)?;
    }
    Ok(())
}

/// What a clean run says on stderr, or `None` when it says nothing (CLOUD-222).
///
/// A clean `check` prints nothing on stdout and exits `0` — §6's cheapest
/// possible signal, and right for the agent path, where the exit code is the
/// whole interface and every byte printed is context spent. It is wrong exactly
/// once: a newcomer who has just paid a cold build cannot tell "evaluated N
/// rules, all clean" from "nothing ran", so the first useful thing the tool does
/// is invisible to the only reader with no priors to fill the silence.
///
/// Four things this returns `None` for, and each is load-bearing:
///
/// * **`machine`** — §4's already-resolved attendedness (`!stderr_tty || <CI
///   signal>`), read here rather than re-derived. A piped or CI run cannot reach
///   the notice, so the agent path keeps byte-for-byte the output it has today
///   **by construction**, which is what makes that assertion testable rather than
///   a promise a reviewer has to take on trust.
/// * **`json`** — the data channel emits its document and nothing else; a `-J`
///   caller parses stdout and this would be noise beside it.
/// * **not clean** — a run with findings has already said something worth more.
/// * **nothing declared and nothing run** — see below.
///
/// The count is the rules that actually **evaluated**, `not_evaluated`
/// subtracted: "checked 12 rules" over a run where four never looked is the
/// false green this engine exists to refuse. A config declaring no rules at all
/// still gets the line, and that is the point rather than an oversight — `0` is
/// the honest answer to "what ran", and it is exactly the reader who suspects
/// nothing ran who most needs to be told they are right.
fn clean_run_notice(
    json: bool,
    machine: bool,
    clean: bool,
    declared: usize,
    not_evaluated: usize,
) -> Option<String> {
    if json || machine || !clean {
        return None;
    }
    let evaluated = declared.saturating_sub(not_evaluated);
    Some(format!("checked {evaluated} rule(s) — nothing to report"))
}

/// A key's value as one pointer-line token.
///
/// A list is reported as its length rather than its contents: the default
/// channel points at policy, it does not carry it (non-negotiable rule 4). An
/// object is reported the same way for the same reason.
fn pointer_value(entry: &resolve::Attributed) -> String {
    match &entry.value {
        serde_json::Value::Array(items) => items.len().to_string(),
        serde_json::Value::Object(fields) => fields.len().to_string(),
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => "-".to_owned(),
        other => other.to_string(),
    }
}

/// `batten lint brief [<path>]` (CLOUD-84).
///
/// Reads a delegation brief from `path`, or from stdin when it is `None` or `-` —
/// the same `-` convention `config lint --host-rules` uses, so a brief can be
/// piped straight from whatever composed it.
///
/// # Exit contract
///
/// The one table, no per-verb exception (non-negotiable rule 5): a missing
/// section is a **policy verdict**, [`ExitCode::Violation`] (`2`), and input that
/// cannot be read is [`ExitCode::Usage`] (`1`). CLOUD-84's Ready block originally
/// stated these the other way round — the `mise-tasks/*-check` shell convention,
/// which is the exact inverse — and CLOUD-307 named this clause by id. Shipping
/// `1` for a missing section would make a policy verdict read to every mediating
/// harness as a config error: fail-loud-do-not-block, on the surface whose whole
/// purpose is to block.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the named path cannot be read, and
/// when the input is not UTF-8. A brief is prose; bytes that are not text are a
/// caller mistake, and answering "no missing sections" over them would be a pass
/// nobody measured.
fn run_lint_brief(path: Option<&str>, json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let text = match path {
        None | Some("-") => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer)?;
            String::from_utf8(buffer).map_err(|_| {
                UsageError::raise("the brief on stdin is not valid UTF-8".to_owned())
            })?
        }
        Some(source) => std::fs::read_to_string(source).map_err(|err| {
            UsageError::raise(format!("cannot read the brief at {source}: {err}"))
        })?,
    };

    let report = brief::problems(&text);
    if json {
        // Emitted unconditionally, including the clean run: JSON that is
        // sometimes absent is unparseable, the same reasoning `config lint -J`
        // records. Ids and counts only — never a byte of the brief (rule 4).
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // A complete brief is SILENT (CLOUD-84 §7(a)). This is the one verb where
        // the house habit of stating a count even at zero is overridden by the
        // issue, and deliberately so: `lint brief` is meant to sit inline in a
        // dispatch path, where a line per successful handoff is noise the reader
        // learns to skip.
        for line in report.lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::verdict(!report.is_clean()))
}

/// `batten config deprecations --against <ref>` (CLOUD-360 §2).
///
/// Its own function rather than an arm, for the seam `config_of` already uses:
/// `run_config` reached `clippy::too_many_lines` when this landed, and a verb
/// with three distinct exit outcomes is the natural place to split.
///
/// THREE OUTCOMES, and the third is the one worth reading. `0` when nothing left
/// the surface unannounced, `2` when something did — the policy verdict, same as
/// any other finding — and `3` when the baseline could not be read at all.
///
/// # Errors
///
/// Raises (→ exit `3`) when the ref carries no published schema, and a
/// [`UsageError`] (→ exit `1`) when either schema is unreadable. Never `0` for
/// either: reporting "no key was removed" having compared nothing is the vacuous
/// pass CLOUD-251 names, and it is the failure this gate would have if an
/// unreadable baseline were treated as an empty schema.
fn run_config_deprecations(json: bool, against: &str, out: &mut dyn Write) -> Result<ExitCode> {
    let Ok(published) = git::show(Path::new("."), against, config::SCHEMA_PATH) else {
        // THE DOCUMENT IS EMITTED ANYWAY. A data channel that is sometimes absent
        // is unparseable by the caller that asked for it, so the could-not-look
        // answer is a document too — distinguished by `baseline`, never by an
        // empty list that reads as clean.
        if json {
            let report = DeprecationReport {
                against,
                baseline: "unavailable",
                removed_without_window: &[],
            };
            writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
        }
        anyhow::bail!("no published schema at {against}, so no removal could be judged");
    };
    let released = config::schema_keys(&published, against)?;
    let derived = config::schema()?;
    let current = config::schema_keys(&derived, "the derived schema")?;
    let unannounced = config::removals_unannounced(
        &released,
        &current,
        config::DEPRECATED_KEYS,
        config::RETIRED_KEYS,
    );
    if json {
        let report = DeprecationReport {
            against,
            baseline: "read",
            removed_without_window: &unannounced,
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // Pointer-only: the key and the remedy, never the schema body.
        for key in &unannounced {
            writeln!(
                out,
                "{key} removed since {against} with no deprecation window"
            )?;
        }
        // The count is stated even at zero, so silence cannot be mistaken for
        // "the gate did not run".
        writeln!(
            out,
            "config-deprecations: {} unannounced removal(s) against {against}",
            unannounced.len()
        )?;
    }
    Ok(ExitCode::verdict(!unannounced.is_empty()))
}

fn run_config(
    command: &ConfigCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        ConfigCommand::Show { json } => {
            let config = resolve::resolve(Path::new("."), overrides)?;
            // The document is the resolver's own serialization paired with the
            // layer that set each key — never composed by hand here, so the
            // emitted shape is stated once, in `resolve::Resolved` (§8).
            let document = config.attributed()?;
            if *json {
                // stdout is the answer: one byte-stable document, keys sorted.
                writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
            } else {
                // The default channel stays pointer/count (non-negotiable rule
                // 4): one `<key> <value> <source>` line per key, with the rule
                // set as a COUNT — printing rule bodies here would put policy
                // content on the channel that is meant to point at it.
                for (key, entry) in &document {
                    writeln!(
                        out,
                        "{key} {} {}",
                        pointer_value(entry),
                        entry.source.as_str()
                    )?;
                }
            }
            Ok(ExitCode::Success)
        }
        // The alarm beside `--config-from`'s control (CLOUD-87): a smell is a
        // verdict about the *config*, so any smell is a Violation — the same
        // code a rule finding returns, because it is the same kind of answer.
        // An unparseable config is a Usage error, raised by the loader.
        // The epoch is a pure function of the tracked files' bytes, so it is
        // read-effect and byte-stable. An unreadable tracked path propagates as
        // a Usage error (exit 1) rather than being skipped: the `[epoch]
        // tracked` set is config, so a path it names that cannot be read is
        // unreadable config, which §7 routes to 1 — see `epoch`.
        ConfigCommand::Epoch { json, no_cache } => {
            // The epoch covers whichever authority governed the run: under
            // `--config-from` that is the ref's surface, never the working
            // tree's (CLOUD-31). An epoch attributing a run to a config that
            // did not govern it would be worse than none.
            //
            // The cached path is byte-identical to the cold one or it is a bug
            // (CLOUD-232); `--no-cache` selects the cold one so a test can hold
            // the two side by side.
            let (value, tracked) = if *no_cache {
                epoch::describe(Path::new("."), overrides.config_from.as_deref())?
            } else {
                epoch::describe_cached(Path::new("."), overrides.config_from.as_deref())?
            };
            if *json {
                // The digest alone cannot say what it covers, and a caller
                // stamping it onto a record needs both halves — so `-J` adds the
                // governing surface rather than re-encoding the value. Paths, not
                // bytes: still a pointer (non-negotiable rule 4).
                let report = EpochReport {
                    epoch: &value,
                    tracked: &tracked,
                };
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
            } else {
                writeln!(out, "{value}")?;
            }
            Ok(ExitCode::Success)
        }
        ConfigCommand::Deprecations { json, against } => {
            run_config_deprecations(*json, against, out)
        }
        ConfigCommand::Lint { json, host_rules } => {
            // The date the expiry smell is computed against, read once at this
            // boundary and threaded in as data (`waiver`'s module docs say why).
            let mut smells = lint::run(
                Path::new("."),
                overrides.config_from.as_deref(),
                waiver::today()?,
            )?;
            // The drift half (CLOUD-54), added only when the caller supplied a
            // payload — so lint's behaviour without the flag is byte-identical
            // to what it was.
            if let Some(source) = host_rules {
                smells.extend(lint::host_drift(Path::new("."), source, overrides)?);
                smells.sort();
            }
            if *json {
                // Emitted unconditionally, including the clean run: JSON that is
                // sometimes absent is unparseable. `at` is rendered through
                // `Where`'s own `Display` rather than by deriving `Serialize` on
                // the domain type, so the line-or-key union has exactly one
                // spelling across both channels.
                let report = LintReport {
                    smells: smells
                        .iter()
                        .map(|smell| SmellView {
                            at: smell.at.to_string(),
                            id: smell.id,
                        })
                        .collect(),
                };
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
            } else {
                for smell in &smells {
                    writeln!(out, "{}", smell.line_text())?;
                }
                // The count is stated even at zero: silence would be
                // indistinguishable from "the lint did not run".
                writeln!(out, "config-lint: {} smell(s)", smells.len())?;
            }
            Ok(ExitCode::verdict(!smells.is_empty()))
        }
    }
}

/// Diagnose whether Batten can run here (CLOUD-66).
///
/// The exit code comes from [`doctor::Report::code`], whose range excludes
/// [`ExitCode::Violation`] by construction: a diagnostic never renders a policy
/// verdict, so a mediating harness can never read "this checkout is
/// misconfigured" as a deny (§7).
fn run_doctor(command: &cli::DoctorCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match *command {
        cli::DoctorCommand::Diagnose { json } => run_diagnose(json, out),
        cli::DoctorCommand::Hooks { json } => run_doctor_hooks(json, out),
    }
}

fn run_diagnose(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose(Path::new("."));
    if json {
        // A data channel emits its document unconditionally, including for a
        // healthy repository: JSON that is sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        for check in &report.checks {
            writeln!(out, "{}", check.line())?;
        }
        let failed = report.checks.iter().filter(|check| !check.ok).count();
        writeln!(
            out,
            "doctor: {} check(s), {failed} failed",
            report.checks.len()
        )?;
    }
    Ok(report.code())
}

/// Is batten wired on every hook surface of every harness (CLOUD-777)?
///
/// The question `doctor` exists to answer, asked of the one thing it could not:
/// its own installation. It ships to a consumer, which the ~300 lines of bash it
/// replaces never did — a repository adopting Batten had no way to ask *am I
/// wired?* at all.
///
/// The exit code comes from [`doctor::WiringReport::code`], whose range excludes
/// [`ExitCode::Violation`] by construction. A sub-verb inherits the promise the
/// parent makes: a mediating harness reads `2` as a deny, and "your wiring is
/// wrong" is not "policy says no".
///
/// The pointer line is `<harness> <event> <reason>` — a host token and a stable
/// reason id, never a path (§6, rule 4). A harness with nothing wrong renders one
/// `ok` line rather than nothing, so a silent run and a healthy one are
/// distinguishable.
fn run_doctor_hooks(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose_hooks(Path::new("."));
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        for harness in &report.harnesses {
            if harness.findings.is_empty() {
                writeln!(
                    out,
                    "{} ok {} registration(s), {} sibling(s)",
                    harness.harness, harness.registrations, harness.siblings
                )?;
                continue;
            }
            for finding in &harness.findings {
                writeln!(
                    out,
                    "{} {} {}",
                    harness.harness, finding.event, finding.reason
                )?;
            }
        }
        let failed = report
            .harnesses
            .iter()
            .filter(|harness| !harness.ok)
            .count();
        writeln!(
            out,
            "doctor hooks: {} harness(es), {failed} unwired",
            report.harnesses.len()
        )?;
    }
    Ok(report.code())
}

fn run_spec(format: SpecFormat, out: &mut dyn Write) -> Result<ExitCode> {
    let described = spec::document(&surface::command());
    match format {
        SpecFormat::Json => {
            let json = spec::to_json(&described)?;
            writeln!(out, "{json}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Emit an artifact derived from the command surface, on stdout.
///
/// Stdout-only is what makes `generate`'s `read` effect structurally honest
/// (§5): the binary writes no file, so refreshing a committed artifact is the
/// caller's redirect (`mise run completions`) and never a side effect of the
/// verb. The completions are generated from the same [`surface::command`] tree
/// the parser is built from, so a committed script cannot describe a surface the
/// binary does not have — which is the property `derived-check` gates.
///
/// Man pages and markdown join on the same terms (CLOUD-69): every format here
/// walks the one [`surface::SURFACE`]-built tree, and every one of them returns
/// bytes for the caller to redirect.
fn run_generate(command: &GenerateCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match command {
        GenerateCommand::Completions { shell } => {
            clap_complete::generate(*shell, &mut surface::command(), "batten", out);
        }
        // One page per command, selected by the same root-relative path the
        // spec and the §5 effect table are keyed by. A single page for the
        // whole tree would document the root and none of the verbs, which is
        // the shape `man batten-config-show` cannot resolve.
        GenerateCommand::Man { command } => {
            write!(
                out,
                "{}",
                render::man(&surface::command(), command.as_deref())?
            )?;
        }
        // The whole surface in one document — the CLI reference CLOUD-171
        // renders at publish time. Deliberately not a committed artifact: a
        // reference derived from the binary at publish time is current by
        // construction, and a committed copy would be the second authority
        // this whole module exists to remove.
        GenerateCommand::Markdown => {
            write!(
                out,
                "{}",
                render::markdown(&spec::describe(&surface::command()))
            )?;
        }
        // Two surfaces, two derivations (CLOUD-239): one schema describing both
        // is what let a validator vouch for override keys the loader drops.
        GenerateCommand::Schema { surface } => match surface {
            cli::SchemaSurface::Authority => writeln!(out, "{}", config::schema()?)?,
            cli::SchemaSurface::Override => writeln!(out, "{}", config::override_schema()?)?,
            cli::SchemaSurface::PolicyInput => {
                writeln!(out, "{}", policy::tree_input_schema()?)?;
            }
            cli::SchemaSurface::PolicyCall => {
                writeln!(out, "{}", policy::call_input_schema()?)?;
            }
        },
        // A refusal rather than empty output for a harness that is a contract
        // and not a host: emitting `{}` would answer "this host registers
        // nothing", which is a different claim from "there is nothing to
        // register with". `UsageError` is exit 1 — the caller named something
        // that cannot be asked for, which is a statement about the invocation.
        GenerateCommand::Hooks { harness } => {
            let wiring = harness.wiring().ok_or_else(|| {
                UsageError::raise(format!(
                    "generate hooks: {} is the neutral contract, not a host — it has no \
                     hook-config surface to register in",
                    harness.as_str()
                ))
            })?;
            writeln!(out, "{}", hook::render_wiring(*harness, &wiring))?;
        }
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The whole decision as a table, because the branch that matters cannot be
    /// reached over a spawned process: this sandbox gives a test no TTY, so
    /// `machine` is always true there and the attended arm would never run. The
    /// e2e suite asserts the SILENT half against the real binary; this asserts
    /// that the other half exists and is reached for the right reasons
    /// (`.claude/rules/rust.md`: extract the decision rather than assert a
    /// conclusion over a precondition the environment never created).
    #[test]
    fn a_clean_run_speaks_only_when_a_person_is_reading() {
        // (json, machine, clean) -> whether a line is emitted.
        let cases = [
            ((false, false, true), true, "attended, clean, human channel"),
            (
                (false, true, true),
                false,
                "piped or CI: the agent path is silent",
            ),
            (
                (true, false, true),
                false,
                "-J: the document is the whole answer",
            ),
            (
                (false, false, false),
                false,
                "findings said something already",
            ),
            ((true, true, false), false, "none of the three hold"),
        ];
        for ((json, machine, clean), speaks, why) in cases {
            assert_eq!(
                clean_run_notice(json, machine, clean, 3, 0).is_some(),
                speaks,
                "{why}"
            );
        }
    }

    /// The count is what RAN, not what was declared. A rule that never looked
    /// must not be counted as one that passed — that is the false green the
    /// engine exists to refuse, and it would be invisible in a line that reads
    /// reassuringly either way.
    #[test]
    fn the_count_subtracts_the_rules_that_never_looked() {
        assert_eq!(
            clean_run_notice(false, false, true, 12, 4).unwrap(),
            "checked 8 rule(s) — nothing to report"
        );
        // Saturating, not panicking: the two numbers come from different places
        // and an inverted pair must not take the process down over a message.
        assert_eq!(
            clean_run_notice(false, false, true, 1, 9).unwrap(),
            "checked 0 rule(s) — nothing to report"
        );
    }

    /// A `base` git cannot resolve is COULD-NOT-LOOK, never "no key here".
    ///
    /// CLOUD-787. `key_facts` is only ever called once a `requires_key` row has
    /// already selected the command, so every failure inside it is the question
    /// being unanswerable — no checkout, a shallow clone whose history is not
    /// there to read, a `base` that resolves to nothing. "Looked and found no
    /// key" is a different answer and it belongs to the CALLER, which is the one
    /// that knows whether any row asked.
    ///
    /// Collapsing the two is the defect the three-valued contract exists to
    /// prevent: `IsNot` here would claim the boundary had inspected a branch's
    /// history and found no issue key, on a call where it never read one.
    ///
    /// Fails by: returning `Look::IsNot` from `key_facts`'s failure arm.
    #[test]
    fn an_unresolvable_base_could_not_look_rather_than_finding_no_key() {
        let facts = key_facts("refs/heads/definitely-not-a-ref-cloud-787");
        assert!(
            facts.could_not_look(),
            "an unresolvable base is could-not-look, got {}",
            facts.as_str()
        );
        assert_eq!(facts.as_str(), "could-not-look");
        assert!(
            !matches!(facts, facts::Look::IsNot),
            "could-not-look must not be spelled as looked-and-found-nothing"
        );
    }

    /// A config declaring nothing still gets the line. The reader who suspects
    /// nothing ran is exactly the one who needs to be told they are right, and
    /// `0` is the honest answer rather than a reason to stay silent.
    #[test]
    fn declaring_no_rules_is_reported_rather_than_hidden() {
        assert_eq!(
            clean_run_notice(false, false, true, 0, 0).unwrap(),
            "checked 0 rule(s) — nothing to report"
        );
    }
}
