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
pub mod attribution;
pub mod baseline;
pub mod brief;
pub mod budget;
pub mod bypass;
pub mod capture;
pub mod ci;
pub mod cli;
pub mod completion;
pub mod config;
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
pub mod findings;
pub mod git;
pub mod hook;
pub mod identity;
pub mod init;
pub mod journal;
pub mod judge;
pub mod lint;
pub mod markers;
pub mod output;
pub mod outputs;
pub mod provision;
pub mod receipt;
pub mod refusal;
pub mod render;
pub mod resolve;
pub mod rules;
pub mod secrets;
pub mod selfwrite;
pub mod session;
pub mod severity;
pub mod spec;
pub mod state;
pub mod stop;
pub mod store;
pub mod surface;
pub mod transcript;
pub mod trust;
pub mod verbs;
pub mod waiver;
pub mod worktree;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

pub use cli::{
    AttributionCommand, Cli, Command, ConfigCommand, DefectsCommand, DesignCommand,
    GenerateCommand, LintCommand, PolicyCommand, ProvisionCommand, ReceiptCommand, SpecFormat,
    StateCommand, WorktreeCommand,
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
        Some(Command::Check { json }) => run_rules(
            out,
            err,
            mode,
            &overrides,
            rules::run_static,
            Surface::ReadOnly,
            json,
        ),
        Some(Command::Enforce { json }) => run_rules(
            out,
            err,
            mode,
            &overrides,
            rules::run_all,
            Surface::Spawning,
            json,
        ),
        Some(Command::Config { command }) => run_config(&command, &overrides, out),
        Some(Command::Spec { format }) => run_spec(format, out),
        Some(Command::Doctor { json }) => run_doctor(json, out),
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
        Some(Command::Exec { command }) => {
            let patterns = load_exec_patterns(&overrides)?;
            // The report goes to the ERROR channel, never `out`: stdout belongs to
            // the wrapped command (CLOUD-285), so a pointer line there would
            // corrupt a document the caller may be parsing.
            exec::run_with(&command, &patterns, err)
        }
        Some(Command::Hook { harness }) => run_hook(harness, mode, &overrides, out, err),
        // CLOUD-479. Touches NO config — this is the per-turn hot path, and the
        // whole point is that it costs less than the `jq` process it replaces.
        // `run_hook` loads policy only past its cheap refusals for the same
        // reason; this has no policy to load at all.
        Some(Command::HookField { harness, field }) => run_hook_field(harness, field, out),
        // The receipt verbs read their own git facts; the §8 config chain does
        // not apply — a receipt records policy (as a digest), it never resolves it.
        Some(Command::Receipt { command }) => match command {
            ReceiptCommand::Record { check } => receipt::run_record(&check),
            ReceiptCommand::Status { check, json } => receipt::run_status(&check, json, out),
        },
        Some(Command::Policy { command }) => match command {
            PolicyCommand::Budget { json } => run_budget(json, &overrides, out),
        },
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
        Some(Command::Worktree { command }) => match command {
            WorktreeCommand::Status { json } => run_worktree_status(json, &overrides, out),
            WorktreeCommand::Reclaim { dry_run } => {
                run_worktree_reclaim(dry_run, mode, &overrides, err)
            }
        },
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
            let refusal = Refusal::new(
                init::CONFIG_EXISTS,
                format!(
                    "{} already exists, and init will not overwrite the committed authority",
                    config::CONFIG_FILE
                ),
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
    let scan = rules::run_static(&config.rules, &config.provisions, &root)?;

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
    // Absent `[worktree]`, and absent `pileup_threshold` inside it, are the same
    // answer: no threshold is declared, so the pileup predicate does not run.
    // Neither is an error — see `run_worktree_status`'s note on what refusing
    // the whole invocation over an absent key cost this verb once already.
    let threshold = config
        .worktree
        .as_ref()
        .and_then(|worktree| worktree.pileup_threshold);
    // The repo root, not the process directory: the three categories are
    // properties of the repository, and answering from a subdirectory would
    // report a clean tree for a dirty one one level up.
    let repo = git::repo_root(Path::new("."))?;
    let at_risk = worktree::status(&repo, target, threshold)?;

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

/// Snapshot and abandon worktrees that are dirty and unreapable (CLOUD-46).
///
/// Reports through `err`, never `out`: like `provision apply` this verb acts on
/// the machine and has no document to emit, and the one thing it prints — which
/// worktrees it removed — belongs on the messaging channel.
///
/// **Confirmation is required and never prompted for.** §4 is explicit that a
/// destructive verb without `-y` refuses with instructions rather than prompting
/// into the void, and this engine's primary caller is a program in a loop: a
/// gate that blocks on a Y/N is a dead gate. So the refusal is unconditional
/// rather than conditioned on attendedness, and it is exit `1` — a usage error,
/// because §7 keeps `2` for verdicts and "you did not pass the flag" is not one.
/// `--dry-run` needs no confirmation: it is structurally incapable of the
/// mutation it previews.
fn run_worktree_reclaim(
    dry_run: bool,
    mode: Mode,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    // A verb that removes worktrees over a threshold nobody declared would be
    // choosing the threshold itself. Absent is a usage error *here* — unlike
    // `worktree status`, which has three other questions to answer and must stay
    // silent about this one — because there is no reclaim to perform at all.
    let threshold = config
        .worktree
        .as_ref()
        .and_then(|worktree| worktree.pileup_threshold)
        .ok_or_else(|| {
            UsageError::raise(format!(
                "no [worktree] pileup_threshold in {}; there is no pileup to reclaim against",
                config::CONFIG_FILE
            ))
        })?;

    if !dry_run && !mode.confirmed {
        return Err(UsageError::raise(
            "worktree reclaim removes worktrees and the work in them; pass --yes to confirm, \
             or --dry-run to preview",
        ));
    }

    let repo = git::repo_root(Path::new("."))?;
    let report = worktree::reclaim(&repo, threshold, dry_run)?;
    for entry in &report {
        writeln!(err, "{}", entry.render())?;
    }
    // A refusal is a verdict about this machine — there is work here nothing
    // could make recoverable — so it takes the policy code, not a failure one.
    Ok(ExitCode::verdict(worktree::any_refused(&report)))
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
    let scan = rules::run_static(&config.rules, &config.provisions, Path::new("."))?;

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
/// entirely — cannot reach this function, and is the launcher's job to report
/// loudly. `mise-tasks/stop-guard` and `mise-tasks/contract-drift` carry that
/// half, copied from `.claude/hooks/batten-hook.sh`.
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
    // The advisory drain rides this surface at the post-tool event (CLOUD-79).
    // It is not part of adjudication and cannot become part of it: `adjudicate`
    // stays a pure function of config plus argv, this is a side effect at the
    // boundary, and it returns nothing the decision reads. The post-tool event
    // is where it belongs precisely because no host offers a deny channel there
    // — an advisory surface at an event that cannot refuse anything is
    // structurally unable to block (house-style §0.3).
    if envelope.event == hook::Event::PostTool {
        drain_advisories(&envelope, overrides, mode, err)?;
    }
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
    let (policy, waivers) = if bypass || (envelope.command.is_empty() && envelope.writes.is_none())
    {
        (hook::Policy::declaring_nothing(), Vec::new())
    } else {
        load_policy(overrides)?
    };
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
    let receipts: hook::ReceiptFacts = if required.is_empty() || !judgeable {
        None
    } else {
        receipt::verdicts(&required)
    };
    // The key evidence (CLOUD-446), resolved on the same terms and for the same
    // reason: two git queries a pure `adjudicate` cannot make, spent only when a
    // `requires_key` row has already selected this command. A repository
    // declaring none — and a call matching none, which is nearly every call —
    // does no git work here at all.
    let keys: hook::KeyFacts = policy.key_base_for(&envelope).and_then(key_facts);
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
    // The end-of-turn facts (CLOUD-85), resolved here for `receipts`' reason:
    // `adjudicate` is contractually pure and this reads git and the findings
    // store. Only on the stop event — every other event allows without
    // consulting them, so no other call pays for the reads.
    let stop = if envelope.event == hook::Event::Stop {
        stop_facts(overrides)?
    } else {
        stop::StopFacts::default()
    };
    let facts = Facts {
        bypass,
        receipts: &receipts,
        keys: &keys,
        stop: &stop,
        waived: &waived,
    };
    decide(harness, &envelope, &policy, &facts, mode, out, err)
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
fn key_facts(base: &str) -> hook::KeyFacts {
    let repo = git::repo_root(Path::new(".")).ok()?;
    if git::is_shallow(&repo).ok()? {
        return None;
    }
    let messages = git::log_messages(&repo, base).ok()??;
    let mut evidence = vec![messages];
    evidence.extend(git::current_branch(&repo).ok().flatten());
    Some(evidence)
}

/// Assemble the end-of-turn gate's inputs (CLOUD-85).
///
/// **Outside a repository, both inputs are absent rather than clean.** `batten
/// hook` is registered once and then mediates every turn in whatever directory
/// the agent is in; answering "nothing is at risk" for a directory Batten does
/// not govern would be a claim nobody made, and answering "deny" would make the
/// guard the reason a turn cannot end.
fn stop_facts(overrides: &Overrides) -> Result<stop::StopFacts> {
    let here = Path::new(".");
    let Ok(repo) = git::repo_root(here) else {
        return Ok(stop::StopFacts::default());
    };
    // Config is optional here, unlike for the mediated-call policy: the at-risk
    // half is a property of the checkout and answers with or without a
    // `batten.toml`, and the two config-supplied knobs simply go unset.
    let (target, threshold) = if here.join(config::CONFIG_FILE).exists() {
        let resolved = resolve::resolve(here, overrides)?;
        let threshold = resolved
            .worktree
            .as_ref()
            .and_then(|worktree| worktree.pileup_threshold);
        (resolved.must_land_on.clone(), threshold)
    } else {
        (None, None)
    };
    // A store this checkout is not bound to yields no denials — an answer, not a
    // gap. `resolve` reads and never writes, which is what keeps the stop gate's
    // `read` effect honest.
    let store_dir = store::bound_dir(&store::resolve(&repo)?);
    stop::facts(
        Some(&repo),
        target.as_deref(),
        threshold,
        store_dir.as_deref(),
    )
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
    let here = Path::new(".");
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
            tool: &envelope.tool,
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
fn drain_advisories(
    envelope: &hook::Envelope,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let here = Path::new(".");
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
    if emitted {
        output::verdict(err, &drain::render(&drained))?;
    } else if repeat && !drained.lines.is_empty() {
        output::verdict(err, drain::UNCHANGED)?;
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
fn load_policy(overrides: &Overrides) -> Result<(hook::Policy, Vec<waiver::Waiver>)> {
    let here = std::path::Path::new(".");
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok((hook::Policy::declaring_nothing(), Vec::new()));
    }
    // The waivers travel beside the policy rather than inside it (CLOUD-610).
    // `Policy` is what `adjudicate` decides against and is resolved without a
    // clock; a waiver is only half a fact until a date is applied to it, so
    // folding the table into `Policy` would put an undecided value in the one
    // structure whose whole point is that everything in it is decided.
    let resolved = resolve::resolve(here, overrides)?;
    let policy = hook::Policy::from_resolved(&resolved)?;
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
fn load_exec_patterns(overrides: &Overrides) -> Result<Vec<outputs::OutputPattern>> {
    let here = Path::new(".");
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(Vec::new());
    }
    Ok(resolve::resolve(here, overrides)?.exec_patterns)
}

/// Everything the boundary looked up because [`hook::adjudicate`] cannot.
///
/// One bundle rather than three parameters, and the grouping is the contract
/// rather than a signature convenience: `adjudicate` is contractually pure — no
/// I/O, no environment, no clock — so every field here is a question about a
/// checkout or a store that had to be answered *before* the decision. A fourth
/// such fact adds a field and touches no call site, which is the point; the
/// alternative was a parameter list that grew one argument per gate until clippy
/// counted them (CLOUD-446).
///
/// `bypass` joined them with CLOUD-610 rather than staying a sibling parameter,
/// and it belongs by the same reading: the hatch is an environment variable, so
/// it is one more thing the boundary looked up because the core may not. Keeping
/// it outside would have left `decide` one argument over clippy's ceiling for a
/// value that answers the same question every other field here answers.
struct Facts<'a> {
    /// The caller-resolved [`hook::BYPASS_ENV`] hatch.
    bypass: bool,
    /// The receipt verdicts this call is judged against, or "could not look".
    receipts: &'a hook::ReceiptFacts,
    /// The tracker-key evidence a `requires_key` row is judged against.
    keys: &'a hook::KeyFacts,
    /// The end-of-turn facts, default on every event but `Stop`.
    stop: &'a stop::StopFacts,
    /// The rules a live waiver suppresses today, with the expiry each claims.
    waived: &'a waiver::Live,
}

/// Map one decoded call onto its harness's decision channel.
///
/// Split out of [`run_hook`] so the mapping is reachable without the process's
/// own stdin: `run_hook` owns the boundary (stdin, the bypass variable, the
/// config load) and this owns the contract CLOUD-40's matrix pins — including
/// the case where writing the decision document itself fails.
fn decide(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    policy: &hook::Policy,
    facts: &Facts<'_>,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match hook::adjudicate(
        policy,
        envelope,
        facts.bypass,
        facts.receipts,
        facts.keys,
        facts.stop,
        facts.waived,
    ) {
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
            let reason = hook::deny_text(&refusal);
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
            let reason = hook::deny_text(&refusal);
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
        transcript::Capability::Absent => Some(TranscriptView {
            capability: capability.as_str(),
            counts: None,
            unprompted_memory_writes: None,
        }),
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
        if !outstanding {
            if let Some(key_id) = secrets::retire(&key_file)? {
                writeln!(
                    err,
                    "batten: secret-identity rotation complete: key {key_id} retired"
                )?;
            }
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
    let capability = transcript::resolve(Path::new("."), declared)?;
    let stream = match &capability {
        transcript::Capability::Unconfigured => return Ok(()),
        transcript::Capability::Absent => {
            output::message(mode, Verbosity::Normal, err, transcript::ABSENT_NOTICE)?;
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
        transcript::Capability::Unconfigured | transcript::Capability::Absent => Vec::new(),
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

fn run_rules(
    out: &mut dyn Write,
    err: &mut dyn Write,
    mode: Mode,
    overrides: &Overrides,
    runner: fn(&[rules::Rule], &[provision::Provision], &Path) -> Result<rules::Scan>,
    surface: Surface,
    json: bool,
) -> Result<ExitCode> {
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
    // Zero-config onboarding's one visible half (CLOUD-70). Ladder-gated on the
    // messaging channel, like `transcript::ABSENT_NOTICE` above it: stdout is
    // the findings channel and must stay byte-identical to a run whose committed
    // authority states the same effective config, so this can only ever be a
    // stderr line. Emitted from this funnel because it is the surface a first
    // contact reaches; `config show` already says the same thing in its own
    // language, by attributing every key to `default`.
    if config.authority == config::Authority::Absent {
        output::message(mode, Verbosity::Normal, err, config::DEFAULTS_NOTE)?;
    }
    // The whole `Scan`, not just its findings: `not_evaluated` is what keeps the
    // store's resolve pass fail-closed (CLOUD-81), and the enforce surface now
    // journals (CLOUD-529), so dropping it here would let a rule that never
    // looked resolve every finding it covers.
    let scan = runner(&config.rules, &config.provisions, &root)?;
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
    findings.extend(
        budget::measure_all(&root, config.budget.as_ref())?
            .iter()
            .filter_map(budget::Report::finding),
    );

    // The defect ledger's gate (CLOUD-52), joining on the same terms and for the
    // same reasons. It is engine-side rather than a `[[rule]]` row because the
    // ledger records the lessons that produced the other gates — one a branch
    // could lower by editing a rule table is worth less than none.
    //
    // Rooted at the repo, not the process directory: the ledger path is
    // repo-relative and the git bases are the repository's, so answering from a
    // subdirectory would read a ledger that is not there. It reads `root` now
    // rather than resolving the root a second time — the whole run shares one
    // anchor (CLOUD-214), which is the same answer this line always wanted.
    if let Some(declared) = config.defects.as_ref() {
        findings.extend(defects::gate(&root, declared)?);
    }

    // The transcript capability (CLOUD-95), resolved BESIDE the runner rather than
    // through it: `runner` is a plain fn pointer over `(&[Rule], &Path)` with
    // nowhere to carry a transcript, and widening that signature to thread an
    // input no rule reads yet would be scaffolding for CLOUD-97/98 built before
    // either exists. This issue lands the substrate and reports its availability;
    // the rules that consume it widen the seam when they have findings to emit.
    //
    // A present-but-undecodable transcript propagates as a `UsageError` from
    // `resolve`, which is exit 1 — loud, and structurally not a deny (§7).
    let capability = transcript::resolve(
        &root,
        config
            .transcript
            .as_ref()
            .and_then(|declared| declared.path.as_deref()),
    )?;
    if matches!(capability, transcript::Capability::Absent) {
        // The human half of the report. Ladder-gated, because it is a statement
        // about Batten rather than a verdict — the `-J` field above is the half
        // that cannot be silenced.
        output::message(mode, Verbosity::Normal, err, transcript::ABSENT_NOTICE)?;
    }

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

    // The working-tree-vs-base delta, computed only when a base ref was named.
    // It is *reporting*, not a verdict: the exit code below comes from the rules
    // as evaluated against the base config, which is what makes the gate
    // un-loweable. Turning a weakening into a violation on its own is `config
    // lint`'s job (CLOUD-87), which reuses this same comparison.
    let delta = match base_ref {
        Some(reference) => {
            let base = trust::load_base(&root, reference)?;
            // A working authority that cannot be read is not a reason to abandon
            // the verdict. `resolve` above already took its policy from the base
            // ref, so the rules being evaluated are the trusted ones and the exit
            // code below is computable; this load feeds the *report*, which the
            // comment above calls "not a verdict". Letting it abort turned the
            // maximal weakening — delete `batten.toml` — into exit 1, a code every
            // mediating harness reads as "do not block", in the one mechanism
            // whose stated purpose is to be un-loweable (CLOUD-243).
            //
            // An unreadable authority grants no policy, so it is compared as one
            // that declares nothing: every key the base declares reports as
            // removed, each under its own key path. That is both true and the
            // loudest this report can be about it.
            let working = config::load(&Path::new(".").join(config::CONFIG_FILE))
                .unwrap_or_else(|_| config::Config::declaring_nothing());
            Some(trust::weakenings(&base, &working))
        }
        None => None,
    };
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
    // The severity axis reaches the exit contract exactly here: blocking is
    // derived through the taxonomy table, never name-matched (CLOUD-168), and
    // the two-valued outcome becomes a code in one place (§7).
    Ok(ExitCode::verdict(rules::any_blocking(
        &findings,
        config.fail_on_warning,
    )))
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
fn run_doctor(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
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
            cli::ConfigSurface::Authority => writeln!(out, "{}", config::schema()?)?,
            cli::ConfigSurface::Override => writeln!(out, "{}", config::override_schema()?)?,
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
