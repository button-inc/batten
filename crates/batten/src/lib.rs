//! Batten is a repo-agnostic policy engine.
//!
//! It gates what gets written, proves what was verified, and refuses to let
//! unlanded work appear finished — enforcing one repository's policy consistently
//! at the pre-commit layer, in CI, and at an agent's tool call.
//!
//! This crate exposes the library surface ([`run`]) that the `batten` binary is a
//! thin wrapper around. Keeping the logic in the library keeps it testable and
//! keeps the binary's `main` trivial.

pub mod brief;
pub mod budget;
pub mod capture;
pub mod ci;
pub mod cli;
pub mod config;
pub mod defects;
pub mod doctor;
pub mod effect;
pub mod epoch;
pub mod error;
pub mod exec;
pub mod exit;
pub mod findings;
pub mod git;
pub mod hook;
pub mod identity;
pub mod journal;
pub mod judge;
pub mod lint;
pub mod markers;
pub mod output;
pub mod outputs;
pub mod provision;
pub mod receipt;
pub mod resolve;
pub mod rules;
pub mod selfwrite;
pub mod session;
pub mod severity;
pub mod spec;
pub mod state;
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
    Cli, Command, ConfigCommand, DefectsCommand, GenerateCommand, LintCommand, PolicyCommand,
    ProvisionCommand, ReceiptCommand, SpecFormat, StateCommand, WorktreeCommand,
};
pub use config::Config;
pub use effect::Effect;
pub use error::{Denial, Passthrough, UsageError};
pub use exit::ExitCode;
pub use output::{Mode, Presentation, Verbosity};
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
        Some(Command::Check { json }) => {
            run_rules(out, err, mode, &overrides, rules::run_static, json)
        }
        Some(Command::Enforce { json }) => {
            run_rules(out, err, mode, &overrides, rules::run_all, json)
        }
        Some(Command::Config { command }) => run_config(&command, &overrides, out),
        Some(Command::Spec { format }) => run_spec(format, out),
        Some(Command::Doctor { json }) => run_doctor(json, out),
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
        Some(Command::Worktree { command }) => match command {
            WorktreeCommand::Status { json } => run_worktree_status(json, &overrides, out),
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
    let found = rules::run_static(&config.rules, Path::new("."))?;

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
        &found,
        schema,
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
        "batten: state record {context}: {} minted, {} updated, {} resolved, {dropped} instances GC'd",
        recorded.minted, recorded.updated, recorded.resolved
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
    // Only now is config touched. Ordering the cheap refusals first is §4's
    // "cheap when irrelevant" applied to the hottest path in the binary — this
    // runs on every mediated tool call — and it is also what keeps a bypassed or
    // command-less call from being able to fail on an unrelated config error.
    let policy = if bypass || envelope.command.is_empty() {
        hook::Policy::declaring_nothing()
    } else {
        load_policy(overrides)?
    };
    decide(harness, &envelope, &policy, bypass, out)
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
fn load_policy(overrides: &Overrides) -> Result<hook::Policy> {
    let here = std::path::Path::new(".");
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(hook::Policy::declaring_nothing());
    }
    hook::Policy::from_resolved(&resolve::resolve(here, overrides)?)
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
    bypass: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match hook::adjudicate(policy, envelope, bypass) {
        hook::Decision::Allow => Ok(ExitCode::Success),
        // One dispatch for every host, because the *shape* of the answer is the
        // adapter's business and the decision is not. A host that reads a body
        // gets one; a host whose channel is the exit code alone gets the §7 `2`
        // with the reason on stderr. Adding a host does not touch this function.
        //
        // The host's OWN event spelling goes back, not our normalized token: a
        // decision document is read by the host, which knows only its own
        // vocabulary. Normalizing inward and echoing outward are different
        // directions, which is why the envelope carries both.
        hook::Decision::Deny(reason) => {
            match hook::encode_deny(harness, &envelope.raw_event, &reason)? {
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

fn run_rules(
    out: &mut dyn Write,
    err: &mut dyn Write,
    mode: Mode,
    overrides: &Overrides,
    runner: fn(&[rules::Rule], &Path) -> Result<Vec<rules::Finding>>,
    json: bool,
) -> Result<ExitCode> {
    // The *resolved* rule set, so a local override's added rules are gates a run
    // actually applies rather than config the tool merely prints. The promotion
    // setting comes off the same resolution, so one §8 chain decides both.
    let base_ref = overrides.config_from.as_deref();
    let config = resolve::resolve(Path::new("."), overrides)?;
    let mut findings = runner(&config.rules, Path::new("."))?;

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
        budget::measure_all(Path::new("."), config.budget.as_ref())?
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
    // subdirectory would read a ledger that is not there.
    if let Some(declared) = config.defects.as_ref() {
        findings.extend(defects::gate(&git::repo_root(Path::new("."))?, declared)?);
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
        Path::new("."),
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
            let base = trust::load_base(Path::new("."), reference)?;
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
        Some(source) => std::fs::read_to_string(source)
            .map_err(|err| UsageError::raise(format!("cannot read the brief at {source}: {err}")))?,
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
/// binary does not have — which is the property `completions-check` gates.
fn run_generate(command: &GenerateCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match command {
        GenerateCommand::Completions { shell } => {
            clap_complete::generate(*shell, &mut surface::command(), "batten", out);
        }
        // Two surfaces, two derivations (CLOUD-239): one schema describing both
        // is what let a validator vouch for override keys the loader drops.
        GenerateCommand::Schema { surface } => match surface {
            cli::ConfigSurface::Authority => writeln!(out, "{}", config::schema()?)?,
            cli::ConfigSurface::Override => writeln!(out, "{}", config::override_schema()?)?,
        },
    }
    Ok(ExitCode::Success)
}
